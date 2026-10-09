// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The engine harness runs the request engine against a scripted agent over an
// in-memory transport. Run inside a testing/synctest bubble, retries and
// deadlines play out on the bubble's clock, so schedules are exact and a
// scenario takes no real time. Everything runs in the client's goroutine: the
// agent answers inside Write, and Read waits on the bubble's clock for the
// next reply or the deadline. A transcript records every write, deadline,
// read and hook call with the time since the scenario started, and the
// agent's replies when it schedules them.

// engineTranscript is the ordered record of one engine scenario. A nil
// transcript records nothing.
type engineTranscript struct {
	start time.Time
	lines []string
}

func newEngineTranscript() *engineTranscript {
	return &engineTranscript{start: time.Now()}
}

func (tr *engineTranscript) addf(format string, args ...any) {
	if tr == nil {
		return
	}
	tr.lines = append(tr.lines, fmt.Sprintf("%-5s ", time.Since(tr.start))+fmt.Sprintf(format, args...))
}

// agentReply is a message the agent sends in answer to a request, after a delay
// counted from the request's write.
type agentReply struct {
	data  []byte
	after time.Duration
}

// engineAgent answers the n-th write (counted from 1) with replies.
type engineAgent func(n int, req []byte) []agentReply

// pendingReply is a reply on its way to the client.
type pendingReply struct {
	due  time.Time
	data []byte
}

// fakeTransport is an in-memory connection to an engineAgent, shaped like a
// TCP socket or a custom net.Conn; fakePacketTransport gives it the shape of a
// UDP socket. Each read returns one reply, the earliest due, as a datagram
// socket does, and fails with os.ErrDeadlineExceeded once the read deadline
// has passed: a reply due at the deadline is not read, as on a real socket. A
// write fails the same way once the write deadline has passed. Writes and
// reads can be made to fail by number. An io.EOF read on a TCP client makes
// the engine reconnect with a real dial, so those cases run on loopback
// sockets (TestEngineTCPReconnect).
type fakeTransport struct {
	tr    *engineTranscript
	agent engineAgent

	pending                     []pendingReply // by due time, then by order of scheduling
	readDeadline, writeDeadline time.Time
	writes, reads               int

	failWrite   func(n int) error // the error of write n, or nil
	failRead    func(n int) error // the error of read n, or nil
	deadlineErr error
}

func newFakeTransport(tr *engineTranscript, agent engineAgent) *fakeTransport {
	return &fakeTransport{tr: tr, agent: agent}
}

func (c *fakeTransport) Write(b []byte) (int, error) {
	return c.write(b, "write")
}

func (c *fakeTransport) write(b []byte, op string) (int, error) {
	c.writes++
	n := c.writes
	if c.tr != nil {
		c.tr.addf("%s #%d: %s", op, n, describeMessage(b))
	}
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		c.tr.addf("%s #%d: deadline", op, n)
		return 0, os.ErrDeadlineExceeded
	}
	if c.failWrite != nil {
		if err := c.failWrite(n); err != nil {
			c.tr.addf("%s #%d fails: %v", op, n, err)
			return 0, err
		}
	}
	if c.agent == nil {
		return len(b), nil
	}
	for _, r := range c.agent(n, bytes.Clone(b)) {
		c.tr.addf("agent answers #%d after %s", n, r.after)
		due := time.Now().Add(r.after)
		i := len(c.pending)
		for i > 0 && c.pending[i-1].due.After(due) {
			i--
		}
		c.pending = slices.Insert(c.pending, i, pendingReply{due: due, data: r.data})
	}
	return len(b), nil
}

func (c *fakeTransport) Read(b []byte) (int, error) {
	return c.read(b, "read")
}

func (c *fakeTransport) read(b []byte, op string) (int, error) {
	c.reads++
	if c.failRead != nil {
		if err := c.failRead(c.reads); err != nil {
			c.tr.addf("%s: %v", op, err)
			return 0, err
		}
	}
	for {
		now := time.Now()
		if !c.readDeadline.IsZero() && !now.Before(c.readDeadline) {
			c.tr.addf("%s: deadline", op)
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.pending) > 0 && !c.pending[0].due.After(now) {
			msg := c.pending[0].data
			c.pending = c.pending[1:]
			if c.tr != nil {
				c.tr.addf("%s: %s", op, describeMessage(msg))
			}
			return copy(b, msg), nil
		}
		var wake time.Time
		if len(c.pending) > 0 {
			wake = c.pending[0].due
		}
		if !c.readDeadline.IsZero() && (wake.IsZero() || c.readDeadline.Before(wake)) {
			wake = c.readDeadline
		}
		if wake.IsZero() {
			panic("fakeTransport: a read without a deadline would block forever")
		}
		time.Sleep(time.Until(wake))
	}
}

func (c *fakeTransport) SetDeadline(t time.Time) error {
	c.tr.addf("deadline +%s", time.Until(t))
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	c.readDeadline, c.writeDeadline = t, t
	return nil
}

func (c *fakeTransport) SetReadDeadline(t time.Time) error {
	c.tr.addf("read deadline +%s", time.Until(t))
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	c.readDeadline = t
	return nil
}

func (c *fakeTransport) SetWriteDeadline(t time.Time) error {
	c.tr.addf("write deadline +%s", time.Until(t))
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	c.writeDeadline = t
	return nil
}

func (c *fakeTransport) Close() error { c.tr.addf("close"); return nil }
func (c *fakeTransport) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
}

func (c *fakeTransport) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 161}
}

// fakePacketTransport is a fakeTransport shaped like a UDP socket, connected
// as Connect leaves it or unconnected: a net.PacketConn, which the engine reads
// with ReadFrom.
type fakePacketTransport struct {
	*fakeTransport
}

func (c fakePacketTransport) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.read(b, "read from")
	return n, c.RemoteAddr(), err
}

func (c fakePacketTransport) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.write(b, fmt.Sprintf("write to %s", addr))
}

// newEngineClient returns a v1/v2c client on conn with a 1 s timeout and 2
// retries, completed by newEngineClientFrom.
func newEngineClient(tb testing.TB, tr *engineTranscript, version SnmpVersion, conn net.Conn) *GoSNMP {
	tb.Helper()
	return newEngineClientFrom(tb, tr, conn, &GoSNMP{
		Version:   version,
		Community: "public",
		Timeout:   time.Second,
		Retries:   2,
	})
}

// newEngineClientFrom completes x on conn as Connect would leave it, with
// request IDs starting after 1000, message IDs after 2000 and fixed salt
// counters, and with hooks that record their calls in tr.
func newEngineClientFrom(tb testing.TB, tr *engineTranscript, conn net.Conn, x *GoSNMP) *GoSNMP {
	tb.Helper()
	if err := x.validateParameters(); err != nil {
		tb.Fatal(err)
	}
	if usp := usmOf(x.SecurityParameters); usp != nil {
		usp.localAESSalt, usp.localDESSalt = 0x100, 0x100
	}
	x.Conn = conn
	x.rxBuf = new([rxBufSize]byte)
	x.requestID, x.msgID = 1000, 2000
	if tr != nil {
		x.PreSend = func(*GoSNMP) { tr.addf("hook PreSend") }
		x.OnSent = func(*GoSNMP) { tr.addf("hook OnSent") }
		x.OnRecv = func(*GoSNMP) { tr.addf("hook OnRecv") }
		x.OnRetry = func(*GoSNMP) { tr.addf("hook OnRetry") }
		x.OnFinish = func(*GoSNMP) { tr.addf("hook OnFinish") }
	}
	return x
}

// decodeMessage decodes a v1/v2c message, as an agent reads a request.
func decodeMessage(b []byte) (*SnmpPacket, error) {
	p := new(SnmpPacket)
	cursor, err := (&GoSNMP{}).unmarshalHeader(b, p)
	if err != nil {
		return nil, err
	}
	if err := unmarshalPayload(b, cursor, p); err != nil {
		return nil, err
	}
	return p, nil
}

// describeMessage summarizes a v1/v2c message for a transcript, or describes
// why it does not decode.
func describeMessage(b []byte) string {
	p, err := decodeMessage(b)
	if err != nil {
		return fmt.Sprintf("%d octets, not decodable (%v)", len(b), err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%v %q %v id=%d", p.Version, p.Community, p.PDUType, p.RequestID)
	switch {
	case p.PDUType == GetBulkRequest:
		fmt.Fprintf(&sb, " nonRepeaters=%d maxRepetitions=%d", p.NonRepeaters, p.MaxRepetitions)
	case p.Error != NoError || p.ErrorIndex != 0:
		fmt.Fprintf(&sb, " error=%v index=%d", p.Error, p.ErrorIndex)
	}
	fmt.Fprintf(&sb, " %s", describeVarbinds(p.Variables))
	return sb.String()
}

func describeVarbinds(vbs []SnmpPDU) string {
	parts := make([]string, 0, len(vbs))
	for _, vb := range vbs {
		if vb.Type == Null {
			parts = append(parts, vb.Name)
			continue
		}
		value := vb.Value
		if b, ok := value.([]byte); ok {
			value = fmt.Sprintf("%q", b)
		}
		parts = append(parts, fmt.Sprintf("%s=%v:%v", vb.Name, vb.Type, value))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// replyTo encodes the answer of an agent to req: a GetResponse with req's
// version, community and request ID carrying vbs, changed by edit when it is
// not nil.
func replyTo(req []byte, edit func(*SnmpPacket), vbs ...SnmpPDU) []byte {
	in, err := decodeMessage(req)
	if err != nil {
		panic(fmt.Sprintf("agent cannot decode the request: %v", err))
	}
	out := &SnmpPacket{
		Version:   in.Version,
		Community: in.Community,
		PDUType:   GetResponse,
		RequestID: in.RequestID,
		Variables: vbs,
	}
	if edit != nil {
		edit(out)
	}
	b, err := out.marshalMsg()
	if err != nil {
		panic(fmt.Sprintf("agent cannot encode the reply: %v", err))
	}
	return b
}

// engineSentinels are the errors an engine result is checked against.
var engineSentinels = []struct {
	name string
	err  error
}{
	{"context.Canceled", context.Canceled},
	{"context.DeadlineExceeded", context.DeadlineExceeded},
	{"os.ErrDeadlineExceeded", os.ErrDeadlineExceeded},
	{"io.EOF", io.EOF},
	{"net.ErrClosed", net.ErrClosed},
	{"syscall.ECONNREFUSED", syscall.ECONNREFUSED},
	{"syscall.ECONNRESET", syscall.ECONNRESET},
	{"syscall.EHOSTUNREACH", syscall.EHOSTUNREACH},
	{"syscall.EACCES", syscall.EACCES},
	{"errEngineWrite", errEngineWrite},
	{"ErrDecryption", ErrDecryption},
	{"ErrInvalidMsgs", ErrInvalidMsgs},
	{"ErrNotInTimeWindow", ErrNotInTimeWindow},
	{"ErrUnknownEngineID", ErrUnknownEngineID},
	{"ErrUnknownPDUHandlers", ErrUnknownPDUHandlers},
	{"ErrUnknownReportPDU", ErrUnknownReportPDU},
	{"ErrUnknownSecurityLevel", ErrUnknownSecurityLevel},
	{"ErrUnknownSecurityModels", ErrUnknownSecurityModels},
	{"ErrUnknownUsername", ErrUnknownUsername},
	{"ErrWrongDigest", ErrWrongDigest},
}

// describeEngineError gives the text of err, cut before a recovered panic's
// stack, and what it is: the sentinels it matches and whether it is a timeout
// net.Error, as callers that classify errors see it.
func describeEngineError(err error) string {
	text, _, stack := strings.Cut(err.Error(), " Stack:")
	if stack {
		text += " Stack: ..."
	}
	var is []string
	for _, s := range engineSentinels {
		if errors.Is(err, s.err) {
			is = append(is, s.name)
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		is = append(is, "net.Error timeout")
	}
	if len(is) == 0 {
		return fmt.Sprintf("error %q", text)
	}
	return fmt.Sprintf("error %q (is %s)", text, strings.Join(is, ", "))
}

// describeEngineResult describes what a request returned.
func describeEngineResult(p *SnmpPacket, err error) string {
	var sb strings.Builder
	switch {
	case p == nil:
		sb.WriteString("packet nil")
	case p.PDUType == 0 && p.Version == 0 && len(p.Variables) == 0:
		sb.WriteString("packet empty")
	default:
		fmt.Fprintf(&sb, "packet %v %q %v id=%d", p.Version, p.Community, p.PDUType, p.RequestID)
		if p.Error != NoError || p.ErrorIndex != 0 {
			fmt.Fprintf(&sb, " error=%v index=%d", p.Error, p.ErrorIndex)
		}
		fmt.Fprintf(&sb, " %s", describeVarbinds(p.Variables))
	}
	if err == nil {
		sb.WriteString(", no error")
	} else {
		sb.WriteString(", " + describeEngineError(err))
	}
	return sb.String()
}
