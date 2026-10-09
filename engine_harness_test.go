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
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The engine harness runs the request engine against a scripted agent over an
// in-memory transport. Run inside a testing/synctest bubble, retries and
// deadlines play out on the bubble's clock, so schedules are exact and a
// scenario takes no real time. A transcript records, in the client's
// goroutine, every write, deadline, read and hook call with the time since the
// scenario started; the agent's replies are recorded when it schedules them.

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

// fakeTransport is an in-memory net.Conn to an engineAgent. Each Read returns
// one message, as a datagram socket does, or os.ErrDeadlineExceeded once the
// deadline passes. A reply due at the same instant as a deadline may come
// either way, so scenarios keep them apart. Writes, deadlines and reads can be
// made to fail.
type fakeTransport struct {
	tr    *engineTranscript
	agent engineAgent

	mu       sync.Mutex
	deadline time.Time
	inbox    chan []byte
	writes   int

	writeErrs   map[int]error // by write number
	deadlineErr error
	readErr     error // returned once by the next Read, instead of a message
}

func newFakeTransport(tr *engineTranscript, agent engineAgent) *fakeTransport {
	return &fakeTransport{tr: tr, agent: agent, inbox: make(chan []byte, 64)}
}

func (c *fakeTransport) Write(b []byte) (int, error) {
	c.writes++
	n := c.writes
	c.tr.addf("write #%d: %s", n, describeMessage(b))
	if err := c.writeErrs[n]; err != nil {
		c.tr.addf("write #%d fails: %v", n, err)
		return 0, err
	}
	if c.agent == nil {
		return len(b), nil
	}
	for _, r := range c.agent(n, bytes.Clone(b)) {
		c.tr.addf("agent answers #%d after %s", n, r.after)
		if r.after <= 0 {
			c.inbox <- r.data
			continue
		}
		time.AfterFunc(r.after, func() { c.inbox <- r.data })
	}
	return len(b), nil
}

func (c *fakeTransport) Read(b []byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	readErr := c.readErr
	c.readErr = nil
	c.mu.Unlock()

	if readErr != nil {
		c.tr.addf("read: %v", readErr)
		return 0, readErr
	}
	var expired <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	var msg []byte
	select {
	case msg = <-c.inbox:
	case <-expired:
		select {
		case msg = <-c.inbox:
		default:
			c.tr.addf("read: deadline")
			return 0, os.ErrDeadlineExceeded
		}
	}
	c.tr.addf("read: %s", describeMessage(msg))
	return copy(b, msg), nil
}

func (c *fakeTransport) SetDeadline(t time.Time) error {
	c.tr.addf("deadline +%s", time.Until(t))
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *fakeTransport) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *fakeTransport) SetWriteDeadline(time.Time) error  { return nil }
func (c *fakeTransport) Close() error                      { c.tr.addf("close"); return nil }
func (c *fakeTransport) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
}

func (c *fakeTransport) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 161}
}

// fakePacketTransport is a fakeTransport shaped like an unconnected UDP
// socket: the engine writes with WriteTo and reads with ReadFrom.
type fakePacketTransport struct {
	*fakeTransport
}

func (c fakePacketTransport) ReadFrom(b []byte) (int, net.Addr, error) {
	c.tr.addf("read from")
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c fakePacketTransport) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.tr.addf("write to %s", addr)
	return c.Write(b)
}

// newEngineClient returns a client on conn configured as Connect would leave
// it, with request IDs starting after 1000 and message IDs after 2000, and
// hooks that record their calls in tr.
func newEngineClient(tb testing.TB, tr *engineTranscript, version SnmpVersion, conn net.Conn) *GoSNMP {
	tb.Helper()
	x := &GoSNMP{
		Version:   version,
		Community: "public",
		Timeout:   time.Second,
		Retries:   2,
	}
	if err := x.validateParameters(); err != nil {
		tb.Fatal(err)
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
	fmt.Fprintf(&sb, "%v %v id=%d", p.Version, p.PDUType, p.RequestID)
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
	{"syscall.ECONNREFUSED", syscall.ECONNREFUSED},
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
	text, _, _ := strings.Cut(err.Error(), " Stack:")
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
		fmt.Fprintf(&sb, "packet %v id=%d", p.PDUType, p.RequestID)
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
