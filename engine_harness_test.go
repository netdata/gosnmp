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
	"maps"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/netdata/gosnmp/internal/usm"
)

// The engine harness runs the request engine against a scripted agent over an
// in-memory transport. Run inside a testing/synctest bubble, retries and
// deadlines play out on the bubble's clock, so schedules are exact and a
// scenario takes no real time. The agent answers inside Write, and Read waits
// on the bubble's clock for the next reply or the deadline, or until another
// goroutine sets a deadline or closes the connection. A transcript records
// every write, deadline, read and hook call with the time since the scenario
// started, and the agent's replies when it schedules them.

// engineTranscript is the ordered record of one engine scenario, safe for
// concurrent use. A nil transcript records nothing.
type engineTranscript struct {
	tb    testing.TB
	start time.Time
	mu    sync.Mutex
	lines []string
}

// maxTranscriptLines fails a scenario whose transcript grows past it, far
// beyond the longest scenario, so that a change making the engine loop (a
// regression or a mutant) fails at once instead of growing the transcript
// until the test times out.
const maxTranscriptLines = 5000

func newEngineTranscript(tb testing.TB) *engineTranscript {
	return &engineTranscript{tb: tb, start: time.Now()}
}

func (tr *engineTranscript) addf(format string, args ...any) {
	if tr == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.lines) >= maxTranscriptLines {
		tr.tb.Fatalf("transcript passed %d lines: the scenario does not end", maxTranscriptLines)
	}
	tr.lines = append(tr.lines, fmt.Sprintf("%-5s ", time.Since(tr.start))+fmt.Sprintf(format, args...))
}

// text returns the transcript's lines.
func (tr *engineTranscript) text() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return strings.Join(tr.lines, "\n")
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
// UDP socket. A read takes from the earliest reply due: on the stream shape
// what the buffer does not hold stays for the next read, as on a TCP socket
// (which may also join replies in one read; scenarios space them apart), on
// the UDP shape the rest is lost, as with a datagram. A read fails with
// os.ErrDeadlineExceeded once the read deadline has passed: a reply due at
// the deadline is not read, as on a real socket. A
// write fails the same way once the write deadline has passed. Writes and
// reads can be made to fail by number. A deadline set and a Close from another
// goroutine wake a waiting read; after Close, reads, writes and deadlines fail
// with net.ErrClosed, as on a socket. A TCP client opens a lost connection
// again with a real dial, so those cases run on loopback sockets
// (TestEngineTCPReconnect, TestEngineTCPLostConnection).
type fakeTransport struct {
	tr    *engineTranscript
	agent engineAgent

	// mu guards the state below, which the engine's goroutine shares with
	// one that sets a deadline or closes the connection.
	mu                          sync.Mutex
	pending                     []pendingReply // by due time, then by order of scheduling
	readDeadline, writeDeadline time.Time
	writes, reads               int
	closed                      bool
	// wake wakes a waiting read when a deadline is set or the connection
	// closes.
	wake chan struct{}

	failWrite   func(n int) error // the error of write n, or nil
	failRead    func(n int) error // the error of read n, or nil
	deadlineErr error
	// holdInterrupt, when set, holds a deadline set in the past until it
	// closes.
	holdInterrupt chan struct{}
	// holdWake, when set, holds a woken read until it closes, so that what
	// woke it (an interrupt, then a Close) completes before the read looks.
	holdWake chan struct{}
	// beforeDeadline, when set, runs before a deadline in the future is set.
	beforeDeadline func()
}

func newFakeTransport(tr *engineTranscript, agent engineAgent) *fakeTransport {
	return &fakeTransport{tr: tr, agent: agent, wake: make(chan struct{}, 1)}
}

func (c *fakeTransport) Write(b []byte) (int, error) {
	return c.write(b, "write")
}

func (c *fakeTransport) write(b []byte, op string) (int, error) {
	c.mu.Lock()
	c.writes++
	n, closed, deadline := c.writes, c.closed, c.writeDeadline
	c.mu.Unlock()
	if c.tr != nil {
		c.tr.addf("%s #%d: %s", op, n, describeMessage(b))
	}
	if closed {
		c.tr.addf("%s #%d fails: %v", op, n, closedWrite)
		return 0, closedWrite
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
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
		c.mu.Lock()
		i := len(c.pending)
		for i > 0 && c.pending[i-1].due.After(due) {
			i--
		}
		c.pending = slices.Insert(c.pending, i, pendingReply{due: due, data: r.data})
		c.mu.Unlock()
	}
	return len(b), nil
}

func (c *fakeTransport) Read(b []byte) (int, error) {
	return c.read(b, "read", true)
}

// read reads the earliest reply due into b, keeping what does not fit for the
// next read when stream is set.
func (c *fakeTransport) read(b []byte, op string, stream bool) (int, error) {
	c.mu.Lock()
	c.reads++
	n := c.reads
	c.mu.Unlock()
	if c.failRead != nil {
		if err := c.failRead(n); err != nil {
			c.tr.addf("%s: %v", op, err)
			return 0, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.closed {
			c.tr.addf("%s: %v", op, closedRead)
			return 0, closedRead
		}
		now := time.Now()
		if !c.readDeadline.IsZero() && !now.Before(c.readDeadline) {
			c.tr.addf("%s: deadline", op)
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.pending) > 0 && !c.pending[0].due.After(now) {
			msg := c.pending[0].data
			n := copy(b, msg)
			if stream && n < len(msg) {
				c.pending[0].data = msg[n:]
			} else {
				c.pending = c.pending[1:]
			}
			if c.tr != nil {
				c.tr.addf("%s: %s", op, describeMessage(msg[:n]))
			}
			return n, nil
		}
		var wake time.Time
		if len(c.pending) > 0 {
			wake = c.pending[0].due
		}
		if !c.readDeadline.IsZero() && (wake.IsZero() || c.readDeadline.Before(wake)) {
			wake = c.readDeadline
		}
		c.mu.Unlock()
		c.waitUntil(wake)
		if c.holdWake != nil {
			<-c.holdWake
		}
		c.mu.Lock()
	}
}

// waitUntil waits until t, or, when t is zero, without a time limit, unless a
// deadline set or a Close wakes it first.
func (c *fakeTransport) waitUntil(t time.Time) {
	if t.IsZero() {
		<-c.wake
		return
	}
	timer := time.NewTimer(time.Until(t))
	defer timer.Stop()
	select {
	case <-c.wake:
	case <-timer.C:
	}
}

// signal wakes a waiting read.
func (c *fakeTransport) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// setDeadlines sets the read deadline when read is set and the write deadline
// when write is set, recording it as name. A deadline in the past, which the
// engine sets to interrupt an attempt, is recorded only when it ends a
// deadline that has not passed: when the Context's deadline is the attempt's,
// the interrupt and the attempt's own deadline race, and change nothing.
func (c *fakeTransport) setDeadlines(name string, t time.Time, read, write bool) error {
	if c.holdInterrupt != nil && t.Before(time.Now()) {
		<-c.holdInterrupt
	}
	if c.beforeDeadline != nil && !t.Before(time.Now()) {
		c.beforeDeadline()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	switch current := c.readDeadline; {
	case c.tr == nil:
	case !t.Before(now):
		c.tr.addf("%s +%s", name, t.Sub(now))
	case current.IsZero() || now.Before(current):
		c.tr.addf("%s in the past", name)
	}
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	if c.closed {
		return closedSet
	}
	if read {
		c.readDeadline = t
	}
	if write {
		c.writeDeadline = t
	}
	c.signal()
	return nil
}

func (c *fakeTransport) SetDeadline(t time.Time) error {
	return c.setDeadlines("deadline", t, true, true)
}

func (c *fakeTransport) SetReadDeadline(t time.Time) error {
	return c.setDeadlines("read deadline", t, true, false)
}

func (c *fakeTransport) SetWriteDeadline(t time.Time) error {
	return c.setDeadlines("write deadline", t, false, true)
}

// Close closes the connection, waking a waiting read; closing it again fails,
// as on a socket.
func (c *fakeTransport) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		c.tr.addf("close fails: %v", closedClose)
		return closedClose
	}
	c.tr.addf("close")
	c.closed = true
	c.signal()
	return nil
}

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
	n, err := c.read(b, fmt.Sprintf("read from %s", c.RemoteAddr()), false)
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
// request IDs starting after 1000, message IDs after 2000 and the next salt
// 0x101, and with hooks that record their calls in tr.
func newEngineClientFrom(tb testing.TB, tr *engineTranscript, conn net.Conn, x *GoSNMP) *GoSNMP {
	tb.Helper()
	if err := x.prepare(); err != nil {
		tb.Fatal(err)
	}
	usm.Salts.Set(0x101)
	x.Conn = conn
	x.rx = new(receiveBuffer)
	x.SetRequestID(1000)
	x.SetMsgID(2000)
	if tr != nil {
		x.PreSend = func(*GoSNMP) { tr.addf("hook PreSend") }
		x.OnSent = func(*GoSNMP) { tr.addf("hook OnSent") }
		x.OnRecv = func(*GoSNMP) { tr.addf("hook OnRecv") }
		x.OnRetry = func(*GoSNMP) { tr.addf("hook OnRetry") }
		x.OnFinish = func(*GoSNMP) { tr.addf("hook OnFinish") }
	}
	return x
}

// configOf returns the client's configuration a request must not write: its
// exported fields, but for the hooks and the Logger (user code), Conn (the
// connection) and the SNMPv3 engine state the client learns
// (SecurityParameters, ContextEngineID).
func configOf(x *GoSNMP) map[string]any {
	v := reflect.ValueOf(x).Elem()
	cfg := make(map[string]any)
	for i := range v.NumField() {
		f := v.Type().Field(i)
		switch {
		case !f.IsExported(), f.Type.Kind() == reflect.Func:
			continue
		}
		switch f.Name {
		case "Logger", "Conn", "SecurityParameters", "ContextEngineID":
			continue
		}
		cfg[f.Name] = v.Field(i).Interface()
	}
	return cfg
}

// addConfigChanges records the configuration fields whose values changed
// from before to the client's current ones: a test's hooks may change them,
// the library may not.
func (tr *engineTranscript) addConfigChanges(before map[string]any, x *GoSNMP) {
	after := configOf(x)
	var changed []string
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if !reflect.DeepEqual(before[name], after[name]) {
			changed = append(changed, name)
		}
	}
	if len(changed) > 0 {
		tr.addf("client configuration changed: %s", strings.Join(changed, ", "))
	}
}

// decodeMessage decodes a v1/v2c message, as an agent reads a request.
func decodeMessage(b []byte) (*SnmpPacket, error) {
	p := new(SnmpPacket)
	cursor, _, err := unmarshalHeader(b, p)
	if err != nil {
		return nil, err
	}
	if err := unmarshalPayload(b, cursor, p); err != nil {
		return nil, err
	}
	return p, nil
}

// describeMessage summarizes a message for a transcript, or describes why it
// does not decode. An SNMPv3 message is described by its header, and by its
// scoped PDU when that is not encrypted.
func describeMessage(b []byte) string {
	if version, _, err := readVersion(b); err == nil && version == Version3 {
		return describeV3Message(b)
	}
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

func describeV3Message(b []byte) string {
	m, err := parseV3Message(b)
	if err != nil {
		return fmt.Sprintf("%d octets, SNMPv3, not decodable (%v)", len(b), err)
	}
	req, err := readAgentRequest(m)
	if err != nil {
		return fmt.Sprintf("%d octets, SNMPv3, not decodable (%v)", len(b), err)
	}
	if req.pdu == nil && m.scopedTag != byte(OctetString) {
		return "3 " + describeAgentRequest(req) + " scoped PDU not decodable"
	}
	if req.pdu == nil {
		return "3 " + describeAgentRequest(req) + " encrypted"
	}
	return "3 " + describeAgentRequest(req)
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
			if len(b) > 64 {
				value = fmt.Sprintf("%q... (%d octets)", b[:16], len(b))
			}
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

// describeEngineError gives the text of err and what it is: the sentinels it
// matches and whether it is a timeout net.Error, as callers that classify
// errors see it.
func describeEngineError(err error) string {
	text := err.Error()
	var equals, is []string
	for _, s := range engineSentinels {
		switch {
		case err == s.err: //nolint:errorlint // the identity is what is described
			equals = append(equals, s.name)
		case errors.Is(err, s.err):
			is = append(is, s.name)
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		is = append(is, "net.Error timeout")
	}
	var parts []string
	if len(equals) > 0 {
		parts = append(parts, "equals "+strings.Join(equals, ", "))
	}
	if len(is) > 0 {
		parts = append(parts, "is "+strings.Join(is, ", "))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("error %q %T", text, err)
	}
	return fmt.Sprintf("error %q %T (%s)", text, err, strings.Join(parts, "; "))
}

// describeEngineResult describes what a request returned.
func describeEngineResult(p *SnmpPacket, err error) string {
	var sb strings.Builder
	switch {
	case p == nil:
		sb.WriteString("packet nil")
	case p.PDUType == 0 && p.Version == 0 && len(p.Variables) == 0:
		sb.WriteString("packet empty")
	case p.Version == Version3:
		fmt.Fprintf(&sb, "packet 3 msgID=%d %s %v id=%d context=%q/%q", p.MsgID, describeFlags(p.MsgFlags), p.PDUType,
			p.RequestID, p.ContextEngineID, p.ContextName)
		if usp := usmOf(p.SecurityParameters); usp != nil {
			fmt.Fprintf(&sb, " usm=%q/%q/%d/%d", usp.UserName, usp.AuthoritativeEngineID, usp.AuthoritativeEngineBoots,
				usp.AuthoritativeEngineTime)
		}
		if p.Error != NoError || p.ErrorIndex != 0 {
			fmt.Fprintf(&sb, " error=%v index=%d", p.Error, p.ErrorIndex)
		}
		fmt.Fprintf(&sb, " %s", describeVarbinds(p.Variables))
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
