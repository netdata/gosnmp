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
	"strconv"
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
// scenario takes no real time. The agent answers inside Write, and ReadFrom
// waits on the bubble's clock for the next reply or the deadline, or until
// another goroutine sets a deadline or closes the connection. A transcript
// records every write, deadline, read and close with the time since the
// scenario started, and the agent's replies when it schedules them.

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

// fakeTransport is an in-memory connection to an engineAgent, shaped like the
// UDP socket Connect opens: the client's transport, written with Write and read
// with ReadFrom, from the agent's address. A read takes the earliest reply
// due, as a datagram: what the buffer does not hold is lost. A read fails with
// os.ErrDeadlineExceeded once the deadline has passed: a reply due at the
// deadline is not read, as on a real socket. A write fails the same way once
// the deadline has passed. Writes and reads can be made to fail by number, and
// deadlines, writes and reads can run the test's code at that moment of a
// request, standing for code that may run then: a Close from another
// goroutine, or a context's methods, the caller's code a request runs. A
// deadline set and a Close from another goroutine wake a waiting read; after
// Close, reads, writes and deadlines fail with net.ErrClosed, as on a socket.
type fakeTransport struct {
	tr    *engineTranscript
	agent engineAgent

	// mu guards the state below, which the engine's goroutine shares with
	// one that sets a deadline or closes the connection.
	mu            sync.Mutex
	pending       []pendingReply // by due time, then by order of scheduling
	deadline      time.Time
	writes, reads int
	closed        bool
	// wake wakes a waiting read when a deadline is set or the connection
	// closes.
	wake chan struct{}

	failWrite   func(n int) error // the error of write n, or nil
	failRead    func(n int) error // the error of read n, or nil
	deadlineErr error
	// holdInterrupt, when set, holds a deadline set in the past until it
	// closes.
	holdInterrupt chan struct{}
	// beforeDeadline, when set, runs before a deadline in the future is set.
	beforeDeadline func()
	// afterWrite, when set, runs after write n succeeded and its replies are
	// on their way, and afterRead after read n returned a reply: the test's
	// code acting on the client during a request (no lock is held).
	afterWrite, afterRead func(n int)
}

func newFakeTransport(tr *engineTranscript, agent engineAgent) *fakeTransport {
	return &fakeTransport{tr: tr, agent: agent, wake: make(chan struct{}, 1)}
}

func (c *fakeTransport) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	n, closed, deadline := c.writes, c.closed, c.deadline
	c.mu.Unlock()
	if c.tr != nil {
		c.tr.addf("write #%d: %s", n, describeMessage(b))
	}
	if closed {
		c.tr.addf("write #%d fails: %v", n, closedWrite)
		return 0, closedWrite
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		c.tr.addf("write #%d: deadline", n)
		return 0, os.ErrDeadlineExceeded
	}
	if c.failWrite != nil {
		if err := c.failWrite(n); err != nil {
			c.tr.addf("write #%d fails: %v", n, err)
			return 0, err
		}
	}
	if c.agent != nil {
		c.schedule(n, b)
	}
	if c.afterWrite != nil {
		c.afterWrite(n)
	}
	return len(b), nil
}

// schedule puts the agent's replies to write n, of b, on their way.
func (c *fakeTransport) schedule(n int, b []byte) {
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
}

// fakeAgentAddr is the agent's address, from which every reply of a fake
// transport comes; shared, so that a read allocates nothing of its own and the
// benchmarks measure the client.
var fakeAgentAddr net.Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 161}

// ReadFrom reads the earliest reply due into b, then runs afterRead.
func (c *fakeTransport) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	c.reads++
	n := c.reads
	c.mu.Unlock()
	size, err := c.readReply(b, n)
	if err == nil && c.afterRead != nil {
		c.afterRead(n)
	}
	return size, fakeAgentAddr, err
}

// readReply is read n's wait for the earliest reply due.
func (c *fakeTransport) readReply(b []byte, n int) (int, error) {
	const op = "read from 127.0.0.2:161"
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
		if !c.deadline.IsZero() && !now.Before(c.deadline) {
			c.tr.addf("%s: deadline", op)
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.pending) > 0 && !c.pending[0].due.After(now) {
			msg := c.pending[0].data
			size := copy(b, msg)
			c.pending = c.pending[1:]
			if c.tr != nil {
				c.tr.addf("%s: %s", op, describeMessage(msg[:size]))
			}
			return size, nil
		}
		var wake time.Time
		if len(c.pending) > 0 {
			wake = c.pending[0].due
		}
		if !c.deadline.IsZero() && (wake.IsZero() || c.deadline.Before(wake)) {
			wake = c.deadline
		}
		c.mu.Unlock()
		c.waitUntil(wake)
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

// SetDeadline sets the deadline of reads and writes. A deadline in the past,
// which the engine sets to interrupt an attempt, is recorded only when it ends
// a deadline that has not passed: when the context's deadline is the
// attempt's, the interrupt and the attempt's own deadline race, and change
// nothing.
func (c *fakeTransport) SetDeadline(t time.Time) error {
	if c.holdInterrupt != nil && t.Before(time.Now()) {
		<-c.holdInterrupt
	}
	if c.beforeDeadline != nil && !t.Before(time.Now()) {
		c.beforeDeadline()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	switch current := c.deadline; {
	case c.tr == nil:
	case !t.Before(now):
		c.tr.addf("deadline +%s", t.Sub(now))
	case current.IsZero() || now.Before(current):
		c.tr.addf("deadline in the past")
	}
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	if c.closed {
		return closedSet
	}
	c.deadline = t
	c.signal()
	return nil
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

// transportOf returns the fake transport that is x's connection.
func transportOf(tb testing.TB, x *Client) *fakeTransport {
	tb.Helper()
	c, ok := x.conn.(*fakeTransport)
	if !ok {
		tb.Fatalf("the client's connection is a %T, not a fake transport", x.conn)
	}
	return c
}

// engineConfig returns the configuration of a v1/v2c client with a 1 s
// timeout and 2 retries.
func engineConfig(version Version) Config {
	return Config{Version: version, Community: "public", Timeout: time.Second, Retries: 2}
}

// newEngineClient returns a client of engineConfig on conn, completed by
// newEngineClientFrom.
func newEngineClient(tb testing.TB, version Version, conn *fakeTransport) *Client {
	tb.Helper()
	return newEngineClientFrom(tb, conn, engineConfig(version))
}

// newEngineClientFrom returns the client NewClient makes of config on conn,
// as Connect would leave it, with request IDs starting after 1000, message IDs
// after 2000 and the next salt 0x101.
func newEngineClientFrom(tb testing.TB, conn *fakeTransport, config Config) *Client {
	tb.Helper()
	x, err := NewClient(config)
	if err != nil {
		tb.Fatal(err)
	}
	usm.Salts.Set(0x101)
	x.conn = conn
	x.rx = new(receiveBuffer)
	x.requestID, x.msgID = 1000, 2000
	return x
}

// decodeMessage decodes a v1/v2c message, as an agent reads a request.
func decodeMessage(b []byte) (*Message, error) {
	p := new(Message)
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
	case p.ErrorStatus != NoError || p.ErrorIndex != 0:
		fmt.Fprintf(&sb, " error=%v index=%d", p.ErrorStatus, p.ErrorIndex)
	}
	fmt.Fprintf(&sb, " %s", describeVarbinds(p.VarBinds))
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

func describeVarbinds(vbs []VarBind) string {
	parts := make([]string, 0, len(vbs))
	for _, vb := range vbs {
		if vb.Value.Type() == Null {
			parts = append(parts, vb.Name)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v:%s", vb.Name, vb.Value.Type(), describeValue(vb.Value)))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// describeValue prints a value for a transcript: octets quoted, a long run cut,
// and "<nil>" for a value without one.
func describeValue(v Value) string {
	if b, ok := v.Bytes(); ok {
		if len(b) > 64 {
			return fmt.Sprintf("%q... (%d octets)", b[:16], len(b))
		}
		return fmt.Sprintf("%q", b)
	}
	if i, ok := v.Int64(); ok {
		return strconv.FormatInt(i, 10)
	}
	if u, ok := v.Uint64(); ok {
		return strconv.FormatUint(u, 10)
	}
	if oid, ok := v.OID(); ok {
		return oid
	}
	if a, ok := v.IP(); ok && a.IsValid() {
		return a.String()
	}
	if f, ok := v.Float32(); ok {
		return fmt.Sprint(f)
	}
	if f, ok := v.Float64(); ok {
		return fmt.Sprint(f)
	}
	return "<nil>"
}

// replyTo encodes the answer of an agent to req: a Response with req's
// version, community and request ID carrying vbs, changed by edit when it is
// not nil.
func replyTo(req []byte, edit func(*Message), vbs ...VarBind) []byte {
	in, err := decodeMessage(req)
	if err != nil {
		panic(fmt.Sprintf("agent cannot decode the request: %v", err))
	}
	out := &Message{
		Version:   in.Version,
		Community: in.Community,
		PDUType:   Response,
		RequestID: in.RequestID,
		VarBinds:  vbs,
	}
	if edit != nil {
		edit(out)
	}
	b, err := out.Encode(nil)
	if err != nil {
		panic(fmt.Sprintf("agent cannot encode the reply: %v", err))
	}
	return b
}

// engineSentinels are the errors an engine result is checked against besides
// the categories (errorCategories).
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
	{"ErrAnswered", ErrAnswered},
}

// describeEngineError gives the text of err and what it is: the sentinels it
// matches and whether it is a timeout net.Error, as callers that classify
// errors see it.
func describeEngineError(err error) string {
	text := err.Error()
	var equals, is []string
	for _, s := range slices.Concat(engineSentinels, errorCategories) {
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
func describeEngineResult(p *Message, err error) string {
	var sb strings.Builder
	switch {
	case p == nil:
		sb.WriteString("packet nil")
	case p.Version == Version3:
		fmt.Fprintf(&sb, "packet 3 msgID=%d %s %v id=%d context=%q/%q", p.MsgID, describeFlags(p.SecurityLevel), p.PDUType,
			p.RequestID, p.ContextEngineID, p.ContextName)
		h := &p.SecurityParameters
		fmt.Fprintf(&sb, " usm=%q/%q/%d/%d", h.UserName, h.AuthoritativeEngineID, h.AuthoritativeEngineBoots,
			h.AuthoritativeEngineTime)
		if p.ErrorStatus != NoError || p.ErrorIndex != 0 {
			fmt.Fprintf(&sb, " error=%v index=%d", p.ErrorStatus, p.ErrorIndex)
		}
		fmt.Fprintf(&sb, " %s", describeVarbinds(p.VarBinds))
	default:
		fmt.Fprintf(&sb, "packet %v %q %v id=%d", p.Version, p.Community, p.PDUType, p.RequestID)
		if p.ErrorStatus != NoError || p.ErrorIndex != 0 {
			fmt.Fprintf(&sb, " error=%v index=%d", p.ErrorStatus, p.ErrorIndex)
		}
		fmt.Fprintf(&sb, " %s", describeVarbinds(p.VarBinds))
	}
	if err == nil {
		sb.WriteString(", no error")
	} else {
		sb.WriteString(", " + describeEngineError(err))
	}
	return sb.String()
}
