// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
)

var engineGolden = goldenFiles{dir: "testdata/engine", title: "Engine"}

const engineOID = ".1.3.6.1.2.1.1.1.0"

// engineScenario is one v1/v2c request run against a scripted agent.
type engineScenario struct {
	v1 bool // SNMPv1 instead of SNMPv2c
	// config, when set, changes the client's configuration before NewClient.
	config func(c *Config)
	setup  func(x *Client, c *fakeTransport)
	// context, when set, gives the request's context, background unless
	// set; its cancel runs when the scenario ends.
	context func() (context.Context, context.CancelFunc)
	agent   engineAgent
	run     func(ctx context.Context, x *Client) (*Message, error) // a Get of engineOID unless set
}

// answer is an agent that answers every request at once with vbs.
func answer(vbs ...VarBind) engineAgent {
	return answerWith(nil, vbs...)
}

// answerWith is an agent that answers every request at once with a reply
// changed by edit.
func answerWith(edit func(*Message), vbs ...VarBind) engineAgent {
	return func(_ int, req []byte) []agentReply {
		return []agentReply{{data: replyTo(req, edit, vbs...)}}
	}
}

// errEngineCause is the cause a scenario cancels its context with.
var errEngineCause = errors.New("engine test cause")

// bareV3Report encodes an SNMPv3 noAuthNoPriv Report answering req whose
// msgData is the Report PDU itself, without the scoped PDU around it, so that
// a v1/v2c client reads it as the PDU after the SNMPv3 header.
func bareV3Report(req []byte, counter string) []byte {
	return bareV3Answer(req, 7, Report, VarBind{Name: counter, Value: Counter32Value(1)})
}

// bareV3Answer is bareV3Report with msgID for a PDU of type pduType with vbs.
func bareV3Answer(req []byte, msgID uint32, pduType PDUType, vbs ...VarBind) []byte {
	in, err := decodeMessage(req)
	if err != nil {
		panic(fmt.Sprintf("agent cannot decode the request: %v", err))
	}
	out := &Message{
		Version: Version3, SecurityLevel: NoAuthNoPriv,
		SecurityParameters: SecurityParameters{UserName: "public"},
		PDUType:            pduType, RequestID: in.RequestID, MsgID: msgID,
		VarBinds: vbs,
	}
	b, err := out.Encode(nil)
	if err != nil {
		panic(fmt.Sprintf("agent cannot encode the reply: %v", err))
	}
	m, err := parseV3Message(b)
	if err != nil {
		panic(fmt.Sprintf("agent cannot read its reply: %v", err))
	}
	r := ber.NewReader(m.scoped)
	for range 2 { // context engine ID and context name
		if _, _, err = r.Next(); err != nil {
			panic(err)
		}
	}
	if m.scopedTag, m.scoped, err = r.Next(); err != nil {
		panic(err)
	}
	return m.bytes()
}

// answerFromSecond is an agent that answers the requests from the second on
// with vbs.
func answerFromSecond(vbs ...VarBind) engineAgent {
	return answerFrom(2, vbs...)
}

// answerFrom is an agent that answers the requests from the first-th on with
// vbs.
func answerFrom(first int, vbs ...VarBind) engineAgent {
	return func(n int, req []byte) []agentReply {
		if n < first {
			return nil
		}
		return []agentReply{{data: replyTo(req, nil, vbs...)}}
	}
}

// errCallerFailure is what the caller's code panics with in the panic
// scenarios.
var errCallerFailure = errors.New("the caller's code failed")

// panicWithError panics with errCallerFailure.
func panicWithError() { panic(errCallerFailure) }

// panicOnNilMap panics with a runtime error: an assignment to a nil map.
func panicOnNilMap() {
	var m map[string]int
	m["key"]++ //nolint:staticcheck // the runtime error is the point
}

// panicsOnce returns a transport function that panics through fail the first
// time it runs, which the transcript names as what with its number n.
func panicsOnce(c *fakeTransport, what string, fail func()) func(n int) error {
	armed := true
	return func(n int) error {
		if armed {
			armed = false
			c.tr.addf("%s #%d panics", what, n)
			fail()
		}
		return nil
	}
}

// asAction drops the error of a transport function that never fails.
func asAction(f func(n int) error) func(n int) {
	return func(n int) { _ = f(n) }
}

// atDeadline makes the fake connection run act as it sets deadline k in the
// future (counted from 1), the deadline of the k-th attempt it sees, before
// setting it.
func atDeadline(c *fakeTransport, k int, act func()) {
	n := 0
	c.beforeDeadline = func() {
		if n++; n == k {
			act()
		}
	}
}

// getAfterPanic runs a Get in which the caller's code panics (the scenario's
// setup arms it), records its result and what its error matches, then runs a
// second Get on the same client, whose result it returns.
func getAfterPanic(ctx context.Context, x *Client) (*Message, error) {
	tr := x.conn.(*fakeTransport).tr
	res, err := x.Get(ctx, []string{engineOID})
	tr.addf("first request: %s", describeEngineResult(res, err))
	var re runtime.Error
	tr.addf("first request's error: matches the caller's error %t, a runtime.Error %t", errors.Is(err, errCallerFailure),
		errors.As(err, &re))
	return x.Get(ctx, []string{engineOID})
}

// answerRaw is an agent that answers every request with its sysDescr reply
// changed by edit as encoded octets.
func answerRaw(edit func(reply []byte) []byte) engineAgent {
	return func(_ int, req []byte) []agentReply {
		return []agentReply{{data: edit(replyTo(req, nil, sysDescr))}}
	}
}

var sysDescr = VarBind{Name: engineOID, Value: OctetStringValue([]byte("codec agent"))}

// replySized is the reply to req of size octets, with one OctetString value.
func replySized(req []byte, size int) []byte {
	n := size - 100
	for {
		r := replyTo(req, nil, VarBind{Name: engineOID, Value: OctetStringValue(bytes.Repeat([]byte{'x'}, n))})
		if len(r) == size {
			return r
		}
		n += size - len(r)
	}
}

// errorStatusOutOfRange is the sysDescr reply to req, its request ID raised by
// idDelta, with the error status -1: the request ID decodes, then the PDU
// fails.
func errorStatusOutOfRange(req []byte, idDelta uint32) []byte {
	r := replyTo(req, func(p *Message) { p.RequestID += idDelta }, sysDescr)
	i := bytes.Index(r, []byte{byte(Integer), 1, 0, byte(Integer), 1, 0}) // error status and index
	if i < 0 {
		panic("no error status")
	}
	r[i+2] = 0xff
	return r
}

// errEngineWrite is the error of a failing write in the engine scenarios.
var errEngineWrite = errors.New("codec write failure")

// refused is the error of a read from a UDP socket whose target port is
// closed.
var refused = &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}

// closedRead, closedWrite, closedSet and closedClose are the errors of a
// read, a write, a deadline and a Close on a UDP socket that net.Conn.Close
// closed.
var (
	closedRead  = &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}
	closedWrite = &net.OpError{Op: "write", Net: "udp", Err: net.ErrClosed}
	closedSet   = &net.OpError{Op: "set", Net: "udp", Err: net.ErrClosed}
	closedClose = &net.OpError{Op: "close", Net: "udp", Err: net.ErrClosed}
)

// withEngineTimeout gives a context that times out after d.
func withEngineTimeout(d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), d)
	}
}

// nilContext gives a nil context, a caller's bug a request refuses.
func nilContext() (context.Context, context.CancelFunc) { return nil, func() {} }

// canceledContext gives a context canceled before the request starts.
func canceledContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}

// canceledAfter gives a context canceled after d. A cancellation at the
// instant an attempt's deadline passes races the read's timeout, so scenarios
// cancel between attempt boundaries.
func canceledAfter(d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(d, cancel)
		return ctx, cancel
	}
}

// canceledBeforeDeadline gives a context with deadline d, canceled after
// cancelAt.
func canceledBeforeDeadline(cancelAt, d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		time.AfterFunc(cancelAt, cancel)
		return ctx, cancel
	}
}

// unreportedDeadline is a context with a deadline that it does not report as
// passed: on a real clock, the moment between the deadline and the timer that
// cancels the context, which a synctest bubble never shows.
type unreportedDeadline struct {
	context.Context
	deadline time.Time
}

func (c unreportedDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

// withUnreportedDeadline gives an unreportedDeadline context with deadline d.
func withUnreportedDeadline(d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		return unreportedDeadline{context.Background(), time.Now().Add(d)}, func() {}
	}
}

// doneAtErrCall gives a context that is done with err as its Err method is
// called the n-th time, as if canceled, or its deadline passed, just then: a
// request checks its context before each attempt and after each failed one,
// so n picks a point between two attempts. It reports no deadline.
func doneAtErrCall(n int, err error) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		return &doneAtErr{Context: context.Background(), n: int64(n), err: err, done: make(chan struct{})}, func() {}
	}
}

// doneAtErr is the context of doneAtErrCall; context.AfterFunc reads it on a
// goroutine of its own.
type doneAtErr struct {
	context.Context
	n     int64
	calls atomic.Int64
	err   error
	done  chan struct{}
}

func (c *doneAtErr) Done() <-chan struct{} { return c.done }

func (c *doneAtErr) Err() error {
	switch n := c.calls.Add(1); {
	case n == c.n:
		close(c.done)
		fallthrough
	case n > c.n:
		return c.err
	}
	return nil
}

func getOIDs(oids ...string) func(ctx context.Context, x *Client) (*Message, error) {
	return func(ctx context.Context, x *Client) (*Message, error) { return x.Get(ctx, oids) }
}

// engineScenarios are the request scenarios of TestEngineRequestCharacterization.
func engineScenarios() map[string]engineScenario {
	twoGets := func(ctx context.Context, x *Client) (*Message, error) {
		if _, err := x.Get(ctx, []string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		return x.Get(ctx, []string{engineOID})
	}
	maxOIDs2 := func(c *Config) { c.MaxOids = 2 }
	twoOIDs := []string{engineOID, ".1.3.6.1.2.1.1.3.0"}
	threeOIDs := []string{engineOID, ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"}

	scenarios := map[string]engineScenario{
		// Operations.
		"get":    {agent: answer(sysDescr)},
		"get/v1": {v1: true, agent: answer(sysDescr)},
		"mk-snmp-packet": {agent: answer(sysDescr), run: func(ctx context.Context, x *Client) (*Message, error) {
			return x.send(ctx, x.NewMessage(GetBulkRequest, []VarBind{{Name: ".1.3.6.1.2.1.1", Value: NullValue()}}, 2, 7))
		}},
		"get/invalid-oid": {agent: answer(), run: getOIDs(".1.3.6.1.x")},

		// The MaxOids limit, at 2.
		"get/max-oids/at-limit":   {agent: answer(sysDescr), config: maxOIDs2, run: getOIDs(twoOIDs...)},
		"get/max-oids/over-limit": {agent: answer(sysDescr), config: maxOIDs2, run: getOIDs(threeOIDs...)},

		// A client Connect never connected.
		"get/no-conn": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.conn = nil }},

		// Timeouts and retries.
		"timeout":            {},
		"timeout/no-retries": {config: func(c *Config) { c.Retries = 0 }},
		// The configured Timeout bounds each attempt.
		"timeout/configured": {config: func(c *Config) { c.Timeout = 3 * time.Second }},
		// A zero Timeout means 1 s.
		"timeout/zero":          {agent: answer(sysDescr), config: func(c *Config) { c.Timeout = 0 }},
		"answer/second-attempt": {agent: answerFromSecond(sysDescr)},

		// Reply matching.
		"answer/late": {agent: func(n int, req []byte) []agentReply {
			if n == 1 {
				return []agentReply{{data: replyTo(req, nil, sysDescr), after: 1500 * time.Millisecond}}
			}
			return nil
		}},
		"answer/late-by-two-attempts": {agent: func(n int, req []byte) []agentReply {
			if n == 1 {
				return []agentReply{{data: replyTo(req, nil, sysDescr), after: 2500 * time.Millisecond}}
			}
			return nil
		}},
		"answer/late-reply-read-by-next-request": {run: twoGets, agent: func(n int, req []byte) []agentReply {
			switch n {
			case 1:
				return []agentReply{{data: replyTo(req, nil, sysDescr), after: 1500 * time.Millisecond}}
			case 2:
				return []agentReply{{data: replyTo(req, nil, sysDescr)}}
			default:
				return []agentReply{{data: replyTo(req, nil, sysDescr), after: 800 * time.Millisecond}}
			}
		}},
		"answer/duplicated": {run: twoGets, agent: func(_ int, req []byte) []agentReply {
			r := replyTo(req, nil, sysDescr)
			return []agentReply{{data: r}, {data: r}}
		}},
		"answer/first-result-after-second-get": {
			run: func(ctx context.Context, x *Client) (*Message, error) {
				first, err := x.Get(ctx, []string{engineOID})
				if err != nil {
					return nil, fmt.Errorf("first Get: %w", err)
				}
				if _, err := x.Get(ctx, []string{engineOID}); err != nil {
					return nil, fmt.Errorf("second Get: %w", err)
				}
				return first, nil
			},
			agent: func(n int, req []byte) []agentReply {
				value := fmt.Sprintf("codec agent %d", n)
				return []agentReply{{data: replyTo(req, nil, VarBind{Name: engineOID, Value: OctetStringValue([]byte(value))})}}
			},
		},
		"answer/wrong-id": {agent: answerWith(func(p *Message) { p.RequestID += 100 }, sysDescr)},
		"answer/zero-id": {
			agent: answerWith(func(p *Message) { p.RequestID = 0 }, sysDescr),
		},
		"answer/v1-trap": {
			agent: func(int, []byte) []agentReply {
				trap := &Message{
					Version: Version1, Community: "public", PDUType: Trap, VarBinds: []VarBind{sysDescr},
					Enterprise: ".1.3.6.1.4.1.8072", AgentAddress: netip.MustParseAddr("127.0.0.2"), GenericTrap: 6, SpecificTrap: 1,
				}
				b, err := trap.Encode(nil)
				if err != nil {
					panic(err)
				}
				return []agentReply{{data: b}}
			},
		},
		"answer/empty": {agent: answerWith(nil)},
		"answer/empty-wrong-id": {
			agent: answerWith(func(p *Message) { p.RequestID += 100 }),
		},
		"answer/empty-with-error-status-wrong-id": {agent: answerWith(func(p *Message) { p.RequestID += 100; p.ErrorStatus = GenErr })},
		"answer/error-status":                     {agent: answerWith(func(p *Message) { p.ErrorStatus, p.ErrorIndex = NoSuchName, 1 }, VarBind{Name: engineOID, Value: NullValue()})},
		"answer/not-a-response": {
			agent: answerWith(func(p *Message) { p.PDUType = GetRequest }, sysDescr),
		},
		"answer/reflected-request": {
			agent: func(_ int, req []byte) []agentReply { return []agentReply{{data: bytes.Clone(req)}} },
		},
		"answer/report": {
			agent: answerWith(func(p *Message) { p.PDUType = Report }, sysDescr),
		},
		"answer/unknown-pdu-type": {
			agent: answerRaw(func(r []byte) []byte {
				r[bytes.IndexByte(r, byte(Response))] = 0xaf
				return r
			}),
		},
		"answer/other-version": {
			agent: answerWith(func(p *Message) { p.Version = Version1 }, sysDescr),
		},
		// Replies that answer nothing, each followed by the answer.
		"answer/other-version-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: replyTo(req, func(p *Message) { p.Version = Version1 }, sysDescr)}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/zero-id-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: replyTo(req, func(p *Message) { p.RequestID = 0 }, sysDescr)}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/empty-wrong-id-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: replyTo(req, func(p *Message) { p.RequestID += 100 })}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/other-version-v3": {
			agent: answerWith(func(p *Message) {
				p.Version, p.SecurityLevel = Version3, NoAuthNoPriv
				p.SecurityParameters = SecurityParameters{UserName: "public"}
			}, sysDescr),
		},
		"answer/other-version-v3-report": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: bareV3Report(req, usmStatsUnknownUserNames)}}
			},
		},
		"answer/other-version-v3-unknown-engine-report": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: bareV3Report(req, usmStatsUnknownEngineIDs)}}
			},
		},
		"answer/other-version-v3-msg-id-zero": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: bareV3Answer(req, 0, Report, VarBind{Name: usmStatsUnknownUserNames, Value: Counter32Value(1)})}}
			},
		},
		"answer/other-version-v3-get-response": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: bareV3Answer(req, 7, Response, sysDescr)}}
			},
		},
		"answer/other-community": {agent: answerWith(func(p *Message) { p.Community = "private" }, sysDescr)},
		"answer/garbage-then-valid": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: garbage}, {data: replyTo(req, nil, sysDescr)}}
			},
		},
		"answer/garbage": {agent: func(int, []byte) []agentReply { return []agentReply{{data: garbage}} }},
		// A reply with the request's ID whose PDU does not decode, then a
		// datagram another sender sent.
		"answer/undecodable-then-garbage": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: errorStatusOutOfRange(req, 0)}, {data: garbage}}
		}},
		"answer/undecodable-other-request": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: errorStatusOutOfRange(req, 100)}}
		}},
		// The largest datagram the receive buffer accepts.
		"answer/largest-udp": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: replySized(req, rxBufSize-1)}}
			},
		},
		// A datagram that fills the receive buffer, which may have been cut
		// short: the attempt fails, and the retry uses the same socket.
		"answer/too-big-udp": {
			config: func(c *Config) { c.Retries = 1 },
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: replySized(req, rxBufSize)}}
			},
		},

		// Transport errors.
		"write-error/once": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failWrite = func(n int) error { return map[int]error{1: errEngineWrite}[n] }
		}},
		"write-error/always": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failWrite = func(int) error { return errEngineWrite }
		}},
		"write-error/timeout-in-text": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failWrite = func(int) error { return errors.New("codec timeout of the write queue") }
		}},
		"deadline-error": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.deadlineErr = errors.New("codec deadline failure")
		}},
		"read-error/once": {agent: answerFromSecond(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failRead = func(n int) error { return map[int]error{1: refused}[n] }
		}},
		"read-error/always": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failRead = func(int) error { return refused }
		}},
		// The connection closed under the read and under the write: from then
		// on its deadline cannot be set either.
		"read-error/closed": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failRead = func(int) error {
				c.deadlineErr = closedSet
				return closedRead
			}
		}},
		"write-error/closed": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failWrite = func(int) error {
				c.deadlineErr = closedSet
				return closedWrite
			}
		}},
		"read-eof/udp": {agent: answerFromSecond(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failRead = func(n int) error { return map[int]error{1: io.EOF}[n] }
		}},

		// The request's context.
		"context/canceled-before": {agent: answer(sysDescr), context: canceledContext},
		// A nil context fails the request before it is sent.
		"context/nil": {agent: answer(sysDescr), context: nilContext},
		"context/canceled-with-cause-before": {agent: answer(sysDescr), context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(errEngineCause)
			return ctx, func() { cancel(nil) }
		}},
		// A context canceled with a cause during an attempt ends the request
		// with context.Canceled too, not the cause.
		"context/canceled-with-cause-while-waiting": {context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancelCause(context.Background())
			time.AfterFunc(300*time.Millisecond, func() { cancel(errEngineCause) })
			return ctx, func() { cancel(nil) }
		}},
		"context/deadline-equal-to-timeout": {
			context: withEngineTimeout(time.Second),
			config:  func(c *Config) { c.Retries = 0 },
		},
		"context/deadline-in-first-attempt":   {context: withEngineTimeout(700 * time.Millisecond)},
		"context/deadline-in-third-attempt":   {context: withEngineTimeout(2500 * time.Millisecond)},
		"context/deadline-after-all-attempts": {context: withEngineTimeout(time.Hour)},
		// A context canceled after the decision to retry, before the next
		// attempt starts: the attempt does not start.
		"context/canceled-between-attempts": {context: doneAtErrCall(3, context.Canceled)},
		// The deadline rule does not wait for the context to report its
		// deadline, also when the deadlines are equal.
		"context/deadline-unreported-in-first-attempt": {context: withUnreportedDeadline(700 * time.Millisecond)},
		"context/deadline-unreported-equal-to-timeout": {
			context: withUnreportedDeadline(time.Second),
			config:  func(c *Config) { c.Retries = 0 },
		},
		// A context whose deadline passed ends the request after an attempt
		// that failed otherwise, before the decision to retry.
		"context/deadline-passed-in-conn-write": {
			context: withEngineTimeout(700 * time.Millisecond),
			setup: func(_ *Client, c *fakeTransport) {
				c.afterWrite = func(n int) {
					c.tr.addf("the Conn's write #%d takes 1s", n)
					time.Sleep(time.Second)
				}
				c.failRead = func(int) error { return refused }
			},
		},
		// A context canceled before its deadline ends the attempt and the
		// request at the cancellation, with context.Canceled.
		"context/canceled-before-deadline": {context: canceledBeforeDeadline(300*time.Millisecond, 700*time.Millisecond)},
		"context/canceled-while-waiting":   {context: canceledAfter(300 * time.Millisecond)},
		"context/canceled-in-last-attempt": {context: canceledAfter(2300 * time.Millisecond)},
		// A context canceled while the reply is on its way, its interrupt held
		// until after the reply: the request ends when the interrupt does, so
		// that its deadline cannot reach a later request.
		"context/canceled-before-a-reply": {
			context: canceledAfter(50 * time.Millisecond),
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: replyTo(req, nil, sysDescr), after: 100 * time.Millisecond}}
			},
			setup: func(_ *Client, c *fakeTransport) {
				hold := make(chan struct{})
				c.holdInterrupt = hold
				go func() {
					time.Sleep(200 * time.Millisecond)
					c.tr.addf("interrupt released")
					close(hold)
				}()
			},
		},
		// A Close while the canceled context's interrupt still sets its
		// deadline, held until 200 ms: Close closes the connection without
		// waiting for the interrupt, and the request ends when the interrupt
		// does.
		"context/canceled-then-closed-while-interrupting": {
			context: canceledAfter(50 * time.Millisecond),
			setup: func(x *Client, c *fakeTransport) {
				hold := make(chan struct{})
				c.holdInterrupt = hold
				time.AfterFunc(100*time.Millisecond, func() {
					c.tr.addf("Close from another goroutine")
					_ = x.Close()
					c.tr.addf("Close returned")
				})
				time.AfterFunc(200*time.Millisecond, func() {
					c.tr.addf("interrupt released")
					close(hold)
				})
			},
		},
		// A context canceled after its request leaves the connection alone:
		// the next request, with another context, is answered.
		"context/canceled-after-request": {agent: answer(sysDescr), run: func(ctx context.Context, x *Client) (*Message, error) {
			first, cancel := context.WithCancel(ctx)
			defer cancel()
			if _, err := x.Get(first, []string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			cancel()
			synctest.Wait()
			return x.Get(ctx, []string{engineOID})
		}},

		// Close.
		"close/before-request": {
			agent: answer(sysDescr),
			setup: func(x *Client, _ *fakeTransport) { _ = x.Close() },
		},
		"close/during-attempt": {
			agent: answerFromSecond(sysDescr),
			setup: func(x *Client, c *fakeTransport) {
				c.afterWrite = func(n int) {
					c.tr.addf("the Conn's write #%d closes the client", n)
					_ = x.Close()
				}
			},
		},
		// A Close before the second attempt sets its deadline: the attempt
		// ends without a write.
		"close/between-attempts": {
			agent: answerFromSecond(sysDescr),
			setup: func(x *Client, c *fakeTransport) {
				atDeadline(c, 2, func() {
					c.tr.addf("the Conn, setting deadline #2, closes the client")
					_ = x.Close()
				})
			},
		},
		// A Close after the reply was read: the reply answers the request.
		"close/after-the-reply": {agent: answer(sysDescr), setup: func(x *Client, c *fakeTransport) {
			c.afterRead = func(n int) {
				c.tr.addf("the Conn's read #%d closes the client", n)
				_ = x.Close()
			}
		}},
		// The client closed from another goroutine, as Netdata's SNMP topology
		// does when its context ends, while the request waits.
		"close/from-another-goroutine": {setup: func(x *Client, _ *fakeTransport) {
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = x.Close()
			}()
		}},

		// Request IDs.
		"request-id/wraps": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.requestID = 0x7FFFFFFF }},
		"request-id/wraps-between-attempts": {agent: answerFromSecond(sysDescr), setup: func(x *Client, _ *fakeTransport) {
			x.requestID = 0x7FFFFFFE
		}},
		"request-id/set": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.requestID = 5 }},

		// The Conn's code panics in a request, which ends.
		"panics/write": {agent: answer(sysDescr), setup: func(_ *Client, c *fakeTransport) {
			c.failWrite = func(n int) error {
				c.tr.addf("the Conn's write #%d panics", n)
				panic("codec write failure")
			}
		}},

		// The caller's code panics in a request, which ends; the next request
		// on the client is answered.
		"panics/write-error": {agent: answer(sysDescr), run: getAfterPanic, setup: func(_ *Client, c *fakeTransport) {
			c.failWrite = panicsOnce(c, "the Conn's write", panicWithError)
		}},
		"panics/after-write-runtime-error": {agent: answer(sysDescr), run: getAfterPanic, setup: func(_ *Client, c *fakeTransport) {
			c.afterWrite = asAction(panicsOnce(c, "the Conn, after its write", panicOnNilMap))
		}},
		"panics/after-read": {agent: answer(sysDescr), run: getAfterPanic, setup: func(_ *Client, c *fakeTransport) {
			c.afterRead = asAction(panicsOnce(c, "the Conn, after its read", panicWithError))
		}},
		// A panic between two attempts, outside either.
		"panics/before-retry-deadline": {agent: answerFromSecond(sysDescr), run: getAfterPanic, setup: func(_ *Client, c *fakeTransport) {
			atDeadline(c, 2, func() {
				c.tr.addf("the Conn, setting deadline #2, panics")
				panicWithError()
			})
		}},
		"panics/read": {agent: answer(sysDescr), run: getAfterPanic, setup: func(_ *Client, c *fakeTransport) {
			c.failRead = func(n int) error {
				if n == 1 {
					c.tr.addf("the Conn's read #1 panics")
					panicWithError()
				}
				return nil
			}
		}},
	}

	return scenarios
}

// TestEngineRequestCharacterization pins what the request engine does for
// v1/v2c requests: the messages it writes, the deadline of each attempt,
// which replies it accepts and what it returns.
// testdata/engine/requests.golden holds the transcripts.
func TestEngineRequestCharacterization(t *testing.T) {
	scenarios := engineScenarios()
	var results []goldenCase
	for _, name := range slices.Sorted(maps.Keys(scenarios)) {
		sc := scenarios[name]
		var dump string
		synctest.Test(t, func(t *testing.T) {
			dump = runEngineScenario(t, sc)
		})
		results = append(results, goldenCase{name: "requests/" + name, dump: dump})
	}
	engineGolden.check(t, "requests", results)
}

// runEngineScenario runs sc in the calling synctest bubble and returns its
// transcript.
func runEngineScenario(t *testing.T, sc engineScenario) string {
	tr := newEngineTranscript(t)
	c := newFakeTransport(tr, sc.agent)
	config := engineConfig(Version2c)
	if sc.v1 {
		config.Version = Version1
	}
	if sc.config != nil {
		sc.config(&config)
	}
	x := newEngineClientFrom(t, c, config)
	ctx := context.Background()
	if sc.context != nil {
		var cancel context.CancelFunc
		ctx, cancel = sc.context()
		defer cancel()
	}
	if sc.setup != nil {
		sc.setup(x, c)
	}
	run := sc.run
	if run == nil {
		run = getOIDs(engineOID)
	}

	tr.addf("client: %v timeout=%s retries=%d", x.config.Version, x.config.Timeout, x.config.Retries)
	var res *Message
	var err error
	if v, _ := recoverPanic(func() { res, err = run(ctx, x) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	after := fmt.Sprintf("client after: next request id=%d", (x.requestID+1)&0x7FFFFFFF)
	tr.addf("%s", after)
	// Let the scenario's own goroutines finish on the bubble's clock: when a
	// regression ends the request before them, what they record afterwards
	// shows in the transcript instead of a synctest deadlock.
	time.Sleep(time.Hour)
	return tr.text()
}

// TestEngineCancelWhileSettingDeadline checks that a context canceled while
// the attempt sets its deadline ends the attempt at once: the interrupt comes
// after the deadline, which cannot undo it.
func TestEngineCancelWhileSettingDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, nil) // the agent never answers
		x := newEngineClient(t, Version2c, c)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c.beforeDeadline = func() {
			c.beforeDeadline = nil
			cancel()
			synctest.Wait() // an interrupt registered already sets its deadline now
		}
		start := time.Now()
		_, err := x.Get(ctx, []string{engineOID})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, time.Duration(0), time.Since(start), "the request ends at the cancellation")
	})
}

// countingContext is a context that is never done and counts the functions
// registered to run when it is done (context.AfterFunc calls its AfterFunc
// method) and those unregistered again.
type countingContext struct {
	context.Context
	done                chan struct{}
	registered, stopped int
}

func (c *countingContext) Done() <-chan struct{} { return c.done }

func (c *countingContext) AfterFunc(func()) func() bool {
	c.registered++
	return func() bool {
		c.stopped++
		return true
	}
}

// TestEngineContextInterruptUnregistered checks that each attempt
// unregisters the interrupt it registers with the request's context, so that
// a context used for many requests does not keep one per attempt.
func TestEngineContextInterruptUnregistered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, answerFromSecond(sysDescr))
		x := newEngineClient(t, Version2c, c)
		ctx := &countingContext{Context: context.Background(), done: make(chan struct{})}
		_, err := x.Get(ctx, []string{engineOID})
		require.NoError(t, err)
		assert.Equal(t, [2]int{2, 2}, [2]int{ctx.registered, ctx.stopped}, "registered, unregistered")
	})
}

// TestEngineLateContextInterrupt checks that a context's interrupt whose
// callback runs only after its attempt ended and the next attempt registered
// leaves the next attempt alone. With one CPU, the callback that cancel starts
// runs only when the test's goroutine blocks: after the next registration.
func TestEngineLateContextInterrupt(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, nil)
		x := newEngineClient(t, Version2c, c)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ended := x.interruptible(ctx, x.conn)
		cancel()
		ended.end()
		// The next attempt sets its deadline, then registers.
		require.NoError(t, x.conn.SetDeadline(time.Time{}))
		next := x.interruptible(context.Background(), x.conn)
		synctest.Wait() // the late callback runs
		c.mu.Lock()
		deadline := c.deadline
		c.mu.Unlock()
		next.end()
		assert.True(t, deadline.IsZero(), "the next attempt's deadline: %v", deadline)
	})
}

// TestRequestPanicNil checks that a panic(nil) in a request ends it with no
// packet and an error, by default (a *runtime.PanicNilError) and under
// GODEBUG=panicnil=1, where recover returns nil: for that setting the test
// runs itself again in a child process.
func TestRequestPanicNil(t *testing.T) {
	child := os.Getenv("GOSNMP_TEST_PANICNIL") != ""
	if !child {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRequestPanicNil$", "-test.count=1", "-test.v") //nolint:gosec // the test binary itself
		cmd.Env = append(os.Environ(), "GOSNMP_TEST_PANICNIL=1", "GODEBUG=panicnil=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		require.Contains(t, string(out), "--- PASS: TestRequestPanicNil", "the child ran the test")
	}
	c := newFakeTransport(nil, answer(sysDescr))
	x := newEngineClient(t, Version2c, c)
	c.failWrite = func(int) error { panic(nil) } //nolint:govet // the nil panic is the point
	res, err := x.Get(context.Background(), []string{engineOID})
	assert.Nil(t, res)
	want := "request panicked: runtime error: panic called with nil argument"
	if child {
		want = "request panicked: <nil>"
	}
	assert.EqualError(t, err, want)
}

// panicInterruptContext panics at stage: in Done or in the AfterFunc method
// context.AfterFunc calls while setting up the attempt's interrupt, or in the
// stop function that AfterFunc method returned, which ending the attempt calls.
type panicInterruptContext struct {
	context.Context
	done  chan struct{}
	stage string
	value any
}

func (c *panicInterruptContext) Done() <-chan struct{} {
	if c.stage == "Done" {
		panic(c.value)
	}
	return c.done
}

func (c *panicInterruptContext) AfterFunc(func()) func() bool {
	if c.stage == "AfterFunc" {
		panic(c.value)
	}
	return func() bool { panic(c.value) }
}

// TestRequestContextPanicCleanup checks that a context that panics while the
// attempt sets up or ends its interrupts leaves no active attempt behind: after
// Close and a new connection, cancellation and Close still end the next request
// without waiting for its timeout.
func TestRequestContextPanicCleanup(t *testing.T) {
	for _, stage := range []string{"Done", "AfterFunc", "stop"} {
		for _, value := range []struct {
			name  string
			panic any
		}{
			{name: "error", panic: errCallerFailure},
			{name: "nil"},
		} {
			for _, interrupt := range []string{"cancel", "close"} {
				t.Run(stage+"/"+value.name+"/"+interrupt, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						config := engineConfig(Version2c)
						config.Timeout, config.Retries = time.Hour, 0
						x := newEngineClientFrom(t, newFakeTransport(nil, nil), config)
						panicking := &panicInterruptContext{
							Context: context.Background(), done: make(chan struct{}),
							stage: stage, value: value.panic,
						}
						res, err := x.Get(panicking, []string{engineOID})
						require.Nil(t, res)
						require.ErrorContains(t, err, "request panicked:")
						if value.panic != nil {
							require.ErrorIs(t, err, errCallerFailure)
						}
						x.mu.Lock()
						active, interrupted := x.attempt.conn, x.attempt.interrupted
						x.mu.Unlock()
						assert.Nil(t, active, "the panic left an active attempt")
						assert.Nil(t, interrupted, "the panic left an interrupt")
						require.NoError(t, x.Close())

						conn := newFakeTransport(nil, nil)
						defer conn.Close()
						x.conn, x.closed = conn, false // as Connect after Close
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						wantErr := context.Canceled
						conn.afterWrite = func(int) { cancel() }
						if interrupt == "close" {
							wantErr = net.ErrClosed
							conn.afterWrite = func(int) { require.NoError(t, x.Close()) }
						}
						start := time.Now()
						res, err = x.Get(ctx, []string{engineOID})
						assert.Nil(t, res)
						assert.ErrorIs(t, err, wantErr)
						assert.Zero(t, time.Since(start), "the interrupt waited for the attempt's timeout")
					})
				})
			}
		}
	}
}

// TestEngineRequestTimeoutError checks what a caller that classifies errors
// sees when every attempt of a request times out on a real socket: the text
// "request timeout", unwrapping to the last attempt's read deadline, a
// timeout net.Error.
func TestEngineRequestTimeoutError(t *testing.T) {
	agent, err := net.ListenPacket("udp4", "127.0.0.1:0") // it never answers
	require.NoError(t, err)
	defer agent.Close()

	x := mustClient(Config{
		Target:    "127.0.0.1",
		Port:      uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Community: "public",
		Version:   Version2c,
		Timeout:   50 * time.Millisecond,
		Retries:   1,
	})
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()

	_, err = x.Get(context.Background(), []string{engineOID})
	require.Error(t, err)
	type classified struct {
		text            string
		deadline        bool
		timeoutNetError bool
	}
	var ne net.Error
	assert.Equal(t, classified{text: "request timeout (after 1 retries)", deadline: true, timeoutNetError: true},
		classified{err.Error(), errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout()})
}

// BenchmarkSendOneRequest measures one SNMPv2c Get through the request engine
// on the in-memory transport, without socket system calls; the agent's
// decoding of the request and encoding of the reply are included.
func BenchmarkSendOneRequest(b *testing.B) {
	const oid = ".1.3.6.1.2.1.31.1.1.1.10.1"
	c := newFakeTransport(nil, func(_ int, req []byte) []agentReply {
		return []agentReply{{data: replyTo(req, nil, VarBind{Name: oid, Value: Counter64Value(3825929753)})}}
	})
	x := newEngineClient(b, Version2c, c)
	pkt := x.NewMessage(GetRequest, []VarBind{{Name: oid, Value: NullValue()}}, 0, 0)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := x.sendOneRequest(ctx, pkt, false, attemptSecurity{}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestExchangeDiscard checks which discarded message's reason an exchange
// records: the one that came closest to answering it, the later of two as
// close, and none for a message that answers another request.
func TestExchangeDiscard(t *testing.T) {
	unread, named, authentic := errors.New("unread"), errors.New("named"), errors.New("authentic")
	type discarded struct {
		err  error
		rank discardRank
	}
	tests := map[string]struct {
		discards []discarded
		want     error
	}{
		"none":                              {},
		"another request's message":         {discards: []discarded{{named, 0}}},
		"unread":                            {discards: []discarded{{unread, rankUnread}}, want: unread},
		"named after unread":                {discards: []discarded{{unread, rankUnread}, {named, rankNamed}}, want: named},
		"unread after named":                {discards: []discarded{{named, rankNamed}, {unread, rankUnread}}, want: named},
		"authentic, then noise":             {discards: []discarded{{authentic, rankAuthentic}, {named, rankNamed}, {unread, rankUnread}}, want: authentic},
		"the later of two as close":         {discards: []discarded{{unread, rankUnread}, {named, rankUnread}}, want: named},
		"another request's after a discard": {discards: []discarded{{unread, rankUnread}, {named, 0}}, want: unread},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var e exchange
			for _, d := range tc.discards {
				e.discard(d.err, d.rank)
			}
			assert.Equal(t, tc.want, e.discarded)
		})
	}
}

// TestExchangeRankOf checks the rank of a discarded message, by the ID it read
// that names the request's attempts, if any (the msgID of an SNMPv3 request,
// the request ID of an SNMPv2c Response), and whether its digest checked.
func TestExchangeRankOf(t *testing.T) {
	earlier := []sentIDs{{requestID: 1, msgID: 5}}
	tests := map[string]struct {
		version  Version
		read     *Message
		verified bool
		want     discardRank
	}{
		"v3/msgID not read":                    {version: Version3, want: rankUnread},
		"v3/another request's msgID":           {version: Version3, read: &Message{MsgID: 6, RequestID: 2}},
		"v3/another request's msgID, verified": {version: Version3, read: &Message{MsgID: 6, RequestID: 2}, verified: true},
		"v3/the attempt's msgID":               {version: Version3, read: &Message{MsgID: 7}, want: rankNamed},
		"v3/an earlier attempt's msgID":        {version: Version3, read: &Message{MsgID: 5}, want: rankNamed},
		"v3/the attempt's msgID, verified":     {version: Version3, read: &Message{MsgID: 7}, verified: true, want: rankAuthentic},
		"v3/the attempt's msgID, a GetRequest": {version: Version3, read: &Message{MsgID: 7, PDUType: GetRequest}, want: rankNamed},
		"v3/a verified GetRequest":             {version: Version3, read: &Message{MsgID: 7, PDUType: GetRequest}, verified: true, want: rankNamed},
		"v3/a verified InformRequest":          {version: Version3, read: &Message{MsgID: 7, PDUType: InformRequest}, verified: true, want: rankNamed},
		"v3/a verified Report":                 {version: Version3, read: &Message{MsgID: 7, PDUType: Report}, verified: true, want: rankAuthentic},
		"v3/a verified Response":               {version: Version3, read: &Message{MsgID: 7, PDUType: Response}, verified: true, want: rankAuthentic},
		"v2c/request ID not read":              {version: Version2c, want: rankUnread},
		"v2c/another request's ID":             {version: Version2c, read: &Message{RequestID: 3, MsgID: 7, PDUType: Response}},
		"v2c/the attempt's request ID":         {version: Version2c, read: &Message{RequestID: 2, PDUType: Response}, want: rankNamed},
		"v2c/an earlier attempt's request ID":  {version: Version2c, read: &Message{RequestID: 1, PDUType: Response}, want: rankNamed},
		"v2c/the attempt's request ID, Report": {version: Version2c, read: &Message{RequestID: 2, PDUType: Report}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			e := exchange{packet: &Message{Version: tc.version, RequestID: 2, MsgID: 7}}
			assert.Equal(t, tc.want, e.rankOf(tc.read, tc.verified, earlier))
		})
	}
}

// TestExchangeDecodeRequestID checks that decode returns an SNMPv1 or SNMPv2c
// message it could not finish when, and only when, it decoded the PDU's
// request ID, which ranks the discard.
func TestExchangeDecodeRequestID(t *testing.T) {
	vbl := craftedVBL(craftedVB(intTLV(5)))
	tests := map[string]struct {
		msg  []byte
		want *uint32 // the request ID of the message returned, nil for none
	}{
		"error status after the request ID": {
			msg: craftedMsg(1, tlv(byte(Response), intTLV(9), intTLV(-1), intTLV(0), vbl)), want: new(uint32(9)),
		},
		"request ID that does not decode": {msg: craftedMsg(1, tlv(byte(Response), octets("x"), intTLV(0), intTLV(0), vbl))},
		"unknown PDU type":                {msg: craftedMsg(1, tlv(0xaf, intTLV(9), intTLV(0), intTLV(0), vbl))},
		"SNMPv1 trap tag":                 {msg: craftedMsg(1, tlv(byte(Trap), intTLV(9), intTLV(0)))},
		"a PDU without its message":       {msg: tlv(byte(Response), intTLV(9), intTLV(-1), intTLV(0), vbl)},
		// Another version is discarded before its request ID is read.
		"SNMPv1 message": {msg: craftedMsg(0, tlv(byte(Response), intTLV(9), intTLV(-1), intTLV(0), vbl))},
		// An SNMPv3 message names its request by its msgID.
		"SNMPv3 message whose msgData is a PDU": {
			msg: craftedV3(intTLV(7), intTLV(65507), octets("\x00"), intTLV(3),
				craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(""), octets("")),
				tlv(byte(Response), intTLV(9), intTLV(-1), intTLV(0), vbl)),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			e := &exchange{x: mustClient(Config{Version: Version2c}), packet: &Message{Version: Version2c, PDUType: GetRequest}}
			reply, _, err := e.decode(tc.msg, nil)
			require.Error(t, err)
			if tc.want == nil {
				assert.Nil(t, reply)
				return
			}
			require.NotNil(t, reply)
			assert.Equal(t, *tc.want, reply.RequestID)
		})
	}
}

// TestExchangeAnswers checks which decoded messages answer a request whose
// current attempt sent request ID 2 and msgID 7 after an attempt that sent 1
// and 5: each field the answer rule compares, both ways.
func TestExchangeAnswers(t *testing.T) {
	earlier := []sentIDs{{requestID: 1, msgID: 5}}
	request := func(version Version) *Message {
		p := &Message{Version: version, PDUType: GetRequest, RequestID: 2, Community: "public"}
		if version == Version3 {
			p.MsgID, p.SecurityLevel, p.ContextEngineID, p.ContextName = 7, AuthNoPriv, []byte("ctx-engine"), "ctx"
			p.SecurityParameters = SecurityParameters{UserName: "user", AuthoritativeEngineID: []byte("engine")}
		}
		return p
	}
	// reply is the answer to the current attempt, a copy of its request.
	reply := func(req *Message) *Message {
		p := *req
		p.PDUType, p.SecurityLevel, p.VarBinds = Response, req.SecurityLevel&AuthPriv, []VarBind{sysDescr}
		return &p
	}
	usm := func(p *Message) *SecurityParameters { return &p.SecurityParameters }
	report := func(counter string) func(p *Message) {
		return func(p *Message) {
			p.PDUType, p.RequestID, p.SecurityLevel, p.VarBinds = Report, 0, NoAuthNoPriv, []VarBind{{Name: counter, Value: Counter32Value(1)}}
			p.ContextEngineID, p.ContextName = []byte("engine"), ""
		}
	}
	tests := map[string]struct {
		version Version
		request func(p *Message)
		reply   func(p *Message)
		answers bool
		err     error
	}{
		"v3/the answer":                    {version: Version3, answers: true},
		"v3/an earlier attempt's answer":   {version: Version3, reply: func(p *Message) { p.MsgID, p.RequestID = 5, 1 }, answers: true},
		"v3/an earlier attempt's ID":       {version: Version3, reply: func(p *Message) { p.RequestID = 1 }, err: errOtherRequestID},
		"v3/the attempt's ID, earlier msg": {version: Version3, reply: func(p *Message) { p.MsgID = 5 }, err: errOtherRequestID},
		"v3/request ID 0":                  {version: Version3, reply: func(p *Message) { p.RequestID = 0 }, err: errOtherRequestID},
		"v3/empty, another request ID": {
			version: Version3, reply: func(p *Message) { p.VarBinds, p.RequestID = nil, 9 }, err: errOtherRequestID,
		},
		"v3/noAuthNoPriv":         {version: Version3, reply: func(p *Message) { p.SecurityLevel = NoAuthNoPriv }, err: errOtherLevel},
		"v3/authPriv":             {version: Version3, reply: func(p *Message) { p.SecurityLevel = AuthPriv }, err: errOtherLevel},
		"v3/to noAuthNoPriv":      {version: Version3, request: func(p *Message) { p.SecurityLevel = NoAuthNoPriv }, err: errOtherLevel},
		"v3/to authPriv":          {version: Version3, request: func(p *Message) { p.SecurityLevel = AuthPriv }, err: errOtherLevel},
		"v3/another user":         {version: Version3, reply: func(p *Message) { usm(p).UserName = "other" }, err: errOtherUser},
		"v3/the empty user":       {version: Version3, reply: func(p *Message) { usm(p).UserName = "" }, err: errOtherUser},
		"v3/to the empty user":    {version: Version3, request: func(p *Message) { usm(p).UserName = "" }, err: errOtherUser},
		"v3/another engine ID":    {version: Version3, reply: func(p *Message) { usm(p).AuthoritativeEngineID = []byte("other") }, err: errOtherEngine},
		"v3/no engine ID":         {version: Version3, reply: func(p *Message) { usm(p).AuthoritativeEngineID = nil }, err: errOtherEngine},
		"v3/to no engine ID":      {version: Version3, request: func(p *Message) { usm(p).AuthoritativeEngineID = nil }, err: errOtherEngine},
		"v3/another context ID":   {version: Version3, reply: func(p *Message) { p.ContextEngineID = []byte("engine") }, err: errOtherContext},
		"v3/to no context ID":     {version: Version3, request: func(p *Message) { p.ContextEngineID = nil }, err: errOtherContext},
		"v3/another context name": {version: Version3, reply: func(p *Message) { p.ContextName = "" }, err: errOtherContext},
		"v3/to another context":   {version: Version3, request: func(p *Message) { p.ContextName = "other" }, err: errOtherContext},
		"v3/a GetRequest":         {version: Version3, reply: func(p *Message) { p.PDUType = GetRequest }, err: errNotAnswer},
		"v3/a Report":             {version: Version3, reply: report(usmStatsUnknownUserNames), answers: true, err: ErrUnknownUsername},
		"v3/a resync Report":      {version: Version3, reply: report(usmStatsNotInTimeWindows), answers: true},
		"v2c/the answer":          {version: Version2c, answers: true},
		"v2c/an earlier attempt's answer": {
			version: Version2c, reply: func(p *Message) { p.RequestID = 1 }, answers: true,
		},
		"v2c/another community": {version: Version2c, reply: func(p *Message) { p.Community = "private" }, answers: true},
		"v2c/request ID 0":      {version: Version2c, reply: func(p *Message) { p.RequestID = 0 }, err: errOtherRequestID},
		"v2c/empty, another request ID": {
			version: Version2c, reply: func(p *Message) { p.VarBinds, p.RequestID = nil, 9 }, err: errOtherRequestID,
		},
		"v2c/a Report": {version: Version2c, reply: func(p *Message) { p.PDUType = Report }, err: errNotAnswer},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := request(tc.version)
			rsp := reply(req)
			if tc.request != nil {
				tc.request(req)
			}
			if tc.reply != nil {
				tc.reply(rsp)
			}
			e := exchange{packet: req}
			answers, err := e.answers(rsp, earlier)
			assert.Equal(t, tc.answers, answers)
			assert.Equal(t, tc.err, err)
		})
	}
}

// TestReportKindOf checks how a Report's first varbind names its counter: by
// the counter's OID and one instance sub-identifier of any value, as net-snmp
// does; anything else is ErrUnknownReportPDU.
func TestReportKindOf(t *testing.T) {
	counter := func(name string) VarBind { return VarBind{Name: name, Value: Counter32Value(1)} }
	tests := map[string]struct {
		version Version
		pduType PDUType
		vbs     []VarBind
		report  bool
		err     error
	}{
		"instance 0":                   {vbs: []VarBind{counter(usmStatsNotInTimeWindows)}, report: true, err: ErrNotInTimeWindow},
		"instance 1":                   {vbs: []VarBind{counter(".1.3.6.1.6.3.15.1.1.2.1")}, report: true, err: ErrNotInTimeWindow},
		"a large instance":             {vbs: []VarBind{counter(".1.3.6.1.6.3.15.1.1.4.4294967295")}, report: true, err: ErrUnknownEngineID},
		"message processing's counter": {vbs: []VarBind{counter(".1.3.6.1.6.3.11.2.1.2.3")}, report: true, err: ErrInvalidMsgs},
		"without an instance":          {vbs: []VarBind{counter(".1.3.6.1.6.3.15.1.1.5")}, report: true, err: ErrUnknownReportPDU},
		"two instance sub-identifiers": {vbs: []VarBind{counter(".1.3.6.1.6.3.15.1.1.5.0.0")}, report: true, err: ErrUnknownReportPDU},
		"the prefix":                   {vbs: []VarBind{counter(".1.3.6.1.6.3.15.1.1")}, report: true, err: ErrUnknownReportPDU},
		"an unknown counter":           {vbs: []VarBind{counter(".1.3.6.1.6.3.15.1.1.9.0")}, report: true, err: ErrUnknownReportPDU},
		"SNMP-TARGET-MIB's counter":    {vbs: []VarBind{counter(".1.3.6.1.6.3.12.1.5.0")}, report: true, err: ErrUnknownReportPDU},
		"a name without a dot":         {vbs: []VarBind{counter("0")}, report: true, err: ErrUnknownReportPDU},
		"no varbinds":                  {report: true, err: ErrUnknownReportPDU},
		"a counter after another name": {vbs: []VarBind{sysDescr, counter(usmStatsWrongDigests)}, report: true, err: ErrUnknownReportPDU},
		"a counter, then another name": {vbs: []VarBind{counter(usmStatsWrongDigests), sysDescr}, report: true, err: ErrWrongDigest},
		"a Response":                   {pduType: Response, vbs: []VarBind{counter(usmStatsWrongDigests)}},
		"an SNMPv2c Report":            {version: Version2c, vbs: []VarBind{counter(usmStatsWrongDigests)}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Message{Version: cmp.Or(tc.version, Version3), PDUType: cmp.Or(tc.pduType, Report), VarBinds: tc.vbs}
			kind, report := reportKindOf(p)
			assert.Equal(t, tc.report, report)
			assert.Equal(t, tc.err, kind.err)
		})
	}
}

// TestExchangeEndErrors checks the error of an exchange that ends without an
// answer, with and without a recorded discard: an attemptsError and an error
// at the context's deadline add the discard; others stay as they are.
func TestExchangeEndErrors(t *testing.T) {
	reason := inCategory(ErrNotInTimeWindow, errors.New("out of window"))
	tests := map[string]struct {
		discarded error
		end       func(e *exchange) error
		wantText  string
		wantIs    []error
		wantNotIs []error
		same      error // the error returned unchanged, if any
	}{
		"timeout": {
			end: func(e *exchange) error {
				return e.attemptsError("request timeout (after 1 retries)", os.ErrDeadlineExceeded)
			},
			wantText: "request timeout (after 1 retries)", wantIs: []error{os.ErrDeadlineExceeded}, wantNotIs: []error{ErrNotInTimeWindow},
		},
		"timeout after a discard": {
			discarded: reason,
			end: func(e *exchange) error {
				return e.attemptsError("request timeout (after 1 retries)", os.ErrDeadlineExceeded)
			},
			wantText: "request timeout (after 1 retries): last discarded reply: out of window",
			wantIs:   []error{os.ErrDeadlineExceeded, ErrNotInTimeWindow},
		},
		"transport error after a discard": {
			discarded: reason,
			end: func(e *exchange) error {
				e.ctx = context.Background()
				return e.endErr(0, attemptOutcome{kind: attemptTransportError, err: errEngineWrite})
			},
			wantText: errEngineWrite.Error(), same: errEngineWrite, wantNotIs: []error{ErrNotInTimeWindow},
		},
		"deadline": {
			end:      func(e *exchange) error { return e.unanswered(context.DeadlineExceeded) },
			wantText: "context deadline exceeded", same: context.DeadlineExceeded,
		},
		"deadline after a discard": {
			discarded: reason,
			end:       func(e *exchange) error { return e.unanswered(context.DeadlineExceeded) },
			wantText:  "context deadline exceeded: last discarded reply: out of window",
			wantIs:    []error{context.DeadlineExceeded, ErrNotInTimeWindow},
		},
		"canceled after a discard": {
			discarded: reason,
			end:       func(e *exchange) error { return e.unanswered(context.Canceled) },
			wantText:  "context canceled", same: context.Canceled, wantNotIs: []error{ErrNotInTimeWindow},
		},
		"timeout at the Context's deadline after a discard": {
			discarded: reason,
			end: func(e *exchange) error {
				return e.unanswered(e.attemptsError("request timeout (after 1 retries)", context.DeadlineExceeded))
			},
			wantText: "request timeout (after 1 retries): last discarded reply: out of window",
			wantIs:   []error{context.DeadlineExceeded, ErrNotInTimeWindow},
		},
		"closed after a discard": {
			discarded: reason,
			end:       func(e *exchange) error { return e.unanswered(errClosed) },
			wantText:  errClosed.Error(), same: errClosed, wantNotIs: []error{ErrNotInTimeWindow},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			e := exchange{x: mustClient(Config{})}
			if tc.discarded != nil {
				e.discard(tc.discarded, rankAuthentic)
			}
			err := tc.end(&e)
			require.EqualError(t, err, tc.wantText)
			if tc.same != nil {
				assert.Equal(t, tc.same, err)
			}
			for _, target := range tc.wantIs {
				assert.ErrorIs(t, err, target)
			}
			for _, target := range tc.wantNotIs {
				assert.NotErrorIs(t, err, target)
			}
		})
	}
}

// BenchmarkGet measures one SNMPv2c Get through send on the in-memory
// transport.
func BenchmarkGet(b *testing.B) {
	c := newFakeTransport(nil, answer(sysDescr))
	x := newEngineClient(b, Version2c, c)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			b.Fatal(err)
		}
	}
}

// errOnCall is a context whose call n of Err runs act first: the caller's code
// that a request runs between its attempts.
type errOnCall struct {
	context.Context
	n, calls int
	act      func()
}

func (c *errOnCall) Err() error {
	c.calls++
	if c.calls == c.n {
		c.act()
	}
	return c.Context.Err()
}

// TestCloseWinsOverAttemptOutcome pins, for every way a request can end
// without a reply, that once Close has run the request fails with the
// client's closed error, which wraps net.ErrClosed: Close runs as an attempt
// ends otherwise, or as the request decides whether to retry, through the
// connection's or the context's code.
func TestCloseWinsOverAttemptOutcome(t *testing.T) {
	tests := map[string]struct {
		retries int
		// set makes the attempt end so, closing x as it does; cancel ends ctx.
		set func(x *Client, c *fakeTransport, cancel context.CancelFunc)
		// errCall, when set, is the call of the context's Err that cancels it
		// and closes x, its last call, after writes writes.
		errCall, writes int
	}{
		"read timeout": {set: func(x *Client, c *fakeTransport, _ context.CancelFunc) {
			c.failRead = func(int) error { _ = x.Close(); return os.ErrDeadlineExceeded }
		}},
		"write timeout": {set: func(x *Client, c *fakeTransport, _ context.CancelFunc) {
			c.failWrite = func(int) error { _ = x.Close(); return os.ErrDeadlineExceeded }
		}},
		"read error": {set: func(x *Client, c *fakeTransport, _ context.CancelFunc) {
			c.failRead = func(int) error { _ = x.Close(); return refused }
		}},
		"write error": {set: func(x *Client, c *fakeTransport, _ context.CancelFunc) {
			c.failWrite = func(int) error { _ = x.Close(); return errEngineWrite }
		}},
		"closed read": {set: func(x *Client, c *fakeTransport, _ context.CancelFunc) {
			c.failRead = func(int) error { _ = x.Close(); return closedRead }
		}},
		"deadline failure": {set: func(x *Client, c *fakeTransport, _ context.CancelFunc) {
			c.deadlineErr = errors.New("codec deadline failure")
			c.beforeDeadline = func() { _ = x.Close() }
		}},
		// The context's interrupt ends the read, and the caller closes the
		// client, as a caller that ends a job does.
		"context interrupt": {set: func(x *Client, c *fakeTransport, cancel context.CancelFunc) {
			c.failRead = func(int) error { cancel(); _ = x.Close(); return os.ErrDeadlineExceeded }
		}},
		// Every attempt times out. The context's Err runs at each attempt's
		// start and at each decision to retry: its third call is the second
		// attempt's start, its second and fourth the decisions after the first
		// and the last attempt.
		"context done at an attempt's start": {
			retries: 1, set: timeoutEveryRead, errCall: 3, writes: 1,
		},
		"context done at the retry decision": {
			retries: 1, set: timeoutEveryRead, errCall: 2, writes: 1,
		},
		"context done after the last attempt": {
			retries: 1, set: timeoutEveryRead, errCall: 4, writes: 2,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			conn := newFakeTransport(nil, nil)
			config := engineConfig(Version2c)
			config.Retries = tc.retries
			x := newEngineClientFrom(t, conn, config)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := base
			if tc.errCall != 0 {
				ctx = &errOnCall{Context: base, n: tc.errCall, act: func() { cancel(); _ = x.Close() }}
			}
			tc.set(x, conn, cancel)

			res, err := x.Get(ctx, []string{engineOID})
			assert.Nil(t, res)
			require.ErrorIs(t, err, errClosed)
			require.ErrorIs(t, err, net.ErrClosed)
			if c, ok := ctx.(*errOnCall); ok {
				assert.Equal(t, [2]int{tc.errCall, tc.writes}, [2]int{c.calls, conn.writes},
					"the context's Err calls and the writes: Close ran where the case says")
			}
		})
	}
}

// timeoutEveryRead makes every read of c time out.
func timeoutEveryRead(_ *Client, c *fakeTransport, _ context.CancelFunc) {
	c.failRead = func(int) error { return os.ErrDeadlineExceeded }
}
