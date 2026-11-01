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
	"os"
	"os/exec"
	"runtime"
	"slices"
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

// engineShape is the kind of connection a scenario's client has.
type engineShape int

const (
	// shapeUDP is a UDP socket as Connect leaves it: a connected
	// net.PacketConn, written with Write and read with ReadFrom.
	shapeUDP engineShape = iota
	// shapeConn is a custom net.Conn, read with Read.
	shapeConn
)

// engineScenario is one v1/v2c request run against a scripted agent.
type engineScenario struct {
	v1    bool // SNMPv1 instead of SNMPv2c
	shape engineShape
	setup func(x *Client, c *fakeTransport)
	// context, when set, gives the client's Context; its cancel runs when
	// the scenario ends.
	context func() (context.Context, context.CancelFunc)
	agent   engineAgent
	run     func(x *Client) (*Message, error) // a Get of engineOID unless set
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
	return bareV3Answer(req, 7, Report, VarBind{Name: counter, Type: Counter32, Value: uint32(1)})
}

// bareV3Answer is bareV3Report with msgID for a PDU of type pduType with vbs.
func bareV3Answer(req []byte, msgID uint32, pduType PDUType, vbs ...VarBind) []byte {
	in, err := decodeMessage(req)
	if err != nil {
		panic(fmt.Sprintf("agent cannot decode the request: %v", err))
	}
	out := &Message{
		Version: Version3, MsgFlags: NoAuthNoPriv, SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: "public"},
		PDUType:            pduType, RequestID: in.RequestID, MsgID: msgID,
		VarBinds: vbs,
	}
	b, err := out.marshalMsg()
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
	m["hook"]++ //nolint:staticcheck // the runtime error is the point
}

// panicOnce makes the hook *h, which the transcript names name, panic through
// fail the first time it runs, after doing what it did before.
func panicOnce(c *fakeTransport, name string, h *func(*Client), fail func()) {
	next, armed := *h, true
	*h = func(x *Client) {
		next(x)
		if armed {
			armed = false
			c.tr.addf("hook %s panics", name)
			fail()
		}
	}
}

// getAfterPanic runs a Get in which the caller's code panics (the scenario's
// setup arms it), records its result and what its error matches, then runs a
// second Get on the same client, whose result it returns.
func getAfterPanic(x *Client) (*Message, error) {
	tr := x.Conn.(fakePacketTransport).tr
	res, err := x.Get([]string{engineOID})
	tr.addf("first request: %s", describeEngineResult(res, err))
	var re runtime.Error
	tr.addf("first request's error: matches the caller's error %t, a runtime.Error %t", errors.Is(err, errCallerFailure),
		errors.As(err, &re))
	return x.Get([]string{engineOID})
}

// answerRaw is an agent that answers every request with its sysDescr reply
// changed by edit as encoded octets.
func answerRaw(edit func(reply []byte) []byte) engineAgent {
	return func(_ int, req []byte) []agentReply {
		return []agentReply{{data: edit(replyTo(req, nil, sysDescr))}}
	}
}

var sysDescr = VarBind{Name: engineOID, Type: OctetString, Value: []byte("codec agent")}

// answerSplit is an agent that answers every request with its reply with vb,
// cut at the offsets cuts, its parts 10ms apart: a read each.
func answerSplit(vb VarBind, cuts ...int) engineAgent {
	return func(_ int, req []byte) []agentReply {
		r := replyTo(req, nil, vb)
		parts := make([]agentReply, 0, len(cuts)+1)
		from := 0
		for _, cut := range cuts {
			parts = append(parts, agentReply{data: r[from:cut], after: time.Duration(len(parts)) * 10 * time.Millisecond})
			from = cut
		}
		return append(parts, agentReply{data: r[from:], after: time.Duration(len(parts)) * 10 * time.Millisecond})
	}
}

// replySized is the reply to req of size octets, with one OctetString value.
func replySized(req []byte, size int) []byte {
	n := size - 100
	for {
		r := replyTo(req, nil, VarBind{Name: engineOID, Type: OctetString, Value: bytes.Repeat([]byte{'x'}, n)})
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

func getOIDs(oids ...string) func(x *Client) (*Message, error) {
	return func(x *Client) (*Message, error) { return x.Get(oids) }
}

// engineScenarios are the request scenarios of TestEngineRequestCharacterization.
func engineScenarios() map[string]engineScenario {
	twoGets := func(x *Client) (*Message, error) {
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		return x.Get([]string{engineOID})
	}
	maxOIDs2 := func(x *Client, _ *fakeTransport) { x.MaxOids = 2 }
	twoOIDs := []string{engineOID, ".1.3.6.1.2.1.1.3.0"}
	threeOIDs := []string{engineOID, ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"}

	scenarios := map[string]engineScenario{
		// Operations.
		"get":    {agent: answer(sysDescr)},
		"get/v1": {v1: true, agent: answer(sysDescr)},
		"mk-snmp-packet": {agent: answer(sysDescr), run: func(x *Client) (*Message, error) {
			return x.send(x.NewMessage(GetBulkRequest, []VarBind{{Name: ".1.3.6.1.2.1.1", Type: Null}}, 2, 7))
		}},
		"get/invalid-oid": {agent: answer(), run: getOIDs(".1.3.6.1.x")},

		// The MaxOids limit, at 2.
		"get/max-oids/at-limit":   {agent: answer(sysDescr), setup: maxOIDs2, run: getOIDs(twoOIDs...)},
		"get/max-oids/over-limit": {agent: answer(sysDescr), setup: maxOIDs2, run: getOIDs(threeOIDs...)},

		// The client.
		"get/no-conn": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.Conn = nil }},
		// A client given a Conn without Connect: the request supplies the
		// Context and the receive buffer.
		"conn-without-connect": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) {
			x.Context, x.rx = nil, nil
		}},
		"conn-without-receive-buffer": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) {
			x.rx = nil
		}},
		"custom-conn": {shape: shapeConn, agent: answer(sysDescr)},

		// Timeouts and retries.
		"timeout":                  {},
		"timeout/no-retries":       {setup: func(x *Client, _ *fakeTransport) { x.Retries = 0 }},
		"timeout/negative-retries": {setup: func(x *Client, _ *fakeTransport) { x.Retries = -3 }},

		// A hook that changes the client during a request.
		"hooks/retry-sets-retries": {setup: func(x *Client, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *Client) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets Retries to 0")
				x.Retries = 0
			}
		}},
		"hooks/retry-cancels-context": {setup: func(x *Client, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *Client) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets a canceled Context")
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				x.Context = ctx
			}
		}},
		"hooks/retry-sets-context-deadline": {setup: func(x *Client, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *Client) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets a Context with a deadline in 500ms")
				x.Context = unreportedDeadline{context.Background(), time.Now().Add(500 * time.Millisecond)}
			}
		}},
		"hooks/retry-replaces-hooks": {agent: answerFrom(3, sysDescr), setup: func(x *Client, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *Client) {
				onRetry(x)
				c.tr.addf("hook OnRetry replaces the hooks")
				replacement := func(name string) func(*Client) {
					return func(*Client) { c.tr.addf("hook %s, the replacement", name) }
				}
				x.PreSend, x.OnSent, x.OnRecv = replacement("PreSend"), replacement("OnSent"), replacement("OnRecv")
				x.OnRetry, x.OnFinish = replacement("OnRetry"), replacement("OnFinish")
			}
		}},
		"timeout/zero":          {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.Timeout = 0 }},
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
			run: func(x *Client) (*Message, error) {
				first, err := x.Get([]string{engineOID})
				if err != nil {
					return nil, fmt.Errorf("first Get: %w", err)
				}
				if _, err := x.Get([]string{engineOID}); err != nil {
					return nil, fmt.Errorf("second Get: %w", err)
				}
				return first, nil
			},
			agent: func(n int, req []byte) []agentReply {
				value := fmt.Sprintf("codec agent %d", n)
				return []agentReply{{data: replyTo(req, nil, VarBind{Name: engineOID, Type: OctetString, Value: []byte(value)})}}
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
					Enterprise: ".1.3.6.1.4.1.8072", AgentAddress: "127.0.0.2", GenericTrap: 6, SpecificTrap: 1,
				}
				b, err := trap.marshalMsg()
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
		"answer/error-status":                     {agent: answerWith(func(p *Message) { p.ErrorStatus, p.ErrorIndex = NoSuchName, 1 }, VarBind{Name: engineOID, Type: Null})},
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
				p.Version, p.MsgFlags, p.SecurityModel = Version3, NoAuthNoPriv, UserSecurityModel
				p.SecurityParameters = &UsmSecurityParameters{UserName: "public"}
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
				return []agentReply{{data: bareV3Answer(req, 0, Report, VarBind{Name: usmStatsUnknownUserNames, Type: Counter32, Value: uint32(1)})}}
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
			setup: func(x *Client, _ *fakeTransport) { x.Retries = 1 },
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: replySized(req, rxBufSize)}}
			},
		},
		// A custom net.Conn whose reply comes in two reads.
		"custom-conn/split": {
			shape: shapeConn,
			setup: func(x *Client, _ *fakeTransport) { x.Retries = 0 },
			agent: answerSplit(sysDescr, 10),
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

		// Context.
		"context/canceled-before": {agent: answer(sysDescr), context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}},
		"context/canceled-with-cause-before": {agent: answer(sysDescr), context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(errEngineCause)
			return ctx, func() { cancel(nil) }
		}},
		"context/deadline-equal-to-timeout": {
			context: withEngineTimeout(time.Second),
			setup:   func(x *Client, _ *fakeTransport) { x.Retries = 0 },
		},
		"context/deadline-in-first-attempt":   {context: withEngineTimeout(700 * time.Millisecond)},
		"context/deadline-in-third-attempt":   {context: withEngineTimeout(2500 * time.Millisecond)},
		"context/deadline-after-all-attempts": {context: withEngineTimeout(time.Hour)},
		"context/deadline-during-hook": {
			context: withEngineTimeout(1500 * time.Millisecond),
			setup: func(x *Client, c *fakeTransport) {
				x.OnRetry = func(*Client) {
					c.tr.addf("hook OnRetry, which takes 1s")
					time.Sleep(time.Second)
				}
			},
		},
		// The deadline rule does not wait for the Context to report its
		// deadline, also when the deadlines are equal.
		"context/deadline-unreported-in-first-attempt": {context: withUnreportedDeadline(700 * time.Millisecond)},
		"context/deadline-unreported-equal-to-timeout": {
			context: withUnreportedDeadline(time.Second),
			setup:   func(x *Client, _ *fakeTransport) { x.Retries = 0 },
		},
		// A Context whose deadline passed ends the request after an attempt
		// that failed otherwise, before OnRetry.
		"context/deadline-passed-in-hook": {
			context: withEngineTimeout(700 * time.Millisecond),
			setup: func(x *Client, c *fakeTransport) {
				x.OnSent = func(*Client) {
					c.tr.addf("hook OnSent, which takes 1s")
					time.Sleep(time.Second)
				}
				c.failRead = func(int) error { return refused }
			},
		},
		// A Context canceled before its deadline ends the attempt and the
		// request at the cancellation, with context.Canceled.
		"context/canceled-before-deadline": {context: canceledBeforeDeadline(300*time.Millisecond, 700*time.Millisecond)},
		"context/canceled-while-waiting":   {context: canceledAfter(300 * time.Millisecond)},
		"context/canceled-in-last-attempt": {context: canceledAfter(2300 * time.Millisecond)},
		// A Context canceled while the reply is on its way, its interrupt held
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
		// A Close while the canceled Context's interrupt still sets its
		// deadline, held until 200 ms: the attempt's interrupt has started, so
		// Close closes the connection without waiting for it, and the request
		// ends when the interrupt does.
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
		// A Context canceled after its request leaves the connection alone:
		// the next request, with another Context, is answered.
		"context/canceled-after-request": {agent: answer(sysDescr), run: func(x *Client) (*Message, error) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x.Context = ctx
			if _, err := x.Get([]string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			cancel()
			synctest.Wait()
			x.Context = context.Background()
			return x.Get([]string{engineOID})
		}},

		// Close.
		"close/before-request": {
			agent: answer(sysDescr),
			setup: func(x *Client, _ *fakeTransport) { _ = x.Close() },
		},
		"close/during-attempt": {
			agent: answerFromSecond(sysDescr),
			setup: func(x *Client, c *fakeTransport) {
				x.OnSent = func(x *Client) {
					c.tr.addf("hook OnSent closes the client")
					_ = x.Close()
				}
			},
		},
		"close/between-attempts": {
			agent: answerFromSecond(sysDescr),
			setup: func(x *Client, c *fakeTransport) {
				x.OnRetry = func(x *Client) {
					c.tr.addf("hook OnRetry closes the client")
					_ = x.Close()
				}
			},
		},
		// A Close after the reply was read: the reply answers the request.
		"close/after-the-reply": {agent: answer(sysDescr), setup: func(x *Client, c *fakeTransport) {
			x.OnRecv = func(x *Client) {
				c.tr.addf("hook OnRecv closes the client")
				_ = x.Close()
			}
		}},
		// A Close after a request in which a hook replaced Conn closes the
		// hook's connection and leaves the one the ended attempt used, the
		// caller's again, alone.
		"close/after-a-request-conn-replaced-by-hook": {
			agent: answer(sysDescr),
			setup: func(x *Client, c *fakeTransport) {
				hookConn := fakePacketTransport{newFakeTransport(c.tr, nil)}
				x.OnSent = func(x *Client) {
					c.tr.addf("hook OnSent replaces Conn")
					x.Conn = hookConn
				}
			},
			run: func(x *Client) (*Message, error) {
				res, err := x.Get([]string{engineOID})
				_ = x.Close()
				return res, err
			},
		},
		// A hook removes Conn: the request fails for want of a connection, not
		// as closed.
		"close/conn-removed-by-hook": {setup: func(x *Client, c *fakeTransport) {
			x.OnRetry = func(x *Client) {
				c.tr.addf("hook OnRetry removes Conn")
				x.Conn = nil
			}
		}},
		// The client closed from another goroutine, as Netdata's SNMP topology
		// does when its context ends, while the request waits.
		// The read the interrupt wakes looks only once Close has closed the
		// connection too: either may come first otherwise.
		"close/from-another-goroutine": {setup: func(x *Client, c *fakeTransport) {
			hold := make(chan struct{})
			c.holdWake = hold
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = x.Close()
				close(hold)
			}()
		}},
		// The connection itself closed from another goroutine, as Netdata's
		// SNMP vnode acquisition does when its context ends.
		"close/connection-from-another-goroutine": {setup: func(_ *Client, c *fakeTransport) {
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = c.Close()
			}()
		}},

		// Request IDs.
		"request-id/wraps": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.SetRequestID(0x7FFFFFFF) }},
		"request-id/wraps-between-attempts": {agent: answerFromSecond(sysDescr), setup: func(x *Client, _ *fakeTransport) {
			x.SetRequestID(0x7FFFFFFE)
		}},
		"request-id/set": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) { x.SetRequestID(5) }},

		// Hooks.
		"hook-panics": {agent: answer(sysDescr), setup: func(x *Client, _ *fakeTransport) {
			x.PreSend = func(*Client) { panic("codec hook failure") }
		}},

		// The caller's code panics in a request, which ends; the next request
		// on the client is answered.
		"hook-panics/presend-error": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *Client, c *fakeTransport) {
			panicOnce(c, "PreSend", &x.PreSend, panicWithError)
		}},
		"hook-panics/onsent-runtime-error": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *Client, c *fakeTransport) {
			panicOnce(c, "OnSent", &x.OnSent, panicOnNilMap)
		}},
		"hook-panics/onrecv": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *Client, c *fakeTransport) {
			panicOnce(c, "OnRecv", &x.OnRecv, panicWithError)
		}},
		"hook-panics/onretry": {agent: answerFromSecond(sysDescr), run: getAfterPanic, setup: func(x *Client, c *fakeTransport) {
			panicOnce(c, "OnRetry", &x.OnRetry, panicWithError)
		}},
		"hook-panics/onfinish": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *Client, c *fakeTransport) {
			panicOnce(c, "OnFinish", &x.OnFinish, panicWithError)
		}},
		"hook-panics/conn-read": {agent: answer(sysDescr), run: getAfterPanic, setup: func(_ *Client, c *fakeTransport) {
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
// which replies it accepts, the hooks it calls and what it returns.
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
	var conn net.Conn
	switch sc.shape {
	case shapeUDP:
		conn = fakePacketTransport{c}
	case shapeConn:
		conn = c
	}
	version := Version2c
	if sc.v1 {
		version = Version1
	}
	x := newEngineClient(t, tr, version, conn)
	if sc.context != nil {
		ctx, cancel := sc.context()
		defer cancel()
		x.Context = ctx
	}
	if sc.setup != nil {
		sc.setup(x, c)
	}
	run := sc.run
	if run == nil {
		run = getOIDs(engineOID)
	}

	tr.addf("client: %v timeout=%s retries=%d", x.Version, x.Timeout, x.Retries)
	var res *Message
	var err error
	before := configOf(x)
	if v, _ := recoverPanic(func() { res, err = run(x) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	tr.addConfigChanges(before, x)
	after := fmt.Sprintf("client after: retries=%d next request id=%d", x.Retries, (x.requestID.Load()+1)&0x7FFFFFFF)
	tr.addf("%s", after)
	// Let the scenario's own goroutines finish on the bubble's clock: when a
	// regression ends the request before them, what they record afterwards
	// shows in the transcript instead of a synctest deadlock.
	time.Sleep(time.Hour)
	return tr.text()
}

// TestEngineCancelWhileSettingDeadline checks that a Context canceled while
// the attempt sets its deadline ends the attempt at once: the interrupt comes
// after the deadline, which cannot undo it.
func TestEngineCancelWhileSettingDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, nil) // the agent never answers
		x := newEngineClient(t, nil, Version2c, fakePacketTransport{c})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		x.Context = ctx
		c.beforeDeadline = func() {
			c.beforeDeadline = nil
			cancel()
			synctest.Wait() // an interrupt registered already sets its deadline now
		}
		start := time.Now()
		_, err := x.Get([]string{engineOID})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, time.Duration(0), time.Since(start), "the request ends at the cancellation")
	})
}

// countingContext is a Context that is never done and counts the functions
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
// unregisters the interrupt it registers with the request's Context, so that
// a Context used for many requests does not keep one per attempt.
func TestEngineContextInterruptUnregistered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, answerFromSecond(sysDescr))
		x := newEngineClient(t, nil, Version2c, fakePacketTransport{c})
		ctx := &countingContext{Context: context.Background(), done: make(chan struct{})}
		x.Context = ctx
		_, err := x.Get([]string{engineOID})
		require.NoError(t, err)
		assert.Equal(t, [2]int{2, 2}, [2]int{ctx.registered, ctx.stopped}, "registered, unregistered")
	})
}

// TestEngineLateContextInterrupt checks that a Context's interrupt whose
// callback runs only after its attempt ended and the next attempt registered
// leaves the next attempt alone. With one CPU, the callback that cancel starts
// runs only when the test's goroutine blocks: after the next registration.
func TestEngineLateContextInterrupt(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, nil)
		x := newEngineClient(t, nil, Version2c, fakePacketTransport{c})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ended := x.interruptible(ctx, x.Conn)
		cancel()
		ended.end()
		// The next attempt sets its deadline, then registers.
		require.NoError(t, x.Conn.SetDeadline(time.Time{}))
		next := x.interruptible(context.Background(), x.Conn)
		synctest.Wait() // the late callback runs
		c.mu.Lock()
		deadline := c.readDeadline
		c.mu.Unlock()
		next.end()
		assert.True(t, deadline.IsZero(), "the next attempt's deadline: %v", deadline)
	})
}

// uncomparableConn is a connection of a type == cannot compare: a struct with
// a func field, used by value.
type uncomparableConn struct {
	net.Conn
	onClose func()
}

// TestEngineUncomparableConn checks a request over a Conn the caller set, of a
// type == cannot compare, on a loopback socket, without Connect and in place
// of the connection Connect opened: the agent answers, and Close returns.
func TestEngineUncomparableConn(t *testing.T) {
	for name, connect := range map[string]bool{"without Connect": false, "after Connect": true} {
		t.Run(name, func(t *testing.T) {
			port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
			caller, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			require.NoError(t, err)
			defer caller.Close()
			x := &Client{
				Target: "127.0.0.1", Port: port, MaxOids: MaxOids,
				Community: "public", Version: Version2c, Timeout: 10 * time.Second,
			}
			if connect {
				require.NoError(t, x.Connect())
				defer x.Conn.Close()
			}
			x.Conn = uncomparableConn{Conn: caller, onClose: func() {}}

			res, err := x.Get([]string{engineOID})
			require.NoError(t, err)
			assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
			closed := make(chan error, 1)
			go func() { closed <- x.Close() }()
			select {
			case err = <-closed:
				assert.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("Close blocks")
			}
		})
	}
}

// TestRequestPanicNil checks that a hook's panic(nil) ends the request with no
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
	x := newEngineClient(t, nil, Version2c, fakePacketTransport{newFakeTransport(nil, answer(sysDescr))})
	x.PreSend = func(*Client) { panic(nil) } //nolint:govet // the nil panic is the point
	res, err := x.Get([]string{engineOID})
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

// TestRequestContextPanicCleanup checks that a Context that panics while the
// attempt sets up or ends its interrupts leaves no active attempt behind: after
// Close and a new Conn, cancellation and Close still interrupt the next request
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
			for _, interrupt := range []string{"cancel", "close-replaced-conn"} {
				t.Run(stage+"/"+value.name+"/"+interrupt, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						x := newEngineClient(t, nil, Version2c, newFakeTransport(nil, nil))
						x.Timeout, x.Retries = time.Hour, 0
						x.Context = &panicInterruptContext{
							Context: context.Background(), done: make(chan struct{}),
							stage: stage, value: value.panic,
						}
						res, err := x.Get([]string{engineOID})
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
						x.Conn = conn // a caller may use a closed client again this way
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						x.Context = ctx
						wantErr := context.Canceled
						x.OnSent = func(*Client) { cancel() }
						if interrupt == "close-replaced-conn" {
							wantErr = net.ErrClosed
							x.OnSent = func(x *Client) {
								x.Conn = newFakeTransport(nil, nil)
								require.NoError(t, x.Close()) // must interrupt conn too
							}
						}
						start := time.Now()
						res, err = x.Get([]string{engineOID})
						assert.Nil(t, res)
						assert.ErrorIs(t, err, wantErr)
						assert.Zero(t, time.Since(start), "the interrupt waited for the attempt's timeout")
					})
				})
			}
		}
	}
}

// TestEngineReadCountOutsideBuffer checks, on a loopback socket, a Conn the
// caller set whose Read breaks the io.Reader contract once, returning a count
// outside the buffer: the attempt fails as a transport error, also when the
// read returns an error that would end the request (a closed connection),
// which the retry cures, and the client answers the next request.
func TestEngineReadCountOutsideBuffer(t *testing.T) {
	type outcome struct {
		failed  []bool // per request
		retries int
	}
	tests := map[string]struct {
		count func(p []byte) int
		err   error // the error of the read that returns count
		want  outcome
	}{
		"more than the buffer": {
			count: func(p []byte) int { return len(p) + 1 },
			want:  outcome{failed: []bool{false, false}, retries: 1},
		},
		"negative": {
			count: func([]byte) int { return -1 },
			want:  outcome{failed: []bool{false, false}, retries: 1},
		},
		"negative, with a closed-connection error": {
			count: func([]byte) int { return -1 }, err: net.ErrClosed,
			want: outcome{failed: []bool{false, false}, retries: 1},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
			var got outcome
			x := &Client{
				Target: "127.0.0.1", Port: port, Community: "public", Version: Version2c,
				Timeout: 300 * time.Millisecond, Retries: 1,
				OnRetry: func(*Client) { got.retries++ },
			}
			require.NoError(t, x.Connect())
			defer x.Close()
			x.Conn = &badCountConn{Conn: x.Conn, count: tc.count, err: tc.err}
			for range 2 {
				_, err := x.Get([]string{engineOID})
				got.failed = append(got.failed, err != nil)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// badCountConn is a Conn whose first Read returns count's count and err
// without reading, breaking the io.Reader contract; its other calls go to Conn.
type badCountConn struct {
	net.Conn
	count func(p []byte) int
	err   error
	done  bool
}

func (c *badCountConn) Read(p []byte) (int, error) {
	if !c.done {
		c.done = true
		return c.count(p), c.err
	}
	return c.Conn.Read(p)
}

// TestEngineRequestTimeoutError checks what a caller that classifies errors
// sees when every attempt of a request times out on a real socket: the text
// "request timeout", unwrapping to the last attempt's read deadline, a
// timeout net.Error.
func TestEngineRequestTimeoutError(t *testing.T) {
	agent, err := net.ListenPacket("udp4", "127.0.0.1:0") // it never answers
	require.NoError(t, err)
	defer agent.Close()

	x := &Client{
		Target:    "127.0.0.1",
		Port:      uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Community: "public",
		Version:   Version2c,
		Timeout:   50 * time.Millisecond,
		Retries:   1,
	}
	require.NoError(t, x.Connect())
	defer x.Close()

	_, err = x.Get([]string{engineOID})
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
		return []agentReply{{data: replyTo(req, nil, VarBind{Name: oid, Type: Counter64, Value: uint64(3825929753)})}}
	})
	x := newEngineClient(b, nil, Version2c, fakePacketTransport{c})
	pkt := x.NewMessage(GetRequest, []VarBind{{Name: oid, Type: Null}}, 0, 0)
	cfg := x.prepareRequest()

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := x.sendOneRequest(&cfg, pkt, false, sourcedClock{}); err != nil {
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
			e := &exchange{x: &Client{Version: Version2c}, packet: &Message{Version: Version2c, PDUType: GetRequest}}
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
			p.MsgID, p.MsgFlags, p.ContextEngineID, p.ContextName = 7, AuthNoPriv|Reportable, "ctx-engine", "ctx"
			p.SecurityParameters = &UsmSecurityParameters{UserName: "user", AuthoritativeEngineID: "engine"}
		}
		return p
	}
	// reply is the answer to the current attempt, a copy of its request.
	reply := func(req *Message) *Message {
		p := *req
		p.PDUType, p.MsgFlags, p.VarBinds = Response, req.MsgFlags&AuthPriv, []VarBind{sysDescr}
		if req.SecurityParameters != nil {
			p.SecurityParameters = req.SecurityParameters.Copy()
		}
		return &p
	}
	usm := func(p *Message) *UsmSecurityParameters { return p.SecurityParameters.usm() }
	report := func(counter string) func(p *Message) {
		return func(p *Message) {
			p.PDUType, p.RequestID, p.MsgFlags, p.VarBinds = Report, 0, NoAuthNoPriv, []VarBind{{Name: counter, Type: Counter32, Value: uint32(1)}}
			p.ContextEngineID, p.ContextName = "engine", ""
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
		"v3/reportable":           {version: Version3, reply: func(p *Message) { p.MsgFlags |= Reportable }, answers: true},
		"v3/not reportable":       {version: Version3, request: func(p *Message) { p.MsgFlags = AuthNoPriv }, reply: func(p *Message) { p.MsgFlags |= Reportable }, answers: true},
		"v3/noAuthNoPriv":         {version: Version3, reply: func(p *Message) { p.MsgFlags = NoAuthNoPriv }, err: errOtherLevel},
		"v3/authPriv":             {version: Version3, reply: func(p *Message) { p.MsgFlags = AuthPriv }, err: errOtherLevel},
		"v3/to noAuthNoPriv":      {version: Version3, request: func(p *Message) { p.MsgFlags = NoAuthNoPriv | Reportable }, err: errOtherLevel},
		"v3/to authPriv":          {version: Version3, request: func(p *Message) { p.MsgFlags = AuthPriv | Reportable }, err: errOtherLevel},
		"v3/another user":         {version: Version3, reply: func(p *Message) { usm(p).UserName = "other" }, err: errOtherUser},
		"v3/the empty user":       {version: Version3, reply: func(p *Message) { usm(p).UserName = "" }, err: errOtherUser},
		"v3/to the empty user":    {version: Version3, request: func(p *Message) { usm(p).UserName = "" }, err: errOtherUser},
		"v3/another engine ID":    {version: Version3, reply: func(p *Message) { usm(p).AuthoritativeEngineID = "other" }, err: errOtherEngine},
		"v3/no engine ID":         {version: Version3, reply: func(p *Message) { usm(p).AuthoritativeEngineID = "" }, err: errOtherEngine},
		"v3/to no engine ID":      {version: Version3, request: func(p *Message) { usm(p).AuthoritativeEngineID = "" }, err: errOtherEngine},
		"v3/another context ID":   {version: Version3, reply: func(p *Message) { p.ContextEngineID = "engine" }, err: errOtherContext},
		"v3/to no context ID":     {version: Version3, request: func(p *Message) { p.ContextEngineID = "" }, err: errOtherContext},
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
	counter := func(name string) VarBind { return VarBind{Name: name, Type: Counter32, Value: uint32(1)} }
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
// at the Context's deadline add the discard; others stay as they are.
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
				e.cfg.ctx = context.Background()
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
			e := exchange{x: &Client{}}
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
	x := newEngineClient(b, nil, Version2c, c)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := x.Get([]string{engineOID}); err != nil {
			b.Fatal(err)
		}
	}
}
