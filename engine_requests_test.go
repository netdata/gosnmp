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
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// engineShape is the kind of connection a scenario's client has.
type engineShape int

const (
	// shapeUDP is a UDP socket as Connect leaves it: a connected
	// net.PacketConn, written with Write and read with ReadFrom.
	shapeUDP engineShape = iota
	// shapeUnconnectedUDP is the socket of UseUnconnectedUDPSocket, written
	// with WriteTo the target's address.
	shapeUnconnectedUDP
	// shapeStream is a TCP socket or a custom net.Conn, read with Read.
	shapeStream
)

// engineScenario is one v1/v2c request run against a scripted agent.
type engineScenario struct {
	v1    bool // SNMPv1 instead of SNMPv2c
	shape engineShape
	setup func(x *GoSNMP, c *fakeTransport)
	// context, when set, gives the client's Context; its cancel runs when
	// the scenario ends.
	context  func() (context.Context, context.CancelFunc)
	agent    engineAgent
	run      func(x *GoSNMP) (*SnmpPacket, error) // a Get of engineOID unless set
	knownBug string
}

// answer is an agent that answers every request at once with vbs.
func answer(vbs ...SnmpPDU) engineAgent {
	return answerWith(nil, vbs...)
}

// answerWith is an agent that answers every request at once with a reply
// changed by edit.
func answerWith(edit func(*SnmpPacket), vbs ...SnmpPDU) engineAgent {
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
	return bareV3Answer(req, 7, Report, SnmpPDU{Name: counter, Type: Counter32, Value: uint32(1)})
}

// bareV3Answer is bareV3Report with msgID for a PDU of type pduType with vbs.
func bareV3Answer(req []byte, msgID uint32, pduType PDUType, vbs ...SnmpPDU) []byte {
	in, err := decodeMessage(req)
	if err != nil {
		panic(fmt.Sprintf("agent cannot decode the request: %v", err))
	}
	out := &SnmpPacket{
		Version: Version3, MsgFlags: NoAuthNoPriv, SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: "public"},
		PDUType:            pduType, RequestID: in.RequestID, MsgID: msgID,
		Variables: vbs,
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
func answerFromSecond(vbs ...SnmpPDU) engineAgent {
	return answerFrom(2, vbs...)
}

// answerFrom is an agent that answers the requests from the first-th on with
// vbs.
func answerFrom(first int, vbs ...SnmpPDU) engineAgent {
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
func panicOnce(c *fakeTransport, name string, h *func(*GoSNMP), fail func()) {
	next, armed := *h, true
	*h = func(x *GoSNMP) {
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
func getAfterPanic(x *GoSNMP) (*SnmpPacket, error) {
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

var sysDescr = SnmpPDU{Name: engineOID, Type: OctetString, Value: []byte("codec agent")}

// framedGarbage is a whole message that does not decode: a SEQUENCE holding a
// NULL.
var framedGarbage = []byte{byte(Sequence), 2, byte(Null), 0}

// answerSplit is an agent that answers every request with its reply with vb,
// cut at the offsets cuts, its parts 10ms apart: on a stream, a read each.
func answerSplit(vb SnmpPDU, cuts ...int) engineAgent {
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
		r := replyTo(req, nil, SnmpPDU{Name: engineOID, Type: OctetString, Value: bytes.Repeat([]byte{'x'}, n)})
		if len(r) == size {
			return r
		}
		n += size - len(r)
	}
}

// overTCP readies a stream scenario's client for TCP with retries.
func overTCP(retries int) func(*GoSNMP, *fakeTransport) {
	return func(x *GoSNMP, _ *fakeTransport) { x.Transport, x.Retries = "tcp", retries }
}

// errorStatusOutOfRange is the sysDescr reply to req, its request ID raised by
// idDelta, with the error status -1: the request ID decodes, then the PDU
// fails.
func errorStatusOutOfRange(req []byte, idDelta uint32) []byte {
	r := replyTo(req, func(p *SnmpPacket) { p.RequestID += idDelta }, sysDescr)
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

func getOIDs(oids ...string) func(x *GoSNMP) (*SnmpPacket, error) {
	return func(x *GoSNMP) (*SnmpPacket, error) { return x.Get(oids) }
}

func setVarbinds(vbs ...SnmpPDU) func(x *GoSNMP) (*SnmpPacket, error) {
	return func(x *GoSNMP) (*SnmpPacket, error) { return x.Set(vbs) }
}

// engineScenarios are the request scenarios of TestEngineRequestCharacterization.
func engineScenarios() map[string]engineScenario {
	twoGets := func(x *GoSNMP) (*SnmpPacket, error) {
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		return x.Get([]string{engineOID})
	}
	maxOIDs2 := func(x *GoSNMP, _ *fakeTransport) { x.MaxOids = 2 }
	twoOIDs := []string{engineOID, ".1.3.6.1.2.1.1.3.0"}
	threeOIDs := []string{engineOID, ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"}
	const setOID = ".1.3.6.1.2.1.1.5.0"

	scenarios := map[string]engineScenario{
		// Operations.
		"get":     {agent: answer(sysDescr)},
		"get/v1":  {v1: true, agent: answer(sysDescr)},
		"getnext": {agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetNext([]string{".1.3.6.1.2.1.1"}) }},
		"getbulk": {agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) {
			return x.GetBulk([]string{".1.3.6.1.2.1.1"}, 1, 10)
		}},
		"getbulk/v1": {v1: true, agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) {
			return x.GetBulk([]string{".1.3.6.1.2.1.1"}, 0, 10)
		}},
		"mk-snmp-packet": {agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) {
			return x.send(x.MkSnmpPacket(GetBulkRequest, []SnmpPDU{{Name: ".1.3.6.1.2.1.1", Type: Null}}, 2, 7))
		}},
		"set/unsupported-type": {agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: Boolean, Value: true})},
		"set/second-varbind-unsupported": {
			agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: Integer, Value: 1}, SnmpPDU{Name: setOID, Type: Boolean, Value: true}),
		},
		"set/integer-with-text": {agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: Integer, Value: "five"})},
		"set/opaque":            {agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: Opaque, Value: []byte{1, 2}})},
		"set/no-such-object":    {agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: NoSuchObject})},
		"set/second-varbind-opaque": {
			agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: Integer, Value: 1}, SnmpPDU{Name: setOID, Type: Opaque, Value: []byte{1, 2}}),
		},
		"set/no-varbinds": {agent: answer(), run: setVarbinds()},
		"get/invalid-oid": {agent: answer(), run: getOIDs(".1.3.6.1.x")},

		// The MaxOids limit, at 2.
		"get/max-oids/at-limit":       {agent: answer(sysDescr), setup: maxOIDs2, run: getOIDs(twoOIDs...)},
		"get/max-oids/over-limit":     {agent: answer(sysDescr), setup: maxOIDs2, run: getOIDs(threeOIDs...)},
		"getnext/max-oids/at-limit":   {agent: answer(sysDescr), setup: maxOIDs2, run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetNext(twoOIDs) }},
		"getnext/max-oids/over-limit": {agent: answer(sysDescr), setup: maxOIDs2, run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetNext(threeOIDs) }},
		"getbulk/max-oids/at-limit":   {agent: answer(sysDescr), setup: maxOIDs2, run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetBulk(twoOIDs, 0, 5) }},
		"getbulk/max-oids/over-limit": {agent: answer(sysDescr), setup: maxOIDs2, run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetBulk(threeOIDs, 0, 5) }},
		"set/max-oids/over-limit": {agent: answer(), setup: maxOIDs2, run: setVarbinds(
			SnmpPDU{Name: setOID, Type: Integer, Value: 1}, SnmpPDU{Name: setOID, Type: Integer, Value: 2}, SnmpPDU{Name: setOID, Type: Integer, Value: 3},
		)},

		// The client.
		"get/no-conn": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.Conn = nil }},
		// A client given a Conn without Connect: the request supplies the
		// Context and the receive buffer.
		"conn-without-connect": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.Context, x.Transport, x.rx = nil, "", nil
		}},
		"conn-without-receive-buffer": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.rx = nil
		}},
		"custom-conn": {shape: shapeStream, agent: answer(sysDescr)},

		// Timeouts and retries.
		"timeout":                  {},
		"timeout/exponential":      {setup: func(x *GoSNMP, _ *fakeTransport) { x.ExponentialTimeout = true }},
		"timeout/no-retries":       {setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = 0 }},
		"timeout/negative-retries": {setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = -3 }},

		// A hook that changes the client during a request.
		"hooks/retry-sets-retries": {setup: func(x *GoSNMP, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *GoSNMP) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets Retries to 0")
				x.Retries = 0
			}
		}},
		"hooks/retry-sets-exponential-timeout": {setup: func(x *GoSNMP, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *GoSNMP) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets ExponentialTimeout")
				x.ExponentialTimeout = true
			}
		}},
		"hooks/retry-cancels-context": {setup: func(x *GoSNMP, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *GoSNMP) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets a canceled Context")
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				x.Context = ctx
			}
		}},
		"hooks/retry-sets-context-deadline": {setup: func(x *GoSNMP, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *GoSNMP) {
				onRetry(x)
				c.tr.addf("hook OnRetry sets a Context with a deadline in 500ms")
				x.Context = unreportedDeadline{context.Background(), time.Now().Add(500 * time.Millisecond)}
			}
		}},
		"hooks/retry-replaces-hooks": {agent: answerFrom(3, sysDescr), setup: func(x *GoSNMP, c *fakeTransport) {
			onRetry := x.OnRetry
			x.OnRetry = func(x *GoSNMP) {
				onRetry(x)
				c.tr.addf("hook OnRetry replaces the hooks")
				replacement := func(name string) func(*GoSNMP) {
					return func(*GoSNMP) { c.tr.addf("hook %s, the replacement", name) }
				}
				x.PreSend, x.OnSent, x.OnRecv = replacement("PreSend"), replacement("OnSent"), replacement("OnRecv")
				x.OnRetry, x.OnFinish = replacement("OnRetry"), replacement("OnFinish")
			}
		}},
		"timeout/zero":          {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.Timeout = 0 }},
		"timeout/tcp":           {shape: shapeStream, setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport = "tcp" }},
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
			run: func(x *GoSNMP) (*SnmpPacket, error) {
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
				return []agentReply{{data: replyTo(req, nil, SnmpPDU{Name: engineOID, Type: OctetString, Value: []byte(value)})}}
			},
		},
		"answer/wrong-id": {agent: answerWith(func(p *SnmpPacket) { p.RequestID += 100 }, sysDescr)},
		"answer/zero-id": {
			agent: answerWith(func(p *SnmpPacket) { p.RequestID = 0 }, sysDescr),
		},
		"answer/v1-trap": {
			agent: func(int, []byte) []agentReply {
				trap := &SnmpPacket{
					Version: Version1, Community: "public", PDUType: Trap, Variables: []SnmpPDU{sysDescr},
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
			agent: answerWith(func(p *SnmpPacket) { p.RequestID += 100 }),
		},
		"answer/empty-with-error-status-wrong-id": {agent: answerWith(func(p *SnmpPacket) { p.RequestID += 100; p.Error = GenErr })},
		"answer/error-status":                     {agent: answerWith(func(p *SnmpPacket) { p.Error, p.ErrorIndex = NoSuchName, 1 }, SnmpPDU{Name: engineOID, Type: Null})},
		"answer/not-a-response": {
			agent: answerWith(func(p *SnmpPacket) { p.PDUType = GetRequest }, sysDescr),
		},
		"answer/reflected-request": {
			agent: func(_ int, req []byte) []agentReply { return []agentReply{{data: bytes.Clone(req)}} },
		},
		"answer/report": {
			agent: answerWith(func(p *SnmpPacket) { p.PDUType = Report }, sysDescr),
		},
		"answer/unknown-pdu-type": {
			agent: answerRaw(func(r []byte) []byte {
				r[bytes.IndexByte(r, byte(GetResponse))] = 0xaf
				return r
			}),
			knownBug: "the error text formats the PDU type's String() as hexadecimal",
		},
		"answer/other-version": {
			agent: answerWith(func(p *SnmpPacket) { p.Version = Version1 }, sysDescr),
		},
		// Replies that answer nothing, each followed by the answer.
		"answer/other-version-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: replyTo(req, func(p *SnmpPacket) { p.Version = Version1 }, sysDescr)}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/zero-id-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: replyTo(req, func(p *SnmpPacket) { p.RequestID = 0 }, sysDescr)}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/empty-wrong-id-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: replyTo(req, func(p *SnmpPacket) { p.RequestID += 100 })}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/other-version-v3": {
			agent: answerWith(func(p *SnmpPacket) {
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
				return []agentReply{{data: bareV3Answer(req, 0, Report, SnmpPDU{Name: usmStatsUnknownUserNames, Type: Counter32, Value: uint32(1)})}}
			},
		},
		"answer/other-version-v3-get-response": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: bareV3Answer(req, 7, GetResponse, sysDescr)}}
			},
		},
		"answer/other-community": {agent: answerWith(func(p *SnmpPacket) { p.Community = "private" }, sysDescr)},
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
		// A whole message that does not decode, then the agent closes the TCP
		// connection: the request's error names the discard.
		"answer/garbage-then-eof-tcp": {
			shape: shapeStream,
			setup: func(x *GoSNMP, c *fakeTransport) {
				x.Transport, x.Retries = "tcp", 0
				c.failRead = func(n int) error { return map[int]error{2: io.EOF}[n] }
			},
			agent: func(int, []byte) []agentReply { return []agentReply{{data: framedGarbage}} },
		},
		// The start of a message, then the agent closes the TCP connection.
		"answer/partial-then-eof-tcp": {
			shape: shapeStream,
			setup: func(x *GoSNMP, c *fakeTransport) {
				x.Transport, x.Retries = "tcp", 0
				c.failRead = func(n int) error { return map[int]error{2: io.EOF}[n] }
			},
			agent: func(int, []byte) []agentReply { return []agentReply{{data: garbage}} },
		},
		"answer/split-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: answerSplit(sysDescr, 10),
		},
		// A reply whose length takes a long form, split after its tag and
		// inside its length octets.
		"answer/split-header-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: answerSplit(SnmpPDU{Name: engineOID, Type: OctetString, Value: bytes.Repeat([]byte{'x'}, 200)}, 1, 2, 3),
		},
		// The reply to the first attempt arrives in two parts, the second
		// after the first attempt's deadline.
		"answer/split-across-attempts-tcp": {
			shape: shapeStream,
			setup: overTCP(1),
			agent: func(n int, req []byte) []agentReply {
				if n > 1 {
					return nil
				}
				r := replyTo(req, nil, sysDescr)
				return []agentReply{{data: r[:10]}, {data: r[10:], after: 1500 * time.Millisecond}}
			},
		},
		// A reply to another request and the reply in one read.
		"answer/joined-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: func(_ int, req []byte) []agentReply {
				stale := replyTo(req, func(p *SnmpPacket) { p.RequestID += 100 }, sysDescr)
				return []agentReply{{data: slices.Concat(stale, replyTo(req, nil, sysDescr))}}
			},
		},
		// Two requests: the first times out with the start of its reply, the
		// second reads the rest of it and its own reply in one read.
		"answer/leftover-next-request-tcp": func() engineScenario {
			var first []byte
			return engineScenario{
				shape: shapeStream,
				setup: overTCP(0),
				agent: func(n int, req []byte) []agentReply {
					r := replyTo(req, nil, sysDescr)
					if n == 1 {
						first = r
						return []agentReply{{data: r[:10]}}
					}
					return []agentReply{{data: slices.Concat(first[10:], r)}}
				},
				run: func(x *GoSNMP) (*SnmpPacket, error) {
					if _, err := x.Get([]string{engineOID}); err == nil {
						return nil, errors.New("the first Get was answered")
					}
					return x.Get([]string{engineOID})
				},
			}
		}(),
		"answer/largest-tcp": {
			shape: shapeStream,
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport = "tcp" },
			agent: func(_ int, req []byte) []agentReply {
				// The largest reply the receive buffer accepts.
				return []agentReply{{data: replySized(req, rxBufSize-1)}}
			},
		},
		// A reply as large as the receive buffer.
		"answer/buffer-size-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: replySized(req, rxBufSize)}}
			},
		},
		// A datagram that fills the receive buffer, which may have been cut
		// short: the attempt fails, and the retry uses the same socket.
		"answer/too-big-udp": {
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = 1 },
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: replySized(req, rxBufSize)}}
			},
		},
		// A message declaring 65536 content octets.
		"answer/too-big-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: func(int, []byte) []agentReply {
				return []agentReply{{data: slices.Concat([]byte{byte(Sequence), 0x83, 0x01, 0x00, 0x00}, make([]byte, 0x10000))}}
			},
		},
		// Octets that do not start a message, then the reply.
		"answer/not-sequence-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: []byte{byte(OctetString), 1, 0}}, {data: replyTo(req, nil, sysDescr), after: 10 * time.Millisecond}}
			},
		},
		// The reply with its length in the indefinite form, then with nine
		// length octets.
		"answer/indefinite-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: func(_ int, req []byte) []agentReply {
				r := replyTo(req, nil, sysDescr)
				return []agentReply{{data: slices.Concat([]byte{byte(Sequence), 0x80}, r[2:], []byte{0, 0})}}
			},
		},
		"answer/length-octets-tcp": {
			shape: shapeStream,
			setup: overTCP(0),
			agent: func(_ int, req []byte) []agentReply {
				r := replyTo(req, nil, sysDescr)
				return []agentReply{{data: slices.Concat([]byte{byte(Sequence), 0x89, 0, 0, 0, 0, 0, 0, 0, 0, r[1]}, r[2:])}}
			},
		},
		// A custom net.Conn under the UDP Transport, whose reply comes in two
		// reads.
		"custom-conn/split": {
			shape: shapeStream,
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = 0 },
			agent: answerSplit(sysDescr, 10),
		},

		// Transport errors.
		"write-error/once": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failWrite = func(n int) error { return map[int]error{1: errEngineWrite}[n] }
		}},
		"write-error/always": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failWrite = func(int) error { return errEngineWrite }
		}},
		"write-error/timeout-in-text": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failWrite = func(int) error { return errors.New("codec timeout of the write queue") }
		}},
		"deadline-error": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.deadlineErr = errors.New("codec deadline failure")
		}},
		"read-error/once": {agent: answerFromSecond(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failRead = func(n int) error { return map[int]error{1: refused}[n] }
		}},
		"read-error/always": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failRead = func(int) error { return refused }
		}},
		// The connection closed under the read and under the write: from then
		// on its deadline cannot be set either.
		"read-error/closed": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failRead = func(int) error {
				c.deadlineErr = closedSet
				return closedRead
			}
		}},
		"write-error/closed": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failWrite = func(int) error {
				c.deadlineErr = closedSet
				return closedWrite
			}
		}},
		"read-eof/udp": {agent: answerFromSecond(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
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
			setup:   func(x *GoSNMP, _ *fakeTransport) { x.Retries = 0 },
		},
		"context/deadline-in-first-attempt":   {context: withEngineTimeout(700 * time.Millisecond)},
		"context/deadline-in-third-attempt":   {context: withEngineTimeout(2500 * time.Millisecond)},
		"context/deadline-after-all-attempts": {context: withEngineTimeout(time.Hour)},
		"context/deadline-during-hook": {
			context: withEngineTimeout(1500 * time.Millisecond),
			setup: func(x *GoSNMP, c *fakeTransport) {
				x.OnRetry = func(*GoSNMP) {
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
			setup:   func(x *GoSNMP, _ *fakeTransport) { x.Retries = 0 },
		},
		// A Context whose deadline passed ends the request after an attempt
		// that failed otherwise, before OnRetry.
		"context/deadline-passed-in-hook": {
			context: withEngineTimeout(700 * time.Millisecond),
			setup: func(x *GoSNMP, c *fakeTransport) {
				x.OnSent = func(*GoSNMP) {
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
			setup: func(_ *GoSNMP, c *fakeTransport) {
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
			setup: func(x *GoSNMP, c *fakeTransport) {
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
		"context/canceled-after-request": {agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) {
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
			setup: func(x *GoSNMP, _ *fakeTransport) { _ = x.Close() },
		},
		"close/during-attempt": {
			agent: answerFromSecond(sysDescr),
			setup: func(x *GoSNMP, c *fakeTransport) {
				x.OnSent = func(x *GoSNMP) {
					c.tr.addf("hook OnSent closes the client")
					_ = x.Close()
				}
			},
		},
		"close/between-attempts": {
			agent: answerFromSecond(sysDescr),
			setup: func(x *GoSNMP, c *fakeTransport) {
				x.OnRetry = func(x *GoSNMP) {
					c.tr.addf("hook OnRetry closes the client")
					_ = x.Close()
				}
			},
		},
		// A Close after the reply was read: the reply answers the request.
		"close/after-the-reply": {agent: answer(sysDescr), setup: func(x *GoSNMP, c *fakeTransport) {
			x.OnRecv = func(x *GoSNMP) {
				c.tr.addf("hook OnRecv closes the client")
				_ = x.Close()
			}
		}},
		// A Close after a request in which a hook replaced Conn closes the
		// hook's connection and leaves the one the ended attempt used, the
		// caller's again, alone.
		"close/after-a-request-conn-replaced-by-hook": {
			agent: answer(sysDescr),
			setup: func(x *GoSNMP, c *fakeTransport) {
				hookConn := fakePacketTransport{newFakeTransport(c.tr, nil)}
				x.OnSent = func(x *GoSNMP) {
					c.tr.addf("hook OnSent replaces Conn")
					x.Conn = hookConn
				}
			},
			run: func(x *GoSNMP) (*SnmpPacket, error) {
				res, err := x.Get([]string{engineOID})
				_ = x.Close()
				return res, err
			},
		},
		// A hook removes Conn: the request fails for want of a connection, not
		// as closed.
		"close/conn-removed-by-hook": {setup: func(x *GoSNMP, c *fakeTransport) {
			x.OnRetry = func(x *GoSNMP) {
				c.tr.addf("hook OnRetry removes Conn")
				x.Conn = nil
			}
		}},
		// The client closed from another goroutine, as Netdata's SNMP topology
		// does when its context ends, while the request waits.
		// The read the interrupt wakes looks only once Close has closed the
		// connection too: either may come first otherwise.
		"close/from-another-goroutine": {setup: func(x *GoSNMP, c *fakeTransport) {
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
		"close/connection-from-another-goroutine": {setup: func(_ *GoSNMP, c *fakeTransport) {
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = c.Close()
			}()
		}},

		// Request IDs.
		"request-id/wraps": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.SetRequestID(0x7FFFFFFF) }},
		"request-id/wraps-between-attempts": {agent: answerFromSecond(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.SetRequestID(0x7FFFFFFE)
		}},
		"request-id/set": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.SetRequestID(5) }},

		// Socket shapes.
		"unconnected": {shape: shapeUnconnectedUDP, agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.opened = connection{conn: x.Conn, uaddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 161}}
		}},

		// Hooks.
		"hook-panics": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.PreSend = func(*GoSNMP) { panic("codec hook failure") }
		}},

		// The caller's code panics in a request, which ends; the next request
		// on the client is answered.
		"hook-panics/presend-error": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *GoSNMP, c *fakeTransport) {
			panicOnce(c, "PreSend", &x.PreSend, panicWithError)
		}},
		"hook-panics/onsent-runtime-error": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *GoSNMP, c *fakeTransport) {
			panicOnce(c, "OnSent", &x.OnSent, panicOnNilMap)
		}},
		"hook-panics/onrecv": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *GoSNMP, c *fakeTransport) {
			panicOnce(c, "OnRecv", &x.OnRecv, panicWithError)
		}},
		"hook-panics/onretry": {agent: answerFromSecond(sysDescr), run: getAfterPanic, setup: func(x *GoSNMP, c *fakeTransport) {
			panicOnce(c, "OnRetry", &x.OnRetry, panicWithError)
		}},
		"hook-panics/onfinish": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *GoSNMP, c *fakeTransport) {
			panicOnce(c, "OnFinish", &x.OnFinish, panicWithError)
		}},
		"hook-panics/logger": {agent: answer(sysDescr), run: getAfterPanic, setup: func(x *GoSNMP, c *fakeTransport) {
			armed := true
			x.Logger = NewLogger(funcLogger(func(s string) {
				if armed && strings.HasPrefix(s, "GET RESPONSE OK") {
					armed = false
					c.tr.addf("Logger panics at %q", "GET RESPONSE OK")
					panicWithError()
				}
			}))
		}},
		"hook-panics/conn-read": {agent: answer(sysDescr), run: getAfterPanic, setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failRead = func(n int) error {
				if n == 1 {
					c.tr.addf("the Conn's read #1 panics")
					panicWithError()
				}
				return nil
			}
		}},
	}

	// A Set of each value type it supports.
	for _, vb := range []SnmpPDU{
		{Type: Integer, Value: 5},
		{Type: OctetString, Value: "codec"},
		{Type: Gauge32, Value: uint32(6)},
		{Type: IPAddress, Value: "192.0.2.1"},
		{Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.8072"},
		{Type: Counter32, Value: uint32(7)},
		{Type: Counter64, Value: uint64(8)},
		{Type: Null},
		{Type: TimeTicks, Value: uint32(9)},
		{Type: Uinteger32, Value: uint32(10)},
		{Type: OpaqueFloat, Value: float32(1.5)},
		{Type: OpaqueDouble, Value: 2.5},
	} {
		vb.Name = setOID
		scenarios["set/"+vb.Type.String()] = engineScenario{agent: answer(vb), run: setVarbinds(vb)}
	}
	return scenarios
}

// TestEngineRequestCharacterization pins what the request engine does for
// v1/v2c requests, known bugs included: the messages it writes, the deadline
// of each attempt, which replies it accepts, the hooks it calls and what it
// returns. testdata/engine/requests.golden holds the transcripts.
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
	case shapeUDP, shapeUnconnectedUDP:
		conn = fakePacketTransport{c}
	case shapeStream:
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

	tr.addf("client: %v timeout=%s retries=%d exponential=%t", x.Version, x.Timeout, x.Retries, x.ExponentialTimeout)
	var res *SnmpPacket
	var err error
	before := configOf(x)
	if v, _ := recoverPanic(func() { res, err = run(x) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	tr.addConfigChanges(before, x)
	after := fmt.Sprintf("client after: retries=%d next request id=%d", x.Retries, (x.requestID.Load()+1)&0x7FFFFFFF)
	x.mu.Lock()
	if x.lost != nil {
		after += ", connection lost"
	}
	x.mu.Unlock()
	tr.addf("%s", after)
	if sc.knownBug != "" {
		tr.addf("known bug: %s", sc.knownBug)
	}
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

// TestEngineTCPReconnect pins, on loopback sockets, what the engine does when
// a TCP agent closes the connection after reading a request: the next attempt
// opens the connection again and sends again; the request fails with the
// reopen's error or when the retries run out, known bugs included.
func TestEngineTCPReconnect(t *testing.T) {
	tests := map[string]struct {
		transport      string        // "tcp" unless set
		acceptAgain    bool          // the agent accepts the reconnection
		ignoreFirst    bool          // the agent reads the first request and keeps the connection open
		staleReply     bool          // the agent answers the request after the reconnect with a reply to the first
		timeout        time.Duration // the client's Timeout; 10 s unless set
		retries        int           // the client's Retries; 1 unless set
		contextTimeout time.Duration // a context deadline before the timeout
		wantErr        string        // describeEngineError, the dial address masked; "" for a reply
		wantHooks      []string
		wantRequests   int32 // requests the agent read
	}{
		"retries run out": {
			acceptAgain: true, wantErr: `error "max retries (1) exceeded" *gosnmp.attemptsError (is io.EOF)`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent"}, wantRequests: 2,
		},
		"retries run out, tcp4": {
			transport: "tcp4", acceptAgain: true, wantErr: `error "max retries (1) exceeded" *gosnmp.attemptsError (is io.EOF)`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent"}, wantRequests: 2,
		},
		"retries run out after a timeout": {
			acceptAgain: true, ignoreFirst: true, timeout: 200 * time.Millisecond,
			wantErr:   `error "max retries (1) exceeded" *gosnmp.attemptsError (is io.EOF)`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent"}, wantRequests: 2,
		},
		"reply to the first request after the reconnect": {
			acceptAgain: true, staleReply: true, timeout: 500 * time.Millisecond,
			wantHooks:    []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent", "OnRecv", "OnFinish"},
			wantRequests: 2,
		},
		"negative retries count as 0": {
			acceptAgain: true, retries: -2, wantErr: `error "max retries (0) exceeded" *gosnmp.attemptsError (is io.EOF)`,
			wantHooks: []string{"PreSend", "OnSent"}, wantRequests: 1,
		},
		"reconnect refused": {
			wantErr:   `error "dial tcp <address>: connect: connection refused" *net.OpError (is syscall.ECONNREFUSED)`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry"}, wantRequests: 1,
		},
		"retries run out under a context deadline": {
			acceptAgain: true, contextTimeout: 5 * time.Second, wantErr: `error "max retries (1) exceeded" *gosnmp.attemptsError (is io.EOF)`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent"}, wantRequests: 2,
		},
	}
	dialAddress := regexp.MustCompile(`dial tcp \S+: `)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			var firstRequest atomic.Pointer[[]byte]
			port := tcpAgent(t, !tc.acceptAgain, func(req []byte) (reply []byte, keepOpen bool) {
				switch n := requests.Add(1); {
				case n == 1:
					firstRequest.Store(&req)
					return nil, tc.ignoreFirst
				case tc.staleReply:
					return replyTo(*firstRequest.Load(), nil, sysDescr), true
				}
				return nil, false
			})

			ctx := context.Background()
			if tc.contextTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.contextTimeout)
				defer cancel()
			}
			transport := tc.transport
			if transport == "" {
				transport = "tcp"
			}
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 10 * time.Second
			}
			var hooks []string
			hook := func(name string) func(*GoSNMP) { return func(*GoSNMP) { hooks = append(hooks, name) } }
			x := &GoSNMP{
				Target:    "127.0.0.1",
				Port:      port,
				Transport: transport,
				Community: "public",
				Version:   Version2c,
				Timeout:   timeout,
				Retries:   cmp.Or(tc.retries, 1),
				Context:   ctx,
				PreSend:   hook("PreSend"),
				OnSent:    hook("OnSent"),
				OnRecv:    hook("OnRecv"),
				OnRetry:   hook("OnRetry"),
				OnFinish:  hook("OnFinish"),
			}
			require.NoError(t, x.Connect())
			defer x.Close()

			res, err := x.Get([]string{engineOID})
			switch {
			case tc.wantErr == "":
				require.NoError(t, err)
				first, decodeErr := decodeMessage(*firstRequest.Load())
				require.NoError(t, decodeErr)
				assert.Equal(t, first.RequestID, res.RequestID, "the reply answers the first request")
			case runtime.GOOS == "windows" && name == "reconnect refused":
				// Windows words the refusal differently and reports WSAECONNREFUSED.
				got := dialAddress.ReplaceAllString(describeEngineError(err), "dial tcp <address>: ")
				assert.True(t, strings.HasPrefix(got, `error "dial tcp <address>: connectex:`), "got %s", got)
			default:
				require.Error(t, err)
				got := dialAddress.ReplaceAllString(describeEngineError(err), "dial tcp <address>: ")
				assert.Equal(t, tc.wantErr, got)
			}
			assert.Equal(t, tc.wantHooks, hooks, "hooks")
			assert.Equal(t, tc.wantRequests, requests.Load(), "requests the agent read")
		})
	}
}

// TestEngineTCPReconnectCallerConn pins that a request over a TCP Conn the
// caller set, without a Context, reconnects over the network it read from
// Transport at its start when the agent closes the connection, though a hook
// changes Transport during the request, and whatever network an earlier
// Connect of the client used; the client closes the caller's connection it
// replaces.
func TestEngineTCPReconnectCallerConn(t *testing.T) {
	tests := map[string]struct {
		before func(t *testing.T, x *GoSNMP) // what the client did before the caller set Conn
	}{
		"without Connect": {},
		"after a UDP Connect and Close": {before: func(t *testing.T, x *GoSNMP) {
			require.NoError(t, x.Connect())
			require.NoError(t, x.Close())
		}},
		"after a UDP Connect, Conn replaced": {before: func(t *testing.T, x *GoSNMP) {
			require.NoError(t, x.Connect())
			conn := x.Conn
			t.Cleanup(func() { _ = conn.Close() })
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			port := tcpAgent(t, false, func(req []byte) (reply []byte, keepOpen bool) {
				if requests.Add(1) == 1 {
					return nil, false // the agent closes the connection
				}
				return replyTo(req, nil, sysDescr), true
			})

			x := &GoSNMP{
				Target:    "127.0.0.1",
				Port:      unusedUDPPort(t),
				Community: "public",
				Version:   Version2c,
				Timeout:   10 * time.Second,
				Retries:   1,
				MaxOids:   MaxOids,
			}
			if tc.before != nil {
				tc.before(t, x)
			}
			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
			require.NoError(t, err)
			x.Conn, x.Context = conn, nil
			x.Transport, x.Port = "tcp", port
			x.OnSent = func(x *GoSNMP) { x.Transport = "udp" }
			defer x.Close()

			res, err := x.Get([]string{engineOID})
			require.NoError(t, err)
			assert.Equal(t, []SnmpPDU{sysDescr}, res.Variables)
			assert.Equal(t, int32(2), requests.Load(), "requests the agent read")
			assert.ErrorIs(t, conn.SetDeadline(time.Time{}), net.ErrClosed, "the reconnect closed the caller's connection")
		})
	}
}

// TestEngineTCPReconnectConnection pins, on loopback sockets, what a TCP
// reopen does with the connection the agent closed: when the new one opens, it
// closes the old one; when its dial is refused, the client keeps the old one,
// still lost, for a later attempt (TestEngineTCPLostConnection).
func TestEngineTCPReconnectConnection(t *testing.T) {
	type outcome struct {
		err       bool
		connFirst bool // Conn is the first connection
		connNil   bool
		firstOpen bool // the client has not closed the first connection
	}
	tests := map[string]struct {
		refuse bool // the agent stops listening after the first connection
		want   outcome
	}{
		"opens":   {want: outcome{}},
		"refused": {refuse: true, want: outcome{err: true, connFirst: true, firstOpen: true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			port := tcpAgent(t, tc.refuse, func(req []byte) (reply []byte, keepOpen bool) {
				if requests.Add(1) == 1 {
					return nil, false // the agent closes the connection
				}
				return replyTo(req, nil, sysDescr), true
			})
			x := &GoSNMP{
				Target: "127.0.0.1", Port: port, Transport: "tcp",
				Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: 1,
			}
			require.NoError(t, x.Connect())
			first := x.Conn
			defer first.Close()
			defer x.Close()

			_, err := x.Get([]string{engineOID})
			assert.Equal(t, tc.want, outcome{
				err:       err != nil,
				connFirst: x.Conn == first,
				connNil:   x.Conn == nil,
				firstOpen: first.SetDeadline(time.Time{}) == nil,
			})
		})
	}
}

// TestEngineTCPLostConnection checks, on loopback sockets, that a client whose
// TCP connection the agent closed or reset recovers once the agent accepts
// again: the next attempt reopens the connection, and after a refused reopen
// the next attempt, in this request or a later one, tries again. A timeout
// keeps the connection, and a connection closed under the client stays
// closed.
func TestEngineTCPLostConnection(t *testing.T) {
	type outcome struct {
		failed []bool // per request
		dials  int32  // Connect's and the reopens'
	}
	tests := map[string]struct {
		// first is what the agent does after reading the first request on its
		// first connection; it serves the connection on when it returns true.
		first  func(conn net.Conn) bool
		refuse []int32 // the dials the client's Control refuses, counted from 1 (Connect's)
		// closeConn closes the client's connection, not the client, after the
		// first request was written.
		closeConn bool
		want      outcome
	}{
		"the agent closes it, two reopens refused": {
			first:  func(conn net.Conn) bool { _ = conn.Close(); return false },
			refuse: []int32{2, 3},
			want:   outcome{failed: []bool{true, true, false, false}, dials: 4},
		},
		"the agent resets it": {
			first: func(conn net.Conn) bool {
				_ = conn.(*net.TCPConn).SetLinger(0) // close with a reset
				_ = conn.Close()
				return false
			},
			want: outcome{failed: []bool{false, false, false, false}, dials: 2},
		},
		"a timeout keeps it": {
			first: func(net.Conn) bool { return true }, // no reply to the first request
			want:  outcome{failed: []bool{false, false, false, false}, dials: 1},
		},
		"a close keeps it closed": {
			first:     func(net.Conn) bool { return true },
			closeConn: true,
			want:      outcome{failed: []bool{true, true, true, true}, dials: 1},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			var served sync.WaitGroup
			t.Cleanup(func() {
				ln.Close()
				served.Wait()
			})
			answer := func(req []byte) ([]byte, bool) { return replyTo(req, nil, sysDescr), true }
			served.Go(func() {
				for first := true; ; first = false {
					conn, acceptErr := ln.Accept()
					if acceptErr != nil {
						return
					}
					served.Go(func() {
						if first {
							if _, readErr := conn.Read(make([]byte, 2048)); readErr != nil || !tc.first(conn) {
								_ = conn.Close()
								return
							}
						}
						serveTCPRequests(conn, answer)
					})
				}
			})

			var dials atomic.Int32
			x := &GoSNMP{
				Target: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp", //nolint:gosec // a TCP port
				Community: "public", Version: Version2c, Timeout: 300 * time.Millisecond, Retries: 1,
				Control: func(string, string, syscall.RawConn) error {
					if slices.Contains(tc.refuse, dials.Add(1)) {
						return syscall.ECONNREFUSED
					}
					return nil
				},
			}
			require.NoError(t, x.Connect())
			defer x.Close()
			if tc.closeConn {
				x.OnSent = func(x *GoSNMP) {
					x.OnSent = nil
					_ = x.Conn.Close()
				}
			}
			var got outcome
			for range 4 {
				_, err := x.Get([]string{engineOID})
				got.failed = append(got.failed, err != nil)
			}
			got.dials = dials.Load()
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestEngineTCPStreamFraming checks, on loopback sockets, how a client reads
// what a TCP agent writes in answer to the first request on its first
// connection: a reply in two writes, a reply to another request and the reply
// in one write, octets that do not start a message, or a message longer than
// the receive buffer; the agent serves the connection on, and every later one.
// The client reads every reply in the attempt it arrives in; a stream it
// cannot read on is lost, and the retry opens a new connection.
func TestEngineTCPStreamFraming(t *testing.T) {
	type outcome struct {
		failed  []bool // per request
		retries int
		dials   int32 // Connect's and the reopens'
	}
	tests := map[string]struct {
		first func(conn net.Conn, req []byte)
		want  outcome
	}{
		"a reply in two writes": {
			first: func(conn net.Conn, req []byte) {
				r := replyTo(req, nil, sysDescr)
				_, _ = conn.Write(r[:10])
				time.Sleep(50 * time.Millisecond)
				_, _ = conn.Write(r[10:])
			},
			want: outcome{failed: []bool{false, false}, retries: 0, dials: 1},
		},
		"two replies in one write": {
			first: func(conn net.Conn, req []byte) {
				stale := replyTo(req, func(p *SnmpPacket) { p.RequestID += 100 }, sysDescr)
				_, _ = conn.Write(slices.Concat(stale, replyTo(req, nil, sysDescr)))
			},
			want: outcome{failed: []bool{false, false}, retries: 0, dials: 1},
		},
		"octets that do not start a message": {
			first: func(conn net.Conn, _ []byte) { _, _ = conn.Write([]byte{byte(OctetString), 1, 0}) },
			want:  outcome{failed: []bool{false, false}, retries: 1, dials: 2},
		},
		"a message longer than the receive buffer": {
			first: func(conn net.Conn, _ []byte) {
				_, _ = conn.Write(slices.Concat([]byte{byte(Sequence), 0x83, 0x01, 0x11, 0x70}, make([]byte, 70000)))
			},
			want: outcome{failed: []bool{false, false}, retries: 1, dials: 2},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			var served sync.WaitGroup
			t.Cleanup(func() {
				ln.Close()
				served.Wait()
			})
			answer := func(req []byte) ([]byte, bool) { return replyTo(req, nil, sysDescr), true }
			served.Go(func() {
				for first := true; ; first = false {
					conn, acceptErr := ln.Accept()
					if acceptErr != nil {
						return
					}
					served.Go(func() {
						if first {
							buf := make([]byte, 2048)
							n, readErr := conn.Read(buf)
							if readErr != nil {
								_ = conn.Close()
								return
							}
							tc.first(conn, buf[:n])
						}
						serveTCPRequests(conn, answer)
					})
				}
			})

			var dials atomic.Int32
			var got outcome
			x := &GoSNMP{
				Target: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp", //nolint:gosec // a TCP port
				Community: "public", Version: Version2c, Timeout: 300 * time.Millisecond, Retries: 1,
				Control: func(string, string, syscall.RawConn) error {
					dials.Add(1)
					return nil
				},
				OnRetry: func(*GoSNMP) { got.retries++ },
			}
			require.NoError(t, x.Connect())
			defer x.Close()
			for range 2 {
				_, err := x.Get([]string{engineOID})
				got.failed = append(got.failed, err != nil)
			}
			got.dials = dials.Load()
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestEngineTCPReopenLookupWithinBounds checks that a TCP reopen looks up its
// named local address within the request's Context and Timeout, for the
// connection Connect opened and for a Conn the caller set: a lookup that does
// not end fails the request at once when the Context is canceled, and when the
// Timeout passes, with an error that matches it, also after a Close, which
// does not cut the lookup short.
func TestEngineTCPReopenLookupWithinBounds(t *testing.T) {
	origins := map[string]bool{"the connection Connect opened": false, "a Conn the caller set": true}
	ends := map[string]struct {
		timeout time.Duration
		end     func(x *GoSNMP, cancel context.CancelFunc)
		want    error
	}{
		"Context canceled": {timeout: time.Minute, end: func(_ *GoSNMP, cancel context.CancelFunc) { cancel() }, want: context.Canceled},
		"Timeout":          {timeout: 100 * time.Millisecond, want: context.DeadlineExceeded},
		"Close":            {timeout: 100 * time.Millisecond, end: func(x *GoSNMP, _ context.CancelFunc) { _ = x.Close() }, want: net.ErrClosed},
	}
	for originName, callerConn := range origins {
		for endName, end := range ends {
			t.Run(originName+", "+endName, func(t *testing.T) {
				dns := newStubDNS(t)
				// The agent resets its first connection after the first request.
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				served := make(chan struct{})
				go func() {
					defer close(served)
					conn, acceptErr := ln.Accept()
					if acceptErr != nil {
						return
					}
					_, _ = conn.Read(make([]byte, 2048))
					_ = conn.(*net.TCPConn).SetLinger(0)
					_ = conn.Close()
				}()
				defer func() {
					ln.Close()
					<-served
				}()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a TCP port
				x := &GoSNMP{
					Target: "127.0.0.1", Port: port, Transport: "tcp", LocalAddr: "bind.codec.invalid.:0",
					Community: "public", Version: Version2c, MaxOids: MaxOids,
					Timeout: end.timeout, Retries: 1, Context: ctx,
				}
				if callerConn {
					x.Conn = dialTCPAgent(t, port)
				} else {
					require.NoError(t, x.Connect())
				}
				defer x.Close()
				dns.answering.Store(false)

				result := make(chan error, 1)
				go func() {
					_, err := x.Get([]string{engineOID})
					result <- err
				}()
				dns.awaitHeld(t) // the reopen's lookup of the local address
				if end.end != nil {
					end.end(x, cancel)
				}
				select {
				case err := <-result:
					assert.ErrorIs(t, err, end.want)
				case <-time.After(2 * time.Second):
					dns.release()
					t.Errorf("the request waits for the lookup; after its release: %v", <-result)
				}
			})
		}
	}
}

// TestEngineTCPReopenContext checks that the request's Context bounds the
// dial of a TCP reopen: canceled during the dial, it fails the dial, and the
// request with the dial's error, which matches context.Canceled.
func TestEngineTCPReopenContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows may complete a TCP connect before it sees the cancellation")
	}
	var requests atomic.Int32
	port := tcpAgent(t, false, func(req []byte) (reply []byte, keepOpen bool) {
		if requests.Add(1) == 1 {
			return nil, false // the agent closes the connection
		}
		return replyTo(req, nil, sysDescr), true
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dials atomic.Int32
	x := &GoSNMP{
		Target: "127.0.0.1", Port: port, Transport: "tcp", Context: ctx,
		Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: 1,
		Control: func(string, string, syscall.RawConn) error {
			if dials.Add(1) == 2 { // the reopen's dial
				cancel()
			}
			return nil
		},
	}
	require.NoError(t, x.Connect())
	defer x.Close()

	_, err := x.Get([]string{engineOID})
	require.ErrorIs(t, err, context.Canceled)
	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "dial", opErr.Op)
	assert.Equal(t, int32(1), requests.Load(), "requests the agent read")
}

// TestEngineTCPReconnectDialSettings pins that a TCP reopen opens the
// connection with the settings Connect opened it with, or, for a Conn the
// caller set, with the client's settings when the request started, and with
// the request's Context and Timeout, though a hook changes the client's Port,
// Control, Context and Timeout before the agent closes the connection.
func TestEngineTCPReconnectDialSettings(t *testing.T) {
	tests := map[string]struct {
		callerConn bool // the caller sets Conn instead of Connect
		closeAt    int  // the request agent A reads and closes the connection after; it ignores those before
		want       int32
	}{
		"Connect's settings":    {closeAt: 1, want: 2},
		"a Conn the caller set": {callerConn: true, closeAt: 2, want: 3},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var requestsA, requestsB, hookControls atomic.Int32
			portA := tcpAgent(t, false, func(req []byte) (reply []byte, keepOpen bool) {
				switch n := int(requestsA.Add(1)); {
				case n < tc.closeAt:
					return nil, true
				case n == tc.closeAt:
					return nil, false
				}
				return replyTo(req, nil, sysDescr), true
			})
			portB := tcpAgent(t, false, func(req []byte) (reply []byte, keepOpen bool) {
				requestsB.Add(1)
				return replyTo(req, nil, sysDescr), true
			})
			x := &GoSNMP{
				Target: "127.0.0.1", Port: portA, Transport: "tcp", MaxOids: MaxOids,
				Community: "public", Version: Version2c, Timeout: 200 * time.Millisecond, Retries: 2,
			}
			if tc.callerConn {
				x.Conn = dialTCPAgent(t, portA)
			} else {
				require.NoError(t, x.Connect())
			}
			defer x.Close()
			// The hook runs before the attempt whose request agent A closes the
			// connection after.
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			hook := func(x *GoSNMP) {
				x.Port, x.Context, x.Timeout = portB, canceled, time.Nanosecond
				x.Control = func(string, string, syscall.RawConn) error {
					hookControls.Add(1)
					return nil
				}
			}
			if tc.closeAt == 1 {
				x.OnSent = func(x *GoSNMP) { x.OnSent = nil; hook(x) }
			} else {
				x.OnRetry = func(x *GoSNMP) { x.OnRetry = nil; hook(x) }
			}

			_, err := x.Get([]string{engineOID})
			require.NoError(t, err)
			type outcome struct{ requestsA, requestsB, hookControls int32 }
			assert.Equal(t, outcome{requestsA: tc.want}, outcome{requestsA.Load(), requestsB.Load(), hookControls.Load()})
		})
	}
}

// TestEngineTCPReconnectClosedDuringDial checks that a Close during the dial of
// a TCP reopen ends the request with net.ErrClosed: the client stays closed,
// and closes the connection the dial opened.
func TestEngineTCPReconnectClosedDuringDial(t *testing.T) {
	for _, retries := range []int{0, 1} {
		t.Run(fmt.Sprintf("refused, retries %d", retries), func(t *testing.T) {
			// The agent stops listening after the first connection, so the
			// reconnect's dial fails after the Close.
			port := tcpAgent(t, true, func([]byte) (reply []byte, keepOpen bool) { return nil, false })
			var x *GoSNMP
			var dials atomic.Int32
			x = &GoSNMP{
				Target: "127.0.0.1", Port: port, Transport: "tcp",
				Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: retries,
				Control: func(string, string, syscall.RawConn) error {
					if dials.Add(1) == 2 { // the reconnect's dial
						_ = x.Close()
					}
					return nil
				},
			}
			require.NoError(t, x.Connect())
			defer x.Close()

			require.ErrorIs(t, getReopening(t, x, retries), net.ErrClosed)
		})
		t.Run(fmt.Sprintf("from another goroutine, retries %d", retries), func(t *testing.T) {
			// The Close runs on another goroutine, unsynchronized with the
			// reconnect's commit, as the race detector needs to see it.
			port, _ := closingAgent(t)
			dialing := make(chan struct{})
			var dials atomic.Int32
			x := &GoSNMP{
				Target: "127.0.0.1", Port: port, Transport: "tcp",
				Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: retries,
				Control: func(string, string, syscall.RawConn) error {
					if dials.Add(1) == 2 { // the reconnect's dial
						close(dialing)
						time.Sleep(50 * time.Millisecond)
					}
					return nil
				},
			}
			require.NoError(t, x.Connect())
			defer x.Close()
			closed := make(chan error, 1)
			go func() {
				<-dialing
				closed <- x.Close()
			}()

			require.ErrorIs(t, getReopening(t, x, retries), net.ErrClosed)
			require.NoError(t, <-closed)
		})
		t.Run(fmt.Sprintf("retries %d", retries), func(t *testing.T) {
			port, second := closingAgent(t)
			var x *GoSNMP
			var dials atomic.Int32
			x = &GoSNMP{
				Target: "127.0.0.1", Port: port, Transport: "tcp",
				Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: retries,
				Control: func(string, string, syscall.RawConn) error {
					if dials.Add(1) == 2 { // the reconnect's dial
						_ = x.Close()
					}
					return nil
				},
			}
			require.NoError(t, x.Connect())
			defer x.Close()

			require.ErrorIs(t, getReopening(t, x, retries), net.ErrClosed)
			assert.Nil(t, x.Conn)
			assert.ErrorIs(t, <-second, io.EOF, "the client closed the reconnect's connection")
		})
	}
}

// getReopening runs a request on a client whose TCP agent closes the
// connection after the first request, up to the attempt that opens the
// connection again: with retries, the request's retry; without, the next
// request's attempt, after the first request failed on the close.
func getReopening(t *testing.T, x *GoSNMP, retries int) error {
	t.Helper()
	_, err := x.Get([]string{engineOID})
	if retries == 0 {
		require.ErrorIs(t, err, io.EOF, "the request the agent closed the connection on")
		_, err = x.Get([]string{engineOID})
	}
	return err
}

// TestEngineTCPReconnectHookReplacedConn checks that a TCP connection the
// agent closed after a hook replaced Conn during the attempt is not opened
// again: the next attempt uses the hook's connection, also on a client closed
// before the caller set its Conn, and for a hook's Conn of a type == cannot
// compare.
func TestEngineTCPReconnectHookReplacedConn(t *testing.T) {
	tests := map[string]struct {
		before       func(t *testing.T, x *GoSNMP, portA uint16) // how the client gets its connection to agent A
		uncomparable bool                                        // the hook's Conn is an uncomparableConn
	}{
		"a hook's Conn of a type == cannot compare": {uncomparable: true, before: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
		}},
		"after Connect": {before: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
		}},
		"Conn set by the caller after Close": {before: func(t *testing.T, x *GoSNMP, portA uint16) {
			x.Transport = "udp"
			require.NoError(t, x.Connect())
			require.NoError(t, x.Close())
			x.Transport, x.Conn = "tcp", dialTCPAgent(t, portA)
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			portA, _ := closingAgent(t)
			var requestsB, dials atomic.Int32
			portB := tcpAgent(t, false, func(req []byte) (reply []byte, keepOpen bool) {
				requestsB.Add(1)
				return replyTo(req, nil, sysDescr), true
			})
			x := &GoSNMP{
				Target: "127.0.0.1", Port: portA, Transport: "tcp",
				Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: 1,
				Control: func(string, string, syscall.RawConn) error {
					dials.Add(1)
					return nil
				},
			}
			tc.before(t, x, portA)
			first := x.Conn
			defer first.Close()
			defer x.Close()
			x.OnSent = func(x *GoSNMP) {
				x.OnSent = nil
				x.Conn = dialTCPAgent(t, portB)
				if tc.uncomparable {
					x.Conn = uncomparableConn{Conn: x.Conn, onClose: func() {}}
				}
			}

			_, err := x.Get([]string{engineOID})
			require.NoError(t, err)
			assert.Equal(t, [2]int32{1, 1}, [2]int32{requestsB.Load(), dials.Load()}, "requests agent B read, dials (Connect's)")
		})
	}
}

// closingAgent listens on a loopback TCP port, closes its first connection
// after reading a request, and sends the result of reading from its second
// connection on second: io.EOF when the client closes it, nil when a request
// arrives, a timeout after 10 s.
func closingAgent(t *testing.T) (port uint16, second <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		first, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = first.Read(make([]byte, 2048))
		first.Close()
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, readErr := conn.Read(make([]byte, 2048))
		result <- readErr
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return uint16(ln.Addr().(*net.TCPAddr).Port), result //nolint:gosec // a TCP port
}

// uncomparableConn is a connection of a type == cannot compare: a struct with
// a func field, used by value.
type uncomparableConn struct {
	net.Conn
	onClose func()
}

// TestEngineTCPReconnectUncomparableConn checks that a request over a Conn the
// caller set, of a type == cannot compare, reconnects when the agent closes
// the connection, and that the client stays usable: Close returns.
func TestEngineTCPReconnectUncomparableConn(t *testing.T) {
	var requests atomic.Int32
	port := tcpAgent(t, false, func(req []byte) (reply []byte, keepOpen bool) {
		if requests.Add(1) == 1 {
			return nil, false // the agent closes the connection
		}
		return replyTo(req, nil, sysDescr), true
	})
	caller := dialTCPAgent(t, port)
	defer caller.Close()
	x := &GoSNMP{
		Target: "127.0.0.1", Port: port, Transport: "tcp", MaxOids: MaxOids,
		Community: "public", Version: Version2c, Timeout: 10 * time.Second, Retries: 1,
		Conn: uncomparableConn{Conn: caller, onClose: func() {}},
	}

	res, err := x.Get([]string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []SnmpPDU{sysDescr}, res.Variables)
	closed := make(chan error, 1)
	go func() { closed <- x.Close() }()
	select {
	case err = <-closed:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocks")
	}
}

// dialTCPAgent connects to the loopback TCP agent on port.
func dialTCPAgent(t *testing.T, port uint16) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	require.NoError(t, err)
	return conn
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
	x.PreSend = func(*GoSNMP) { panic(nil) } //nolint:govet // the nil panic is the point
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
						x.OnSent = func(*GoSNMP) { cancel() }
						if interrupt == "close-replaced-conn" {
							wantErr = net.ErrClosed
							x.OnSent = func(x *GoSNMP) {
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

// TestEngineReadCountOutsideBuffer checks, on loopback sockets, a Conn the
// caller set whose Read breaks the io.Reader contract once, returning a count
// outside the buffer: the attempt fails as a transport error, which the retry
// cures (over TCP the connection is lost and opened again), and the client
// answers the next request.
func TestEngineReadCountOutsideBuffer(t *testing.T) {
	type outcome struct {
		failed  []bool // per request
		retries int
		dials   int32 // Connect's and the reopens'
	}
	answer := func(req []byte) []byte { return replyTo(req, nil, sysDescr) }
	tests := map[string]struct {
		transport string
		count     func(p []byte) int
		want      outcome
	}{
		"TCP, more than the buffer": {
			transport: "tcp", count: func(p []byte) int { return len(p) + 1 },
			want: outcome{failed: []bool{false, false}, retries: 1, dials: 2},
		},
		"TCP, negative": {
			transport: "tcp", count: func([]byte) int { return -1 },
			want: outcome{failed: []bool{false, false}, retries: 1, dials: 2},
		},
		"UDP, more than the buffer": {
			transport: "udp", count: func(p []byte) int { return len(p) + 1 },
			want: outcome{failed: []bool{false, false}, retries: 1, dials: 1},
		},
		"UDP, negative": {
			transport: "udp", count: func([]byte) int { return -1 },
			want: outcome{failed: []bool{false, false}, retries: 1, dials: 1},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var port uint16
			if tc.transport == "tcp" {
				port = tcpAgent(t, false, func(req []byte) ([]byte, bool) { return answer(req), true })
			} else {
				port, _ = udpAgent(t, func(_ int, req []byte) []byte { return answer(req) })
			}
			var dials atomic.Int32
			var got outcome
			x := &GoSNMP{
				Target: "127.0.0.1", Port: port, Transport: tc.transport, Community: "public", Version: Version2c,
				Timeout: 300 * time.Millisecond, Retries: 1,
				Control: func(string, string, syscall.RawConn) error {
					dials.Add(1)
					return nil
				},
				OnRetry: func(*GoSNMP) { got.retries++ },
			}
			require.NoError(t, x.Connect())
			defer x.Close()
			x.Conn = &badCountConn{Conn: x.Conn, count: tc.count}
			for range 2 {
				_, err := x.Get([]string{engineOID})
				got.failed = append(got.failed, err != nil)
			}
			got.dials = dials.Load()
			assert.Equal(t, tc.want, got)
		})
	}
}

// badCountConn is a Conn whose first Read returns count's count without
// reading, breaking the io.Reader contract; its other calls go to Conn.
type badCountConn struct {
	net.Conn
	count func(p []byte) int
	done  bool
}

func (c *badCountConn) Read(p []byte) (int, error) {
	if !c.done {
		c.done = true
		return c.count(p), nil
	}
	return c.Conn.Read(p)
}

// tcpAgent listens on a loopback TCP port and serves each connection with
// serveTCPRequests and handle; with refuseAgain it stops listening after the
// first connection. It returns the port; the listener closes when the test
// ends.
func tcpAgent(t *testing.T, refuseAgain bool, handle func(req []byte) (reply []byte, keepOpen bool)) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for first := true; ; first = false {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			if first && refuseAgain {
				ln.Close()
			}
			go serveTCPRequests(conn, handle)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a TCP port
}

// serveTCPRequests reads requests from conn, whole ones in each read (the
// client writes each in one write), and hands each to handle, which returns the
// reply to write, if any, and whether to keep the connection open; conn closes
// when it is not kept open, when a read ends inside a request, or when the
// client closes it.
func serveTCPRequests(conn net.Conn, handle func(req []byte) (reply []byte, keepOpen bool)) {
	defer conn.Close()
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return
		}
		// Requests the client wrote back to back can arrive in one read.
		r := ber.NewReader(bytes.Clone(buf[:n]))
		for r.Len() > 0 {
			rest := r.Rest()
			if _, _, err := r.Next(); err != nil {
				return
			}
			reply, keepOpen := handle(rest[:len(rest)-r.Len()])
			if reply != nil {
				if _, err := conn.Write(reply); err != nil {
					return
				}
			}
			if !keepOpen {
				return
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

	x := &GoSNMP{
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

// TestEngineReplyLogger pins that a reply carries the client's Logger.
func TestEngineReplyLogger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newFakeTransport(nil, answer(sysDescr))
		x := newEngineClient(t, nil, Version2c, c)
		x.Logger = NewLogger(log.New(io.Discard, "", 0))
		res, err := x.Get([]string{engineOID})
		require.NoError(t, err)
		assert.Equal(t, x.Logger, res.Logger)
	})
}

// BenchmarkSendOneRequest measures one SNMPv2c Get through the request engine
// on the in-memory transport, without socket system calls; the agent's
// decoding of the request and encoding of the reply are included.
func BenchmarkSendOneRequest(b *testing.B) {
	const oid = ".1.3.6.1.2.1.31.1.1.1.10.1"
	c := newFakeTransport(nil, func(_ int, req []byte) []agentReply {
		return []agentReply{{data: replyTo(req, nil, SnmpPDU{Name: oid, Type: Counter64, Value: uint64(3825929753)})}}
	})
	x := newEngineClient(b, nil, Version2c, fakePacketTransport{c})
	pkt := x.MkSnmpPacket(GetRequest, []SnmpPDU{{Name: oid, Type: Null}}, 0, 0)
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
// the request ID of an SNMPv2c GetResponse), and whether its digest checked.
func TestExchangeRankOf(t *testing.T) {
	earlier := []sentIDs{{requestID: 1, msgID: 5}}
	tests := map[string]struct {
		version  SnmpVersion
		read     *SnmpPacket
		verified bool
		want     discardRank
	}{
		"v3/msgID not read":                    {version: Version3, want: rankUnread},
		"v3/another request's msgID":           {version: Version3, read: &SnmpPacket{MsgID: 6, RequestID: 2}},
		"v3/another request's msgID, verified": {version: Version3, read: &SnmpPacket{MsgID: 6, RequestID: 2}, verified: true},
		"v3/the attempt's msgID":               {version: Version3, read: &SnmpPacket{MsgID: 7}, want: rankNamed},
		"v3/an earlier attempt's msgID":        {version: Version3, read: &SnmpPacket{MsgID: 5}, want: rankNamed},
		"v3/the attempt's msgID, verified":     {version: Version3, read: &SnmpPacket{MsgID: 7}, verified: true, want: rankAuthentic},
		"v3/the attempt's msgID, a GetRequest": {version: Version3, read: &SnmpPacket{MsgID: 7, PDUType: GetRequest}, want: rankNamed},
		"v3/a verified GetRequest":             {version: Version3, read: &SnmpPacket{MsgID: 7, PDUType: GetRequest}, verified: true, want: rankNamed},
		"v3/a verified InformRequest":          {version: Version3, read: &SnmpPacket{MsgID: 7, PDUType: InformRequest}, verified: true, want: rankNamed},
		"v3/a verified Report":                 {version: Version3, read: &SnmpPacket{MsgID: 7, PDUType: Report}, verified: true, want: rankAuthentic},
		"v3/a verified GetResponse":            {version: Version3, read: &SnmpPacket{MsgID: 7, PDUType: GetResponse}, verified: true, want: rankAuthentic},
		"v2c/request ID not read":              {version: Version2c, want: rankUnread},
		"v2c/another request's ID":             {version: Version2c, read: &SnmpPacket{RequestID: 3, MsgID: 7, PDUType: GetResponse}},
		"v2c/the attempt's request ID":         {version: Version2c, read: &SnmpPacket{RequestID: 2, PDUType: GetResponse}, want: rankNamed},
		"v2c/an earlier attempt's request ID":  {version: Version2c, read: &SnmpPacket{RequestID: 1, PDUType: GetResponse}, want: rankNamed},
		"v2c/the attempt's request ID, Report": {version: Version2c, read: &SnmpPacket{RequestID: 2, PDUType: Report}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			e := exchange{packet: &SnmpPacket{Version: tc.version, RequestID: 2, MsgID: 7}}
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
			msg: craftedMsg(1, tlv(byte(GetResponse), intTLV(9), intTLV(-1), intTLV(0), vbl)), want: new(uint32(9)),
		},
		"request ID that does not decode": {msg: craftedMsg(1, tlv(byte(GetResponse), octets("x"), intTLV(0), intTLV(0), vbl))},
		"unknown PDU type":                {msg: craftedMsg(1, tlv(0xaf, intTLV(9), intTLV(0), intTLV(0), vbl))},
		"SNMPv1 trap tag":                 {msg: craftedMsg(1, tlv(byte(Trap), intTLV(9), intTLV(0)))},
		"a PDU without its message":       {msg: tlv(byte(GetResponse), intTLV(9), intTLV(-1), intTLV(0), vbl)},
		// Another version is discarded before its request ID is read.
		"SNMPv1 message": {msg: craftedMsg(0, tlv(byte(GetResponse), intTLV(9), intTLV(-1), intTLV(0), vbl))},
		// An SNMPv3 message names its request by its msgID.
		"SNMPv3 message whose msgData is a PDU": {
			msg: craftedV3(intTLV(7), intTLV(65507), octets("\x00"), intTLV(3),
				craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(""), octets("")),
				tlv(byte(GetResponse), intTLV(9), intTLV(-1), intTLV(0), vbl)),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			e := &exchange{x: &GoSNMP{Version: Version2c}, packet: &SnmpPacket{Version: Version2c, PDUType: GetRequest}}
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
	request := func(version SnmpVersion) *SnmpPacket {
		p := &SnmpPacket{Version: version, PDUType: GetRequest, RequestID: 2, Community: "public"}
		if version == Version3 {
			p.MsgID, p.MsgFlags, p.ContextEngineID, p.ContextName = 7, AuthNoPriv|Reportable, "ctx-engine", "ctx"
			p.SecurityParameters = &UsmSecurityParameters{UserName: "user", AuthoritativeEngineID: "engine"}
		}
		return p
	}
	// reply is the answer to the current attempt, a copy of its request.
	reply := func(req *SnmpPacket) *SnmpPacket {
		p := *req
		p.PDUType, p.MsgFlags, p.Variables = GetResponse, req.MsgFlags&AuthPriv, []SnmpPDU{sysDescr}
		if req.SecurityParameters != nil {
			p.SecurityParameters = req.SecurityParameters.Copy()
		}
		return &p
	}
	usm := func(p *SnmpPacket) *UsmSecurityParameters { return p.SecurityParameters.usm() }
	report := func(counter string) func(p *SnmpPacket) {
		return func(p *SnmpPacket) {
			p.PDUType, p.RequestID, p.MsgFlags, p.Variables = Report, 0, NoAuthNoPriv, []SnmpPDU{{Name: counter, Type: Counter32, Value: uint32(1)}}
			p.ContextEngineID, p.ContextName = "engine", ""
		}
	}
	tests := map[string]struct {
		version SnmpVersion
		request func(p *SnmpPacket)
		reply   func(p *SnmpPacket)
		answers bool
		err     error
	}{
		"v3/the answer":                    {version: Version3, answers: true},
		"v3/an earlier attempt's answer":   {version: Version3, reply: func(p *SnmpPacket) { p.MsgID, p.RequestID = 5, 1 }, answers: true},
		"v3/an earlier attempt's ID":       {version: Version3, reply: func(p *SnmpPacket) { p.RequestID = 1 }, err: errOtherRequestID},
		"v3/the attempt's ID, earlier msg": {version: Version3, reply: func(p *SnmpPacket) { p.MsgID = 5 }, err: errOtherRequestID},
		"v3/request ID 0":                  {version: Version3, reply: func(p *SnmpPacket) { p.RequestID = 0 }, err: errOtherRequestID},
		"v3/empty, another request ID": {
			version: Version3, reply: func(p *SnmpPacket) { p.Variables, p.RequestID = nil, 9 }, err: errOtherRequestID,
		},
		"v3/reportable":           {version: Version3, reply: func(p *SnmpPacket) { p.MsgFlags |= Reportable }, answers: true},
		"v3/not reportable":       {version: Version3, request: func(p *SnmpPacket) { p.MsgFlags = AuthNoPriv }, reply: func(p *SnmpPacket) { p.MsgFlags |= Reportable }, answers: true},
		"v3/noAuthNoPriv":         {version: Version3, reply: func(p *SnmpPacket) { p.MsgFlags = NoAuthNoPriv }, err: errOtherLevel},
		"v3/authPriv":             {version: Version3, reply: func(p *SnmpPacket) { p.MsgFlags = AuthPriv }, err: errOtherLevel},
		"v3/to noAuthNoPriv":      {version: Version3, request: func(p *SnmpPacket) { p.MsgFlags = NoAuthNoPriv | Reportable }, err: errOtherLevel},
		"v3/to authPriv":          {version: Version3, request: func(p *SnmpPacket) { p.MsgFlags = AuthPriv | Reportable }, err: errOtherLevel},
		"v3/another user":         {version: Version3, reply: func(p *SnmpPacket) { usm(p).UserName = "other" }, err: errOtherUser},
		"v3/the empty user":       {version: Version3, reply: func(p *SnmpPacket) { usm(p).UserName = "" }, err: errOtherUser},
		"v3/to the empty user":    {version: Version3, request: func(p *SnmpPacket) { usm(p).UserName = "" }, err: errOtherUser},
		"v3/another engine ID":    {version: Version3, reply: func(p *SnmpPacket) { usm(p).AuthoritativeEngineID = "other" }, err: errOtherEngine},
		"v3/no engine ID":         {version: Version3, reply: func(p *SnmpPacket) { usm(p).AuthoritativeEngineID = "" }, err: errOtherEngine},
		"v3/to no engine ID":      {version: Version3, request: func(p *SnmpPacket) { usm(p).AuthoritativeEngineID = "" }, err: errOtherEngine},
		"v3/another context ID":   {version: Version3, reply: func(p *SnmpPacket) { p.ContextEngineID = "engine" }, err: errOtherContext},
		"v3/to no context ID":     {version: Version3, request: func(p *SnmpPacket) { p.ContextEngineID = "" }, err: errOtherContext},
		"v3/another context name": {version: Version3, reply: func(p *SnmpPacket) { p.ContextName = "" }, err: errOtherContext},
		"v3/to another context":   {version: Version3, request: func(p *SnmpPacket) { p.ContextName = "other" }, err: errOtherContext},
		"v3/a GetRequest":         {version: Version3, reply: func(p *SnmpPacket) { p.PDUType = GetRequest }, err: errNotAnswer},
		"v3/a Report":             {version: Version3, reply: report(usmStatsUnknownUserNames), answers: true, err: ErrUnknownUsername},
		"v3/a resync Report":      {version: Version3, reply: report(usmStatsNotInTimeWindows), answers: true},
		"v2c/the answer":          {version: Version2c, answers: true},
		"v2c/an earlier attempt's answer": {
			version: Version2c, reply: func(p *SnmpPacket) { p.RequestID = 1 }, answers: true,
		},
		"v2c/another community": {version: Version2c, reply: func(p *SnmpPacket) { p.Community = "private" }, answers: true},
		"v2c/request ID 0":      {version: Version2c, reply: func(p *SnmpPacket) { p.RequestID = 0 }, err: errOtherRequestID},
		"v2c/empty, another request ID": {
			version: Version2c, reply: func(p *SnmpPacket) { p.Variables, p.RequestID = nil, 9 }, err: errOtherRequestID,
		},
		"v2c/a Report": {version: Version2c, reply: func(p *SnmpPacket) { p.PDUType = Report }, err: errNotAnswer},
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
	counter := func(name string) SnmpPDU { return SnmpPDU{Name: name, Type: Counter32, Value: uint32(1)} }
	tests := map[string]struct {
		version SnmpVersion
		pduType PDUType
		vbs     []SnmpPDU
		report  bool
		err     error
	}{
		"instance 0":                   {vbs: []SnmpPDU{counter(usmStatsNotInTimeWindows)}, report: true, err: ErrNotInTimeWindow},
		"instance 1":                   {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.15.1.1.2.1")}, report: true, err: ErrNotInTimeWindow},
		"a large instance":             {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.15.1.1.4.4294967295")}, report: true, err: ErrUnknownEngineID},
		"message processing's counter": {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.11.2.1.2.3")}, report: true, err: ErrInvalidMsgs},
		"without an instance":          {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.15.1.1.5")}, report: true, err: ErrUnknownReportPDU},
		"two instance sub-identifiers": {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.15.1.1.5.0.0")}, report: true, err: ErrUnknownReportPDU},
		"the prefix":                   {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.15.1.1")}, report: true, err: ErrUnknownReportPDU},
		"an unknown counter":           {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.15.1.1.9.0")}, report: true, err: ErrUnknownReportPDU},
		"SNMP-TARGET-MIB's counter":    {vbs: []SnmpPDU{counter(".1.3.6.1.6.3.12.1.5.0")}, report: true, err: ErrUnknownReportPDU},
		"a name without a dot":         {vbs: []SnmpPDU{counter("0")}, report: true, err: ErrUnknownReportPDU},
		"no varbinds":                  {report: true, err: ErrUnknownReportPDU},
		"a counter after another name": {vbs: []SnmpPDU{sysDescr, counter(usmStatsWrongDigests)}, report: true, err: ErrUnknownReportPDU},
		"a counter, then another name": {vbs: []SnmpPDU{counter(usmStatsWrongDigests), sysDescr}, report: true, err: ErrWrongDigest},
		"a GetResponse":                {pduType: GetResponse, vbs: []SnmpPDU{counter(usmStatsWrongDigests)}},
		"an SNMPv2c Report":            {version: Version2c, vbs: []SnmpPDU{counter(usmStatsWrongDigests)}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &SnmpPacket{Version: cmp.Or(tc.version, Version3), PDUType: cmp.Or(tc.pduType, Report), Variables: tc.vbs}
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
		"agent closed after a discard": {
			discarded: reason,
			end:       func(e *exchange) error { return e.attemptsError("max retries (1) exceeded", io.EOF) },
			wantText:  "max retries (1) exceeded: last discarded reply: out of window",
			wantIs:    []error{io.EOF, ErrNotInTimeWindow},
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
			e := exchange{x: &GoSNMP{}}
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
