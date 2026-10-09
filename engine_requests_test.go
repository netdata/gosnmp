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
	"log"
	"maps"
	"net"
	"regexp"
	"runtime"
	"slices"
	"strings"
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
	in, err := decodeMessage(req)
	if err != nil {
		panic(fmt.Sprintf("agent cannot decode the request: %v", err))
	}
	out := &SnmpPacket{
		Version: Version3, MsgFlags: NoAuthNoPriv, SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: "public"},
		PDUType:            Report, RequestID: in.RequestID, MsgID: 7,
		Variables: []SnmpPDU{{Name: counter, Type: Counter32, Value: uint32(1)}},
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
	return func(n int, req []byte) []agentReply {
		if n < 2 {
			return nil
		}
		return []agentReply{{data: replyTo(req, nil, vbs...)}}
	}
}

// answerRaw is an agent that answers every request with its sysDescr reply
// changed by edit as encoded octets.
func answerRaw(edit func(reply []byte) []byte) engineAgent {
	return func(_ int, req []byte) []agentReply {
		return []agentReply{{data: edit(replyTo(req, nil, sysDescr))}}
	}
}

var sysDescr = SnmpPDU{Name: engineOID, Type: OctetString, Value: []byte("codec agent")}

// errEngineWrite is the error of a failing write in the engine scenarios.
var errEngineWrite = errors.New("codec write failure")

// refused is the error of a read from a UDP socket whose target port is
// closed.
var refused = &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}

// withEngineTimeout gives a context that times out after d.
func withEngineTimeout(d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), d)
	}
}

// canceledAfter gives a context canceled after d.
func canceledAfter(d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(d, cancel)
		return ctx, cancel
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
			knownBug: "Set checks the type of the first varbind only; a later one fails in the encoder, after an attempt has started",
		},
		"set/integer-with-text": {agent: answer(), run: setVarbinds(SnmpPDU{Name: setOID, Type: Integer, Value: "five"})},
		"set/no-varbinds": {
			agent: answer(), run: setVarbinds(),
			knownBug: "Set reads the first varbind without a length check and panics outside send's recover",
		},
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
		"conn-without-connect": {
			agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.Context, x.rxBuf = nil, nil },
			knownBug: "a client given a Conn without Connect has no Context and no receive buffer: send recovers the nil dereference into an error",
		},
		"custom-conn": {shape: shapeStream, agent: answer(sysDescr)},

		// Timeouts and retries.
		"timeout":                  {knownBug: "OnRetry runs even when no retry follows"},
		"timeout/exponential":      {setup: func(x *GoSNMP, _ *fakeTransport) { x.ExponentialTimeout = true }},
		"timeout/no-retries":       {setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = 0 }},
		"timeout/negative-retries": {setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = -3 }},
		"timeout/zero":             {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.Timeout = 0 }},
		"timeout/tcp":              {shape: shapeStream, setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport = "tcp" }},
		"answer/second-attempt":    {agent: answerFromSecond(sysDescr)},

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
			agent:    answerWith(func(p *SnmpPacket) { p.RequestID = 0 }, sysDescr),
			knownBug: "a reply with request ID 0 is accepted for any request",
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
			knownBug: "a reply with request ID 0 is accepted for any request, even a v1 Trap",
		},
		"answer/empty": {agent: answerWith(nil)},
		"answer/empty-wrong-id": {
			agent:    answerWith(func(p *SnmpPacket) { p.RequestID += 100 }),
			knownBug: "a reply without varbinds is accepted before its request ID is checked",
		},
		"answer/empty-with-error-status-wrong-id": {agent: answerWith(func(p *SnmpPacket) { p.RequestID += 100; p.Error = GenErr })},
		"answer/error-status":                     {agent: answerWith(func(p *SnmpPacket) { p.Error, p.ErrorIndex = NoSuchName, 1 }, SnmpPDU{Name: engineOID, Type: Null})},
		"answer/not-a-response": {
			agent:    answerWith(func(p *SnmpPacket) { p.PDUType = GetRequest }, sysDescr),
			knownBug: "the reply's PDU type is not checked",
		},
		"answer/report": {
			agent:    answerWith(func(p *SnmpPacket) { p.PDUType = Report }, sysDescr),
			knownBug: "the reply's PDU type is not checked",
		},
		"answer/unknown-pdu-type": {
			agent: answerRaw(func(r []byte) []byte {
				r[bytes.IndexByte(r, byte(GetResponse))] = 0xaf
				return r
			}),
			knownBug: "the error text formats the PDU type's String() as hexadecimal",
		},
		"answer/other-version": {
			agent:    answerWith(func(p *SnmpPacket) { p.Version = Version1 }, sysDescr),
			knownBug: "a reply of another SNMP version is accepted, though RFC 3412 hands each message to the model of its own version",
		},
		"answer/other-version-v3": {
			agent: answerWith(func(p *SnmpPacket) {
				p.Version, p.MsgFlags, p.SecurityModel = Version3, NoAuthNoPriv, UserSecurityModel
				p.SecurityParameters = &UsmSecurityParameters{UserName: "public"}
			}, sysDescr),
		},
		"answer/other-version-v3-report": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: bareV3Report(req, usmStatsUnknownUserNames)}}
		}},
		"answer/other-community": {agent: answerWith(func(p *SnmpPacket) { p.Community = "private" }, sysDescr)},
		"answer/garbage-then-valid": {
			agent: func(_ int, req []byte) []agentReply {
				return []agentReply{{data: []byte{0x30, 0x03, 0x02, 0x01}}, {data: replyTo(req, nil, sysDescr)}}
			},
			knownBug: "an undecodable reply ends the attempt and the request is sent again at once, instead of reading on",
		},
		"answer/garbage": {agent: func(int, []byte) []agentReply { return []agentReply{{data: []byte{0x30, 0x03, 0x02, 0x01}}} }},
		"answer/split-tcp": {
			shape: shapeStream,
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport, x.Retries = "tcp", 0 },
			agent: func(_ int, req []byte) []agentReply {
				r := replyTo(req, nil, sysDescr)
				return []agentReply{{data: r[:10]}, {data: r[10:], after: 10 * time.Millisecond}}
			},
			knownBug: "a TCP reply must arrive in one read",
		},
		"answer/largest-tcp": {
			shape: shapeStream,
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport = "tcp" },
			agent: func(_ int, req []byte) []agentReply {
				// The largest reply the receive buffer accepts.
				size := rxBufSize - 100
				for {
					r := replyTo(req, nil, SnmpPDU{Name: engineOID, Type: OctetString, Value: bytes.Repeat([]byte{'x'}, size)})
					if len(r) == rxBufSize-1 {
						return []agentReply{{data: r}}
					}
					size += rxBufSize - 1 - len(r)
				}
			},
		},
		"answer/too-big-tcp": {
			shape: shapeStream,
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport = "tcp" },
			agent: func(int, []byte) []agentReply { return []agentReply{{data: make([]byte, rxBufSize+10)}} },
		},

		// Transport errors.
		"write-error/once": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failWrite = func(n int) error { return map[int]error{1: errEngineWrite}[n] }
		}},
		"write-error/always": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failWrite = func(int) error { return errEngineWrite }
		}},
		"write-error/timeout-in-text": {
			agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
				c.failWrite = func(int) error { return errors.New("codec timeout of the write queue") }
			},
			knownBug: "a timeout is recognized by the word in the error's text, so another error with that word becomes a request timeout",
		},
		"deadline-error": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.deadlineErr = errors.New("codec deadline failure")
		}},
		"read-error/once": {agent: answerFromSecond(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failRead = func(n int) error { return map[int]error{1: refused}[n] }
		}},
		"read-error/always": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.failRead = func(int) error { return refused }
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
		"context/canceled-while-waiting": {
			context:  canceledAfter(300 * time.Millisecond),
			knownBug: "cancellation is noticed only when the attempt's deadline passes",
		},
		"context/canceled-in-last-attempt": {
			context:  canceledAfter(2300 * time.Millisecond),
			knownBug: "a cancellation during the last attempt is reported as a request timeout",
		},

		// Request IDs.
		"request-id/wraps": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.requestID.Store(0x7FFFFFFF) }},
		"request-id/wraps-between-attempts": {agent: answerFromSecond(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.requestID.Store(0x7FFFFFFE)
		}},
		"request-id/set": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.SetRequestID(5) }},

		// Socket shapes.
		"unconnected": {shape: shapeUnconnectedUDP, agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.uaddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 161}
		}},

		// Hooks.
		"hook-panics": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.PreSend = func(*GoSNMP) { panic("codec hook failure") }
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
	if v, _ := recoverPanic(func() { res, err = run(x) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	tr.addf("client after: retries=%d next request id=%d", x.Retries, (x.requestID.Load()+1)&0x7FFFFFFF)
	if sc.knownBug != "" {
		tr.addf("known bug: %s", sc.knownBug)
	}
	return strings.Join(tr.lines, "\n")
}

// TestEngineTCPReconnect pins, on loopback sockets, what the engine does when
// a TCP agent closes the connection after reading a request: it reconnects
// and sends again, and gives up on the reconnect's error or when the retries
// run out, known bugs included.
func TestEngineTCPReconnect(t *testing.T) {
	tests := map[string]struct {
		transport      string        // "tcp" unless set
		acceptAgain    bool          // the agent accepts the reconnection
		ignoreFirst    bool          // the agent reads the first request and keeps the connection open
		staleReply     bool          // the agent answers the request after the reconnect with a reply to the first
		timeout        time.Duration // the client's Timeout; 10 s unless set
		contextTimeout time.Duration // a context deadline before the timeout
		wantErr        string        // describeEngineError, the dial address masked; "" for a reply
		wantHooks      []string
		wantRequests   int32 // requests the agent read
		knownBug       string
	}{
		"retries run out": {
			acceptAgain: true, wantErr: `error "max retries (1) exceeded" *errors.errorString`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent", "OnRetry"}, wantRequests: 2,
		},
		"retries run out, tcp4": {
			transport: "tcp4", acceptAgain: true, wantErr: `error "max retries (1) exceeded" *errors.errorString`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent", "OnRetry"}, wantRequests: 2,
		},
		"retries run out after a timeout": {
			acceptAgain: true, ignoreFirst: true, timeout: 200 * time.Millisecond,
			wantErr:   `error "max retries (1) exceeded" *errors.errorString`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent", "OnRetry"}, wantRequests: 2,
		},
		"reply to the first request after the reconnect": {
			acceptAgain: true, staleReply: true, timeout: 500 * time.Millisecond,
			wantHooks:    []string{"PreSend", "OnSent", "OnRetry", "PreSend", "OnSent", "OnRecv", "OnFinish"},
			wantRequests: 2,
		},
		"reconnect refused": {
			wantErr:   `error "dial tcp <address>: connect: connection refused" *net.OpError (is syscall.ECONNREFUSED)`,
			wantHooks: []string{"PreSend", "OnSent"}, wantRequests: 1,
		},
		"context deadline": {
			acceptAgain: true, contextTimeout: 5 * time.Second,
			wantErr:   `error "recover: runtime error: invalid memory address or nil pointer dereference Stack: ..." *errors.errorString`,
			wantHooks: []string{"PreSend", "OnSent", "OnRetry"}, wantRequests: 1,
			knownBug: "after the reconnect under a context deadline, the engine reads the nil error of the reconnect",
		},
	}
	dialAddress := regexp.MustCompile(`dial tcp \S+: `)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a TCP port
			var requests atomic.Int32
			var firstRequest atomic.Pointer[[]byte]
			done := make(chan struct{})
			go func() {
				defer close(done)
				for first := true; ; first = false {
					conn, acceptErr := ln.Accept()
					if acceptErr != nil {
						return
					}
					if first && !tc.acceptAgain {
						ln.Close()
					}
					go serveTCPRequests(conn, func(req []byte) (reply []byte, keepOpen bool) {
						switch n := requests.Add(1); {
						case n == 1:
							firstRequest.Store(&req)
							return nil, tc.ignoreFirst
						case tc.staleReply:
							return replyTo(*firstRequest.Load(), nil, sysDescr), true
						}
						return nil, false
					})
				}
			}()
			defer func() {
				ln.Close()
				<-done
			}()

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
				Retries:   1,
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
				assert.Equal(t, tc.wantErr, got, "known bug: %q", tc.knownBug)
			}
			assert.Equal(t, tc.wantHooks, hooks, "hooks")
			assert.Equal(t, tc.wantRequests, requests.Load(), "requests the agent read")
		})
	}
}

// serveTCPRequests reads requests from conn, one per read, and hands each to
// handle, which returns the reply to write, if any, and whether to keep the
// connection open; conn closes when it is not kept open or the client closes
// it.
func serveTCPRequests(conn net.Conn, handle func(req []byte) (reply []byte, keepOpen bool)) {
	defer conn.Close()
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return
		}
		reply, keepOpen := handle(bytes.Clone(buf[:n]))
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
	pkt := x.mkSnmpPacket(GetRequest, []SnmpPDU{{Name: oid, Type: Null}}, 0, 0)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := x.sendOneRequest(pkt); err != nil {
			b.Fatal(err)
		}
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
