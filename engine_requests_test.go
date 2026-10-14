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
		// A client given a Conn without Connect: the request supplies the
		// Context and the receive buffer.
		"conn-without-connect": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.Context, x.Transport, x.rxBuf = nil, "", nil
		}},
		"conn-without-receive-buffer": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.rxBuf = nil
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
		},
		"answer/empty": {agent: answerWith(nil)},
		"answer/empty-wrong-id": {
			agent:    answerWith(func(p *SnmpPacket) { p.RequestID += 100 }),
			knownBug: "a reply without varbinds is accepted before its request ID is checked",
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
			agent:    answerWith(func(p *SnmpPacket) { p.Version = Version1 }, sysDescr),
			knownBug: "a reply of another SNMP version is accepted, though RFC 3412 hands each message to the model of its own version",
		},
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
		"close/from-another-goroutine": {setup: func(x *GoSNMP, _ *fakeTransport) {
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = x.Close()
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
	tr.addf("client after: retries=%d next request id=%d", x.Retries, (x.requestID.Load()+1)&0x7FFFFFFF)
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
		if _, _, err := x.sendOneRequest(&cfg, pkt); err != nil {
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
