// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var engineGolden = goldenFiles{dir: "testdata/engine", title: "Engine"}

const engineOID = ".1.3.6.1.2.1.1.1.0"

// engineScenario is one v1/v2c request run against a scripted agent.
type engineScenario struct {
	v1          bool // SNMPv1 instead of SNMPv2c
	unconnected bool // the transport is an unconnected UDP socket
	setup       func(x *GoSNMP, c *fakeTransport)
	// context, when set, gives the client's Context; its cancel runs when
	// the scenario ends.
	context  func() (context.Context, context.CancelFunc)
	agent    engineAgent
	run      func(x *GoSNMP) (*SnmpPacket, error) // a Get of engineOID unless set
	knownBug string
}

// answer is an agent that answers every request at once with vbs.
func answer(vbs ...SnmpPDU) engineAgent {
	return func(_ int, req []byte) []agentReply {
		return []agentReply{{data: replyTo(req, nil, vbs...)}}
	}
}

// answerWith is an agent that answers every request at once with a reply
// changed by edit.
func answerWith(edit func(*SnmpPacket), vbs ...SnmpPDU) engineAgent {
	return func(_ int, req []byte) []agentReply {
		return []agentReply{{data: replyTo(req, edit, vbs...)}}
	}
}

var sysDescr = SnmpPDU{Name: engineOID, Type: OctetString, Value: []byte("codec agent")}

// errEngineWrite is the error of a failing write in the engine scenarios.
var errEngineWrite = errors.New("codec write failure")

// engineScenarios are the request scenarios of TestEngineRequestCharacterization.
func engineScenarios() map[string]engineScenario {
	twoGets := func(x *GoSNMP) (*SnmpPacket, error) {
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		return x.Get([]string{engineOID})
	}
	tooManyOIDs := make([]string, MaxOids+1)
	for i := range tooManyOIDs {
		tooManyOIDs[i] = fmt.Sprintf(".1.3.6.1.2.1.2.2.1.1.%d", i)
	}

	return map[string]engineScenario{
		// Operations.
		"get":          {agent: answer(sysDescr)},
		"get/v1":       {v1: true, agent: answer(sysDescr)},
		"get/two-oids": {agent: answer(sysDescr, SnmpPDU{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(42)}), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.Get([]string{engineOID, ".1.3.6.1.2.1.1.3.0"}) }},
		"getnext":      {agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetNext([]string{".1.3.6.1.2.1.1"}) }},
		"getbulk":      {agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetBulk([]string{".1.3.6.1.2.1.1"}, 1, 10) }},
		"getbulk/v1":   {v1: true, agent: answer(sysDescr), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetBulk([]string{".1.3.6.1.2.1.1"}, 0, 10) }},
		"set": {agent: answer(SnmpPDU{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte("codec")}), run: func(x *GoSNMP) (*SnmpPacket, error) {
			return x.Set([]SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: "codec"}})
		}},
		"set/unsupported-type": {agent: answer(), run: func(x *GoSNMP) (*SnmpPacket, error) {
			return x.Set([]SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: Boolean, Value: true}})
		}},
		"set/no-varbinds": {
			agent: answer(), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.Set(nil) },
			knownBug: "Set reads the first varbind without a length check and panics outside send's recover",
		},
		"get/too-many-oids":     {agent: answer(), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.Get(tooManyOIDs) }},
		"getnext/too-many-oids": {agent: answer(), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetNext(tooManyOIDs) }},
		"getbulk/too-many-oids": {agent: answer(), run: func(x *GoSNMP) (*SnmpPacket, error) { return x.GetBulk(tooManyOIDs, 0, 10) }},
		"set/too-many-varbinds": {agent: answer(), run: func(x *GoSNMP) (*SnmpPacket, error) {
			vbs := make([]SnmpPDU, MaxOids+1)
			for i := range vbs {
				vbs[i] = SnmpPDU{Name: fmt.Sprintf(".1.3.6.1.2.1.1.5.%d", i), Type: Integer, Value: i}
			}
			return x.Set(vbs)
		}},
		"get/no-conn": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.Conn = nil }},

		// Timeouts and retries.
		"timeout":                  {knownBug: "OnRetry also runs after the last attempt has failed"},
		"timeout/exponential":      {setup: func(x *GoSNMP, _ *fakeTransport) { x.ExponentialTimeout = true }},
		"timeout/no-retries":       {setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = 0 }},
		"timeout/negative-retries": {setup: func(x *GoSNMP, _ *fakeTransport) { x.Retries = -3 }},
		"answer/second-attempt": {agent: func(n int, req []byte) []agentReply {
			if n == 1 {
				return nil
			}
			return []agentReply{{data: replyTo(req, nil, sysDescr)}}
		}},

		// Reply matching.
		"answer/late": {agent: func(n int, req []byte) []agentReply {
			if n == 1 {
				return []agentReply{{data: replyTo(req, nil, sysDescr), after: 1500 * time.Millisecond}}
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
		"answer/wrong-id": {agent: answerWith(func(p *SnmpPacket) { p.RequestID += 100 }, sysDescr)},
		"answer/zero-id":  {agent: answerWith(func(p *SnmpPacket) { p.RequestID = 0 }, sysDescr)},
		"answer/empty":    {agent: answerWith(nil)},
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
		"answer/other-version":   {agent: answerWith(func(p *SnmpPacket) { p.Version = Version1 }, sysDescr)},
		"answer/other-community": {agent: answerWith(func(p *SnmpPacket) { p.Community = "private" }, sysDescr)},
		"answer/garbage-then-valid": {agent: func(_ int, req []byte) []agentReply {
			return []agentReply{{data: []byte{0x30, 0x03, 0x02, 0x01}}, {data: replyTo(req, nil, sysDescr)}}
		}},
		"answer/garbage": {agent: func(int, []byte) []agentReply { return []agentReply{{data: []byte{0x30, 0x03, 0x02, 0x01}}} }},
		"answer/split-tcp": {
			setup: func(x *GoSNMP, _ *fakeTransport) { x.Transport = "tcp" },
			agent: func(_ int, req []byte) []agentReply {
				r := replyTo(req, nil, sysDescr)
				return []agentReply{{data: r[:10]}, {data: r[10:]}}
			},
			knownBug: "a TCP reply must arrive in one read; its parts are decoded as separate messages",
		},

		// Transport errors.
		"write-error/once": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.writeErrs = map[int]error{1: errEngineWrite}
		}},
		"write-error/always": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.writeErrs = map[int]error{1: errEngineWrite, 2: errEngineWrite, 3: errEngineWrite}
		}},
		"deadline-error": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.deadlineErr = errors.New("codec deadline failure")
		}},
		"read-error": {agent: answer(sysDescr), setup: func(_ *GoSNMP, c *fakeTransport) {
			c.readErr = &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
		}},

		// Context.
		"context/canceled-before": {agent: answer(sysDescr), context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}},
		"context/deadline-in-first-attempt":   {context: withEngineTimeout(700 * time.Millisecond)},
		"context/deadline-in-third-attempt":   {context: withEngineTimeout(2500 * time.Millisecond)},
		"context/deadline-after-all-attempts": {context: withEngineTimeout(time.Hour)},
		"context/canceled-while-waiting": {
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(300*time.Millisecond, cancel)
				return ctx, cancel
			},
			knownBug: "cancellation is noticed only when the attempt's deadline passes",
		},

		// Request IDs.
		"request-id/wraps":   {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.requestID = 0x7FFFFFFF }},
		"request-id/set":     {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) { x.SetRequestID(5) }},
		"request-id/retries": {agent: func(n int, req []byte) []agentReply { return answer(sysDescr)(n, req)[:min(n-1, 1)] }},

		// Socket shapes.
		"unconnected": {unconnected: true, agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.uaddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 161}
		}},
		"unconnected/no-address": {unconnected: true, agent: answer(sysDescr)},

		// Hooks.
		"hook-panics": {agent: answer(sysDescr), setup: func(x *GoSNMP, _ *fakeTransport) {
			x.PreSend = func(*GoSNMP) { panic("codec hook failure") }
		}},
	}
}

// withEngineTimeout gives a context that times out after d.
func withEngineTimeout(d time.Duration) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), d)
	}
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
	tr := newEngineTranscript()
	c := newFakeTransport(tr, sc.agent)
	var conn net.Conn = c
	if sc.unconnected {
		conn = fakePacketTransport{c}
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
		run = func(x *GoSNMP) (*SnmpPacket, error) { return x.Get([]string{engineOID}) }
	}

	tr.addf("client: %v timeout=%s retries=%d exponential=%t", x.Version, x.Timeout, x.Retries, x.ExponentialTimeout)
	var res *SnmpPacket
	var err error
	if v, _ := recoverPanic(func() { res, err = run(x) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	tr.addf("client after: retries=%d next request id=%d", x.Retries, (x.requestID+1)&0x7FFFFFFF)
	if sc.knownBug != "" {
		tr.addf("known bug: %s", sc.knownBug)
	}
	return strings.Join(tr.lines, "\n")
}

// TestEngineTCPEOFWithContextDeadline pins a known bug: when a TCP agent
// closes the connection during an attempt whose deadline comes from the
// context, the engine reconnects and then reads the error of the successful
// reconnect, which is nil; send recovers the panic into an error.
func TestEngineTCPEOFWithContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 2048))
			}()
		}
	}()

	// The context deadline comes before the timeout, so it bounds the attempt.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	x := &GoSNMP{
		Target:    "127.0.0.1",
		Port:      uint16(ln.Addr().(*net.TCPAddr).Port), //nolint:gosec // a TCP port
		Transport: "tcp",
		Community: "public",
		Version:   Version2c,
		Timeout:   10 * time.Second,
		Retries:   1,
		Context:   ctx,
	}
	require.NoError(t, x.Connect())
	defer x.Close()

	_, err = x.Get([]string{engineOID})
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "recover: runtime error: invalid memory address or nil pointer dereference"),
		"got %q", err)
}

// BenchmarkSendOneRequest measures one SNMPv2c Get through the request engine
// on the in-memory transport; the agent's decoding of the request and encoding
// of the reply are included.
func BenchmarkSendOneRequest(b *testing.B) {
	const oid = ".1.3.6.1.2.1.31.1.1.1.10.1"
	c := newFakeTransport(nil, func(_ int, req []byte) []agentReply {
		return []agentReply{{data: replyTo(req, nil, SnmpPDU{Name: oid, Type: Counter64, Value: uint64(3825929753)})}}
	})
	x := newEngineClient(b, nil, Version2c, c)
	pkt := x.mkSnmpPacket(GetRequest, []SnmpPDU{{Name: oid, Type: Null}}, 0, 0)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := x.sendOneRequest(pkt); err != nil {
			b.Fatal(err)
		}
	}
}
