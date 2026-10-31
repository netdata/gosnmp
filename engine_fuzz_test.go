// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"os"
	"slices"
	"testing"
	"time"
)

// engineReplyRequest is a FuzzEngineReply request: SNMPv2c (user ""), or
// SNMPv3 by a user of the fake agent, whose engine the client knows unless
// discover is set.
type engineReplyRequest struct {
	user     string
	discover bool
}

// engineReplyRequests are SNMPv2c, SNMPv3 at each security level, and SNMPv3
// starting with the engine discovery.
var engineReplyRequests = []engineReplyRequest{
	{user: ""},
	{user: "codec-noauth"},
	{user: "codec-md5"},
	{user: "codec-sha-aes"},
	{user: "codec-md5", discover: true},
}

// FuzzEngineReply reads any octets as the reply to each exchange of a request,
// below send's recover (GoSNMP.request), so that a panic fails it: the decode,
// its security processing, the answer predicate, the engine commit, the
// discovery and the resynchronization. The first argument selects the request
// (engineReplyRequests). The request IDs and msgIDs are fixed, so mutated
// replies keep naming the first exchange. Seeds are the fake agent's answers
// and Reports to the first exchange.
func FuzzEngineReply(f *testing.F) {
	for i, r := range engineReplyRequests {
		for _, reply := range engineReplySeeds(f, r) {
			f.Add(uint8(i), reply) //nolint:gosec // i indexes a short list
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, reply []byte) {
		x := engineReplyClient(engineReplyRequests[int(which)%len(engineReplyRequests)])
		// One read per exchange (the discovery, the request, a resend), each
		// followed by the attempt's timeout.
		exchange := []streamRead{{data: reply}, {err: os.ErrDeadlineExceeded}}
		x.Conn = &replyConn{streamConn{reads: slices.Concat(exchange, exchange, exchange)}}
		packet, err := x.oidRequest(GetRequest, []string{engineOID}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = x.request(packet)
	})
}

// TestEngineReplySeeds checks that FuzzEngineReply's seeds reach the end of
// the reply path: each answers the first exchange of its request.
func TestEngineReplySeeds(t *testing.T) {
	for _, r := range engineReplyRequests {
		seeds := engineReplySeeds(t, r)
		if len(seeds) == 0 {
			t.Fatalf("%+v: no seeds", r)
		}
		for i, reply := range seeds {
			e := engineReplyExchange(t, r)
			e.x.Conn = &replyConn{streamConn{reads: []streamRead{{data: reply}, {err: os.ErrDeadlineExceeded}}}}
			if out := e.attempt(nil); out.kind != attemptReply || out.packet == nil {
				t.Errorf("%+v seed %d: the attempt ended as %d, %v, not with an answer", r, i, out.kind, out.err)
			}
		}
	}
}

// engineReplyClient returns a client for r whose next request ID and msgID
// are 1001 and 2001, without a Conn.
func engineReplyClient(r engineReplyRequest) *GoSNMP {
	x := &GoSNMP{Version: Version2c, Community: "public", Transport: udp, Timeout: time.Second, MaxOids: MaxOids}
	if r.user != "" {
		creds := agentCreds[r.user]
		x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, NoAuthNoPriv
		switch {
		case creds.priv > NoPriv:
			x.MsgFlags = AuthPriv
		case creds.auth > NoAuth:
			x.MsgFlags = AuthNoPriv
		}
		sp := &UsmSecurityParameters{
			UserName:                 r.user,
			AuthenticationProtocol:   creds.auth,
			AuthenticationPassphrase: creds.authPass,
			PrivacyProtocol:          creds.priv,
			PrivacyPassphrase:        creds.privPass,
		}
		if !r.discover {
			sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = agentEngineID,
				agentBoots, agentTimeBase
		}
		x.SecurityParameters = sp
	}
	x.SetRequestID(1000)
	x.SetMsgID(2000)
	return x
}

// engineReplyExchange returns the first exchange of r's request (a Get of
// engineOID, or the engine discovery), before its attempt.
func engineReplyExchange(tb testing.TB, r engineReplyRequest) *exchange {
	tb.Helper()
	x := engineReplyClient(r)
	packet, err := x.oidRequest(GetRequest, []string{engineOID}, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	if x.Version == Version3 {
		if err := x.reconcileEngine(); err != nil {
			tb.Fatal(err)
		}
		if r.discover {
			packet = newDiscoveryPacket(x.Logger)
		} else {
			x.engine.stamp(packet)
		}
	}
	cfg := x.prepareRequest()
	return &exchange{x: x, packet: packet, cfg: cfg, timeout: cfg.timeout, discovery: r.discover, clock: x.engine.clock}
}

// engineReplySeeds returns replies to the first exchange of r's request
// (engineReplyExchange): for SNMPv2c the answer and one with an error status;
// for SNMPv3 the fake agent's answer, and its notInTimeWindow and
// unknownEngineIDs Reports; for the discovery its unknownEngineIDs Report and
// the unknownUserNames Report some devices send instead.
func engineReplySeeds(tb testing.TB, r engineReplyRequest) [][]byte {
	tb.Helper()
	e := engineReplyExchange(tb, r)
	e.packet.RequestID = e.x.nextRequestID()
	req, err := e.encode()
	if err != nil {
		tb.Fatal(err)
	}
	if r.user == "" {
		noSuchName := func(p *SnmpPacket) { p.Error, p.ErrorIndex = NoSuchName, 1 }
		return [][]byte{replyTo(req, nil, sysDescr), replyTo(req, noSuchName, sysDescr)}
	}
	scripts := []func(int, agentRequest) (agentAnswer, bool){
		nil,
		onRequest(1, agentAnswer{report: usmStatsNotInTimeWindows, level: e.packet.MsgFlags & AuthNoPriv}),
		onRequest(1, agentAnswer{report: usmStatsUnknownEngineIDs, level: NoAuthNoPriv}),
	}
	if r.discover {
		scripts = scripts[:1]
		scripts = append(scripts, onRequest(1, agentAnswer{report: usmStatsUnknownUserNames, level: NoAuthNoPriv}))
	}
	var seeds [][]byte
	for _, script := range scripts {
		agent := newFakeV3Agent(nil, agentCreds, sysDescr)
		agent.script = script
		for _, reply := range agent.handle(1, req) {
			seeds = append(seeds, reply.data)
		}
	}
	return seeds
}

// replyConn is a Conn the caller set under Transport "udp", read with Read,
// one message per read: its reads are a streamConn's; writes and deadlines
// succeed.
type replyConn struct {
	streamConn
}

func (c *replyConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *replyConn) SetDeadline(time.Time) error { return nil }
