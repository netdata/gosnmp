// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"os"
	"testing"
	"time"
)

// engineReplyUsers select the FuzzEngineReply requests: SNMPv2c (""), and
// SNMPv3 by a user of the fake agent at each security level.
var engineReplyUsers = []string{"", "codec-noauth", "codec-md5", "codec-sha-aes"}

// FuzzEngineReply reads any octets as the reply to a request in one attempt
// (exchange.attempt), below send's recover, so that a panic fails it: the
// decode, its security processing, the answer predicate and the commit. The
// first argument selects the request: SNMPv2c, or SNMPv3 with the fake agent's
// engine ID, boots and time, which the client knows (no discovery). The
// request ID and msgID are fixed, so mutated replies keep naming the request.
// Seeds are the agent's answers and Reports.
func FuzzEngineReply(f *testing.F) {
	for i, user := range engineReplyUsers {
		for _, reply := range engineReplySeeds(f, user) {
			f.Add(uint8(i), reply) //nolint:gosec // i indexes a short list
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, reply []byte) {
		e := engineReplyExchange(t, engineReplyUsers[int(which)%len(engineReplyUsers)])
		e.x.Conn = &replyConn{streamConn{reads: []streamRead{{data: reply}, {err: os.ErrDeadlineExceeded}}}}
		e.attempt(nil)
	})
}

// TestEngineReplySeeds checks that FuzzEngineReply's seeds reach the end of
// the reply path: each answers its request.
func TestEngineReplySeeds(t *testing.T) {
	for _, user := range engineReplyUsers {
		seeds := engineReplySeeds(t, user)
		if len(seeds) == 0 {
			t.Fatalf("user %q: no seeds", user)
		}
		for i, reply := range seeds {
			e := engineReplyExchange(t, user)
			e.x.Conn = &replyConn{streamConn{reads: []streamRead{{data: reply}, {err: os.ErrDeadlineExceeded}}}}
			if out := e.attempt(nil); out.kind != attemptReply || out.packet == nil {
				t.Errorf("user %q seed %d: the attempt ended as %d, %v, not with an answer", user, i, out.kind, out.err)
			}
		}
	}
}

// engineReplyExchange returns the exchange of a Get of engineOID for user
// (SNMPv2c for ""), before its attempt, on a client that knows the fake
// agent's engine and whose next request ID and msgID are 1001 and 2001.
func engineReplyExchange(tb testing.TB, user string) *exchange {
	tb.Helper()
	x := &GoSNMP{Version: Version2c, Community: "public", Transport: udp, Timeout: time.Second, MaxOids: MaxOids}
	if user != "" {
		creds := agentCreds[user]
		x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, NoAuthNoPriv
		switch {
		case creds.priv > NoPriv:
			x.MsgFlags = AuthPriv
		case creds.auth > NoAuth:
			x.MsgFlags = AuthNoPriv
		}
		x.SecurityParameters = &UsmSecurityParameters{
			UserName:                 user,
			AuthoritativeEngineID:    agentEngineID,
			AuthoritativeEngineBoots: agentBoots,
			AuthoritativeEngineTime:  agentTimeBase,
			AuthenticationProtocol:   creds.auth,
			AuthenticationPassphrase: creds.authPass,
			PrivacyProtocol:          creds.priv,
			PrivacyPassphrase:        creds.privPass,
		}
	}
	x.SetRequestID(1000)
	x.SetMsgID(2000)
	packet, err := x.oidRequest(GetRequest, []string{engineOID}, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	if x.Version == Version3 {
		if err := x.reconcileEngine(); err != nil {
			tb.Fatal(err)
		}
		x.engine.stamp(packet)
	}
	cfg := x.prepareRequest()
	return &exchange{x: x, packet: packet, cfg: cfg, timeout: cfg.timeout, clock: x.engine.clock}
}

// engineReplySeeds returns replies to user's request (engineReplyExchange): for
// SNMPv2c the answer and one with an error status, for SNMPv3 the fake
// agent's answer, and its notInTimeWindow and unknownEngineIDs Reports.
func engineReplySeeds(tb testing.TB, user string) [][]byte {
	tb.Helper()
	e := engineReplyExchange(tb, user)
	e.packet.RequestID = e.x.nextRequestID()
	req, err := e.encode()
	if err != nil {
		tb.Fatal(err)
	}
	if user == "" {
		noSuchName := func(p *SnmpPacket) { p.Error, p.ErrorIndex = NoSuchName, 1 }
		return [][]byte{replyTo(req, nil, sysDescr), replyTo(req, noSuchName, sysDescr)}
	}
	var seeds [][]byte
	for _, script := range []func(int, agentRequest) (agentAnswer, bool){
		nil,
		onRequest(1, agentAnswer{report: usmStatsNotInTimeWindows, level: e.packet.MsgFlags & AuthNoPriv}),
		onRequest(1, agentAnswer{report: usmStatsUnknownEngineIDs, level: NoAuthNoPriv}),
	} {
		agent := newFakeV3Agent(nil, agentCreds, sysDescr)
		agent.script = script
		for _, r := range agent.handle(1, req) {
			seeds = append(seeds, r.data)
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
