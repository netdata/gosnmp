// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/netdata/gosnmp/internal/ber"
)

// agentCreds are the users of the fake SNMPv3 agent in the engine tests.
var agentCreds = map[string]agentUser{
	"codec-noauth":         {auth: NoAuth, priv: NoPriv},
	"codec-md5":            {auth: MD5, authPass: "codec-md5-pass", priv: NoPriv},
	"codec-sha-aes":        {auth: SHA, authPass: "codec-sha-pass", priv: AES, privPass: "codec-aes-pass"},
	"codec-sha256-des":     {auth: SHA256, authPass: "codec-sha256-pass", priv: DES, privPass: "codec-des-pass"},
	"codec-sha256-aes":     {auth: SHA256, authPass: "codec-sha256-pass", priv: AES, privPass: "codec-aes-pass"},
	"codec-sha512-aes256c": {auth: SHA512, authPass: "codec-sha512-pass", priv: AES256C, privPass: "codec-aes256c-pass"},
}

// v3Scenario is one SNMPv3 request run against the fake agent.
type v3Scenario struct {
	user  string     // the client's user, with agentCreds credentials unless creds is set
	creds *agentUser // the client's credentials
	// config, when set, changes the client's configuration before NewClient.
	config func(c *Config)
	setup  func(x *Client)
	script func(n int, req agentRequest) (agentAnswer, bool)
	run    func(x *Client, a *fakeV3Agent) (*Message, error) // a Get of engineOID unless set
}

// getTwice runs a Get, then between applies a change to the agent 10 s
// later, then runs a second Get, whose result it returns.
func getTwice(between func(a *fakeV3Agent)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return getAfter(10*time.Second, between)
}

// getAfter is getTwice with the pause d between the two Gets.
func getAfter(d time.Duration, between func(a *fakeV3Agent)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return func(x *Client, a *fakeV3Agent) (*Message, error) {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(d)
		if between != nil {
			between(a)
		}
		return x.Get(context.Background(), []string{engineOID})
	}
}

// getThen runs a Get, then between applies a change to the agent 10 s later,
// then runs second, whose result it returns.
func getThen(between func(a *fakeV3Agent), second func(x *Client) (*Message, error)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return func(x *Client, a *fakeV3Agent) (*Message, error) {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		between(a)
		return second(x)
	}
}

// getWithin runs a Get within the context ctx gives, which bounds that Get
// only.
func getWithin(ctx func() (context.Context, context.CancelFunc)) func(x *Client) (*Message, error) {
	return func(x *Client) (*Message, error) {
		c, cancel := ctx()
		defer cancel()
		return x.Get(c, []string{engineOID})
	}
}

// getWithinV3 is getWithin as a scenario's run.
func getWithinV3(ctx func() (context.Context, context.CancelFunc)) func(x *Client, _ *fakeV3Agent) (*Message, error) {
	get := getWithin(ctx)
	return func(x *Client, _ *fakeV3Agent) (*Message, error) { return get(x) }
}

// rebootSilentAfterResync reboots the agent, which then answers a request
// with the old boots with its notInTimeWindow Report and leaves the
// resynchronized one unanswered.
func rebootSilentAfterResync(a *fakeV3Agent) {
	a.reboot()
	a.script = func(_ int, req agentRequest) (agentAnswer, bool) {
		if req.boots == a.boots {
			return agentAnswer{drop: true, why: "silent after the resynchronization"}, true
		}
		return agentAnswer{}, false
	}
}

// changeThenGet runs a Get, then change, which the transcript names as what,
// on the client 10 s later, then a second Get, whose result it returns.
func changeThenGet(what string, change func(x *Client)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return func(x *Client, a *fakeV3Agent) (*Message, error) {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		a.tr.addf("caller %s", what)
		change(x)
		return x.Get(context.Background(), []string{engineOID})
	}
}

// encodeThenGet runs a Get, then change, which the transcript names as what,
// on the client 10 s later, then EncodeMessage (encodeMessage), then a second
// Get, whose result it returns.
func encodeThenGet(what string, change func(x *Client)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return func(x *Client, a *fakeV3Agent) (*Message, error) {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		a.tr.addf("caller %s", what)
		change(x)
		encodeMessage(x, a)
		return x.Get(context.Background(), []string{engineOID})
	}
}

// encodeMessage runs EncodeMessage of a Get and adds to the transcript the
// message as the fake agent reads it, whether its digest checks with the
// agent's key of its user, and the client's engine state.
func encodeMessage(x *Client, a *fakeV3Agent) {
	out, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Value: NullValue()}}, 0, 0)
	if err != nil {
		a.tr.addf("EncodeMessage: error %v; client %s", err, describeEngineState(x))
		return
	}
	m, err := parseV3Message(out)
	if err != nil {
		a.tr.addf("EncodeMessage: not an SNMPv3 message: %v", err)
		return
	}
	req, err := readAgentRequest(m)
	if err != nil {
		a.tr.addf("EncodeMessage: unreadable: %v", err)
		return
	}
	digest := "no digest"
	if req.flags&AuthNoPriv != 0 {
		ok := false
		if u := a.users[req.user]; u != nil {
			fips140.WithoutEnforcement(func() { ok = agentDigestOK(out, m, u) })
		}
		digest = map[bool]string{true: "digest checks", false: "digest wrong"}[ok]
	}
	a.tr.addf("EncodeMessage: %s, %s; client %s", describeAgentRequest(req), digest, describeEngineState(x))
}

// afterReadThenGet runs a Get after whose read n the fake connection runs
// change, which the transcript names as what, then a second Get 10 s later,
// whose result it returns.
func afterReadThenGet(n int, what string, change func(x *Client)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return func(x *Client, a *fakeV3Agent) (*Message, error) {
		afterRead(x, a, n, what, change)
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		return x.Get(context.Background(), []string{engineOID})
	}
}

// afterRead makes x's fake connection run change after its read n, which the
// transcript names as what: code that acts on the client during a request.
func afterRead(x *Client, a *fakeV3Agent, n int, what string, change func(x *Client)) {
	c := transportOf(a.tr.tb, x)
	c.afterRead = func(k int) {
		if k == n {
			a.tr.addf("the Conn's read #%d %s", k, what)
			change(x)
		}
	}
}

// agentUserOf returns the User of the agentCreds credentials of name.
func agentUserOf(name string) User {
	return agentCreds[name].user(name)
}

// seedEngine gives the client the engine state a request learns of an agent
// with engineID, boots and time (none for zeros, as for an engine ID taken
// from a Report): the scenarios that start with the engine known.
func seedEngine(engineID string, boots, engineTime uint32) func(*Client) {
	return func(x *Client) {
		x.startEngine()
		next, err := x.engine.withEngine(&x.config.User, []byte(engineID))
		if err != nil {
			panic(err)
		}
		if boots != 0 || engineTime != 0 {
			next.clock = clockOf(boots, engineTime, time.Now(), fromUnauthenticated)
		}
		x.commitEngine(next)
	}
}

// sendOIDs sends a request of pduType for oids, with maxRepetitions for a
// GetBulk, as the walks send their GetNext and GetBulk requests.
func sendOIDs(pduType PDUType, oids []string, maxRepetitions uint32) func(x *Client) (*Message, error) {
	return func(x *Client) (*Message, error) {
		packetOut, err := x.oidRequest(pduType, oids, maxRepetitions)
		if err != nil {
			return nil, err
		}
		return x.send(context.Background(), packetOut)
	}
}

// getThrice runs three Gets 10 s apart, applying between to the agent before
// the second; it records the second Get's result and returns the third's.
func getThrice(between func(a *fakeV3Agent)) func(x *Client, a *fakeV3Agent) (*Message, error) {
	return func(x *Client, a *fakeV3Agent) (*Message, error) {
		res, err := getTwice(between)(x, a)
		a.tr.addf("second Get: %s", describeEngineResult(res, err))
		time.Sleep(10 * time.Second)
		return x.Get(context.Background(), []string{engineOID})
	}
}

// otherKey encrypts an answer with a key the client does not have.
func otherKey(p *agentOut) {
	p.keys.priv = bytes.Repeat([]byte{0x5a}, len(p.keys.priv))
}

// otherAuthKey signs an answer with a key the client does not have.
func otherAuthKey(p *agentOut) {
	p.keys.auth = bytes.Repeat([]byte{0x5a}, len(p.keys.auth))
}

// encryptedForAuthNoPriv encrypts an authNoPriv answer, with a privacy
// protocol the user does not have.
func encryptedForAuthNoPriv(p *agentOut) {
	p.SecurityLevel = AuthPriv
	p.keys.privProtocol, p.keys.priv = AES, bytes.Repeat([]byte{0x5a}, 16)
}

// olderBoots gives an answer engine boots lower than the agent's: an
// authentic answer outside the client's time window.
func olderBoots(p *agentOut) {
	p.SecurityParameters.AuthoritativeEngineBoots = agentBoots - 1
}

// garbage is a datagram that does not decode.
var garbage = []byte{0x30, 0x03, 0x02, 0x01}

// headerField gives an encoded message field i of msgGlobalData (0 msgID,
// 1 msgMaxSize, 2 msgFlags, 3 msgSecurityModel), the TLV field: a value the
// encoder does not write.
func headerField(i int, field []byte) func(m *v3Message) {
	return func(m *v3Message) {
		r := ber.NewReader(m.header)
		var fields [][]byte
		for r.Len() > 0 {
			tag, content, err := r.Next()
			if err != nil {
				panic(err)
			}
			fields = append(fields, tlv(tag, content))
		}
		fields[i] = field
		m.header = bytes.Join(fields, nil)
	}
}

// msgFlagsOctets gives an encoded message a msgFlags OCTET STRING of the
// octets, none for an empty one.
func msgFlagsOctets(octets ...byte) func(m *v3Message) {
	return headerField(2, tlv(byte(OctetString), octets))
}

// securityModel2 gives an encoded message the msgSecurityModel 2; the encoder
// writes only the User-based Security Model's, 3.
func securityModel2(m *v3Message) {
	headerField(3, tlv(byte(Integer), []byte{2}))(m)
}

// snmpUnknownContexts is the counter of RFC 3413 (SNMP-TARGET-MIB) a command
// responder reports for an unknown context, at the request's security level.
const snmpUnknownContexts = ".1.3.6.1.6.3.12.1.5.0"

// forgeReport signs a Report with another key and gives it other engine
// boots and time.
func forgeReport(p *agentOut) {
	p.keys.auth = bytes.Repeat([]byte{0x5a}, len(p.keys.auth))
	p.SecurityParameters.AuthoritativeEngineBoots, p.SecurityParameters.AuthoritativeEngineTime = 99, 5
}

// asV2c turns an answer into an SNMPv2c message with the same request ID.
func asV2c(p *agentOut) {
	p.Version, p.Community = Version2c, "public"
}

// withoutEngineID takes the engine ID out of an answer and its context.
func withoutEngineID(p *agentOut) {
	p.SecurityParameters.AuthoritativeEngineID = nil
	p.ContextEngineID = nil
}

// fromOversizedEngine makes an answer name an engine ID longer than net-snmp
// v5.9.4 parses (64 octets), which its agent drops without a Report.
func fromOversizedEngine(p *agentOut) {
	p.SecurityParameters.AuthoritativeEngineID = bytes.Repeat([]byte{0x42}, 65)
	p.ContextEngineID = nil
}

// fromOtherEngine makes an answer come from the agent's other engine ID.
func fromOtherEngine(p *agentOut) {
	p.SecurityParameters.AuthoritativeEngineID = []byte(agentOtherEngineID)
	p.ContextEngineID = []byte(agentOtherEngineID)
}

// signedByOtherEngine makes an answer come from the agent's other engine ID,
// signed with the user's key localized to it: another agent with the same
// credentials.
func signedByOtherEngine(p *agentOut) {
	fromOtherEngine(p)
	u := agentUserOf(p.SecurityParameters.UserName)
	key, err := u.authKey([]byte(agentOtherEngineID))
	if err != nil {
		panic(err)
	}
	p.keys.auth = key
}

// otherEngineTime gives an answer engine boots and time the agent does not
// have.
func otherEngineTime(p *agentOut) {
	p.SecurityParameters.AuthoritativeEngineBoots, p.SecurityParameters.AuthoritativeEngineTime = 99, 5
}

// timeJump moves the agent's engine time ten days ahead with its boots
// unchanged, leaving the client's engine time far behind.
func timeJump(a *fakeV3Agent) { a.timeBase += 886000 }

// unauthenticatedTimeWindow makes the agent answer a request outside its time
// window with a notInTimeWindow Report at noAuthNoPriv that carries its engine
// boots and time, as some devices (UniFi access points) do against RFC 3414
// section 3.2 step 7 a; edit, when set, changes each such Report.
func unauthenticatedTimeWindow(a *fakeV3Agent, edit func(*agentOut)) {
	a.script = func(_ int, req agentRequest) (agentAnswer, bool) {
		if req.boots == a.boots && absDiff(req.engineTime, a.engineTime()) <= agentTimeWindow {
			return agentAnswer{}, false
		}
		return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated", edit: edit}, true
	}
}

// malformedSecondVarbind appends a varbind whose value does not decode to the
// varbind list of an encoded plaintext answer.
func malformedSecondVarbind(m *v3Message) {
	split := func(b []byte) (fields [][]byte) {
		r := ber.NewReader(b)
		for r.Len() > 0 {
			tag, content, err := r.Next()
			if err != nil {
				panic(err)
			}
			fields = append(fields, tlv(tag, content))
		}
		return fields
	}
	content := func(field []byte) []byte {
		r := ber.NewReader(field)
		_, c, err := r.Next()
		if err != nil {
			panic(err)
		}
		return c
	}
	scoped := split(m.scoped)        // context engine ID, context name, PDU
	pdu := split(content(scoped[2])) // request ID, error status, error index, varbinds
	bad := tlv(ber.Sequence, tlv(byte(ObjectIdentifier), []byte{0x2b, 6, 1}), []byte{byte(Counter32), 5, 1})
	pdu[3] = tlv(ber.Sequence, content(pdu[3]), bad)
	scoped[2] = tlv(scoped[2][0], bytes.Join(pdu, nil))
	m.scoped = bytes.Join(scoped, nil)
}

// withoutScopedPDU encodes an answer that ends after its security parameters.
func withoutScopedPDU(m v3Message) []byte {
	var usm [][]byte
	for i, f := range m.usm {
		usm = append(usm, tlv(m.usmTags[i], f))
	}
	return tlv(ber.Sequence, tlv(byte(Integer), m.version), tlv(ber.Sequence, m.header),
		tlv(byte(OctetString), tlv(ber.Sequence, usm...)))
}

// onRequest scripts the answer to request n only.
func onRequest(n int, ans agentAnswer) func(int, agentRequest) (agentAnswer, bool) {
	return func(k int, _ agentRequest) (agentAnswer, bool) { return ans, k == n }
}

// reportOIDs are the Report counters the engine maps to errors, and one it
// does not know.
var reportOIDs = map[string]string{
	"unsupported-sec-levels":  usmStatsUnsupportedSecLevels,
	"not-in-time-windows":     usmStatsNotInTimeWindows,
	"unknown-user-names":      usmStatsUnknownUserNames,
	"unknown-engine-ids":      usmStatsUnknownEngineIDs,
	"wrong-digests":           usmStatsWrongDigests,
	"decryption-errors":       usmStatsDecryptionErrors,
	"unknown-security-models": snmpUnknownSecurityModels,
	"invalid-msgs":            snmpInvalidMsgs,
	"unknown-pdu-handlers":    snmpUnknownPDUHandlers,
	"other":                   ".1.3.6.1.6.3.15.1.1.9.0",
}

// v3Scenarios are the scenarios of TestEngineV3Characterization.
func v3Scenarios() map[string]v3Scenario {
	scenarios := map[string]v3Scenario{
		// Discovery, then the request, for each security level.
		"discovery/noauth":          {user: "codec-noauth"},
		"discovery/md5":             {user: "codec-md5"},
		"discovery/sha-aes":         {user: "codec-sha-aes"},
		"discovery/sha256-des":      {user: "codec-sha256-des"},
		"discovery/sha512-aes256c":  {user: "codec-sha512-aes256c"},
		"discovery/then-second-get": {user: "codec-sha-aes", run: getTwice(nil)},
		"discovery/no-answer": {user: "codec-md5", script: func(int, agentRequest) (agentAnswer, bool) {
			return agentAnswer{drop: true, why: "silent agent"}, true
		}},
		// A request's context ends it with its error and no message, never
		// marked answered, also after an answered discovery or resync Report.
		"context/nil": {user: "codec-md5", run: getWithinV3(nilContext)},
		"context/canceled-in-discovery": {
			user: "codec-md5", run: getWithinV3(canceledAfter(300 * time.Millisecond)),
			script: func(int, agentRequest) (agentAnswer, bool) {
				return agentAnswer{drop: true, why: "silent agent"}, true
			},
		},
		"context/canceled-after-discovery": {
			user: "codec-md5", run: getWithinV3(canceledAfter(300 * time.Millisecond)),
			script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{drop: true, why: "silent after discovery"}, n > 1
			},
		},
		"context/deadline-after-discovery": {
			user: "codec-md5", run: getWithinV3(withEngineTimeout(1500 * time.Millisecond)),
			script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{drop: true, why: "silent after discovery"}, n > 1
			},
		},
		"context/deadline-after-resync-report": {
			user: "codec-md5",
			run:  getThen(rebootSilentAfterResync, getWithin(withEngineTimeout(1500*time.Millisecond))),
		},
		"context/canceled-after-lent-resync": {
			user: "codec-noauth", run: getWithinV3(canceledAfter(300 * time.Millisecond)),
			script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch {
				case n == 2:
					return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unknown engine ID, from the other engine", edit: fromOtherEngine}, true
				case n > 2:
					return agentAnswer{drop: true, why: "silent after the Report"}, true
				}
				return agentAnswer{}, false
			},
		},
		"discovery/other-report": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnsupportedSecLevels, why: "answers discovery with another Report",
		})},
		// Discovery answered by a Response, in the agent's engine and
		// context engine, and without them.
		"discovery/report-without-varbinds": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "answers discovery with a Report without varbinds",
			edit: func(p *agentOut) { p.VarBinds = nil },
		})},
		"discovery/get-response": {user: "codec-md5", script: onRequest(1, agentAnswer{
			why: "answers discovery with a Response",
		})},
		"discovery/get-response-without-engine-id": {user: "codec-md5", script: onRequest(1, agentAnswer{
			why: "answers discovery with a Response without an engine ID", edit: withoutEngineID,
		})},
		"answer/unauthenticated-empty-identity": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				why: "Response without authentication, user name and engine ID",
				edit: func(p *agentOut) {
					usp := &p.SecurityParameters
					usp.UserName, usp.AuthoritativeEngineID = "", nil
				},
			}),
		},
		"discovery/unknown-user-names-report": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownUserNames, why: "answers discovery like some devices",
		})},
		"discovery/context-name": {user: "codec-md5", config: func(c *Config) {
			c.ContextName = "codec-vrf"
		}},
		"discovery/other-security-model": {
			user: "codec-md5", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report with security model 2",
				raw: securityModel2,
			}),
		},
		"discovery/empty-msg-flags": {
			user: "codec-md5", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report with an empty msgFlags", raw: msgFlagsOctets(),
			}),
		},
		"discovery/report-without-context-engine-id": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "discovery Report without a context engine ID",
			edit: func(p *agentOut) { p.ContextEngineID = nil },
		})},
		"discovery/context-engine-id-differs": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "discovery Report with another context engine ID",
			edit: func(p *agentOut) { p.ContextEngineID = []byte("codec-proxied-context") },
		})},
		"discovery/request-unanswered": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{drop: true, why: "silent after discovery"}, n > 1
		}},

		// Engine ID known in advance.
		"known-engine/time-unknown": {user: "codec-md5", setup: seedEngine(agentEngineID, 0, 0)},
		"known-engine/time-known":   {user: "codec-sha-aes", setup: seedEngine(agentEngineID, agentBoots, agentTimeBase)},
		"known-engine/other-engine": {user: "codec-md5", setup: seedEngine(agentOtherEngineID, 0, 0)},
		// An unauthenticated unknownEngineIDs Report forged from another
		// engine ends an authenticated request: it lends no engine ID.
		"known-engine/forged-report-from-other-engine": {
			user: "codec-sha-aes", setup: seedEngine(agentEngineID, 0, 0),
			script: onRequest(1, agentAnswer{report: usmStatsUnknownEngineIDs, why: "forged, unauthenticated", edit: fromOtherEngine}),
		},

		// The agent changes between two requests.
		"reboot": {user: "codec-sha-aes", run: getTwice(func(a *fakeV3Agent) { a.reboot() })},
		// RFC 3414 section 3.2 step 7 sends notInTimeWindow at authNoPriv and
		// takes the engine time only from authentic messages: the client sends
		// the request once more with the boots and time of an unauthenticated
		// one and stores the authenticated answer's.
		"reboot/unauthenticated-report": {user: "codec-md5", run: getTwice(func(a *fakeV3Agent) {
			a.reboot()
			a.script = func(_ int, req agentRequest) (agentAnswer, bool) {
				if req.boots == a.boots {
					return agentAnswer{}, false
				}
				return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated"}, true
			}
		})},
		"reboot/retransmit-unanswered": {user: "codec-md5", run: getTwice(rebootSilentAfterResync)},

		// Reports without authentication to an authenticated request: from
		// agents that send notInTimeWindow so, and ones that must not be
		// acted on.
		"unauthenticated-report/time-jump/md5": {user: "codec-md5", run: getThrice(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		})},
		"unauthenticated-report/time-jump/sha-aes": {user: "codec-sha-aes", run: getTwice(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		})},
		"unauthenticated-report/time-jump/sha256-des": {user: "codec-sha256-des", run: getTwice(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		})},
		"unauthenticated-report/reboot/sha-aes": {user: "codec-sha-aes", run: getTwice(func(a *fakeV3Agent) {
			a.reboot()
			unauthenticatedTimeWindow(a, nil)
		})},
		"unauthenticated-report/time-jump/getnext": {user: "codec-md5", run: getThen(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		}, sendOIDs(GetNextRequest, []string{engineOID}, 0))},
		"unauthenticated-report/time-jump/getbulk": {user: "codec-md5", run: getThen(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		}, sendOIDs(GetBulkRequest, []string{engineOID}, 2))},
		// A notInTimeWindow Report lends its time only, not the other engine
		// ID it names.
		"unauthenticated-report/noauth-other-engine": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: usmStatsNotInTimeWindows, why: "not in time window, from the other engine", edit: func(p *agentOut) {
				fromOtherEngine(p)
				p.SecurityParameters.AuthoritativeEngineTime += 7
			},
		})},
		"unauthenticated-report/engine-id-differs": {user: "codec-md5", run: getTwice(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, fromOtherEngine)
		})},
		"unauthenticated-report/always": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{report: usmStatsNotInTimeWindows, why: "always not in time window, unauthenticated"}, n > 1
		}},
		"unauthenticated-report/forged-time": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			switch {
			case n == 2:
				return agentAnswer{report: usmStatsNotInTimeWindows, why: "forged, unauthenticated", edit: otherEngineTime}, true
			case n > 2:
				return agentAnswer{drop: true, why: "silent after the Report"}, true
			}
			return agentAnswer{}, false
		}},
		"unauthenticated-report/forged-time-answered": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsNotInTimeWindows, why: "forged, unauthenticated", edit: otherEngineTime,
		})},
		"unauthenticated-report/other-msg-id": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, for another message",
			edit: func(p *agentOut) { p.MsgID += 100 },
		})},
		"unauthenticated-report/earlier-attempt": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			switch n {
			case 2:
				return agentAnswer{drop: true, why: "no answer"}, true
			case 3:
				return agentAnswer{
					report: usmStatsUnknownUserNames, why: "unauthenticated, with the msgID of the first attempt",
					edit: func(p *agentOut) { p.MsgID-- },
				}, true
			}
			return agentAnswer{}, false
		}},
		"unauthenticated-report/unknown-engine-other-msg-id": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "unauthenticated, from the other engine, for another message",
			edit: func(p *agentOut) {
				fromOtherEngine(p)
				p.MsgID += 100
			},
		})},
		"unauthenticated-report/encrypted": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, level: AuthPriv, why: "encrypted, msgFlags rewritten to noAuthNoPriv",
			raw: msgFlagsOctets(byte(NoAuthNoPriv)),
		})},
		"unauthenticated-report/two-varbinds": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, two varbinds",
			edit: func(p *agentOut) { p.VarBinds = append(p.VarBinds, sysDescr) },
		})},
		"unauthenticated-report/empty": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, no varbinds",
			edit: func(p *agentOut) { p.VarBinds = nil },
		})},
		"unauthenticated-report/without-scoped-pdu": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, ends after its security parameters",
			encode: withoutScopedPDU,
		})},
		"unauthenticated-report/privacy-flag-only": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "plaintext, msgFlags privacy without authentication",
			raw: msgFlagsOctets(byte(AuthPriv &^ AuthNoPriv)),
		})},
		"unauthenticated-report/malformed-second-varbind": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, a second varbind that does not decode",
			raw: malformedSecondVarbind,
		})},
		"unauthenticated-report/other-security-model": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, security model 2",
			raw: securityModel2,
		})},
		// The Report of the capture that showed the problem: the agent does not
		// read the PDU of a request outside its time window, so the request ID is
		// 0 and only the msgID ties the Report to the request.
		"unauthenticated-report/time-jump/request-id-zero": {user: "codec-sha-aes", run: getTwice(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, func(p *agentOut) { p.RequestID = 0 })
		})},
		"unauthenticated-report/silent-after-unknown-engine": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			switch {
			case n == 2:
				return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unauthenticated, from the other engine", edit: fromOtherEngine}, true
			case n > 2:
				return agentAnswer{drop: true, why: "silent after the Report"}, true
			}
			return agentAnswer{}, false
		}},
		// A Report another agent with the same credentials sent, for another
		// message or with the request's msgID, followed by two Gets.
		"answer/other-agent-report/other-message": {user: "codec-md5", run: getThrice(nil), script: onRequest(2, agentAnswer{
			report: snmpUnknownContexts, level: AuthNoPriv, why: "signed by another agent with the same credentials, for another message",
			edit: func(p *agentOut) {
				signedByOtherEngine(p)
				p.MsgID += 100
			},
		})},
		"answer/other-agent-report/same-message": {user: "codec-md5", run: getThrice(nil), script: onRequest(2, agentAnswer{
			report: snmpUnknownContexts, level: AuthNoPriv, why: "signed by another agent with the same credentials",
			edit: signedByOtherEngine,
		})},
		// An authentic Report for another message answers no request.
		"answer/authentic-report/other-message": {user: "codec-md5", run: getThrice(nil), script: onRequest(2, agentAnswer{
			report: snmpUnknownContexts, level: AuthNoPriv, why: "authentic, for another message, a later engine time",
			edit: func(p *agentOut) {
				p.MsgID += 100
				p.SecurityParameters.AuthoritativeEngineTime += 50
			},
		})},
		// A reply naming another engine ID is not the request's answer, even
		// when the request's key signs it.
		"answer/other-engine-id-request-key": {user: "codec-md5", run: getThrice(nil), script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "names the other engine ID, signed with the user's key localized to the agent's",
			edit: fromOtherEngine,
		})},
		"answer/forged-report/empty-identity": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, level: AuthNoPriv, why: "Report signed with another key, without a user name and engine ID",
			edit: func(p *agentOut) {
				forgeReport(p)
				usp := &p.SecurityParameters
				usp.UserName, usp.AuthoritativeEngineID = "", nil
			},
		})},
		// A client with authentication keys that sends at noAuthNoPriv does
		// not check the digest of an authNoPriv answer.
		"report-later/noauth-request-authenticated-report": {
			user: "codec-md5", config: func(c *Config) { c.SecurityLevel = NoAuthNoPriv },
			run: getTwice(nil), script: onRequest(3, agentAnswer{
				report: usmStatsUnknownUserNames, level: AuthNoPriv, why: "authNoPriv Report from another engine ID 10 s later",
				edit: fromOtherEngine,
			}),
		},

		// The client's notion of the engine time advances with its clock
		// (RFC 3414 section 2.3): a request after 150 s of silence is in the
		// time window.
		"time-window/silence-over-150s": {user: "codec-md5", run: getAfter(200*time.Second, nil)},
		"time-window/always-not-in-time-window": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "always not in time window"}, n > 1
			},
		},
		// Discovery answered by a Report without an engine ID fails (RFC 3414
		// section 3.2 step 3; net-snmp's probe fails the same way): the client
		// learns nothing, and the next request discovers again.
		"discovery/report-without-engine-id/md5": {
			user: "codec-md5", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report without an engine ID", edit: withoutEngineID,
			}),
		},
		"discovery/report-without-engine-id/sha256-des": {
			user: "codec-sha256-des", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report without an engine ID", edit: withoutEngineID,
			}),
		},
		"discovery/report-without-engine-id/sha-aes": {
			user: "codec-sha-aes", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report without an engine ID", edit: withoutEngineID,
			}),
		},
		// A request without authentication needs no key, but no engine ID
		// either: it fails the same way.
		"discovery/report-without-engine-id/noauth": {
			user: "codec-noauth", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report without an engine ID", edit: withoutEngineID,
			}),
		},

		// A panic after the discovery's commit, as the request's first attempt
		// sets its deadline, ends the request; the next request uses the
		// engine state the discovery committed.
		"user-code/panic-after-discovery": {
			user: "codec-md5",
			run: func(x *Client, a *fakeV3Agent) (*Message, error) {
				atDeadline(transportOf(a.tr.tb, x), 2, func() {
					a.tr.addf("the Conn, setting deadline #2, panics after the discovery")
					panicWithError()
				})
				res, err := x.Get(context.Background(), []string{engineOID})
				a.tr.addf("first request: %s", describeEngineResult(res, err))
				time.Sleep(10 * time.Second)
				return x.Get(context.Background(), []string{engineOID})
			},
		},

		// send's resynchronization after a notInTimeWindow Report.
		"resync/panic-in-retransmission": {
			user:   "codec-md5",
			script: onRequest(2, agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}),
			run: func(x *Client, a *fakeV3Agent) (*Message, error) {
				transportOf(a.tr.tb, x).failWrite = func(n int) error {
					if n == 3 {
						a.tr.addf("the Conn's write #3, the retransmission, panics")
						panic("codec write failure")
					}
					return nil
				}
				return x.Get(context.Background(), []string{engineOID})
			},
		},
		"resync/retransmission-answered-by-report": {
			user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 2:
					return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window"}, true
				case 3:
					return agentAnswer{report: usmStatsUnknownUserNames, why: "unknown user"}, true
				}
				return agentAnswer{}, false
			},
		},
		// A Report is matched by its msgID (RFC 3412 section 7.2 step 10); its
		// request ID may be 0 when the agent could not read the request.
		"resync/report-for-other-request-id": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window, for another request ID",
				edit: func(p *agentOut) { p.RequestID += 100 },
			}),
		},
		"resync/retransmission-answered-by-authenticated-report": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 2:
					return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}, true
				case 3:
					return agentAnswer{
						report: snmpUnknownContexts, level: AuthNoPriv, why: "unknown context, a later engine time",
						edit: func(p *agentOut) { p.SecurityParameters.AuthoritativeEngineTime += 7 },
					}, true
				}
				return agentAnswer{}, false
			},
		},
		"resync/retransmission-answer-other-security-model": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 2:
					return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated"}, true
				case 3:
					return agentAnswer{level: AuthNoPriv, why: "Response with security model 2", raw: securityModel2}, true
				}
				return agentAnswer{}, false
			},
		},
		"resync/retransmission-answer-time": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 2:
					return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}, true
				case 3:
					return agentAnswer{level: AuthNoPriv, why: "a later engine time", edit: func(p *agentOut) {
						p.SecurityParameters.AuthoritativeEngineTime += 7
					}}, true
				}
				return agentAnswer{}, false
			},
		},
		// Once the client has an engine ID it does not take another from an
		// unauthenticated Report (RFC 3414 section 1.5.2; net-snmp neither):
		// the request ends with ErrUnknownEngineID, and an application that
		// expects a replaced device calls ForgetEngine to rediscover.
		"engine-change": {
			user: "codec-md5", run: getTwice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) }),
		},
		"engine-change/sha-aes": {
			user: "codec-sha-aes", run: getTwice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) }),
		},
		// A client without authentication follows the agent's engine ID, and
		// its context engine ID follows (net-snmp keeps the first one).
		"engine-change/noauth": {
			user: "codec-noauth", run: getThrice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) }),
		},
		// The result of a request is the caller's: writing into its header
		// leaves the engine state as it is, also after a request took the
		// engine ID the result names.
		"engine-change/noauth/caller-writes-result": {
			user: "codec-noauth", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
				res, err := getTwice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) })(x, a)
				if err != nil {
					return nil, fmt.Errorf("second Get: %w", err)
				}
				a.tr.addf("caller clears the second result's engine ID; client %s", describeEngineState(x))
				clear(res.SecurityParameters.AuthoritativeEngineID)
				a.tr.addf("client %s", describeEngineState(x))
				time.Sleep(10 * time.Second)
				return x.Get(context.Background(), []string{engineOID})
			},
		},
		"unknown-engine-report/noauth-retransmit-unanswered": {
			user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch {
				case n == 2:
					return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unknown engine ID, from the other engine", edit: fromOtherEngine}, true
				case n > 2:
					return agentAnswer{drop: true, why: "silent after the Report"}, true
				}
				return agentAnswer{}, false
			},
		},
		"unknown-engine-report/noauth-always": {
			user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{report: usmStatsUnknownEngineIDs, why: "always unknown engine ID, from the other engine", edit: fromOtherEngine}, n > 1
			},
		},
		"engine-change/sha-aes-answered-from-new-engine": {
			user: "codec-sha-aes", run: getThrice(func(a *fakeV3Agent) {
				a.setEngineID(agentOtherEngineID)
				a.script = func(n int, _ agentRequest) (agentAnswer, bool) {
					return agentAnswer{level: AuthPriv, why: "answers the old engine ID from the new one"}, n == 3
				}
			}),
		},
		"engine-change/md5-answered-from-new-engine": {
			user: "codec-md5", run: getThrice(func(a *fakeV3Agent) {
				a.setEngineID(agentOtherEngineID)
				a.script = func(n int, _ agentRequest) (agentAnswer, bool) {
					return agentAnswer{level: AuthNoPriv, why: "answers the old engine ID from the new one"}, n == 3
				}
			}),
		},

		// The caller makes the client forget the agent's engine between two
		// requests (E30): the next request discovers it again.
		"caller/forget-engine": {user: "codec-md5", run: changeThenGet(
			"calls ForgetEngine", func(x *Client) { x.ForgetEngine() })},
		// A forged answer to the discovery gives the client another engine ID
		// (E29a): the agent answers the authenticated request with an
		// unauthenticated unknownEngineIDs Report, which ends it with
		// ErrUnknownEngineID; the caller forgets the engine (J7 (b)), and the
		// next request discovers the agent's.
		"caller/forged-discovery-then-forget-engine": {
			user: "codec-md5", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "forged discovery answer, from the other engine", edit: fromOtherEngine,
			}),
			run: func(x *Client, a *fakeV3Agent) (*Message, error) {
				res, err := x.Get(context.Background(), []string{engineOID})
				a.tr.addf("first Get: %s", describeEngineResult(res, err))
				if !errors.Is(err, ErrUnknownEngineID) {
					return res, err
				}
				a.tr.addf("caller calls ForgetEngine")
				x.ForgetEngine()
				return x.Get(context.Background(), []string{engineOID})
			},
		},
		// EncodeMessage takes the engine state as a request starts it: the
		// engine ID, the keys localized to it and the latest boots and time
		// received, not advanced; a ForgetEngine since the last request
		// applies to it as to a request.
		"caller/encode-after-get/known-engine": {
			user: "codec-md5", setup: seedEngine(agentEngineID, 0, 0),
			run: func(x *Client, a *fakeV3Agent) (*Message, error) {
				res, err := x.Get(context.Background(), []string{engineOID})
				time.Sleep(10 * time.Second)
				encodeMessage(x, a)
				return res, err
			},
		},
		"caller/encode-after-forget-engine": {user: "codec-md5", run: encodeThenGet(
			"calls ForgetEngine", func(x *Client) { x.ForgetEngine() })},
		"caller/encode-after-forget-engine/noauth": {user: "codec-noauth", run: encodeThenGet(
			"calls ForgetEngine", func(x *Client) { x.ForgetEngine() })},

		// The fake connection's code forgets the engine during a request,
		// which keeps its state: the next request discovers the engine again.
		"user-code/discovery-answer-forgets-engine": {
			user: "codec-md5", run: afterReadThenGet(1, "calls ForgetEngine", func(x *Client) { x.ForgetEngine() }),
		},

		// A Response to a request without authentication naming another
		// engine ID than the request's answers nothing (RFC 3412 section 7.2
		// step 12 b), here none.
		"noauth/answer-without-engine-id": {
			user: "codec-noauth", run: getTwice(nil),
			script: onRequest(2, agentAnswer{why: "Response without an engine ID", edit: withoutEngineID}),
		},
		// An unknownEngineIDs Report without an engine ID has none to lend.
		"noauth/unknown-engine-report-without-engine-id": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "Report without an engine ID", edit: withoutEngineID,
			}),
		},
		// The parameters of a request without authentication have an
		// authentication protocol: an authenticated answer from the engine an
		// unauthenticated Report named checks with the user's key localized to
		// it, and answers nothing, at another level than the request's: the
		// resend times out with that reason.
		"noauth/lent-engine-authenticated-answer": {
			user: "codec-md5", config: func(c *Config) { c.SecurityLevel = NoAuthNoPriv },
			script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch {
				case n == 2:
					return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unknown engine ID, from the other engine", edit: fromOtherEngine}, true
				case n == 3:
					return agentAnswer{level: AuthNoPriv, why: "authNoPriv from the other engine", edit: signedByOtherEngine}, true
				case n > 3:
					return agentAnswer{drop: true, why: "silent"}, true
				}
				return agentAnswer{}, false
			},
		},

		// The engine boots and time requests carry and take from answers.
		// An agent that restarts without raising its boots, answering
		// notInTimeWindow with and without authentication.
		"clock/restart-same-boots/authenticated-report": {
			user: "codec-md5", run: getThrice(func(a *fakeV3Agent) { a.restartWithoutBoots() }),
		},
		"clock/restart-same-boots/unauthenticated-report": {
			user: "codec-md5", run: getThrice(func(a *fakeV3Agent) {
				a.restartWithoutBoots()
				unauthenticatedTimeWindow(a, nil)
			}),
		},
		// Devices that do not check the time of requests and never report
		// notInTimeWindow, whose answers fall outside the time window: one that
		// restarts without raising its boots, and a failover pair sharing an
		// engine ID that fails back to the unit with lower boots. The failed
		// request drops the clock, and the next one's answer sets it.
		"clock/no-time-check/restart-same-boots": {user: "codec-md5", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.noTimeCheck = true
			return getThrice(func(a *fakeV3Agent) { a.restartWithoutBoots() })(x, a)
		}},
		"clock/no-time-check/boots-down": {user: "codec-md5", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.noTimeCheck = true
			return getThrice(func(a *fakeV3Agent) { a.boots-- })(x, a)
		}},
		// The resend an unauthenticated notInTimeWindow Report lent its clock
		// to is answered outside the time window on every attempt, with other
		// boots than the Report's: the clock is dropped, and the next request's
		// boots and time zero get the agent's authenticated Report.
		"clock/resend-answers-outside-window": {
			user: "codec-md5", run: getThrice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch {
				case n == 3:
					return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated"}, true
				case n >= 4 && n <= 6:
					return agentAnswer{level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots}, true
				}
				return agentAnswer{}, false
			},
		},
		// A device whose engine time stands still and that checks the time of
		// requests: after 150 s of silence the client's advancing time is
		// outside its window, and its authenticated notInTimeWindow Report
		// sets the clock (one more round trip, as with net-snmp).
		"clock/frozen-time/silence-over-150s": {user: "codec-md5", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.frozen = true
			return getAfter(200*time.Second, nil)(x, a)
		}},
		// An engine at boots 2147483647 checks the time of authenticated
		// messages only (RFC 3414 section 3.2 step 7): discovery and a
		// request without authentication still work.
		"clock/noauth/engine-boots-max": {user: "codec-noauth", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.boots = maxEngineValue
			return getTwice(nil)(x, a)
		}},
		"clock/boots-max-after-update": {
			user: "codec-md5", run: getThrice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "Response with engine boots 2147483647",
				edit: func(p *agentOut) { p.SecurityParameters.AuthoritativeEngineBoots = maxEngineValue },
			}),
		},
		// Discovery's unauthenticated time is no notion step 7 checks the
		// first authenticated answer against, which sets the clock the next
		// request carries.
		"clock/verified-after-discovery-time-ahead": {
			user: "codec-md5", run: getTwice(nil),
			script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 1:
					return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unknown engine ID, an engine time 1000 s ahead", edit: func(p *agentOut) {
						p.SecurityParameters.AuthoritativeEngineTime += 1000
					}}, true
				case 2:
					return agentAnswer{level: AuthNoPriv, why: "authNoPriv answer"}, true
				}
				return agentAnswer{}, false
			},
		},
		// The resend an unauthenticated notInTimeWindow Report lends its boots
		// and time to is lost twice, then answered.
		"clock/lent-clock-retries": {
			user: "codec-md5", run: getTwice(func(a *fakeV3Agent) {
				timeJump(a)
				lost := 0
				a.script = func(_ int, req agentRequest) (agentAnswer, bool) {
					switch {
					case req.boots != a.boots || absDiff(req.engineTime, a.engineTime()) > agentTimeWindow:
						return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated"}, true
					case lost < 2:
						lost++
						return agentAnswer{drop: true, why: "lost"}, true
					}
					return agentAnswer{}, false
				}
			}),
		},
		// Two authenticated notInTimeWindow Reports with other engine times,
		// to the request and to its resend.
		"clock/second-resync-report-other-time": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				if n < 2 {
					return agentAnswer{}, false
				}
				ahead := uint32(50 * (n - 1)) //nolint:gosec // a small request count
				return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window", edit: func(p *agentOut) {
					p.SecurityParameters.AuthoritativeEngineTime += ahead
				}}, true
			},
		},

		// Requests the agent rejects.
		"wrong-priv-passphrase/aes": {user: "codec-sha-aes", creds: &agentUser{
			auth: SHA, authPass: "codec-sha-pass", priv: AES, privPass: "codec-wrong-pass",
		}},
		"wrong-priv-passphrase/des": {user: "codec-sha256-des", creds: &agentUser{
			auth: SHA256, authPass: "codec-sha256-pass", priv: DES, privPass: "codec-wrong-pass",
		}},
		"wrong-priv-protocol/aes-to-des-user": {
			user: "codec-sha256-des", creds: &agentUser{
				auth: SHA256, authPass: "codec-sha256-pass", priv: AES, privPass: "codec-des-pass",
			},
		},
		"wrong-passphrase": {
			user: "codec-md5", creds: &agentUser{auth: MD5, authPass: "codec-wrong-pass", priv: NoPriv},
		},
		"unknown-user/noauth": {user: "codec-nobody", creds: &agentUser{auth: NoAuth, priv: NoPriv}},
		"unknown-user/auth": {
			user: "codec-nobody", creds: &agentUser{auth: MD5, authPass: "codec-md5-pass", priv: NoPriv},
		},
		"unsupported-level": {
			user: "codec-md5", creds: &agentUser{auth: MD5, authPass: "codec-md5-pass", priv: AES, privPass: "codec-aes-pass"},
		},

		// Answers that do not match the request.
		"answer/report-for-other-message": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report for another message",
				edit: func(p *agentOut) { p.MsgID, p.RequestID = p.MsgID+100, p.RequestID+100 },
			}),
		},
		"answer/wrong-msg-id": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, edit: func(p *agentOut) { p.MsgID += 100 }, why: "Response for another message",
			}),
		},
		"answer/empty-other-message": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "empty Response for another message",
			edit: func(p *agentOut) {
				p.VarBinds = nil
				p.MsgID += 100
			},
		})},
		"answer/wrong-request-id": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, edit: func(p *agentOut) { p.RequestID += 100 }, why: "Response for another request",
		})},
		"answer/unauthenticated": {user: "codec-md5", script: onRequest(2, agentAnswer{
			why: "Response without authentication",
		})},
		"answer/not-encrypted": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, why: "Response without encryption",
			}),
		},
		"answer/encrypted-to-authnopriv": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "Response encrypted for an authNoPriv request", edit: encryptedForAuthNoPriv,
			}, n > 1
		}},
		"answer/encrypted-with-other-key": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			level: AuthPriv, why: "Response encrypted with another key", edit: otherKey,
		})},
		// The final error comes from decoding the wrong plaintext, so it
		// changes with the salts and keys.
		"answer/always-encrypted-with-other-key": {user: "codec-sha-aes", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{level: AuthPriv, why: "Response encrypted with another key", edit: otherKey}, n > 1
		}},
		"answer/other-context": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, why: "Response in another context",
				edit: func(p *agentOut) {
					p.ContextEngineID, p.ContextName = []byte("codec-other-context"), "codec-other-name"
				},
			}),
		},
		"answer/other-user/noauth": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "Response for another user", edit: func(p *agentOut) { p.SecurityParameters.UserName = "codec-other-user" },
			}),
		},
		"answer/other-user/md5": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response for another user",
			edit: func(p *agentOut) { p.SecurityParameters.UserName = "codec-other-user" },
		})},
		// The reportableFlag and the reserved bits of an answer's msgFlags are
		// not part of its level: the Response answers.
		"answer/reserved-msg-flags": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "Response with msgFlags 0xfc", raw: msgFlagsOctets(0xfc),
			}),
		},
		"answer/empty-msg-flags": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "Response with an empty msgFlags", raw: msgFlagsOctets(),
			}),
		},
		"answer/other-version/noauth": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{why: "SNMPv2c Response", edit: asV2c}),
		},
		// A request sent back unchanged carries the client's own msgID,
		// request ID and, when authenticated, its own digest and ciphertext.
		"answer/reflected-request/noauth": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{reflect: true, why: "the request sent back"}),
		},
		"answer/reflected-request/discovery": {
			user: "codec-md5", script: onRequest(1, agentAnswer{reflect: true, why: "the discovery request sent back"}),
		},
		"answer/reflected-request/md5": {
			user: "codec-md5", script: onRequest(2, agentAnswer{reflect: true, why: "the request sent back"}),
		},
		"answer/reflected-request/sha-aes": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{reflect: true, why: "the request sent back"}),
		},
		// An SNMPv2c message whose body reads as a scoped PDU, with the
		// request's request ID, does not answer an SNMPv3 request.
		"answer/other-version/noauth-scoped-body": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "an SNMPv2c message carrying the scoped PDU",
				encode: func(m v3Message) []byte {
					return tlv(0x30, tlv(byte(Integer), []byte{byte(Version2c)}), tlv(byte(OctetString), []byte("public")),
						tlv(m.scopedTag, m.scoped))
				},
			}),
		},
		"answer/other-version/md5": {
			user: "codec-md5", script: onRequest(2, agentAnswer{level: AuthNoPriv, why: "SNMPv2c Response", edit: asV2c}),
		},
		"answer/other-version/sha-aes": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{level: AuthPriv, why: "SNMPv2c Response", edit: asV2c}),
		},
		"answer/other-security-model": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "Response with security model 2", raw: securityModel2,
			}),
		},
		// A Report carries one varbind (RFC 3412 section 7.1 step 3 d): one with
		// two, or none, is classified by its first, as net-snmp does.
		"answer/report-two-varbinds": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, why: "Report with two varbinds",
				edit: func(p *agentOut) { p.VarBinds = append(p.VarBinds, sysDescr) },
			}),
		},
		"answer/report-two-varbinds-error-oid": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report with two varbinds",
				edit: func(p *agentOut) { p.VarBinds = append(p.VarBinds, sysDescr) },
			}),
		},
		"answer/report-unknown-first-varbind": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, why: "Report whose first varbind is not a counter",
				edit: func(p *agentOut) { p.VarBinds = append([]VarBind{sysDescr}, p.VarBinds...) },
			}),
		},
		"answer/report-without-varbinds": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report without varbinds",
				edit: func(p *agentOut) { p.VarBinds = nil },
			}),
		},
		// Report counters named with another instance than 0, or without
		// exactly one instance sub-identifier.
		"report-instance/not-in-time-windows": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: strings.TrimSuffix(usmStatsNotInTimeWindows, "0") + "1", why: "notInTimeWindows Report, instance 1",
		})},
		"report-instance/unknown-engine-ids-discovery": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: strings.TrimSuffix(usmStatsUnknownEngineIDs, "0") + "1", why: "unknownEngineIDs Report, instance 1",
		})},
		"report-instance/wrong-digests": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: strings.TrimSuffix(usmStatsWrongDigests, "0") + "5", why: "wrongDigests Report, instance 5",
		})},
		"report-instance/counter-without-instance": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: strings.TrimSuffix(usmStatsWrongDigests, ".0"), why: "wrongDigests Report without an instance",
		})},
		"report-instance/two-instance-sub-identifiers": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: usmStatsWrongDigests + ".0", why: "wrongDigests Report, instance 0.0",
		})},

		// Reports after the engine is known: whether their engine
		// parameters are stored.
		"report-later/md5": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				report: snmpUnknownContexts, level: AuthNoPriv, why: "authenticated unknown context Report 10 s later",
			}),
		},
		"report-later/noauth-other-engine": {user: "codec-noauth", run: getTwice(nil), script: onRequest(3, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated Report from another engine ID 10 s later",
			edit: fromOtherEngine,
		})},

		// Authentic replies with older engine values (RFC 3414 section 3.2
		// step 7 b: an older time within the time window is accepted, the
		// latest kept; lower boots are outside it, and the request is sent
		// again), and forged Reports.
		"time-window/older-time": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "Response with an older engine time",
				edit: func(p *agentOut) { p.SecurityParameters.AuthoritativeEngineTime = agentTimeBase - 100 },
			}),
		},
		"time-window/older-boots": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots,
			}),
		},
		// Every attempt answered outside the time window: the request ends
		// with an error that matches ErrNotInTimeWindow and the client drops
		// its engine time.
		"time-window/older-boots-every-attempt": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots}, n > 2
			},
		},
		"answer/forged-report/not-in-time-windows": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "Report signed with another key", edit: forgeReport,
		})},
		"answer/forged-report/unknown-user-names": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, level: AuthNoPriv, why: "Report signed with another key", edit: forgeReport,
		})},
		"answer/error-report-other-security-model": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, level: AuthNoPriv, why: "authenticated Report with security model 2",
				raw: securityModel2,
			}),
		},
		"answer/report-other-security-model": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "Report with security model 2",
				raw: securityModel2,
			}),
		},

		// A message the client rejects, then the answer, both to the same
		// attempt.
		"discard/undecodable-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response with an empty msgFlags", raw: msgFlagsOctets(), then: true,
		})},
		"discard/other-user-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response for another user", then: true,
			edit: func(p *agentOut) { p.SecurityParameters.UserName = "codec-other-user" },
		})},
		"discard/wrong-digest-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response signed with another key", edit: otherAuthKey, then: true,
		})},
		// A forged answer naming an engine ID longer than an agent parses is
		// discarded, so the client neither keeps nor lends it.
		"discard/oversized-engine-id-discovery-then-answer": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "forged discovery answer naming a 65-octet engine ID",
			edit: fromOversizedEngine, then: true,
		})},
		"discard/oversized-engine-id-report-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "forged Report naming a 65-octet engine ID",
			edit: fromOversizedEngine, then: true,
		})},
		"discard/unsupported-level-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response encrypted for an authNoPriv request", edit: encryptedForAuthNoPriv, then: true,
		})},
		"discard/decryption-then-answer": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			level: AuthPriv, why: "Response encrypted with another key", edit: otherKey, then: true,
		})},
		"discard/unauthenticated-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			why: "Response without authentication", then: true,
		})},
		"discard/not-in-time-window-then-answer": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots, then: true,
			}),
		},
		// Every attempt answered with lower boots, then a datagram that does
		// not decode: the request's error is the time window's.
		"discard/not-in-time-window-then-noise": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots, noise: garbage}, n > 2
			},
		},
		// Every attempt answered with lower boots, then for the same message
		// signed with another key: the request's error is the time window's.
		"discard/not-in-time-window-then-wrong-digest": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{
					level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots,
					also: &agentAnswer{level: AuthNoPriv, why: "Response signed with another key", edit: otherAuthKey},
				}, n > 2
			},
		},
		// Every attempt answered for another message, signed with another key:
		// nothing answers the request.
		"discard/other-message-wrong-digest": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "Response for another message, signed with another key",
				edit: func(p *agentOut) { otherAuthKey(p); p.MsgID += 100 },
			}, n > 1
		}},
		// Responses with the request's msgID that differ from the request
		// in one field RFC 3412 section 7.2 step 12 b compares, each followed
		// by the agent's answer.
		"discard/not-encrypted-then-answer": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response without encryption", then: true,
		})},
		"discard/authenticated-to-noauth-then-answer": {
			user: "codec-md5", config: func(c *Config) { c.SecurityLevel = NoAuthNoPriv },
			script: onRequest(2, agentAnswer{level: AuthNoPriv, why: "authNoPriv Response", then: true}),
		},
		"discard/other-engine-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			why: "Response naming the other engine ID", then: true,
			edit: func(p *agentOut) { p.SecurityParameters.AuthoritativeEngineID = []byte(agentOtherEngineID) },
		})},
		"discard/other-context-engine-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response with another context engine ID", then: true,
			edit: func(p *agentOut) { p.ContextEngineID = []byte("codec-other-context") },
		})},
		"discard/other-context-name-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "Response with another context name", then: true,
			edit: func(p *agentOut) { p.ContextName = "codec-other-name" },
		})},
		"discard/empty-user-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			why: "Response without a user name", then: true,
			edit: func(p *agentOut) { p.SecurityParameters.UserName = "" },
		})},
		"discard/other-version-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			why: "SNMPv2c Response", edit: asV2c, then: true,
		})},
		// The first attempt is lost; the second is answered with its msgID and
		// the first attempt's request ID, then by the agent.
		"discard/other-attempt-request-id-then-answer": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			switch n {
			case 2:
				return agentAnswer{drop: true, why: "lost"}, true
			case 3:
				return agentAnswer{
					level: AuthNoPriv, why: "Response with the first attempt's request ID", then: true,
					edit: func(p *agentOut) { p.RequestID-- },
				}, true
			}
			return agentAnswer{}, false
		}},
		// Every attempt answered with a reply that names it but does not
		// answer it, by one reason each: the request's error ends with the
		// reason and matches its category.
		"discard/every-attempt/other-version": {user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{why: "SNMPv2c Response", edit: asV2c}, n > 1
		}},
		"discard/every-attempt/reflected-request": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{reflect: true, why: "the request sent back"}, n > 1
		}},
		"discard/every-attempt/other-request-id": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "Response for another request", edit: func(p *agentOut) { p.RequestID += 100 },
			}, n > 1
		}},
		"discard/every-attempt/other-level": {user: "codec-sha-aes", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{level: AuthNoPriv, why: "Response without encryption"}, n > 1
		}},
		// Security processing rejects another user's name; the empty one of
		// discovery passes it, and step 12 b discards it.
		"discard/every-attempt/empty-user": {user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				why: "Response without a user name", edit: func(p *agentOut) { p.SecurityParameters.UserName = "" },
			}, n > 1
		}},
		"discard/every-attempt/other-engine": {user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				why:  "Response naming the other engine ID",
				edit: func(p *agentOut) { p.SecurityParameters.AuthoritativeEngineID = []byte(agentOtherEngineID) },
			}, n > 1
		}},
		"discard/every-attempt/other-context": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "Response with another context name",
				edit: func(p *agentOut) { p.ContextName = "codec-other-name" },
			}, n > 1
		}},
		// Every attempt answered with lower boots, then the request sent back
		// unchanged: the request's error is the time window's.
		"discard/not-in-time-window-then-reflected": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{
					level: AuthNoPriv, why: "Response with lower engine boots", edit: olderBoots,
					also: &agentAnswer{reflect: true, why: "the request sent back"},
				}, n > 2
			},
		},
		// A context deadline ends the second Get, whose answers come from an
		// agent that restarted without raising its boots and does not check
		// the time window.
		"clock/no-time-check/restart-same-boots/context-deadline": {user: "codec-md5", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.noTimeCheck = true
			if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			a.restartWithoutBoots()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			res, err := x.Get(ctx, []string{engineOID})
			a.tr.addf("second Get, with a Context deadline after 1.5 s: %s", describeEngineResult(res, err))
			time.Sleep(10 * time.Second)
			return x.Get(context.Background(), []string{engineOID})
		}},
		// The context's deadline passes after the second Get's first attempt
		// discarded the answer of an agent that restarted without raising its
		// boots and does not check the time window, before the next attempt:
		// the next attempt does not start.
		"clock/no-time-check/restart-same-boots/context-deadline-between-attempts": {user: "codec-md5", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.noTimeCheck = true
			if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			a.restartWithoutBoots()
			ctx, cancel := doneAtErrCall(3, context.DeadlineExceeded)()
			defer cancel()
			res, err := x.Get(ctx, []string{engineOID})
			a.tr.addf("second Get, with a context whose deadline passes before its second attempt: %s", describeEngineResult(res, err))
			time.Sleep(10 * time.Second)
			return x.Get(context.Background(), []string{engineOID})
		}},
		// Close ends the second Get once it has read the answer of an agent
		// that restarted without raising its boots and does not check the
		// time window.
		"clock/no-time-check/restart-same-boots/closed": {user: "codec-md5", run: func(x *Client, a *fakeV3Agent) (*Message, error) {
			a.noTimeCheck = true
			if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			a.restartWithoutBoots()
			c := transportOf(a.tr.tb, x)
			first := c.reads + 1
			afterRead(x, a, first, "closes the client", func(x *Client) { _ = x.Close() })
			return x.Get(context.Background(), []string{engineOID})
		}},
	}

	// Every Report counter after discovery, unauthenticated to a
	// noAuthNoPriv and to an authNoPriv user, and authenticated to an
	// authNoPriv user.
	for name, oid := range reportOIDs {
		scenarios["report/md5-unauthenticated/"+name] = v3Scenario{
			user: "codec-md5", script: onRequest(2, agentAnswer{report: oid, why: "scripted Report, unauthenticated"}),
		}
		scenarios["report/noauth/"+name] = v3Scenario{user: "codec-noauth", script: onRequest(2, agentAnswer{report: oid, why: "scripted Report"})}
		scenarios["report/md5/"+name] = v3Scenario{user: "codec-md5", script: onRequest(2, agentAnswer{report: oid, level: AuthNoPriv, why: "scripted Report"})}
	}
	return scenarios
}

// TestEngineV3Characterization pins what the request engine does with an
// SNMPv3 agent: engine discovery, the request at each security level, an
// agent that reboots or changes its engine ID, each Report counter, and
// answers that do not match the request. testdata/engine/v3.golden holds the
// transcripts.
func TestEngineV3Characterization(t *testing.T) {
	scenarios := v3Scenarios()
	var results []goldenCase
	for _, name := range slices.Sorted(maps.Keys(scenarios)) {
		sc := scenarios[name]
		var dump string
		synctest.Test(t, func(t *testing.T) {
			dump = runV3Scenario(t, sc)
		})
		results = append(results, goldenCase{name: "v3/" + name, dump: dump})
	}
	engineGolden.check(t, "v3", results)
}

// TestEngineV3Polls pins the engine boots and time of an authNoPriv client
// that polls an agent every 10 s for 10 minutes, one line per request and its
// answers: an agent that checks the time window, and one whose engine time
// stands still and that does not check it. testdata/engine/v3-polls.golden
// holds them.
func TestEngineV3Polls(t *testing.T) {
	agents := map[string]func(a *fakeV3Agent){
		"window-checking-agent":     nil,
		"frozen-time-no-time-check": func(a *fakeV3Agent) { a.frozen, a.noTimeCheck = true, true },
	}
	var results []goldenCase
	for _, name := range slices.Sorted(maps.Keys(agents)) {
		var dump string
		synctest.Test(t, func(t *testing.T) {
			dump = runV3Polls(t, agents[name])
		})
		results = append(results, goldenCase{name: "v3-polls/" + name, dump: dump})
	}
	engineGolden.check(t, "v3-polls", results)
}

// runV3Polls runs a Get every 10 s for 10 minutes against the fake agent that
// setup changes, in the calling synctest bubble, and returns one line per
// request: its PDU, security level, engine boots and time, and those of the
// agent's answers.
func runV3Polls(t *testing.T, setup func(a *fakeV3Agent)) string {
	tr := newEngineTranscript(t)
	var agent *fakeV3Agent
	fips140.WithoutEnforcement(func() { agent = newFakeV3Agent(nil, agentCreds, sysDescr) })
	if setup != nil {
		setup(agent)
	}
	c := newFakeTransport(nil, func(n int, data []byte) (replies []agentReply) {
		fips140.WithoutEnforcement(func() { replies = agent.handle(n, data) })
		answers := make([]string, 0, len(replies))
		for _, r := range replies {
			answers = append(answers, describePollMessage(r.data))
		}
		if len(answers) == 0 {
			answers = append(answers, "no answer")
		}
		tr.addf("#%d %s -> %s", n, describePollMessage(data), strings.Join(answers, ", "))
		return replies
	})
	creds := agentCreds["codec-md5"]
	x := newEngineClientFrom(t, c, Config{
		Version:       Version3,
		SecurityLevel: AuthNoPriv,
		User:          creds.user("codec-md5"),
		Timeout:       time.Second,
		Retries:       2,
	})
	for range 60 {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			tr.addf("Get: %v", err)
		}
		time.Sleep(10 * time.Second)
	}
	tr.addf("client after: boots=%d time=%d", x.engine.clock.boots, x.engine.clock.latest)
	return tr.text()
}

// describePollMessage describes an SNMPv3 message for runV3Polls: its PDU type
// (encrypted when it cannot be read) and a Report's counter, its security
// level, and its engine boots and time.
func describePollMessage(data []byte) string {
	m, err := parseV3Message(data)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	msg, err := readAgentRequest(m)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	pdu := "encrypted"
	if msg.pdu != nil {
		pdu = msg.pdu.PDUType.String()
		if msg.pdu.PDUType == Report && len(msg.pdu.VarBinds) == 1 {
			pdu += " " + msg.pdu.VarBinds[0].Name
		}
	}
	return fmt.Sprintf("%s %s boots=%d time=%d", pdu, describeFlags(msg.flags), msg.boots, msg.engineTime)
}

// runV3Scenario runs sc in the calling synctest bubble and returns its
// transcript. The agent and the key oracle run without FIPS 140-only
// enforcement: they stand for the other side, not the client.
func runV3Scenario(t *testing.T, sc v3Scenario) string {
	tr := newEngineTranscript(t)
	var agent *fakeV3Agent
	fips140.WithoutEnforcement(func() { agent = newFakeV3Agent(tr, agentCreds, sysDescr) })
	agent.script = sc.script
	c := newFakeTransport(tr, func(n int, data []byte) (replies []agentReply) {
		fips140.WithoutEnforcement(func() { replies = agent.handle(n, data) })
		return replies
	})

	creds, ok := agentCreds[sc.user]
	if sc.creds != nil {
		creds, ok = *sc.creds, true
	}
	if !ok {
		t.Fatalf("no credentials for %q", sc.user)
	}
	flags := NoAuthNoPriv
	switch {
	case creds.priv > NoPriv:
		flags = AuthPriv
	case creds.auth > NoAuth:
		flags = AuthNoPriv
	}
	config := Config{
		Version:       Version3,
		SecurityLevel: flags,
		User:          creds.user(sc.user),
		Timeout:       time.Second,
		Retries:       2,
	}
	if sc.config != nil {
		sc.config(&config)
	}
	x := newEngineClientFrom(t, c, config)
	if sc.setup != nil {
		sc.setup(x)
	}
	run := sc.run
	if run == nil {
		run = func(x *Client, _ *fakeV3Agent) (*Message, error) {
			return x.Get(context.Background(), []string{engineOID})
		}
	}

	tr.addf("client: user=%q %s timeout=%s retries=%d", sc.user, describeFlags(x.config.SecurityLevel), x.config.Timeout, x.config.Retries)
	var res *Message
	var err error
	if v, _ := recoverPanic(func() { res, err = run(x, agent) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	tr.addf("client after: %s", describeEngineState(x))
	return tr.text()
}

// describeEngineState describes the client's engine state: its engine ID,
// the latest engine boots and time it received, the engine ID its keys are
// localized to and the context engine ID of its requests.
func describeEngineState(x *Client) string {
	s := &x.engine
	return fmt.Sprintf("engine=%q boots=%d time=%d keys=%s context engine=%q", s.engineID, s.clock.boots,
		s.clock.latest, describeKeys(s, &x.config.User), s.contextEngineID())
}

// describeKeys names the engine ID the keys of s, user's, are localized to:
// "current" for its own, "none" without keys.
func describeKeys(s *engineState, user *User) string {
	if len(s.keys.auth) == 0 && len(s.keys.priv) == 0 {
		return "none"
	}
	for _, id := range []string{string(s.engineID), agentEngineID, agentOtherEngineID} {
		var want usmKeys
		var err error
		fips140.WithoutEnforcement(func() { want, err = user.localize([]byte(id)) })
		if err != nil || !bytes.Equal(want.auth, s.keys.auth) || !bytes.Equal(want.priv, s.keys.priv) {
			continue
		}
		if id == string(s.engineID) {
			return "current"
		}
		return fmt.Sprintf("%q", id)
	}
	return "unknown"
}

// BenchmarkGetV3 measures one SNMPv3 authNoPriv Get through send, after
// discovery, against the fake agent; the agent's checks and answer are
// included.
func BenchmarkGetV3(b *testing.B) {
	agent := newFakeV3Agent(nil, agentCreds, sysDescr)
	c := newFakeTransport(nil, agent.handle)
	creds := agentCreds["codec-md5"]
	x := newEngineClientFrom(b, c, Config{
		Version:       Version3,
		SecurityLevel: AuthNoPriv,
		User:          creds.user("codec-md5"),
		Timeout:       time.Second,
		Retries:       2,
	})
	if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := x.Get(context.Background(), []string{engineOID}); err != nil {
			b.Fatal(err)
		}
	}
}
