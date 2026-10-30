// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"crypto/fips140"
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
	user   string     // the client's user, with agentCreds credentials unless creds is set
	creds  *agentUser // the client's credentials
	setup  func(x *GoSNMP, sp *UsmSecurityParameters)
	script func(n int, req agentRequest) (agentAnswer, bool)
	run    func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) // a Get of engineOID unless set
	// knownBug names the known bug the scenario pins.
	knownBug string
}

// getTwice runs a Get, then between applies a change to the agent 10 s
// later, then runs a second Get, whose result it returns.
func getTwice(between func(a *fakeV3Agent)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return getAfter(10*time.Second, between)
}

// getAfter is getTwice with the pause d between the two Gets.
func getAfter(d time.Duration, between func(a *fakeV3Agent)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(d)
		if between != nil {
			between(a)
		}
		return x.Get([]string{engineOID})
	}
}

// getThen runs a Get, then between applies a change to the agent 10 s later,
// then runs second, whose result it returns.
func getThen(between func(a *fakeV3Agent), second func(x *GoSNMP) (*SnmpPacket, error)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		between(a)
		return second(x)
	}
}

// changeThenGet runs a Get, then change, which the transcript names as what,
// on the client 10 s later, then a second Get, whose result it returns.
func changeThenGet(what string, change func(x *GoSNMP, sp *UsmSecurityParameters)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		a.tr.addf("caller %s", what)
		change(x, x.SecurityParameters.usm())
		return x.Get([]string{engineOID})
	}
}

// onFinishThenGet runs a Get whose call n of OnFinish also runs change, which
// the transcript names as what, then a second Get 10 s later, whose result it
// returns.
func onFinishThenGet(n int, what string, change func(x *GoSNMP)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		onFinish, calls := x.OnFinish, 0
		x.OnFinish = func(x *GoSNMP) {
			onFinish(x)
			if calls++; calls == n {
				a.tr.addf("hook OnFinish %s", what)
				change(x)
			}
		}
		if _, err := x.Get([]string{engineOID}); err != nil {
			return nil, fmt.Errorf("first Get: %w", err)
		}
		time.Sleep(10 * time.Second)
		return x.Get([]string{engineOID})
	}
}

// userParameters returns new security parameters with the user's agentCreds
// credentials.
func userParameters(user string) *UsmSecurityParameters {
	creds := agentCreds[user]
	return &UsmSecurityParameters{
		UserName:                 user,
		AuthenticationProtocol:   creds.auth,
		AuthenticationPassphrase: creds.authPass,
		PrivacyProtocol:          creds.priv,
		PrivacyPassphrase:        creds.privPass,
	}
}

// setEngineOID sets engineOID: a request that changes the agent.
func setEngineOID(x *GoSNMP) (*SnmpPacket, error) {
	return x.Set([]SnmpPDU{{Name: engineOID, Type: OctetString, Value: "codec"}})
}

// getThrice runs three Gets 10 s apart, applying between to the agent before
// the second; it records the second Get's result and returns the third's.
func getThrice(between func(a *fakeV3Agent)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		res, err := getTwice(between)(x, a)
		a.tr.addf("second Get: %s", describeEngineResult(res, err))
		time.Sleep(10 * time.Second)
		return x.Get([]string{engineOID})
	}
}

// getsAt runs one Get per level, 10 s apart, the client's MsgFlags set to the
// level before each: a client whose requests change level. It records each
// Get's result but the last, which it returns.
func getsAt(levels ...SnmpV3MsgFlags) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		var res *SnmpPacket
		var err error
		for i, level := range levels {
			if i > 0 {
				a.tr.addf("Get %d: %s", i, describeEngineResult(res, err))
				time.Sleep(10 * time.Second)
			}
			x.MsgFlags = level
			res, err = x.Get([]string{engineOID})
		}
		return res, err
	}
}

// otherKey encrypts an answer with a key the client does not have.
func otherKey(p *SnmpPacket) {
	usp := p.SecurityParameters.usm()
	usp.PrivacyKey = bytes.Repeat([]byte{0x5a}, len(usp.PrivacyKey))
}

// otherAuthKey signs an answer with a key the client does not have.
func otherAuthKey(p *SnmpPacket) {
	usp := p.SecurityParameters.usm()
	usp.SecretKey = bytes.Repeat([]byte{0x5a}, len(usp.SecretKey))
}

// encryptedForAuthNoPriv encrypts an authNoPriv answer, with a privacy
// protocol the user does not have.
func encryptedForAuthNoPriv(p *SnmpPacket) {
	usp := p.SecurityParameters.usm()
	p.MsgFlags = AuthPriv
	usp.PrivacyProtocol, usp.PrivacyKey = AES, bytes.Repeat([]byte{0x5a}, 16)
}

// olderBoots gives an answer engine boots lower than the agent's: an
// authentic answer outside the client's time window.
func olderBoots(p *SnmpPacket) {
	p.SecurityParameters.usm().AuthoritativeEngineBoots = agentBoots - 1
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
func forgeReport(p *SnmpPacket) {
	usp := p.SecurityParameters.usm()
	usp.SecretKey = bytes.Repeat([]byte{0x5a}, len(usp.SecretKey))
	usp.AuthoritativeEngineBoots, usp.AuthoritativeEngineTime = 99, 5
}

// asV2c turns an answer into an SNMPv2c message with the same request ID.
func asV2c(p *SnmpPacket) {
	p.Version, p.Community = Version2c, "public"
}

// withoutEngineID takes the engine ID out of an answer and its context.
func withoutEngineID(p *SnmpPacket) {
	p.SecurityParameters.usm().AuthoritativeEngineID = ""
	p.ContextEngineID = ""
}

// onLogging runs a Get with a Logger that calls do the first time it is
// given msg: user code that changes the client or panics inside the engine.
func onLogging(msg string, do func(x *GoSNMP)) func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	return func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
		done := false
		x.Logger = NewLogger(funcLogger(func(s string) {
			if s == msg && !done {
				done = true
				a.tr.addf("Logger is given %q", msg)
				do(x)
			}
		}))
		return x.Get([]string{engineOID})
	}
}

// funcLogger is a LoggerInterface that hands each line to a function.
type funcLogger func(string)

func (l funcLogger) Print(v ...any) { l(fmt.Sprint(v...)) }

func (l funcLogger) Printf(format string, v ...any) { l(fmt.Sprintf(format, v...)) }

// fromOtherEngine makes an answer come from the agent's other engine ID.
func fromOtherEngine(p *SnmpPacket) {
	p.SecurityParameters.usm().AuthoritativeEngineID = agentOtherEngineID
	p.ContextEngineID = agentOtherEngineID
}

// signedByOtherEngine makes an answer come from the agent's other engine ID,
// signed with the user's key localized to it: another agent with the same
// credentials.
func signedByOtherEngine(p *SnmpPacket) {
	fromOtherEngine(p)
	usp := p.SecurityParameters.usm()
	creds := agentCreds[usp.UserName]
	other := &UsmSecurityParameters{
		UserName:                 usp.UserName,
		AuthenticationProtocol:   creds.auth,
		AuthenticationPassphrase: creds.authPass,
		AuthoritativeEngineID:    agentOtherEngineID,
	}
	if err := other.InitSecurityKeys(); err != nil {
		panic(err)
	}
	usp.SecretKey = other.SecretKey
}

// configuredKeys gives the client the user's keys localized to engineID, as
// configured keys, and no passphrases.
func configuredKeys(engineID string) func(*GoSNMP, *UsmSecurityParameters) {
	return func(_ *GoSNMP, sp *UsmSecurityParameters) {
		creds := agentCreds[sp.UserName]
		k := &UsmSecurityParameters{
			UserName:                 sp.UserName,
			AuthenticationProtocol:   creds.auth,
			AuthenticationPassphrase: creds.authPass,
			PrivacyProtocol:          creds.priv,
			PrivacyPassphrase:        creds.privPass,
			AuthoritativeEngineID:    engineID,
		}
		if err := k.InitSecurityKeys(); err != nil {
			panic(err)
		}
		sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey = engineID, k.SecretKey, k.PrivacyKey
		sp.AuthenticationPassphrase, sp.PrivacyPassphrase = "", ""
	}
}

// otherEngineTime gives an answer engine boots and time the agent does not
// have.
func otherEngineTime(p *SnmpPacket) {
	usp := p.SecurityParameters.usm()
	usp.AuthoritativeEngineBoots, usp.AuthoritativeEngineTime = 99, 5
}

// timeJump moves the agent's engine time ten days ahead with its boots
// unchanged, leaving the client's engine time far behind.
func timeJump(a *fakeV3Agent) { a.timeBase += 886000 }

// unauthenticatedTimeWindow makes the agent answer a request outside its time
// window with a notInTimeWindow Report at noAuthNoPriv that carries its engine
// boots and time, as some devices (UniFi access points) do against RFC 3414
// section 3.2 step 7 a; edit, when set, changes each such Report.
func unauthenticatedTimeWindow(a *fakeV3Agent, edit func(*SnmpPacket)) {
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
	bad := tlv(byte(Sequence), tlv(byte(ObjectIdentifier), []byte{0x2b, 6, 1}), []byte{byte(Counter32), 5, 1})
	pdu[3] = tlv(byte(Sequence), content(pdu[3]), bad)
	scoped[2] = tlv(scoped[2][0], bytes.Join(pdu, nil))
	m.scoped = bytes.Join(scoped, nil)
}

// withoutScopedPDU encodes an answer that ends after its security parameters.
func withoutScopedPDU(m v3Message) []byte {
	var usm [][]byte
	for i, f := range m.usm {
		usm = append(usm, tlv(m.usmTags[i], f))
	}
	return tlv(byte(Sequence), tlv(byte(Integer), m.version), tlv(byte(Sequence), m.header),
		tlv(byte(OctetString), tlv(byte(Sequence), usm...)))
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
		"discovery/other-report": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnsupportedSecLevels, why: "answers discovery with another Report",
		})},
		// Discovery answered by a GetResponse, in the agent's engine and
		// context engine, and without them.
		"discovery/report-without-varbinds": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "answers discovery with a Report without varbinds",
			edit: func(p *SnmpPacket) { p.Variables = nil },
		})},
		"discovery/get-response": {user: "codec-md5", script: onRequest(1, agentAnswer{
			why: "answers discovery with a GetResponse",
		})},
		"discovery/get-response-without-engine-id": {user: "codec-md5", script: onRequest(1, agentAnswer{
			why: "answers discovery with a GetResponse without an engine ID", edit: withoutEngineID,
		})},
		"answer/unauthenticated-empty-identity": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				why: "GetResponse without authentication, user name and engine ID",
				edit: func(p *SnmpPacket) {
					usp := p.SecurityParameters.usm()
					usp.UserName, usp.AuthoritativeEngineID = "", ""
				},
			}),
		},
		"discovery/unknown-user-names-report": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownUserNames, why: "answers discovery like some devices",
		})},
		"discovery/context-engine-id-set": {user: "codec-md5", setup: func(x *GoSNMP, _ *UsmSecurityParameters) {
			x.ContextEngineID = "codec-context"
		}},
		"discovery/context-name": {user: "codec-md5", setup: func(x *GoSNMP, _ *UsmSecurityParameters) {
			x.ContextName = "codec-vrf"
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
			edit: func(p *SnmpPacket) { p.ContextEngineID = "" },
		})},
		"discovery/context-engine-id-differs": {user: "codec-md5", script: onRequest(1, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "discovery Report with another context engine ID",
			edit: func(p *SnmpPacket) { p.ContextEngineID = "codec-proxied-context" },
		})},
		"discovery/request-unanswered": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{drop: true, why: "silent after discovery"}, n > 1
		}},

		// Engine ID known in advance.
		"known-engine/time-unknown": {user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
			sp.AuthoritativeEngineID = agentEngineID
		}},
		"known-engine/time-known": {user: "codec-sha-aes", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
			sp.AuthoritativeEngineID = agentEngineID
			sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = agentBoots, agentTimeBase
		}},
		"known-engine/other-engine": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = agentOtherEngineID
			},
		},
		// Keys given without passphrases serve only the engine ID they were
		// localized to, and a reply naming another one derives none: the
		// client reads it as a client with passphrases does, so an
		// unauthenticated unknownEngineIDs Report ends the request.
		"known-engine/other-engine/keys-only": {user: "codec-sha-aes", setup: configuredKeys(agentOtherEngineID)},
		// The same holds for a forged one from another engine.
		"known-engine/keys-only/forged-report-from-other-engine": {
			user: "codec-sha-aes", setup: configuredKeys(agentEngineID),
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
		"reboot/retransmit-unanswered": {
			user: "codec-md5", run: getTwice(func(a *fakeV3Agent) {
				a.reboot()
				a.script = func(_ int, req agentRequest) (agentAnswer, bool) {
					if req.boots == a.boots {
						return agentAnswer{drop: true, why: "silent after the resynchronization"}, true
					}
					return agentAnswer{}, false
				}
			}),
		},

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
		}, func(x *GoSNMP) (*SnmpPacket, error) { return x.GetNext([]string{engineOID}) })},
		"unauthenticated-report/time-jump/getbulk": {user: "codec-md5", run: getThen(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		}, func(x *GoSNMP) (*SnmpPacket, error) { return x.GetBulk([]string{engineOID}, 0, 2) })},
		"unauthenticated-report/time-jump/set": {user: "codec-md5", run: getThen(func(a *fakeV3Agent) {
			timeJump(a)
			unauthenticatedTimeWindow(a, nil)
		}, setEngineOID)},
		"unauthenticated-report/noauth-set": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: usmStatsNotInTimeWindows, why: "not in time window", edit: func(p *SnmpPacket) {
				p.SecurityParameters.usm().AuthoritativeEngineTime += 7
			},
		}), run: func(x *GoSNMP, _ *fakeV3Agent) (*SnmpPacket, error) { return setEngineOID(x) }},
		// A notInTimeWindow Report lends its time only, not the other engine
		// ID it names.
		"unauthenticated-report/noauth-other-engine": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			report: usmStatsNotInTimeWindows, why: "not in time window, from the other engine", edit: func(p *SnmpPacket) {
				fromOtherEngine(p)
				p.SecurityParameters.usm().AuthoritativeEngineTime += 7
			},
		})},
		"reboot/set": {user: "codec-md5", run: getThen(func(a *fakeV3Agent) { a.reboot() }, setEngineOID)},
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
			edit: func(p *SnmpPacket) { p.MsgID += 100 },
		})},
		"unauthenticated-report/earlier-attempt": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			switch n {
			case 2:
				return agentAnswer{drop: true, why: "no answer"}, true
			case 3:
				return agentAnswer{
					report: usmStatsUnknownUserNames, why: "unauthenticated, with the msgID of the first attempt",
					edit: func(p *SnmpPacket) { p.MsgID-- },
				}, true
			}
			return agentAnswer{}, false
		}},
		"unauthenticated-report/unknown-engine-other-msg-id": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownEngineIDs, why: "unauthenticated, from the other engine, for another message",
			edit: func(p *SnmpPacket) {
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
			edit: func(p *SnmpPacket) { p.Variables = append(p.Variables, sysDescr) },
		})},
		"unauthenticated-report/empty": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated, no varbinds",
			edit: func(p *SnmpPacket) { p.Variables = nil },
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
			unauthenticatedTimeWindow(a, func(p *SnmpPacket) { p.RequestID = 0 })
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
		"unauthenticated-report/version-changed-by-hook": {
			user:   "codec-md5",
			script: onRequest(2, agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated"}),
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onFinish, calls := x.OnFinish, 0
				x.OnFinish = func(x *GoSNMP) {
					onFinish(x)
					if calls++; calls == 2 {
						x.Version = Version2c
						a.tr.addf("hook OnFinish sets the client's version to 2c")
					}
				}
				return x.Get([]string{engineOID})
			},
		},
		"unauthenticated-report/security-model-changed-by-hook": {
			user:   "codec-md5",
			script: onRequest(2, agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window, unauthenticated"}),
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onRecv := x.OnRecv
				x.OnRecv = func(x *GoSNMP) {
					onRecv(x)
					if a.counters[usmStatsNotInTimeWindows] == 1 && x.SecurityModel == UserSecurityModel {
						x.SecurityModel = 2
						a.tr.addf("hook OnRecv sets the client's security model to 2")
					}
				}
				return x.Get([]string{engineOID})
			},
		},
		// A Report another agent with the same credentials sent, for another
		// message or with the request's msgID, followed by two Gets.
		"answer/other-agent-report/other-message": {user: "codec-md5", run: getThrice(nil), script: onRequest(2, agentAnswer{
			report: snmpUnknownContexts, level: AuthNoPriv, why: "signed by another agent with the same credentials, for another message",
			edit: func(p *SnmpPacket) {
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
			edit: func(p *SnmpPacket) {
				p.MsgID += 100
				p.SecurityParameters.usm().AuthoritativeEngineTime += 50
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
			edit: func(p *SnmpPacket) {
				forgeReport(p)
				usp := p.SecurityParameters.usm()
				usp.UserName, usp.AuthoritativeEngineID = "", ""
			},
		})},
		// A client with authentication keys that sends at noAuthNoPriv does
		// not check the digest of an authNoPriv answer.
		"report-later/noauth-request-authenticated-report": {
			user: "codec-md5", setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.MsgFlags = NoAuthNoPriv },
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
		// A key given without a passphrase serves only the engine ID it was
		// localized to, here none: discovery cannot give the client the agent's,
		// and the request fails there, the client's engine fields unchanged.
		"empty-key/key-only-user-empty-passphrase": {
			user: "codec-md5", creds: &agentUser{auth: MD5, authPass: ""},
			setup: func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.SecretKey = bytes.Repeat([]byte{0x11}, 16) },
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

		// The client's Logger is user code that runs inside send, before the
		// negotiation.
		"hooks/logger-changes-security-model": {
			user: "codec-md5",
			run:  onLogging("SEND INIT", func(x *GoSNMP) { x.SecurityModel = 2 }),
		},
		"hooks/logger-changes-version": {
			user: "codec-md5",
			run:  onLogging("SEND INIT", func(x *GoSNMP) { x.Version = Version2c }),
		},
		// The discovery exchange's OnFinish changes the client: the request
		// keeps its retries, timeout and hooks.
		"hooks/discovery-changes-client": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{drop: true, why: "no answer"}, n == 2 || n == 3
			},
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onFinish, done := x.OnFinish, false
				x.OnFinish = func(x *GoSNMP) {
					onFinish(x)
					if !done {
						done = true
						a.tr.addf("hook OnFinish sets Retries to 0, Timeout to 5s and replaces OnSent")
						x.Retries, x.Timeout = 0, 5*time.Second
						x.OnSent = func(*GoSNMP) { a.tr.addf("hook OnSent, the replacement") }
					}
				}
				return x.Get([]string{engineOID})
			},
		},
		// The resync exchange's OnFinish changes the client before the resend.
		"hooks/resync-changes-client": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 2:
					return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}, true
				case 3:
					return agentAnswer{drop: true, why: "no answer"}, true
				}
				return agentAnswer{}, false
			},
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onFinish, calls := x.OnFinish, 0
				x.OnFinish = func(x *GoSNMP) {
					onFinish(x)
					if calls++; calls == 2 {
						a.tr.addf("hook OnFinish sets Retries to 0 and replaces OnSent")
						x.Retries = 0
						x.OnSent = func(*GoSNMP) { a.tr.addf("hook OnSent, the replacement") }
					}
				}
				return x.Get([]string{engineOID})
			},
		},
		"hooks/logger-changes-context-name": {
			user: "codec-md5",
			run:  onLogging("SEND INIT", func(x *GoSNMP) { x.ContextName = "codec-other-name" }),
		},
		// The request stays SNMPv3 when the Logger changes the client's version
		// after the negotiation; after a discovery answer without an engine ID
		// the client has no key.
		"hooks/logger-changes-version-after-negotiation": {
			user: "codec-md5",
			run:  onLogging("SEND END NEGOTIATE SECURITY PARAMS", func(x *GoSNMP) { x.Version = Version2c }),
		},
		"hooks/logger-panics-after-failed-retransmission": {
			user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 2:
					return agentAnswer{report: usmStatsNotInTimeWindows, why: "not in time window"}, true
				case 3:
					return agentAnswer{report: usmStatsUnknownUserNames, why: "unknown user"}, true
				}
				return agentAnswer{}, false
			},
			run: onLogging("ERROR out-of-time-window retransmit error: unknown username", func(*GoSNMP) {
				panic("logger failure")
			}),
			knownBug: "send recovers a panic into an error, with the result the request had when it panicked",
		},
		"hooks/onrecv-lowers-msg-flags": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, level: AuthNoPriv, why: "Report signed with another key", edit: forgeReport,
			}),
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onRecv, calls := x.OnRecv, 0
				x.OnRecv = func(x *GoSNMP) {
					onRecv(x)
					if calls++; calls == 2 {
						x.MsgFlags = NoAuthNoPriv
						a.tr.addf("hook OnRecv sets the client's msgFlags to noAuthNoPriv")
					}
				}
				return x.Get([]string{engineOID})
			},
		},
		"hooks/onfinish-changes-version": {
			user: "codec-md5",
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onFinish, calls := x.OnFinish, 0
				x.OnFinish = func(x *GoSNMP) {
					onFinish(x)
					if calls++; calls == 2 {
						x.Version = Version2c
						a.tr.addf("hook OnFinish sets the client's version to 2c")
					}
				}
				return x.Get([]string{engineOID})
			},
		},

		// send's resynchronization after a notInTimeWindow Report.
		"resync/panic-in-retransmission": {
			user:   "codec-md5",
			script: onRequest(2, agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}),
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				preSend, calls := x.PreSend, 0
				x.PreSend = func(x *GoSNMP) {
					preSend(x)
					if calls++; calls == 3 {
						a.tr.addf("hook PreSend panics in the retransmission")
						panic("hook failure")
					}
				}
				return x.Get([]string{engineOID})
			},
			knownBug: "send recovers a panic into an error, with the result the request had when it panicked",
		},
		"resync/security-model-changed-by-hook": {
			user:   "codec-md5",
			script: onRequest(2, agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}),
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onFinish, calls := x.OnFinish, 0
				x.OnFinish = func(x *GoSNMP) {
					onFinish(x)
					if calls++; calls == 2 {
						x.SecurityModel = 2
						a.tr.addf("hook OnFinish sets the client's security model to 2")
					}
				}
				return x.Get([]string{engineOID})
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
				edit: func(p *SnmpPacket) { p.RequestID += 100 },
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
						edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineTime += 7 },
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
					return agentAnswer{level: AuthNoPriv, why: "GetResponse with security model 2", raw: securityModel2}, true
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
					return agentAnswer{level: AuthNoPriv, why: "a later engine time", edit: func(p *SnmpPacket) {
						p.SecurityParameters.usm().AuthoritativeEngineTime += 7
					}}, true
				}
				return agentAnswer{}, false
			},
		},
		// Once the client has an engine ID it does not take another from an
		// unauthenticated Report (RFC 3414 section 1.5.2; net-snmp neither):
		// the request ends with ErrUnknownEngineID, and an application that
		// expects a replaced device clears the engine ID to rediscover.
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

		// The caller changes the engine fields between two requests: a change
		// applies from the next request.
		"caller/engine-id-reset": {user: "codec-md5", run: changeThenGet(
			"clears the engine ID and the context engine ID", func(x *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID, x.ContextEngineID = "", ""
			})},
		"caller/engine-id-reset/context-kept": {user: "codec-md5", run: changeThenGet(
			"clears the engine ID", func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = "" })},
		"caller/other-engine-id": {user: "codec-md5", run: changeThenGet(
			"sets the other engine ID", func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = agentOtherEngineID
			})},
		"caller/other-engine-id/keys-only": {
			user: "codec-sha-aes", setup: configuredKeys(agentEngineID), run: changeThenGet(
				"sets the other engine ID", func(_ *GoSNMP, sp *UsmSecurityParameters) {
					sp.AuthoritativeEngineID = agentOtherEngineID
				}),
		},
		// Keys given without the engine ID they were localized to cannot take
		// the one discovery finds; the caller then sets it.
		"caller/keys-only-engine-id-after-failed-discovery": {
			user: "codec-sha-aes", setup: func(x *GoSNMP, sp *UsmSecurityParameters) {
				configuredKeys(agentEngineID)(x, sp)
				sp.AuthoritativeEngineID = ""
			},
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				res, err := x.Get([]string{engineOID})
				a.tr.addf("first Get: %s", describeEngineResult(res, err))
				a.tr.addf("caller sets the engine ID the keys were localized to")
				x.SecurityParameters.usm().AuthoritativeEngineID = agentEngineID
				return x.Get([]string{engineOID})
			},
		},
		// Keys derived into the parameters before they have an engine ID are
		// localized to none: the engine ID the caller sets takes keys derived
		// for it.
		"caller/derived-keys-then-engine-id": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				if err := sp.InitSecurityKeys(); err != nil {
					panic(err)
				}
			},
			script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report without an engine ID", edit: withoutEngineID,
			}),
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				res, err := x.Get([]string{engineOID})
				a.tr.addf("first Get: %s", describeEngineResult(res, err))
				a.tr.addf("caller sets the agent's engine ID")
				x.SecurityParameters.usm().AuthoritativeEngineID = agentEngineID
				return x.Get([]string{engineOID})
			},
		},
		"caller/new-security-parameters": {user: "codec-md5", run: changeThenGet(
			"sets new security parameters", func(x *GoSNMP, _ *UsmSecurityParameters) {
				x.SecurityParameters = userParameters("codec-md5")
			})},
		"caller/changed-passphrase": {
			user: "codec-md5", run: changeThenGet(
				"changes the authentication passphrase", func(_ *GoSNMP, sp *UsmSecurityParameters) {
					sp.AuthenticationPassphrase = "codec-other-pass"
				}),
		},
		"caller/context-engine-id/engine-change/noauth": {
			user: "codec-noauth", setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.ContextEngineID = "codec-context" },
			run: getThrice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) }),
		},
		// A decode of a trap derives keys into the client's own parameters,
		// for their engine ID, here none.
		"caller/trap-decode-then-get": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			_, err := x.UnmarshalTrap([]byte{0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00}, false)
			a.tr.addf("UnmarshalTrap: %v; client keys=%s", err, describeKeys(x.SecurityParameters.usm()))
			return x.Get([]string{engineOID})
		}},
		"caller/encode-after-get/known-engine": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = agentEngineID },
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				res, err := x.Get([]string{engineOID})
				out, encErr := x.SnmpEncodePacket(GetRequest, []SnmpPDU{{Name: engineOID, Type: Null}}, 0, 0)
				a.tr.addf("SnmpEncodePacket: %d octets, error %v", len(out), encErr)
				return res, err
			},
		},

		// A hook changes the engine fields during a request: the change applies
		// from the next request.
		"hooks/discovery-onfinish-clears-engine-id": {
			user: "codec-md5", run: onFinishThenGet(1, "clears the engine ID", func(x *GoSNMP) {
				x.SecurityParameters.usm().AuthoritativeEngineID = ""
			}),
		},
		"hooks/request-onfinish-replaces-security-parameters": {
			user: "codec-md5", run: onFinishThenGet(2, "sets new security parameters", func(x *GoSNMP) {
				x.SecurityParameters = userParameters("codec-md5")
			}),
		},
		"hooks/logger-sets-context-engine-id": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			if _, err := onLogging("SEND INIT", func(x *GoSNMP) { x.ContextEngineID = "codec-context" })(x, a); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			return x.Get([]string{engineOID})
		}},

		// A GetResponse to a request without authentication naming another
		// engine ID than the request's answers nothing (RFC 3412 section 7.2
		// step 12 b): without one, and from another engine to a client given
		// keys without passphrases.
		"noauth/answer-without-engine-id": {
			user: "codec-noauth", run: getTwice(nil),
			script: onRequest(2, agentAnswer{why: "GetResponse without an engine ID", edit: withoutEngineID}),
		},
		"noauth/keys-only-answer-from-other-engine": {
			user: "codec-md5", setup: func(x *GoSNMP, sp *UsmSecurityParameters) {
				configuredKeys(agentEngineID)(x, sp)
				x.MsgFlags = NoAuthNoPriv
			},
			script: onRequest(1, agentAnswer{why: "GetResponse from the other engine", edit: fromOtherEngine}),
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
			user: "codec-md5", setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.MsgFlags = NoAuthNoPriv },
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
		"clock/no-time-check/restart-same-boots": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			a.noTimeCheck = true
			return getThrice(func(a *fakeV3Agent) { a.restartWithoutBoots() })(x, a)
		}},
		"clock/no-time-check/boots-down": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
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
					return agentAnswer{level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots}, true
				}
				return agentAnswer{}, false
			},
		},
		// A device whose engine time stands still and that checks the time of
		// requests: after 150 s of silence the client's advancing time is
		// outside its window, and its authenticated notInTimeWindow Report
		// sets the clock (one more round trip, as with net-snmp).
		"clock/frozen-time/silence-over-150s": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			a.frozen = true
			return getAfter(200*time.Second, nil)(x, a)
		}},
		// An engine at boots 2147483647 checks the time of authenticated
		// messages only (RFC 3414 section 3.2 step 7): discovery and a
		// request without authentication still work.
		"clock/noauth/engine-boots-max": {user: "codec-noauth", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			a.boots = maxEngineValue
			return getTwice(nil)(x, a)
		}},
		"clock/boots-max-after-update": {
			user: "codec-md5", run: getThrice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "GetResponse with engine boots 2147483647",
				edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineBoots = maxEngineValue },
			}),
		},
		// A client whose parameters have an authentication protocol and whose
		// requests change level: authenticated answers set the clock its
		// requests without authentication carry.
		"clock/noauth/verified-old-time": {
			user: "codec-md5", run: getsAt(AuthNoPriv, AuthNoPriv, NoAuthNoPriv), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "authNoPriv answer with an engine time 200 s old",
				edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineTime -= 200 },
			}),
		},
		"clock/noauth/authenticated-then-unauthenticated": {
			user: "codec-md5", run: getsAt(AuthNoPriv, NoAuthNoPriv, NoAuthNoPriv), script: onRequest(3, agentAnswer{
				why:  "noAuthNoPriv answer with an engine time 500 s ahead",
				edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineTime += 500 },
			}),
		},
		// Discovery's unauthenticated time is no notion step 7 checks the
		// first authenticated answer against.
		"clock/noauth/verified-after-discovery-time-ahead": {
			user: "codec-md5", run: getsAt(AuthNoPriv, NoAuthNoPriv),
			script: func(n int, _ agentRequest) (agentAnswer, bool) {
				switch n {
				case 1:
					return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unknown engine ID, an engine time 1000 s ahead", edit: func(p *SnmpPacket) {
						p.SecurityParameters.usm().AuthoritativeEngineTime += 1000
					}}, true
				case 2:
					return agentAnswer{level: AuthNoPriv, why: "authNoPriv answer"}, true
				}
				return agentAnswer{}, false
			},
		},
		"clock/set-after-authenticated-answer": {
			user: "codec-md5", run: getThen(func(*fakeV3Agent) {}, setEngineOID),
		},
		"clock/set-after-discovery": {
			user: "codec-md5", run: func(x *GoSNMP, _ *fakeV3Agent) (*SnmpPacket, error) { return setEngineOID(x) },
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
		// The caller sets the engine boots and time, with and without the
		// engine ID.
		"clock/caller-clock/known-engine": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = agentEngineID, agentBoots, agentTimeBase
			},
			run: getThen(func(*fakeV3Agent) {}, setEngineOID),
		},
		"clock/caller-clock/known-engine/set-first": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = agentEngineID, agentBoots, agentTimeBase
			},
			run: func(x *GoSNMP, _ *fakeV3Agent) (*SnmpPacket, error) { return setEngineOID(x) },
		},
		"clock/caller-clock/no-engine-id": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = agentBoots, agentTimeBase-500
			},
		},
		// Two authenticated notInTimeWindow Reports with other engine times,
		// to the request and to its resend.
		"clock/second-resync-report-other-time": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				if n < 2 {
					return agentAnswer{}, false
				}
				ahead := uint32(50 * (n - 1)) //nolint:gosec // a small request count
				return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window", edit: func(p *SnmpPacket) {
					p.SecurityParameters.usm().AuthoritativeEngineTime += ahead
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
				edit: func(p *SnmpPacket) { p.MsgID, p.RequestID = p.MsgID+100, p.RequestID+100 },
			}),
		},
		"answer/wrong-msg-id": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, edit: func(p *SnmpPacket) { p.MsgID += 100 }, why: "GetResponse for another message",
			}),
		},
		"answer/empty-other-message": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "empty GetResponse for another message",
			edit: func(p *SnmpPacket) {
				p.Variables = nil
				p.MsgID += 100
			},
		})},
		"answer/wrong-request-id": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, edit: func(p *SnmpPacket) { p.RequestID += 100 }, why: "GetResponse for another request",
		})},
		"answer/unauthenticated": {user: "codec-md5", script: onRequest(2, agentAnswer{
			why: "GetResponse without authentication",
		})},
		"answer/not-encrypted": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, why: "GetResponse without encryption",
			}),
		},
		"answer/encrypted-to-authnopriv": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "GetResponse encrypted for an authNoPriv request", edit: encryptedForAuthNoPriv,
			}, n > 1
		}},
		"answer/encrypted-with-other-key": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			level: AuthPriv, why: "GetResponse encrypted with another key", edit: otherKey,
		})},
		// The final error comes from decoding the wrong plaintext, so it
		// changes with the salts and keys.
		"answer/always-encrypted-with-other-key": {user: "codec-sha-aes", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{level: AuthPriv, why: "GetResponse encrypted with another key", edit: otherKey}, n > 1
		}},
		"answer/other-context": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, why: "GetResponse in another context",
				edit: func(p *SnmpPacket) { p.ContextEngineID, p.ContextName = "codec-other-context", "codec-other-name" },
			}),
		},
		"answer/other-user/noauth": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "GetResponse for another user", edit: func(p *SnmpPacket) { p.SecurityParameters.usm().UserName = "codec-other-user" },
			}),
		},
		"answer/other-user/md5": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse for another user",
			edit: func(p *SnmpPacket) { p.SecurityParameters.usm().UserName = "codec-other-user" },
		})},
		"answer/empty-msg-flags": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "GetResponse with an empty msgFlags", raw: msgFlagsOctets(),
			}),
		},
		"answer/other-version/noauth": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{why: "SNMPv2c GetResponse", edit: asV2c}),
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
		"answer/reflected-request/md5-set": {
			user: "codec-md5", script: onRequest(2, agentAnswer{reflect: true, why: "the request sent back"}),
			run: func(x *GoSNMP, _ *fakeV3Agent) (*SnmpPacket, error) { return setEngineOID(x) },
		},
		"answer/reflected-request/sha-aes-set": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{reflect: true, why: "the request sent back"}),
			run: func(x *GoSNMP, _ *fakeV3Agent) (*SnmpPacket, error) { return setEngineOID(x) },
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
			user: "codec-md5", script: onRequest(2, agentAnswer{level: AuthNoPriv, why: "SNMPv2c GetResponse", edit: asV2c}),
		},
		"answer/other-version/sha-aes": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{level: AuthPriv, why: "SNMPv2c GetResponse", edit: asV2c}),
		},
		"hooks/privacy-protocol-changed-on-retry": {
			user: "codec-sha-aes", script: onRequest(2, agentAnswer{drop: true, why: "no answer"}),
			setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.Retries = 1 },
			run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
				onRetry := x.OnRetry
				x.OnRetry = func(x *GoSNMP) {
					onRetry(x)
					x.SecurityParameters.usm().PrivacyProtocol = DES
					a.tr.addf("hook OnRetry sets the client's privacy protocol to DES")
				}
				return x.Get([]string{engineOID})
			},
		},
		"answer/other-security-model": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "GetResponse with security model 2", raw: securityModel2,
			}),
		},
		// A Report carries one varbind (RFC 3412 section 7.1 step 3 d): one with
		// two, or none, is classified by its first, as net-snmp does.
		"answer/report-two-varbinds": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, why: "Report with two varbinds",
				edit: func(p *SnmpPacket) { p.Variables = append(p.Variables, sysDescr) },
			}),
		},
		"answer/report-two-varbinds-error-oid": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report with two varbinds",
				edit: func(p *SnmpPacket) { p.Variables = append(p.Variables, sysDescr) },
			}),
		},
		"answer/report-unknown-first-varbind": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, why: "Report whose first varbind is not a counter",
				edit: func(p *SnmpPacket) { p.Variables = append([]SnmpPDU{sysDescr}, p.Variables...) },
			}),
		},
		"answer/report-without-varbinds": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report without varbinds",
				edit: func(p *SnmpPacket) { p.Variables = nil },
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
				level: AuthNoPriv, why: "GetResponse with an older engine time",
				edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineTime = agentTimeBase - 100 },
			}),
		},
		"time-window/older-boots": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots,
			}),
		},
		// Every attempt answered outside the time window: the request ends
		// with an error that matches ErrNotInTimeWindow, without OnFinish,
		// and the client drops its engine time.
		"time-window/older-boots-every-attempt": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots}, n > 2
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
			level: AuthNoPriv, why: "GetResponse with an empty msgFlags", raw: msgFlagsOctets(), then: true,
		})},
		"discard/other-user-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse for another user", then: true,
			edit: func(p *SnmpPacket) { p.SecurityParameters.usm().UserName = "codec-other-user" },
		})},
		"discard/wrong-digest-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse signed with another key", edit: otherAuthKey, then: true,
		})},
		"discard/unsupported-level-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse encrypted for an authNoPriv request", edit: encryptedForAuthNoPriv, then: true,
		})},
		"discard/decryption-then-answer": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			level: AuthPriv, why: "GetResponse encrypted with another key", edit: otherKey, then: true,
		})},
		"discard/unauthenticated-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			why: "GetResponse without authentication", then: true,
		})},
		"discard/not-in-time-window-then-answer": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots, then: true,
			}),
		},
		// Every attempt answered with lower boots, then a datagram that does
		// not decode: the request's error is the time window's.
		"discard/not-in-time-window-then-noise": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots, noise: garbage}, n > 2
			},
		},
		// Every attempt answered with lower boots, then for the same message
		// signed with another key: the request's error is the time window's.
		"discard/not-in-time-window-then-wrong-digest": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{
					level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots,
					also: &agentAnswer{level: AuthNoPriv, why: "GetResponse signed with another key", edit: otherAuthKey},
				}, n > 2
			},
		},
		// Every attempt answered for another message, signed with another key:
		// nothing answers the request.
		"discard/other-message-wrong-digest": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "GetResponse for another message, signed with another key",
				edit: func(p *SnmpPacket) { otherAuthKey(p); p.MsgID += 100 },
			}, n > 1
		}},
		// GetResponses with the request's msgID that differ from the request
		// in one field RFC 3412 section 7.2 step 12 b compares, each followed
		// by the agent's answer.
		"discard/not-encrypted-then-answer": {user: "codec-sha-aes", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse without encryption", then: true,
		})},
		"discard/authenticated-to-noauth-then-answer": {
			user: "codec-md5", setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.MsgFlags = NoAuthNoPriv },
			script: onRequest(2, agentAnswer{level: AuthNoPriv, why: "authNoPriv GetResponse", then: true}),
		},
		"discard/other-engine-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			why: "GetResponse naming the other engine ID", then: true,
			edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineID = agentOtherEngineID },
		})},
		"discard/other-context-engine-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse with another context engine ID", then: true,
			edit: func(p *SnmpPacket) { p.ContextEngineID = "codec-other-context" },
		})},
		"discard/other-context-name-then-answer": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse with another context name", then: true,
			edit: func(p *SnmpPacket) { p.ContextName = "codec-other-name" },
		})},
		"discard/empty-user-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			why: "GetResponse without a user name", then: true,
			edit: func(p *SnmpPacket) { p.SecurityParameters.usm().UserName = "" },
		})},
		"discard/other-version-then-answer": {user: "codec-noauth", script: onRequest(2, agentAnswer{
			why: "SNMPv2c GetResponse", edit: asV2c, then: true,
		})},
		// The first attempt is lost; the second is answered with its msgID and
		// the first attempt's request ID, then by the agent.
		"discard/other-attempt-request-id-then-answer": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			switch n {
			case 2:
				return agentAnswer{drop: true, why: "lost"}, true
			case 3:
				return agentAnswer{
					level: AuthNoPriv, why: "GetResponse with the first attempt's request ID", then: true,
					edit: func(p *SnmpPacket) { p.RequestID-- },
				}, true
			}
			return agentAnswer{}, false
		}},
		// Every attempt answered with lower boots, then the request sent back
		// unchanged: the request's error is the time window's.
		"discard/not-in-time-window-then-reflected": {
			user: "codec-md5", run: getTwice(nil), script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{
					level: AuthNoPriv, why: "GetResponse with lower engine boots", edit: olderBoots,
					also: &agentAnswer{reflect: true, why: "the request sent back"},
				}, n > 2
			},
		},
		// A Context deadline ends the second Get, whose answers come from an
		// agent that restarted without raising its boots and does not check
		// the time window.
		"clock/no-time-check/restart-same-boots/context-deadline": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			a.noTimeCheck = true
			if _, err := x.Get([]string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			a.restartWithoutBoots()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			x.Context = ctx
			res, err := x.Get([]string{engineOID})
			a.tr.addf("second Get, with a Context deadline after 1.5 s: %s", describeEngineResult(res, err))
			time.Sleep(10 * time.Second)
			x.Context = context.Background()
			return x.Get([]string{engineOID})
		}},
		// The Context's deadline passes while OnRetry runs after the second
		// Get's first attempt discarded the answer of an agent that restarted
		// without raising its boots and does not check the time window: the
		// next attempt does not start.
		"clock/no-time-check/restart-same-boots/context-deadline-in-retry": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			a.noTimeCheck = true
			if _, err := x.Get([]string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			a.restartWithoutBoots()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			x.Context = ctx
			onRetry := x.OnRetry
			x.OnRetry = func(x *GoSNMP) {
				onRetry(x)
				a.tr.addf("hook OnRetry waits 1 s")
				time.Sleep(time.Second)
			}
			res, err := x.Get([]string{engineOID})
			a.tr.addf("second Get, with a Context deadline after 1.5 s: %s", describeEngineResult(res, err))
			time.Sleep(10 * time.Second)
			x.Context, x.OnRetry = context.Background(), onRetry
			return x.Get([]string{engineOID})
		}},
		// Close ends the second Get once it has read the answer of an agent
		// that restarted without raising its boots and does not check the
		// time window.
		"clock/no-time-check/restart-same-boots/closed": {user: "codec-md5", run: func(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
			a.noTimeCheck = true
			if _, err := x.Get([]string{engineOID}); err != nil {
				return nil, fmt.Errorf("first Get: %w", err)
			}
			time.Sleep(10 * time.Second)
			a.restartWithoutBoots()
			onRecv := x.OnRecv
			x.OnRecv = func(x *GoSNMP) {
				onRecv(x)
				a.tr.addf("hook OnRecv closes the client")
				_ = x.Close()
			}
			return x.Get([]string{engineOID})
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
// SNMPv3 agent, known bugs included: engine discovery, the request at each
// security level, an agent that reboots or changes its engine ID, each
// Report counter, and answers that do not match the request.
// testdata/engine/v3.golden holds the transcripts.
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
	x := newEngineClientFrom(t, nil, fakePacketTransport{c}, &GoSNMP{
		Version:       Version3,
		MsgFlags:      AuthNoPriv,
		SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{
			UserName:                 "codec-md5",
			AuthenticationProtocol:   creds.auth,
			AuthenticationPassphrase: creds.authPass,
		},
		Timeout: time.Second,
		Retries: 2,
	})
	for range 60 {
		if _, err := x.Get([]string{engineOID}); err != nil {
			tr.addf("Get: %v", err)
		}
		time.Sleep(10 * time.Second)
	}
	usp := x.SecurityParameters.usm()
	tr.addf("client after: boots=%d time=%d", usp.AuthoritativeEngineBoots, usp.AuthoritativeEngineTime)
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
		if msg.pdu.PDUType == Report && len(msg.pdu.Variables) == 1 {
			pdu += " " + msg.pdu.Variables[0].Name
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
	sp := &UsmSecurityParameters{
		UserName:                 sc.user,
		AuthenticationProtocol:   creds.auth,
		AuthenticationPassphrase: creds.authPass,
		PrivacyProtocol:          creds.priv,
		PrivacyPassphrase:        creds.privPass,
	}
	flags := NoAuthNoPriv
	switch {
	case creds.priv > NoPriv:
		flags = AuthPriv
	case creds.auth > NoAuth:
		flags = AuthNoPriv
	}
	x := &GoSNMP{
		Version:            Version3,
		MsgFlags:           flags,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		Timeout:            time.Second,
		Retries:            2,
	}
	if sc.setup != nil {
		sc.setup(x, sp)
	}
	x = newEngineClientFrom(t, tr, fakePacketTransport{c}, x)
	run := sc.run
	if run == nil {
		run = func(x *GoSNMP, _ *fakeV3Agent) (*SnmpPacket, error) { return x.Get([]string{engineOID}) }
	}

	tr.addf("client: user=%q %s timeout=%s retries=%d", sc.user, describeFlags(x.MsgFlags), x.Timeout, x.Retries)
	var res *SnmpPacket
	var err error
	before := configOf(x)
	if v, _ := recoverPanic(func() { res, err = run(x, agent) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	tr.addConfigChanges(before, x)
	usp := x.SecurityParameters.usm()
	tr.addf("client after: engine=%q boots=%d time=%d keys=%s context engine=%q", usp.AuthoritativeEngineID,
		usp.AuthoritativeEngineBoots, usp.AuthoritativeEngineTime, describeKeys(usp), x.ContextEngineID)
	if sc.knownBug != "" {
		tr.addf("known bug: %s", sc.knownBug)
	}
	return tr.text()
}

// describeKeys names the engine ID the keys of sp are localized to: "current"
// for its own, "none" without keys.
func describeKeys(sp *UsmSecurityParameters) string {
	if len(sp.SecretKey) == 0 && len(sp.PrivacyKey) == 0 {
		return "none"
	}
	for _, id := range []string{sp.AuthoritativeEngineID, agentEngineID, agentOtherEngineID} {
		want := &UsmSecurityParameters{
			UserName:                 sp.UserName,
			AuthenticationProtocol:   sp.AuthenticationProtocol,
			AuthenticationPassphrase: sp.AuthenticationPassphrase,
			PrivacyProtocol:          sp.PrivacyProtocol,
			PrivacyPassphrase:        sp.PrivacyPassphrase,
			AuthoritativeEngineID:    id,
		}
		var err error
		fips140.WithoutEnforcement(func() { err = want.InitSecurityKeys() })
		if err != nil || !bytes.Equal(want.SecretKey, sp.SecretKey) ||
			!bytes.Equal(want.PrivacyKey, sp.PrivacyKey) {
			continue
		}
		if id == sp.AuthoritativeEngineID {
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
	x := newEngineClientFrom(b, nil, fakePacketTransport{c}, &GoSNMP{
		Version:       Version3,
		MsgFlags:      AuthNoPriv,
		SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{
			UserName:                 "codec-md5",
			AuthenticationProtocol:   creds.auth,
			AuthenticationPassphrase: creds.authPass,
		},
		Timeout: time.Second,
		Retries: 2,
	})
	if _, err := x.Get([]string{engineOID}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := x.Get([]string{engineOID}); err != nil {
			b.Fatal(err)
		}
	}
}
