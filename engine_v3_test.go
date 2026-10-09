// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
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

// otherKey encrypts an answer with a key the client does not have.
func otherKey(p *SnmpPacket) {
	usp := p.SecurityParameters.usm()
	usp.PrivacyKey = bytes.Repeat([]byte{0x5a}, len(usp.PrivacyKey))
}

// emptyMsgFlags gives an encoded answer an empty msgFlags OCTET STRING.
func emptyMsgFlags(m *v3Message) {
	r := ber.NewReader(m.header)
	var fields [][]byte
	for r.Len() > 0 {
		tag, content, err := r.Next()
		if err != nil {
			panic(err)
		}
		fields = append(fields, tlv(tag, content))
	}
	fields[2] = tlv(byte(OctetString))
	m.header = bytes.Join(fields, nil)
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

// fromOtherEngine makes an answer come from the agent's other engine ID.
func fromOtherEngine(p *SnmpPacket) {
	p.SecurityParameters.usm().AuthoritativeEngineID = agentOtherEngineID
	p.ContextEngineID = agentOtherEngineID
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
		"answer/unauthenticated-empty-identity": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				why: "GetResponse without authentication, user name and engine ID",
				edit: func(p *SnmpPacket) {
					usp := p.SecurityParameters.usm()
					usp.UserName, usp.AuthoritativeEngineID = "", ""
				},
			}),
			knownBug: "the engine discovery exception accepts any message with an empty user name and engine ID without its digest",
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
				edit: func(p *SnmpPacket) { p.SecurityModel = 2 },
			}),
			knownBug: "a discovery Report with another security model fails the request instead of being discarded (RFC 3412 section 7.2 step 4)",
		},
		"discovery/empty-msg-flags": {
			user: "codec-md5", script: onRequest(1, agentAnswer{
				report: usmStatsUnknownEngineIDs, why: "discovery Report with an empty msgFlags", raw: emptyMsgFlags,
			}),
			knownBug: "a reply with an empty msgFlags is accepted and carries the request's flags (RFC 3412 section 6: one octet)",
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
			knownBug: "the unauthenticated unknownEngineID Report fails the digest check and is discarded, so the client never adopts the engine ID",
		},

		// The agent changes between two requests.
		"reboot": {user: "codec-sha-aes", run: getTwice(func(a *fakeV3Agent) { a.reboot() })},
		// RFC 3414 section 3.2 step 7 sends notInTimeWindow at authNoPriv and
		// takes the engine time only from authentic messages: discarding an
		// unauthenticated one conforms.
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
			knownBug: "the retransmission's error is replaced by ErrNotInTimeWindow",
		},
		"time-window/silence-over-150s": {
			user: "codec-md5", run: getAfter(200*time.Second, nil),
			knownBug: "the client sends the engine time of the last message, not the current one (RFC 3414 section 3.1 step 6 a), so a request after 150 s of silence is first answered with notInTimeWindow",
		},
		"time-window/always-not-in-time-window": {
			user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "always not in time window"}, n > 1
			},
			knownBug: "a notInTimeWindow Report answering the resynchronized retransmission is returned with a nil error",
		},
		"engine-change": {
			user: "codec-md5", run: getTwice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) }),
			knownBug: "the unauthenticated unknownEngineID Report fails the digest check and is discarded, so the client never adopts the engine ID",
		},
		"engine-change/noauth": {
			user: "codec-noauth", run: getThrice(func(a *fakeV3Agent) { a.setEngineID(agentOtherEngineID) }),
			knownBug: "the context engine ID stays the old engine's after the client adopts a new engine ID",
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
			knownBug: "the retransmission's error is replaced by ErrUnknownEngineID",
		},
		"unknown-engine-report/noauth-always": {
			user: "codec-noauth", script: func(n int, _ agentRequest) (agentAnswer, bool) {
				return agentAnswer{report: usmStatsUnknownEngineIDs, why: "always unknown engine ID, from the other engine", edit: fromOtherEngine}, n > 1
			},
			knownBug: "an unknownEngineID Report answering the retransmission is returned with a nil error",
		},
		"engine-change/sha-aes-answered-from-new-engine": {
			user: "codec-sha-aes", run: getThrice(func(a *fakeV3Agent) {
				a.setEngineID(agentOtherEngineID)
				a.script = func(n int, _ agentRequest) (agentAnswer, bool) {
					return agentAnswer{level: AuthPriv, why: "answers the old engine ID from the new one"}, n == 3
				}
			}),
			knownBug: "a GetResponse from another engine ID than the request's is accepted and its engine ID adopted (RFC 3412 section 7.2 step 12 b)",
		},
		"engine-change/md5-answered-from-new-engine": {
			user: "codec-md5", run: getThrice(func(a *fakeV3Agent) {
				a.setEngineID(agentOtherEngineID)
				a.script = func(n int, _ agentRequest) (agentAnswer, bool) {
					return agentAnswer{level: AuthNoPriv, why: "answers the old engine ID from the new one"}, n == 3
				}
			}),
			knownBug: "a GetResponse from another engine ID than the request's is accepted and its engine ID adopted (RFC 3412 section 7.2 step 12 b)",
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
			knownBug: "the unauthenticated decryptionErrors Report fails the digest check and is discarded: the caller never sees ErrDecryption",
		},
		"wrong-passphrase": {
			user: "codec-md5", creds: &agentUser{auth: MD5, authPass: "codec-wrong-pass", priv: NoPriv},
			knownBug: "the unauthenticated wrongDigest Report fails the digest check and is discarded: the caller never sees ErrWrongDigest",
		},
		"unknown-user/noauth": {user: "codec-nobody", creds: &agentUser{auth: NoAuth, priv: NoPriv}},
		"unknown-user/auth": {
			user: "codec-nobody", creds: &agentUser{auth: MD5, authPass: "codec-md5-pass", priv: NoPriv},
			knownBug: "the unauthenticated unknownUserName Report fails the digest check and is discarded: the caller never sees ErrUnknownUsername",
		},
		"unsupported-level": {
			user: "codec-md5", creds: &agentUser{auth: MD5, authPass: "codec-md5-pass", priv: AES, privPass: "codec-aes-pass"},
			knownBug: "the unauthenticated unsupportedSecLevel Report fails the digest check and is discarded",
		},

		// Answers that do not match the request.
		"answer/report-for-other-message": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report for another message",
				edit: func(p *SnmpPacket) { p.MsgID, p.RequestID = p.MsgID+100, p.RequestID+100 },
			}),
			knownBug: "a Report is mapped without checking its msgID or request ID",
		},
		"answer/wrong-msg-id": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				level: AuthNoPriv, edit: func(p *SnmpPacket) { p.MsgID += 100 }, why: "GetResponse for another message",
			}),
			knownBug: "the reply's msgID is not checked",
		},
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
			knownBug: "an authNoPriv reply to an authPriv request is accepted (RFC 3412 section 7.2 step 12 b)",
		},
		"answer/encrypted-to-authnopriv": {user: "codec-md5", script: func(n int, _ agentRequest) (agentAnswer, bool) {
			return agentAnswer{
				level: AuthNoPriv, why: "GetResponse encrypted for an authNoPriv request",
				edit: func(p *SnmpPacket) {
					usp := p.SecurityParameters.usm()
					p.MsgFlags = AuthPriv
					usp.PrivacyProtocol, usp.PrivacyKey = AES, bytes.Repeat([]byte{0x5a}, 16)
					usp.PrivacyParameters = []byte{0, 0, 0, 0, 0, 0, 0, 1}
				},
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
			knownBug: "a GetResponse in another context than the request's is accepted (RFC 3412 section 7.2 step 12 b)",
		},
		"answer/other-user/noauth": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "GetResponse for another user", edit: func(p *SnmpPacket) { p.SecurityParameters.usm().UserName = "codec-other-user" },
			}),
			knownBug: "a GetResponse for another user than the request's is accepted (RFC 3412 section 7.2 step 12 b)",
		},
		"answer/other-user/md5": {user: "codec-md5", script: onRequest(2, agentAnswer{
			level: AuthNoPriv, why: "GetResponse for another user",
			edit: func(p *SnmpPacket) { p.SecurityParameters.usm().UserName = "codec-other-user" },
		})},
		"answer/empty-msg-flags": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "GetResponse with an empty msgFlags", raw: emptyMsgFlags,
			}),
			knownBug: "a reply with an empty msgFlags is accepted and carries the request's flags (RFC 3412 section 6: one octet)",
		},
		"answer/other-security-model": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				why: "GetResponse with security model 2", edit: func(p *SnmpPacket) { p.SecurityModel = 2 },
			}),
			knownBug: "a reply with another security model is accepted, then returned together with the model mismatch error",
		},
		"answer/report-two-varbinds": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, why: "Report with two varbinds",
				edit: func(p *SnmpPacket) { p.Variables = append(p.Variables, sysDescr) },
			}),
			knownBug: "a Report with more than one varbind is returned as a successful reply",
		},
		"answer/report-two-varbinds-error-oid": {
			user: "codec-noauth", script: onRequest(2, agentAnswer{
				report: usmStatsUnknownUserNames, why: "Report with two varbinds",
				edit: func(p *SnmpPacket) { p.Variables = append(p.Variables, sysDescr) },
			}),
			knownBug: "a Report with more than one varbind is returned as a successful reply",
		},

		// Reports after the engine is known: whether their engine
		// parameters are stored.
		"report-later/md5": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				report: snmpUnknownContexts, level: AuthNoPriv, why: "authenticated unknown context Report 10 s later",
			}),
			knownBug: "the engine boots and time of an authenticated error Report are not stored (RFC 3414 section 3.2 step 7 b)",
		},
		"report-later/noauth-other-engine": {user: "codec-noauth", run: getTwice(nil), script: onRequest(3, agentAnswer{
			report: usmStatsUnknownUserNames, why: "unauthenticated Report from another engine ID 10 s later",
			edit: fromOtherEngine,
		})},

		// Authentic replies with older engine values, and forged Reports.
		"time-window/older-time": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "GetResponse with an older engine time",
				edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineTime = agentTimeBase - 100 },
			}),
			knownBug: "an authentic reply with an older engine time is adopted (RFC 3414 section 3.2 step 7 b keeps the latest)",
		},
		"time-window/older-boots": {
			user: "codec-md5", run: getTwice(nil), script: onRequest(3, agentAnswer{
				level: AuthNoPriv, why: "GetResponse with lower engine boots",
				edit: func(p *SnmpPacket) { p.SecurityParameters.usm().AuthoritativeEngineBoots = agentBoots - 1 },
			}),
			knownBug: "an authentic reply with lower engine boots is accepted and adopted (RFC 3414 section 3.2 step 7 b: outside the time window)",
		},
		"answer/forged-report/not-in-time-windows": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "Report signed with another key", edit: forgeReport,
		})},
		"answer/forged-report/unknown-user-names": {user: "codec-md5", script: onRequest(2, agentAnswer{
			report: usmStatsUnknownUserNames, level: AuthNoPriv, why: "Report signed with another key", edit: forgeReport,
		})},
		"answer/report-other-security-model": {
			user: "codec-md5", script: onRequest(2, agentAnswer{
				report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "Report with security model 2",
				edit: func(p *SnmpPacket) { p.SecurityModel = 2 },
			}),
			knownBug: "a Report with another security model is acted on, the request sent again, instead of being discarded (RFC 3412 section 7.2 step 4)",
		},
	}

	// Every Report counter after discovery, unauthenticated to a
	// noAuthNoPriv and to an authNoPriv user, and authenticated to an
	// authNoPriv user. An unauthenticated notInTimeWindow Report is
	// discarded by RFC 3414 section 3.2 step 7.
	for name, oid := range reportOIDs {
		unauth := v3Scenario{user: "codec-md5", script: onRequest(2, agentAnswer{report: oid, why: "scripted Report, unauthenticated"})}
		if oid != usmStatsNotInTimeWindows {
			unauth.knownBug = "an unauthenticated Report fails the digest check and is discarded: the caller never sees its error"
		}
		scenarios["report/md5-unauthenticated/"+name] = unauth
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

// runV3Scenario runs sc in the calling synctest bubble and returns its
// transcript. The agent and the key oracle run without FIPS 140-only
// enforcement: they stand for the other side, not the client.
func runV3Scenario(t *testing.T, sc v3Scenario) string {
	tr := newEngineTranscript()
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
	if v, _ := recoverPanic(func() { res, err = run(x, agent) }); v != nil {
		tr.addf("panic: %v", v)
	} else {
		tr.addf("result: %s", describeEngineResult(res, err))
	}
	usp := x.SecurityParameters.usm()
	tr.addf("client after: engine=%q boots=%d time=%d keys=%s context engine=%q", usp.AuthoritativeEngineID,
		usp.AuthoritativeEngineBoots, usp.AuthoritativeEngineTime, describeKeys(usp), x.ContextEngineID)
	if sc.knownBug != "" {
		tr.addf("known bug: %s", sc.knownBug)
	}
	return strings.Join(tr.lines, "\n")
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
