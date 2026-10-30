// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEngineV3MaximumBoots checks that clock recovery cannot admit exhausted
// boots, while the highest usable boots and lower-boots recovery still work.
// Every reply traverses encoding, authentication, matching and settlement.
func TestEngineV3MaximumBoots(t *testing.T) {
	for _, path := range []string{"response", "authenticated-report", "lent-clock-response"} {
		for _, boots := range []struct {
			name  string
			value uint32
		}{
			{name: "lower", value: agentBoots - 1},
			{name: "highest-usable", value: maxEngineValue - 1},
			{name: "exhausted", value: maxEngineValue},
		} {
			t.Run(path+"/"+boots.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					tr := newEngineTranscript(t)
					a := newFakeV3Agent(tr, agentCreds, sysDescr)
					c := newFakeTransport(tr, a.handle)
					sp := userParameters("codec-md5")
					sp.AuthoritativeEngineID = agentEngineID
					x := newEngineClientFrom(t, tr, fakePacketTransport{c}, &GoSNMP{
						Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel,
						SecurityParameters: sp, Timeout: time.Second, Retries: 1,
					})
					_, err := x.Get([]string{engineOID})
					require.NoError(t, err)
					before := sp.Copy().usm()
					before.SecretKey = bytes.Clone(sp.SecretKey)
					beforeContext := x.ContextEngineID

					a.boots = boots.value
					switch path {
					case "response":
						a.noTimeCheck = true
					case "authenticated-report":
						if boots.value == maxEngineValue {
							// An exhausted authoritative engine always reports a
							// time-window error (RFC 3414 section 3.2 step 7 a).
							a.script = func(int, agentRequest) (agentAnswer, bool) {
								return agentAnswer{
									report: usmStatsNotInTimeWindows, level: AuthNoPriv,
									why: "engine boots exhausted",
								}, true
							}
						}
					case "lent-clock-response":
						// This defective peer reports without authentication and
						// returns data once the lent boots and time match its own.
						a.noTimeCheck = true
						unauthenticatedTimeWindow(a, nil)
					}

					finished := 0
					x.OnFinish = func(x *GoSNMP) {
						finished++
						assert.NotEqual(t, uint32(maxEngineValue), x.SecurityParameters.usm().AuthoritativeEngineBoots,
							"an exhausted clock must never be committed")
					}
					result, err := x.Get([]string{engineOID})
					wantFailure := boots.value == maxEngineValue || path == "response" && boots.value < agentBoots
					if wantFailure {
						assert.ErrorIs(t, err, ErrNotInTimeWindow)
						assert.Nil(t, result, "a rejected reply must not be returned as an admitted Report or Response")
						wantFinished := 0
						if path == "lent-clock-response" {
							wantFinished = 1 // the unauthenticated Report, before the rejected resend
						}
						assert.Equal(t, wantFinished, finished)
						assert.Zero(t, sp.AuthoritativeEngineBoots)
						assert.Zero(t, sp.AuthoritativeEngineTime)
						assert.False(t, x.engine.clock.known())
					} else {
						require.NoError(t, err)
						require.NotNil(t, result)
						assert.Equal(t, GetResponse, result.PDUType)
						assert.Equal(t, boots.value, sp.AuthoritativeEngineBoots)
						assert.Equal(t, fromAuthenticated, x.engine.clock.source)
						wantFinished := 1
						if path != "response" {
							wantFinished = 2 // Report and successful resend
						}
						assert.Equal(t, wantFinished, finished)
					}
					assert.Equal(t, before.AuthoritativeEngineID, sp.AuthoritativeEngineID)
					assert.Equal(t, before.SecretKey, sp.SecretKey)
					assert.Equal(t, beforeContext, x.ContextEngineID)
				})
			})
		}
	}
}
