// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
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
					x := newEngineClientFrom(t, c, Config{
						Version: Version3, SecurityLevel: AuthNoPriv,
						User: agentUserOf("codec-md5"), Timeout: time.Second, Retries: 1,
					})
					seedEngine(agentEngineID, 0, 0)(x)
					_, err := x.Get(context.Background(), []string{engineOID})
					require.NoError(t, err)
					beforeEngineID := bytes.Clone(x.engine.engineID)
					beforeKey := bytes.Clone(x.engine.keys.auth)
					beforeContext := bytes.Clone(x.engine.contextEngineID())

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

					// Each attempt's write follows the commits before it.
					c.afterWrite = func(int) {
						assert.NotEqual(t, uint32(maxEngineValue), x.engine.clock.boots,
							"an exhausted clock must never be committed")
					}
					result, err := x.Get(context.Background(), []string{engineOID})
					wantFailure := boots.value == maxEngineValue || path == "response" && boots.value < agentBoots
					if wantFailure {
						assert.ErrorIs(t, err, ErrNotInTimeWindow)
						assert.Nil(t, result, "a rejected reply must not be returned as an admitted Report or Response")
						assert.Zero(t, x.engine.clock.boots)
						assert.Zero(t, x.engine.clock.latest)
						assert.False(t, x.engine.clock.known())
					} else {
						require.NoError(t, err)
						require.NotNil(t, result)
						assert.Equal(t, Response, result.PDUType)
						assert.Equal(t, boots.value, x.engine.clock.boots)
						assert.Equal(t, fromAuthenticated, x.engine.clock.source)
					}
					assert.Equal(t, beforeEngineID, x.engine.engineID)
					assert.Equal(t, beforeKey, x.engine.keys.auth)
					assert.Equal(t, beforeContext, x.engine.contextEngineID())
				})
			})
		}
	}
}
