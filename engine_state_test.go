// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stateUser is the SHA/AES user of the engine state tests.
var stateUser = User{
	Name: "codec-user", AuthProtocol: SHA, AuthPassphrase: "codec-auth-pass",
	PrivProtocol: AES, PrivPassphrase: "codec-priv-pass",
}

// undiscovered is the engine state of u before discovery: no engine ID, and
// keys with u's protocols only.
func undiscovered(u User) engineState {
	return engineState{user: u, keys: usmKeys{authProtocol: u.AuthProtocol, privProtocol: u.PrivProtocol}}
}

// stateKeys returns u's keys localized to engineID.
func stateKeys(t *testing.T, u User, engineID string) usmKeys {
	t.Helper()
	keys, err := u.localize([]byte(engineID))
	require.NoError(t, err)
	return keys
}

// TestEngineStart pins how the start of a request takes the configuration
// into the engine state (startEngine): the first request takes the user, with
// no engine ID and keys with the user's protocols only; another user, a changed passphrase or name
// included, keeps the engine ID and clock and derives the keys again for the
// engine ID; keys that do not derive end the request and change nothing, also
// before discovery; after ForgetEngine the state starts over from the user,
// and a failed start keeps the request to forget for the next one.
func TestEngineStart(t *testing.T) {
	otherPass := stateUser
	otherPass.AuthPassphrase = "codec-other-pass"
	otherName := stateUser
	otherName.Name = "codec-other"
	noPass := stateUser
	noPass.AuthPassphrase = ""
	clock := clockOf(7, 1000, time.Unix(1_000_000_000, 0), fromAuthenticated)
	known := engineState{
		user: stateUser, engineID: []byte(usmCharEngineID), clock: clock,
		keys: stateKeys(t, stateUser, usmCharEngineID),
	}
	withUser := func(s engineState, u User) engineState {
		s.user = u
		if len(s.engineID) != 0 {
			s.keys = stateKeys(t, u, string(s.engineID))
		}
		return s
	}

	tests := map[string]struct {
		state      engineState
		user       User
		forget     bool
		want       engineState
		wantForget bool
		wantErr    string
	}{
		"the first request":    {user: stateUser, want: undiscovered(stateUser)},
		"nothing changed":      {state: known, user: stateUser, want: known},
		"a changed passphrase": {state: known, user: otherPass, want: withUser(known, otherPass)},
		"another name":         {state: known, user: otherName, want: withUser(known, otherName)},
		"keys that do not derive": {
			state: known, user: noPass, want: known,
			wantErr: "usm: no authentication key, want 20 octets",
		},
		"keys that do not derive, before discovery": {
			user: noPass, want: engineState{}, wantErr: "usm: no authentication key, want 20 octets",
		},
		"ForgetEngine":                   {state: known, user: stateUser, forget: true, want: undiscovered(stateUser)},
		"ForgetEngine and another user":  {state: known, user: otherPass, forget: true, want: undiscovered(otherPass)},
		"ForgetEngine, keys that do not": {state: known, user: noPass, forget: true, want: known, wantForget: true, wantErr: "usm: no authentication key, want 20 octets"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Version: Version3, User: tc.user, engine: tc.state, forgetEngine: tc.forget}
			err := x.startEngine()
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, x.engine, "the engine state")
			assert.Equal(t, tc.wantForget, x.forgetEngine, "forget")
		})
	}
}

// TestEngineForgetEngine pins that ForgetEngine changes no state by itself:
// a running request keeps its engine state, and the next start drops it.
func TestEngineForgetEngine(t *testing.T) {
	known := engineState{user: stateUser, engineID: []byte(usmCharEngineID), keys: stateKeys(t, stateUser, usmCharEngineID)}
	x := &Client{Version: Version3, User: stateUser, engine: known}
	x.ForgetEngine()
	assert.Equal(t, known, x.engine, "the state, before the next start")
	require.NoError(t, x.startEngine())
	assert.Equal(t, undiscovered(stateUser), x.engine, "the state after the next start")
	assert.False(t, x.forgetEngine)
}

// TestEngineWithEngine pins the state for another engine ID (withEngine): the
// same state for its own engine ID, an error for an empty one, and keys
// derived for another one with no clock; keys that do not derive are an
// error.
func TestEngineWithEngine(t *testing.T) {
	noPass := stateUser
	noPass.PrivPassphrase = ""
	given := engineState{
		user: stateUser, engineID: []byte(usmCharEngineID), keys: stateKeys(t, stateUser, usmCharEngineID),
		clock: clockOf(7, 1000, time.Unix(1_000_000_000, 0), fromAuthenticated),
	}
	other := engineState{user: stateUser, engineID: []byte(usmOtherEngineID), keys: stateKeys(t, stateUser, usmOtherEngineID)}
	noPassState := given
	noPassState.user = noPass

	tests := map[string]struct {
		state    engineState
		engineID string
		want     engineState
		wantErr  string
	}{
		"its own engine ID":       {state: given, engineID: usmCharEngineID, want: given},
		"no engine ID":            {state: given, engineID: "", wantErr: "the answer names no engine ID"},
		"another engine ID":       {state: given, engineID: usmOtherEngineID, want: other},
		"keys that do not derive": {state: noPassState, engineID: usmOtherEngineID, wantErr: "usm: no privacy key, want 16 octets"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			before := tc.state
			got, err := tc.state.withEngine([]byte(tc.engineID))
			assert.Equal(t, before, tc.state, "the state")
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestEngineSettleKeepsEngine pins why the resend after a stored Report needs
// no new engine ID or keys: settle commits a verified Report only when it
// names the request's engine ID (receiveReply), so the commit takes its clock
// and keeps the engine ID and keys.
func TestEngineSettleKeepsEngine(t *testing.T) {
	known := engineState{user: stateUser, engineID: []byte(usmCharEngineID), keys: stateKeys(t, stateUser, usmCharEngineID)}
	x := &Client{Version: Version3, User: stateUser, engine: known}
	packet := x.NewMessage(GetRequest, nil, 0, 0)
	x.engine.stamp(packet)
	report := &Message{
		Version: Version3, SecurityLevel: AuthNoPriv, PDUType: Report,
		VarBinds:           []VarBind{{Name: usmStatsNotInTimeWindows}},
		SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), AuthoritativeEngineBoots: 9, AuthoritativeEngineTime: 99},
	}
	e := exchange{x: x, packet: packet, sec: attemptSecurity{keys: known.keys}}
	out, err := e.settle(attemptOutcome{kind: attemptReply, packet: report, verified: true})
	require.NoError(t, err)
	require.True(t, out.committed)
	assert.Equal(t, [2]any{known.engineID, known.keys}, [2]any{x.engine.engineID, x.engine.keys})
	assert.Equal(t, [3]any{uint32(9), uint32(99), fromAuthenticated}, [3]any{x.engine.clock.boots, x.engine.clock.latest, x.engine.clock.source})
}

// TestEngineClockAt pins the engine boots and time a clock gives after an
// elapsed time (RFC 3414 section 2.3): past 2147483647 the time wraps and the
// boots go up by one, unless they are at 2147483647 (net-snmp's
// get_enginetime).
func TestEngineClockAt(t *testing.T) {
	received := time.Unix(1_000_000_000, 0)
	tests := map[string]struct {
		boots, latest       uint32
		elapsed             time.Duration
		wantBoots, wantTime uint32
	}{
		"just received":                 {boots: 7, latest: 1000, wantBoots: 7, wantTime: 1000},
		"whole seconds":                 {boots: 7, latest: 1000, elapsed: 10999 * time.Millisecond, wantBoots: 7, wantTime: 1010},
		"at the maximum":                {boots: 7, latest: maxEngineValue - 10, elapsed: 10 * time.Second, wantBoots: 7, wantTime: maxEngineValue},
		"past the maximum":              {boots: 7, latest: maxEngineValue - 10, elapsed: 15 * time.Second, wantBoots: 8, wantTime: 5},
		"from the maximum":              {boots: 7, latest: maxEngineValue, elapsed: time.Second, wantBoots: 8, wantTime: 1},
		"boots at the maximum stay":     {boots: maxEngineValue, latest: maxEngineValue, elapsed: 3 * time.Second, wantBoots: maxEngineValue, wantTime: 3},
		"boots below the maximum go up": {boots: maxEngineValue - 1, latest: maxEngineValue, elapsed: 3 * time.Second, wantBoots: maxEngineValue, wantTime: 3},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := engineClock{boots: tc.boots, latest: tc.latest, received: received}
			boots, engineTime := c.at(received.Add(tc.elapsed))
			assert.Equal(t, [2]uint32{tc.wantBoots, tc.wantTime}, [2]uint32{boots, engineTime})
		})
	}
}

// TestEngineClockStep7 pins RFC 3414 section 3.2 step 7 b on the engine path,
// against a clock of boots 7 and time 1000: b(1) with an equal time as an
// update (equal set, net-snmp), b(2) on the clock after b(1).
func TestEngineClockStep7(t *testing.T) {
	received := time.Unix(1_000_000_000, 0)
	known := engineClock{boots: 7, latest: 1000, received: received}
	tests := map[string]struct {
		clock             engineClock
		boots, engineTime uint32
		elapsed           time.Duration
		want              engineClock // after b(1)
		wantUpdated       bool
		wantInWindow      bool
	}{
		"first contact": {
			boots: 3, engineTime: 5, elapsed: time.Hour,
			want: engineClock{boots: 3, latest: 5, received: received.Add(time.Hour)}, wantUpdated: true, wantInWindow: true,
		},
		"first contact at the maximum boots": {
			boots: maxEngineValue, engineTime: 5,
			want: engineClock{boots: maxEngineValue, latest: 5, received: received}, wantUpdated: true,
		},
		"newer time": {
			clock: known, boots: 7, engineTime: 1001, elapsed: 200 * time.Second,
			want: engineClock{boots: 7, latest: 1001, received: received.Add(200 * time.Second)}, wantUpdated: true, wantInWindow: true,
		},
		"equal time, 200 s later": {
			clock: known, boots: 7, engineTime: 1000, elapsed: 200 * time.Second,
			want: engineClock{boots: 7, latest: 1000, received: received.Add(200 * time.Second)}, wantUpdated: true, wantInWindow: true,
		},
		"higher boots, lower time": {
			clock: known, boots: 8, engineTime: 1,
			want: engineClock{boots: 8, latest: 1, received: received}, wantUpdated: true, wantInWindow: true,
		},
		"older time within the window": {
			clock: known, boots: 7, engineTime: 900, elapsed: 50 * time.Second,
			want: known, wantInWindow: true,
		},
		"older time at the window's edge": {
			clock: known, boots: 7, engineTime: 900, elapsed: 50*time.Second + 999*time.Millisecond,
			want: known, wantInWindow: true,
		},
		"older time past the window": {
			clock: known, boots: 7, engineTime: 900, elapsed: 51 * time.Second,
			want: known,
		},
		"lower boots": {
			clock: known, boots: 6, engineTime: 5000,
			want: known,
		},
		"maximum boots": {
			clock: known, boots: maxEngineValue, engineTime: 1,
			want: engineClock{boots: maxEngineValue, latest: 1, received: received}, wantUpdated: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			now := received.Add(tc.elapsed)
			got, updated := tc.clock.update(tc.boots, tc.engineTime, now, true)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantUpdated, updated, "updated")
			assert.Equal(t, tc.wantInWindow, got.inWindow(tc.boots, tc.engineTime, now), "in the time window")
		})
	}
	t.Run("an equal time is no update for a receiver", func(t *testing.T) {
		got, updated := known.update(7, 1000, received.Add(time.Second), false)
		assert.Equal(t, known, got)
		assert.False(t, updated)
	})
}

// TestEngineTimeFor pins the engine boots and time an attempt carries
// (sourcedClock.timeFor): any known clock's, whatever its source, since every
// request is a read request; zeros without a clock.
func TestEngineTimeFor(t *testing.T) {
	received := time.Unix(1_000_000_000, 0)
	now := received.Add(10 * time.Second)
	clock := func(source clockSource) sourcedClock { return clockOf(7, 1000, received, source) }
	tests := map[string]struct {
		clock sourcedClock
		want  [2]uint32
	}{
		"authenticated":      {clock: clock(fromAuthenticated), want: [2]uint32{7, 1010}},
		"unauthenticated":    {clock: clock(fromUnauthenticated), want: [2]uint32{7, 1010}},
		"lent by a Report":   {clock: clock(fromTimeWindowReport), want: [2]uint32{7, 1010}},
		"no clock":           {},
		"no clock, a source": {clock: sourcedClock{source: fromAuthenticated}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			boots, engineTime := tc.clock.timeFor(now)
			assert.Equal(t, tc.want, [2]uint32{boots, engineTime})
		})
	}
}

// TestEngineResetsClock pins when a verified answer outside the time window
// sets the clock (exchange.resetsClock): when it answers a resend an
// unauthenticated notInTimeWindow Report lent its clock (boots 7, time 3, 10 s
// ago) to, with the lent boots and a time within 150 s of the lent time now.
func TestEngineResetsClock(t *testing.T) {
	lentAt := time.Unix(1_000_000_000, 0)
	now := lentAt.Add(10 * time.Second)
	lent := clockOf(7, 3, lentAt, fromTimeWindowReport)
	tests := map[string]struct {
		clock             sourcedClock
		boots, engineTime uint32
		want              bool
	}{
		"the lent time":            {clock: lent, boots: 7, engineTime: 13, want: true},
		"150 s ahead":              {clock: lent, boots: 7, engineTime: 163, want: true},
		"151 s ahead":              {clock: lent, boots: 7, engineTime: 164},
		"150 s behind":             {clock: clockOf(7, 300, lentAt, fromTimeWindowReport), boots: 7, engineTime: 160, want: true},
		"151 s behind":             {clock: clockOf(7, 300, lentAt, fromTimeWindowReport), boots: 7, engineTime: 159},
		"other boots":              {clock: lent, boots: 8, engineTime: 13},
		"lent by another Report":   {clock: clockOf(7, 3, lentAt, fromUnauthenticated), boots: 7, engineTime: 13},
		"the engine state's clock": {clock: clockOf(7, 3, lentAt, fromAuthenticated), boots: 7, engineTime: 13},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			e := exchange{sec: attemptSecurity{clock: tc.clock}}
			assert.Equal(t, tc.want, e.resetsClock(tc.boots, tc.engineTime, now))
		})
	}
}

// TestEngineLendClock pins the clock a resync Report lends to a resend
// (lendEngineParameters): its boots and time, unauthenticated, marked for
// resetsClock only when it is a notInTimeWindow Report; an unknownEngineIDs
// Report also lends its engine ID, as the request's engine and context engine
// ID, with keys localized to it for the user the request started with, also
// when a hook has set another User since.
func TestEngineLendClock(t *testing.T) {
	known := engineState{user: stateUser, engineID: []byte(usmCharEngineID), keys: stateKeys(t, stateUser, usmCharEngineID)}
	hookUser := stateUser
	hookUser.AuthPassphrase = "codec-other-pass"
	tests := map[string]struct {
		counter    string
		wantSource clockSource
		wantEngine string
		wantKeys   usmKeys
	}{
		"notInTimeWindow": {counter: usmStatsNotInTimeWindows, wantSource: fromTimeWindowReport, wantEngine: usmCharEngineID, wantKeys: known.keys},
		"unknownEngineIDs": {
			counter: usmStatsUnknownEngineIDs, wantSource: fromUnauthenticated, wantEngine: usmOtherEngineID,
			wantKeys: stateKeys(t, stateUser, usmOtherEngineID),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Version: Version3, User: stateUser, engine: known}
			packet := x.NewMessage(GetRequest, nil, 0, 0)
			x.engine.stamp(packet)
			x.User = hookUser
			report := &Message{
				Version: Version3, PDUType: Report, VarBinds: []VarBind{{Name: tc.counter}},
				SecurityParameters: SecurityParameters{
					AuthoritativeEngineID: []byte(usmOtherEngineID), AuthoritativeEngineBoots: 9, AuthoritativeEngineTime: 99,
				},
			}
			kind, _ := reportKindOf(report)
			before := time.Now()
			sec, err := x.lendEngineParameters(packet, report, kind, attemptSecurity{keys: known.keys})
			require.NoError(t, err)
			assert.Equal(t, [3]any{uint32(9), uint32(99), tc.wantSource}, [3]any{sec.clock.boots, sec.clock.latest, sec.clock.source})
			assert.False(t, sec.clock.received.Before(before), "received at the lend")
			assert.Equal(t, tc.wantEngine, string(packet.SecurityParameters.AuthoritativeEngineID))
			assert.Equal(t, tc.wantEngine, string(packet.ContextEngineID))
			assert.Equal(t, tc.wantKeys, sec.keys)
			assert.Equal(t, known, x.engine, "the engine state")
		})
	}
}
