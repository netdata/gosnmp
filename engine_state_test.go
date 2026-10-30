// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// engineView is what a test compares of an engine state and the exported
// fields that mirror it.
type engineView struct {
	engineID             string
	authKey, privKey     []byte
	authGiven, privGiven bool
	context              string
	// The clock, but when it was received.
	clocked                 bool
	clockBoots, clockLatest uint32
	clockSource             clockSource
	// The exported fields.
	fieldEngineID         string
	fieldAuthKey          []byte
	fieldPrivKey          []byte
	fieldContextEngineID  string
	fieldBoots, fieldTime uint32
}

func viewEngine(x *GoSNMP) engineView {
	sp := x.SecurityParameters.usm()
	return engineView{
		engineID:             x.engine.engineID,
		authKey:              x.engine.authKey,
		privKey:              x.engine.privKey,
		authGiven:            x.engine.authGiven,
		privGiven:            x.engine.privGiven,
		context:              x.engine.context,
		clocked:              x.engine.clock.known(),
		clockBoots:           x.engine.clock.boots,
		clockLatest:          x.engine.clock.latest,
		clockSource:          x.engine.clock.source,
		fieldEngineID:        sp.AuthoritativeEngineID,
		fieldAuthKey:         sp.SecretKey,
		fieldPrivKey:         sp.PrivacyKey,
		fieldContextEngineID: x.ContextEngineID,
		fieldBoots:           sp.AuthoritativeEngineBoots,
		fieldTime:            sp.AuthoritativeEngineTime,
	}
}

// stateKeys returns the SHA/AES keys of the passphrases localized to
// engineID.
func stateKeys(t *testing.T, authPass, privPass, engineID string) (authKey, privKey []byte) {
	t.Helper()
	sp := &UsmSecurityParameters{
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: authPass,
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        privPass,
		AuthoritativeEngineID:    engineID,
	}
	require.NoError(t, sp.InitSecurityKeys())
	return sp.SecretKey, sp.PrivacyKey
}

// TestEngineReconcile pins how the start of a request takes the caller's
// changes to the exported fields into the engine state (reconcileEngine): a
// field that no longer holds the state's value is the caller's, another
// SecurityParameters value is the caller's whole, a key the caller gives
// stays until the engine ID changes, the keys the client derives derive again
// for other credentials, and a key given without its passphrase serves only
// its engine ID.
func TestEngineReconcile(t *testing.T) {
	const (
		authPass, privPass = "codec-auth-pass", "codec-priv-pass"
		otherPass          = "codec-other-pass"
		thirdPass          = "codec-third-pass"
	)
	authE1, privE1 := stateKeys(t, authPass, privPass, usmCharEngineID)
	authE2, privE2 := stateKeys(t, authPass, privPass, usmOtherEngineID)
	authOther, _ := stateKeys(t, otherPass, privPass, usmCharEngineID)
	_, privOther := stateKeys(t, authPass, otherPass, usmCharEngineID)
	_, privThird := stateKeys(t, authPass, thirdPass, usmCharEngineID)

	// noClock is a view without a clock, as for an engine ID the caller
	// changed (RFC 3414 section 2.3).
	noClock := func(v engineView) engineView {
		v.clocked, v.clockBoots, v.clockLatest, v.clockSource, v.fieldBoots, v.fieldTime = false, 0, 0, 0, 0, 0
		return v
	}
	// authenticatedClock commits the clock of an authenticated message with
	// boots 7 and time 1010.
	authenticatedClock := func(x *GoSNMP, _ *UsmSecurityParameters) {
		next := x.engine
		next.clock = clockOf(7, 1010, time.Now(), fromAuthenticated)
		x.commitEngine(next)
	}

	// Each case starts from a client whose state followed its parameters
	// (SHA/AES passphrases, engine usmCharEngineID, boots 7, time 1000: the
	// caller's clock) once; each step changes the client and reconciles again.
	tests := map[string]struct {
		setup   func(x *GoSNMP, sp *UsmSecurityParameters)
		steps   []func(x *GoSNMP, sp *UsmSecurityParameters)
		want    func(v engineView) engineView // from the view after the setup
		wantErr error                         // of the last step; the state stays as before it
	}{
		"nothing changed": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(*GoSNMP, *UsmSecurityParameters) {}},
			want:  func(v engineView) engineView { return v },
		},
		"the caller's key": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.SecretKey = bytes.Clone(authOther)
			}},
			want: func(v engineView) engineView {
				v.authKey, v.authGiven, v.fieldAuthKey = authOther, true, authOther
				return v
			},
		},
		"the caller's key stays for other credentials": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.SecretKey = bytes.Clone(authOther) },
				func(_ *GoSNMP, sp *UsmSecurityParameters) {
					sp.AuthenticationPassphrase, sp.PrivacyPassphrase = thirdPass, thirdPass
				},
			},
			want: func(v engineView) engineView {
				v.authKey, v.authGiven, v.fieldAuthKey = authOther, true, authOther
				v.privKey, v.fieldPrivKey = privThird, privThird
				return v
			},
		},
		// A key equal to what its passphrase derives is the client's, however
		// it reached the field.
		"a key the passphrase derives is the client's": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.SecretKey = bytes.Clone(authOther) },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = otherPass },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = authPass },
			},
			want: func(v engineView) engineView { return v },
		},
		"keys derived into the field before the first request": {
			setup: func(_ *GoSNMP, sp *UsmSecurityParameters) { require.NoError(t, sp.InitSecurityKeys()) },
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthenticationPassphrase = otherPass
			}},
			want: func(v engineView) engineView {
				v.authKey, v.fieldAuthKey = authOther, authOther
				return v
			},
		},
		"the caller's key derives again for another engine ID": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.SecretKey = bytes.Clone(authOther) },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = usmOtherEngineID },
			},
			want: func(v engineView) engineView {
				v.engineID, v.fieldEngineID, v.fieldContextEngineID = usmOtherEngineID, usmOtherEngineID, usmOtherEngineID
				v.authKey, v.fieldAuthKey, v.privKey, v.fieldPrivKey = authE2, authE2, privE2, privE2
				return noClock(v)
			},
		},
		"an emptied key derives, and again for other credentials": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.SecretKey = bytes.Clone(authOther) },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.SecretKey = nil },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = otherPass },
			},
			want: func(v engineView) engineView {
				v.authKey, v.fieldAuthKey = authOther, authOther
				return v
			},
		},
		"another value is the caller's whole": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(x *GoSNMP, sp *UsmSecurityParameters) {
					x.SecurityParameters = sp.Copy()
					x.SecurityParameters.usm().SecretKey = bytes.Clone(authOther)
				},
				func(x *GoSNMP, _ *UsmSecurityParameters) {
					sp := x.SecurityParameters.usm()
					sp.AuthenticationPassphrase, sp.PrivacyPassphrase = thirdPass, otherPass
				},
			},
			want: func(v engineView) engineView {
				v.authKey, v.authGiven, v.fieldAuthKey = authOther, true, authOther
				v.privKey, v.fieldPrivKey = privOther, privOther
				return v
			},
		},
		// The keys of another value that its passphrases no longer derive
		// are the caller's.
		"another value's keys its passphrase does not derive": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(x *GoSNMP, sp *UsmSecurityParameters) {
					x.SecurityParameters = sp.Copy()
					x.SecurityParameters.usm().AuthenticationPassphrase = otherPass
				},
				func(x *GoSNMP, _ *UsmSecurityParameters) {
					x.SecurityParameters.usm().AuthenticationPassphrase = thirdPass
				},
			},
			want: func(v engineView) engineView {
				v.authGiven = true
				return v
			},
		},
		"a configured context engine ID stays": {
			setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.ContextEngineID = "codec-context" },
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = otherPass },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = usmOtherEngineID },
			},
			want: func(v engineView) engineView {
				authKey, privKey := stateKeys(t, otherPass, privPass, usmOtherEngineID)
				v.engineID, v.fieldEngineID = usmOtherEngineID, usmOtherEngineID
				v.authKey, v.fieldAuthKey, v.privKey, v.fieldPrivKey = authKey, authKey, privKey, privKey
				return noClock(v)
			},
		},
		"a configured context engine ID equal to the engine ID stays": {
			setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.ContextEngineID = "codec-context" },
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				func(x *GoSNMP, _ *UsmSecurityParameters) { x.ContextEngineID = usmCharEngineID },
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = usmOtherEngineID },
			},
			want: func(v engineView) engineView {
				v.engineID, v.fieldEngineID = usmOtherEngineID, usmOtherEngineID
				v.authKey, v.fieldAuthKey, v.privKey, v.fieldPrivKey = authE2, authE2, privE2, privE2
				v.context, v.fieldContextEngineID = usmCharEngineID, usmCharEngineID
				return noClock(v)
			},
		},
		"an emptied context engine ID follows the engine ID": {
			setup: func(x *GoSNMP, _ *UsmSecurityParameters) { x.ContextEngineID = "codec-context" },
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(x *GoSNMP, _ *UsmSecurityParameters) {
				x.ContextEngineID = ""
			}},
			want: func(v engineView) engineView {
				v.context, v.fieldContextEngineID = "", usmCharEngineID
				return v
			},
		},
		"keys given without an engine ID serve the first engine ID set": {
			setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				usmKeysOnly(sp, usmCharEngineID)
				sp.AuthoritativeEngineID = ""
			},
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = usmCharEngineID
			}},
			want: func(v engineView) engineView {
				v.engineID, v.fieldEngineID, v.fieldContextEngineID = usmCharEngineID, usmCharEngineID, usmCharEngineID
				return noClock(v)
			},
		},
		"keys derived without an engine ID derive again for the first one set": {
			setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = ""
				require.NoError(t, sp.InitSecurityKeys())
			},
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = usmCharEngineID
			}},
			want: func(v engineView) engineView {
				v.engineID, v.fieldEngineID, v.fieldContextEngineID = usmCharEngineID, usmCharEngineID, usmCharEngineID
				v.authKey, v.fieldAuthKey, v.privKey, v.fieldPrivKey = authE1, authE1, privE1, privE1
				v.authGiven, v.privGiven = false, false
				return noClock(v)
			},
		},
		// Boots and time are one pair, the caller's an unauthenticated clock.
		"the caller's boots and time": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				authenticatedClock,
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineTime = 5 },
			},
			want: func(v engineView) engineView {
				v.clockLatest, v.fieldTime = 5, 5
				return v
			},
		},
		"the caller's zero boots and time are no clock": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = 0, 0
			}},
			want: noClock,
		},
		"an authenticated clock stays for other credentials": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				authenticatedClock,
				func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = otherPass },
			},
			want: func(v engineView) engineView {
				v.authKey, v.fieldAuthKey = authOther, authOther
				v.clockLatest, v.clockSource, v.fieldTime = 1010, fromAuthenticated, 1010
				return v
			},
		},
		"another engine ID with the caller's boots and time": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				authenticatedClock,
				func(_ *GoSNMP, sp *UsmSecurityParameters) {
					sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = usmOtherEngineID, 9, 99
				},
			},
			want: func(v engineView) engineView {
				v.engineID, v.fieldEngineID, v.fieldContextEngineID = usmOtherEngineID, usmOtherEngineID, usmOtherEngineID
				v.authKey, v.fieldAuthKey, v.privKey, v.fieldPrivKey = authE2, authE2, privE2, privE2
				v.clockBoots, v.clockLatest, v.fieldBoots, v.fieldTime = 9, 99, 9, 99
				return v
			},
		},
		"another value's boots and time": {
			steps: []func(*GoSNMP, *UsmSecurityParameters){
				authenticatedClock,
				func(x *GoSNMP, sp *UsmSecurityParameters) { x.SecurityParameters = sp.Copy() },
			},
			want: func(v engineView) engineView {
				v.clockLatest, v.fieldTime = 1010, 1010
				return v
			},
		},
		"an authentication key without its passphrase serves its engine ID only": {
			setup: func(_ *GoSNMP, sp *UsmSecurityParameters) { usmKeysOnly(sp, usmCharEngineID) },
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = usmOtherEngineID
			}},
			wantErr: errAuthKeyBoundToEngine,
		},
		"a privacy key without its passphrase serves its engine ID only": {
			setup: func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.PrivacyKey, sp.PrivacyPassphrase = bytes.Clone(privE1), ""
			},
			steps: []func(*GoSNMP, *UsmSecurityParameters){func(_ *GoSNMP, sp *UsmSecurityParameters) {
				sp.AuthoritativeEngineID = usmOtherEngineID
			}},
			wantErr: errPrivKeyBoundToEngine,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sp := &UsmSecurityParameters{
				UserName:                 "codec-user",
				AuthenticationProtocol:   SHA,
				AuthenticationPassphrase: authPass,
				PrivacyProtocol:          AES,
				PrivacyPassphrase:        privPass,
				AuthoritativeEngineID:    usmCharEngineID,
				AuthoritativeEngineBoots: 7,
				AuthoritativeEngineTime:  1000,
			}
			x := &GoSNMP{Version: Version3, SecurityParameters: sp}
			if tc.setup != nil {
				tc.setup(x, sp)
			}
			require.NoError(t, x.reconcileEngine())
			after := viewEngine(x)
			if tc.setup == nil {
				require.Equal(t, engineView{
					engineID: usmCharEngineID, authKey: authE1, privKey: privE1, fieldEngineID: usmCharEngineID,
					clocked: true, clockBoots: 7, clockLatest: 1000, clockSource: fromUnauthenticated,
					fieldAuthKey: authE1, fieldPrivKey: privE1, fieldContextEngineID: usmCharEngineID,
					fieldBoots: 7, fieldTime: 1000,
				}, after, "the state after the first reconciliation")
			}

			var err error
			for i, step := range tc.steps {
				before := x.engine
				step(x, x.SecurityParameters.usm())
				if err = x.reconcileEngine(); err != nil {
					require.Equal(t, len(tc.steps)-1, i, "step %d failed: %v", i, err)
					assert.Equal(t, before, x.engine, "the state after a failed reconciliation")
				}
			}
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want(after), viewEngine(x))
		})
	}
}

// TestEngineMirror pins the mirror's compare-and-write: a commit writes the
// engine state into the exported fields that still hold the previous state,
// as copies of the keys, and leaves a field the caller changed since.
func TestEngineMirror(t *testing.T) {
	authE2, privE2 := stateKeys(t, "codec-auth-pass", "codec-priv-pass", usmOtherEngineID)
	newClient := func(t *testing.T) (*GoSNMP, *UsmSecurityParameters) {
		sp := &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthenticationProtocol:   SHA,
			AuthenticationPassphrase: "codec-auth-pass",
			PrivacyProtocol:          AES,
			PrivacyPassphrase:        "codec-priv-pass",
			AuthoritativeEngineID:    usmCharEngineID,
			AuthoritativeEngineBoots: 7,
			AuthoritativeEngineTime:  1000,
		}
		x := &GoSNMP{Version: Version3, SecurityParameters: sp}
		require.NoError(t, x.reconcileEngine())
		return x, sp
	}
	commitOtherEngine := func(t *testing.T, x *GoSNMP) {
		next, err := x.engine.withEngine(usmOtherEngineID)
		require.NoError(t, err)
		next.clock = clockOf(8, 5, time.Now(), fromAuthenticated)
		x.commitEngine(next)
	}

	t.Run("fields that follow the state", func(t *testing.T) {
		x, sp := newClient(t)
		commitOtherEngine(t, x)
		assert.Equal(t, []any{usmOtherEngineID, uint32(8), uint32(5), authE2, privE2, usmOtherEngineID},
			[]any{
				sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime,
				sp.SecretKey, sp.PrivacyKey, x.ContextEngineID,
			})
		sp.SecretKey[0] ^= 0xff
		sp.PrivacyKey[0] ^= 0xff
		assert.Equal(t, []any{authE2, privE2}, []any{x.engine.authKey, x.engine.privKey}, "the state's keys")
	})
	t.Run("fields the caller changed", func(t *testing.T) {
		x, sp := newClient(t)
		sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots = "codec-caller-engine", 99
		sp.SecretKey, sp.PrivacyKey = []byte("caller-auth"), []byte("caller-priv")
		x.ContextEngineID = "codec-caller-context"
		commitOtherEngine(t, x)
		assert.Equal(t, []any{
			"codec-caller-engine", uint32(99), uint32(1000), []byte("caller-auth"), []byte("caller-priv"),
			"codec-caller-context",
		}, []any{
			sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots,
			sp.AuthoritativeEngineTime, sp.SecretKey, sp.PrivacyKey, x.ContextEngineID,
		})
	})
}

// TestEngineWithEngine pins the state for another engine ID (withEngine): the
// same state for its own engine ID, an error for an empty one, keys derived
// for another one from the passphrases (the caller's keys, too, as keys the
// client derived) and no clock, and an error without a passphrase (the keys
// are bound to their engine ID).
func TestEngineWithEngine(t *testing.T) {
	authE1, privE1 := stateKeys(t, "codec-auth-pass", "codec-priv-pass", usmCharEngineID)
	authE2, privE2 := stateKeys(t, "codec-auth-pass", "codec-priv-pass", usmOtherEngineID)
	given := engineState{
		engineID:  usmCharEngineID,
		authKey:   authE1,
		privKey:   privE1,
		authGiven: true,
		privGiven: true,
		clock:     clockOf(7, 1000, time.Unix(1_000_000_000, 0), fromAuthenticated),
		cred: credentials{
			authProtocol:   SHA,
			authPassphrase: "codec-auth-pass",
			privProtocol:   AES,
			privPassphrase: "codec-priv-pass",
		},
	}
	keysOnly := given
	keysOnly.cred.authPassphrase, keysOnly.cred.privPassphrase = "", ""
	other := given
	other.engineID, other.authKey, other.privKey, other.authGiven, other.privGiven = usmOtherEngineID, authE2, privE2, false, false
	other.clock = sourcedClock{}

	tests := map[string]struct {
		state    engineState
		engineID string
		want     engineState
		wantErr  error
	}{
		"its own engine ID":            {state: given, engineID: usmCharEngineID, want: given},
		"no engine ID":                 {state: given, engineID: "", wantErr: ErrUnknownEngineID},
		"another engine ID":            {state: given, engineID: usmOtherEngineID, want: other},
		"keys without a passphrase":    {state: keysOnly, engineID: usmOtherEngineID, wantErr: errAuthKeyBoundToEngine},
		"keys only, its own engine ID": {state: keysOnly, engineID: usmCharEngineID, want: keysOnly},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			before := tc.state
			got, err := tc.state.withEngine(tc.engineID)
			assert.Equal(t, before, tc.state, "the state")
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
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
	t.Run("an equal time is no update on the trap path", func(t *testing.T) {
		got, updated := known.update(7, 1000, received.Add(time.Second), false)
		assert.Equal(t, known, got)
		assert.False(t, updated)
	})
}

// TestEngineTimeFor pins the engine boots and time an attempt carries
// (sourcedClock.timeFor): an authenticated clock's for every request, another
// clock's for read requests and requests without authentication, else zeros.
func TestEngineTimeFor(t *testing.T) {
	received := time.Unix(1_000_000_000, 0)
	now := received.Add(10 * time.Second)
	clock := func(source clockSource) sourcedClock { return clockOf(7, 1000, received, source) }
	tests := map[string]struct {
		clock sourcedClock
		flags SnmpV3MsgFlags
		pdu   PDUType
		want  [2]uint32
	}{
		"authenticated, Set":                      {clock: clock(fromAuthenticated), flags: AuthNoPriv, pdu: SetRequest, want: [2]uint32{7, 1010}},
		"authenticated, Get":                      {clock: clock(fromAuthenticated), flags: AuthPriv, pdu: GetRequest, want: [2]uint32{7, 1010}},
		"unauthenticated, Get":                    {clock: clock(fromUnauthenticated), flags: AuthNoPriv, pdu: GetRequest, want: [2]uint32{7, 1010}},
		"unauthenticated, GetNext":                {clock: clock(fromUnauthenticated), flags: AuthNoPriv, pdu: GetNextRequest, want: [2]uint32{7, 1010}},
		"unauthenticated, GetBulk":                {clock: clock(fromUnauthenticated), flags: AuthPriv, pdu: GetBulkRequest, want: [2]uint32{7, 1010}},
		"unauthenticated, Set":                    {clock: clock(fromUnauthenticated), flags: AuthNoPriv, pdu: SetRequest},
		"unauthenticated, Set, no authentication": {clock: clock(fromUnauthenticated), flags: NoAuthNoPriv, pdu: SetRequest, want: [2]uint32{7, 1010}},
		"lent by a Report, Set":                   {clock: clock(fromTimeWindowReport), flags: AuthNoPriv, pdu: SetRequest},
		"lent by a Report, Get":                   {clock: clock(fromTimeWindowReport), flags: AuthNoPriv, pdu: GetRequest, want: [2]uint32{7, 1010}},
		"no clock":                                {flags: NoAuthNoPriv, pdu: GetRequest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			boots, engineTime := tc.clock.timeFor(&SnmpPacket{MsgFlags: tc.flags, PDUType: tc.pdu}, now)
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
			e := exchange{clock: tc.clock}
			assert.Equal(t, tc.want, e.resetsClock(tc.boots, tc.engineTime, now))
		})
	}
}
