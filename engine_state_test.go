// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"testing"

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

	// Each case starts from a client whose state followed its parameters
	// (SHA/AES passphrases, engine usmCharEngineID, boots 7, time 1000) once;
	// each step changes the client and reconciles again.
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
				return v
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
				return v
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
				return v
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
		next.boots, next.engineTime = 8, 5
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
// client derived), and none without a passphrase (H24).
func TestEngineWithEngine(t *testing.T) {
	authE1, privE1 := stateKeys(t, "codec-auth-pass", "codec-priv-pass", usmCharEngineID)
	authE2, privE2 := stateKeys(t, "codec-auth-pass", "codec-priv-pass", usmOtherEngineID)
	given := engineState{
		engineID:  usmCharEngineID,
		authKey:   authE1,
		privKey:   privE1,
		authGiven: true,
		privGiven: true,
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
