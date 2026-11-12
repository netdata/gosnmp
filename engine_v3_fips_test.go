// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto/fips140"
	"maps"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
)

// v3FIPSScenarios are the scenarios of TestEngineV3FIPS140Only. A user whose
// keys FIPS 140-only mode refuses to derive, or an authPriv user, whose cipher
// it refuses, fails NewClient (TestEngineV3FIPS140OnlyNewClient); the encoder's
// own refusal is TestUSMFIPS140OnlyEncrypt's.
func v3FIPSScenarios() map[string]v3Scenario {
	return map[string]v3Scenario{
		"discovery/noauth": {user: "codec-noauth"},
		// The user's privacy protocol is one the mode refuses; a level
		// without privacy does not use it.
		"discovery/sha256-des-authnopriv": {
			user: "codec-sha256-des", config: func(c *Config) { c.SecurityLevel = AuthNoPriv },
		},
	}
}

// TestEngineV3FIPS140Only pins, when run with GODEBUG=fips140=only, what the
// request engine does in FIPS 140-only mode with the configurations NewClient
// takes there: discovery and requests without authentication, and an
// authNoPriv user whose privacy protocol the mode refuses. The agent runs
// without enforcement. testdata/engine/v3-fips.golden holds
// the transcripts; regenerate it with
// GODEBUG=fips140=only go test -run TestEngineV3FIPS140Only -update .
func TestEngineV3FIPS140Only(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	scenarios := v3FIPSScenarios()
	var results []goldenCase
	for _, name := range slices.Sorted(maps.Keys(scenarios)) {
		sc := scenarios[name]
		var dump string
		synctest.Test(t, func(t *testing.T) {
			dump = runV3Scenario(t, sc)
		})
		results = append(results, goldenCase{name: "v3-fips/" + name, dump: dump})
	}
	engineGolden.check(t, "v3-fips", results)
}

// TestEngineV3FIPS140OnlyNewClient checks that NewClient refuses, before any
// discovery, a configuration whose messages FIPS 140-only mode would refuse,
// with an error naming the field: keys that do not derive (MD5, SHA-1), at
// any level, since NewClient derives every key; and, at a level with privacy,
// a privacy cipher the mode refuses (DES, AES-CFB: every privacy protocol). A
// level without privacy takes any privacy protocol.
func TestEngineV3FIPS140OnlyNewClient(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	const (
		md5Refused  = "Config.User: crypto/md5: use of MD5 is not allowed in FIPS 140-only mode"
		sha1Refused = "Config.User: crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"
	)
	type test struct {
		level   SecurityLevel
		auth    AuthProtocol
		priv    PrivProtocol
		wantErr string // "" for a client
	}
	tests := map[string]test{
		"MD5":                      {level: AuthNoPriv, auth: MD5, wantErr: md5Refused},
		"SHA":                      {level: AuthNoPriv, auth: SHA, wantErr: sha1Refused},
		"SHA-AES":                  {level: AuthPriv, auth: SHA, priv: AES, wantErr: sha1Refused},
		"MD5 at noAuthNoPriv":      {level: NoAuthNoPriv, auth: MD5, wantErr: md5Refused},
		"SHA256":                   {level: AuthNoPriv, auth: SHA256},
		"SHA256-DES at authNoPriv": {level: AuthNoPriv, auth: SHA256, priv: DES},
	}
	for _, priv := range usmPrivProtocols[1:] {
		cipher := "AES-CFB"
		if priv == DES {
			cipher = "DES"
		}
		tests["SHA256-"+priv.String()] = test{
			level: AuthPriv, auth: SHA256, priv: priv,
			wantErr: "Config.User.PrivProtocol " + priv.String() + ": " + cipher + " is not allowed in FIPS 140-only mode",
		}
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user := User{Name: "codec-user", AuthProtocol: tc.auth, AuthPassphrase: "codec-auth-pass", PrivProtocol: tc.priv}
			if tc.priv > NoPriv {
				user.PrivPassphrase = "codec-priv-pass"
			}
			x, err := NewClient(Config{Version: Version3, SecurityLevel: tc.level, User: user, ContextName: "codec-context"})
			if tc.wantErr == "" {
				assert.NoError(t, err)
				assert.NotNil(t, x)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
			assert.Nil(t, x)
		})
	}
}
