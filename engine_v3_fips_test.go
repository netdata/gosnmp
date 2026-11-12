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
// keys FIPS 140-only mode refuses to derive fails NewClient
// (TestEngineV3FIPS140OnlyNewClient).
func v3FIPSScenarios() map[string]v3Scenario {
	return map[string]v3Scenario{
		"discovery/noauth":         {user: "codec-noauth"},
		"discovery/sha256-des":     {user: "codec-sha256-des"},
		"discovery/sha256-aes":     {user: "codec-sha256-aes"},
		"discovery/sha512-aes256c": {user: "codec-sha512-aes256c"},
	}
}

// TestEngineV3FIPS140Only pins, when run with GODEBUG=fips140=only, what the
// request engine does when FIPS 140-only mode refuses an algorithm: MD5 and
// SHA-1 for the key derivation and digests, DES and AES-CFB for privacy.
// The agent runs without enforcement. testdata/engine/v3-fips.golden holds
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

// TestEngineV3FIPS140OnlyNewClient checks that the user's keys must derive
// when NewClient makes the client, before any discovery: a refusal fails
// NewClient with an error naming the user.
func TestEngineV3FIPS140OnlyNewClient(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	tests := map[string]struct {
		auth    AuthProtocol
		priv    PrivProtocol
		wantErr string
	}{
		"MD5":     {auth: MD5, priv: NoPriv, wantErr: "Config.User: crypto/md5: use of MD5 is not allowed in FIPS 140-only mode"},
		"SHA":     {auth: SHA, priv: NoPriv, wantErr: "Config.User: crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"},
		"SHA-AES": {auth: SHA, priv: AES, wantErr: "Config.User: crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user := User{Name: "codec-user", AuthProtocol: tc.auth, AuthPassphrase: "codec-auth-pass", PrivProtocol: tc.priv}
			level := AuthNoPriv
			if tc.priv > NoPriv {
				user.PrivPassphrase, level = "codec-priv-pass", AuthPriv
			}
			x, err := NewClient(Config{Version: Version3, SecurityLevel: level, User: user, ContextName: "codec-context"})
			assert.EqualError(t, err, tc.wantErr)
			assert.Nil(t, x)
		})
	}
}
