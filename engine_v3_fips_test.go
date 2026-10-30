// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto/fips140"
	"io"
	"maps"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getFirstOf2 runs two Gets, records the first one's result and returns the
// second's.
func getFirstOf2(x *GoSNMP, a *fakeV3Agent) (*SnmpPacket, error) {
	res, err := x.Get([]string{engineOID})
	a.tr.addf("first Get: %s", describeEngineResult(res, err))
	return x.Get([]string{engineOID})
}

// v3FIPSScenarios are the scenarios of TestEngineV3FIPS140Only.
func v3FIPSScenarios() map[string]v3Scenario {
	return map[string]v3Scenario{
		"discovery/noauth": {user: "codec-noauth"},
		// A refused key derivation ends each request before discovery: no
		// traffic, nothing learned.
		"discovery/md5":            {user: "codec-md5", run: getFirstOf2},
		"discovery/sha-aes":        {user: "codec-sha-aes", run: getFirstOf2},
		"discovery/sha256-des":     {user: "codec-sha256-des"},
		"discovery/sha256-aes":     {user: "codec-sha256-aes"},
		"discovery/sha512-aes256c": {user: "codec-sha512-aes256c"},
		// A refused key derivation for a given engine ID ends the request.
		"known-engine/md5": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = agentEngineID },
		},
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

// TestEngineV3FIPS140OnlyDiscoveryPreflight checks that passphrase-backed
// keys must derive before discovery, even when the caller supplied keys.
// A refusal sends nothing and leaves the configuration and state unchanged.
func TestEngineV3FIPS140OnlyDiscoveryPreflight(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	tests := []struct {
		name        string
		auth        SnmpV3AuthProtocol
		priv        SnmpV3PrivProtocol
		authKeyOnly bool
		wantErr     string
	}{
		{
			name: "MD5", auth: MD5, priv: NoPriv,
			wantErr: "crypto/md5: use of MD5 is not allowed in FIPS 140-only mode",
		},
		{
			name: "SHA", auth: SHA, priv: NoPriv,
			wantErr: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode",
		},
		{
			name: "SHA-AES", auth: SHA, priv: AES,
			wantErr: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode",
		},
		{
			name: "SHA-AES/privacy-only-passphrase", auth: SHA, priv: AES, authKeyOnly: true,
			wantErr: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode",
		},
	}
	keySets := []struct {
		name       string
		auth, priv bool
	}{
		{name: "missing"},
		{name: "authentication", auth: true},
		{name: "privacy", priv: true},
		{name: "both", auth: true, priv: true},
	}
	for _, tc := range tests {
		for _, keys := range keySets {
			if tc.priv == NoPriv && keys.priv || tc.authKeyOnly && !keys.auth {
				continue
			}
			t.Run(tc.name+"/"+keys.name, func(t *testing.T) {
				sp := &UsmSecurityParameters{
					UserName:                 "codec-user",
					AuthenticationProtocol:   tc.auth,
					AuthenticationPassphrase: "codec-auth-pass",
					PrivacyProtocol:          tc.priv,
				}
				if tc.priv > NoPriv {
					sp.PrivacyPassphrase = "codec-priv-pass"
				}
				fips140.WithoutEnforcement(func() { require.NoError(t, sp.InitSecurityKeys()) })
				if !keys.auth {
					sp.SecretKey = nil
				}
				if !keys.priv {
					sp.PrivacyKey = nil
				}
				if tc.authKeyOnly {
					sp.AuthenticationPassphrase = ""
				}

				tr := newEngineTranscript(t)
				c := newFakeTransport(tr, nil)
				c.failRead = func(int) error { return io.EOF }
				flags := AuthNoPriv
				if tc.priv > NoPriv {
					flags = AuthPriv
				}
				x := newEngineClientFrom(t, tr, fakePacketTransport{c}, &GoSNMP{
					Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel,
					SecurityParameters: sp, ContextEngineID: "codec-context", Timeout: time.Second, Retries: 2,
				})
				before := sp.Copy().usm()
				before.SecretKey, before.PrivacyKey = slices.Clone(sp.SecretKey), slices.Clone(sp.PrivacyKey)
				for range 2 {
					_, err := x.Get([]string{engineOID})
					assert.EqualError(t, err, tc.wantErr)
					assert.Zero(t, c.writes, "discovery must not be sent")
					assert.Zero(t, c.reads)
					assert.Equal(t, before, sp.Copy(), "the configured keys must be preserved")
					assert.Equal(t, engineState{}, x.engine)
					assert.Equal(t, "codec-context", x.ContextEngineID)
				}
			})
		}
	}
}
