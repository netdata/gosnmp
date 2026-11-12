// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"crypto/fips140"
	"io"
	"maps"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

// getFirstOf2 runs two Gets, records the first one's result and returns the
// second's.
func getFirstOf2(x *Client, a *fakeV3Agent) (*Message, error) {
	res, err := x.Get(context.Background(), []string{engineOID})
	a.tr.addf("first Get: %s", describeEngineResult(res, err))
	return x.Get(context.Background(), []string{engineOID})
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

// TestEngineV3FIPS140OnlyDiscoveryPreflight checks that the user's keys must
// derive before discovery, and before EncodeMessage encodes a message. A
// refusal sends nothing, returns no message and leaves the configuration and
// state unchanged.
func TestEngineV3FIPS140OnlyDiscoveryPreflight(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	tests := map[string]struct {
		auth    AuthProtocol
		priv    PrivProtocol
		wantErr string
	}{
		"MD5":     {auth: MD5, priv: NoPriv, wantErr: "crypto/md5: use of MD5 is not allowed in FIPS 140-only mode"},
		"SHA":     {auth: SHA, priv: NoPriv, wantErr: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"},
		"SHA-AES": {auth: SHA, priv: AES, wantErr: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user := User{Name: "codec-user", AuthProtocol: tc.auth, AuthPassphrase: "codec-auth-pass", PrivProtocol: tc.priv}
			if tc.priv > NoPriv {
				user.PrivPassphrase = "codec-priv-pass"
			}

			tr := newEngineTranscript(t)
			c := newFakeTransport(tr, nil)
			c.failRead = func(int) error { return io.EOF }
			flags := AuthNoPriv
			if tc.priv > NoPriv {
				flags = AuthPriv
			}
			x := newEngineClientFrom(t, c, &Client{
				Version: Version3, SecurityLevel: flags,
				User: user, ContextName: "codec-context", Timeout: time.Second, Retries: 2,
			})
			for range 2 {
				res, err := x.Get(context.Background(), []string{engineOID})
				assert.EqualError(t, err, tc.wantErr)
				assert.Nil(t, res)
				assert.Zero(t, c.writes, "discovery must not be sent")
				assert.Zero(t, c.reads)
				assert.Equal(t, user, x.User, "the configured user must be preserved")
				assert.Equal(t, engineState{}, x.engine)
				assert.Equal(t, "codec-context", x.ContextName)
			}
			out, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Value: NullValue()}}, 0, 0)
			assert.EqualError(t, err, tc.wantErr)
			assert.Nil(t, out)
			assert.Equal(t, engineState{}, x.engine)
		})
	}
}
