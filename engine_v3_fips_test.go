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
	const cfbPanic = "AES-CFB panics in FIPS 140-only mode; send recovers it into an error that carries the stack"
	const partialState = "a failed key derivation leaves the agent's engine ID adopted without keys, boots or time, so the next request skips the discovery"
	return map[string]v3Scenario{
		"discovery/noauth":         {user: "codec-noauth"},
		"discovery/md5":            {user: "codec-md5", run: getFirstOf2, knownBug: partialState},
		"discovery/sha-aes":        {user: "codec-sha-aes", run: getFirstOf2, knownBug: partialState},
		"discovery/sha256-des":     {user: "codec-sha256-des"},
		"discovery/sha256-aes":     {user: "codec-sha256-aes", knownBug: cfbPanic},
		"discovery/sha512-aes256c": {user: "codec-sha512-aes256c", knownBug: cfbPanic},
		"known-engine/md5": {
			user: "codec-md5", setup: func(_ *GoSNMP, sp *UsmSecurityParameters) { sp.AuthoritativeEngineID = agentEngineID },
			knownBug: "the key derivation error is ignored when the engine ID is known",
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
