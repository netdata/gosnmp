// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"crypto"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLocalizedKeyRFC3414 checks key localization against RFC 3414 appendix
// A.3.1 (MD5) and A.3.2 (SHA): passphrase "maplesyrup" localized to the
// engine ID 00 00 00 00 00 00 00 00 00 00 00 02.
func TestLocalizedKeyRFC3414(t *testing.T) {
	engineID := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	tests := map[string]struct {
		hash crypto.Hash
		want string
	}{
		"MD5": {hash: crypto.MD5, want: "526f5eed9fcce26f8964c2930787d82b"},
		"SHA": {hash: crypto.SHA1, want: "6695febc9288e36282235fc7151f128497b38f3f"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := NewCache().LocalizedKey(tc.hash, "maplesyrup", engineID)
			require.NoError(t, err)
			assert.Equal(t, tc.want, hex.EncodeToString(key))
		})
	}
}

// TestLocalizedKeyEmptyPassphrase checks that localizing an empty passphrase
// is an error, with no key.
func TestLocalizedKeyEmptyPassphrase(t *testing.T) {
	key, err := NewCache().LocalizedKey(crypto.SHA1, "", []byte("codec-engine"))
	require.EqualError(t, err, "usm: empty passphrase")
	assert.Nil(t, key)
}

// TestPrivacyKeyTooShort checks that a privacy key shorter than its cipher
// key, without an extension or still after one, fails with the rule's
// *KeyError, and that a protocol without a cipher fails.
func TestPrivacyKeyTooShort(t *testing.T) {
	tests := map[string]struct {
		p    Priv
		want *KeyError
	}{
		"no extension":          {p: Priv{Cipher: AESCFB, KeyLen: 32}, want: &KeyError{Kind: "privacy", Len: 16, Want: 32}},
		"extended, still short": {p: Priv{Cipher: AESCFB, KeyLen: 40, Extension: Blumenthal}, want: &KeyError{Kind: "privacy", Len: 32, Want: 40}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewCache().PrivacyKey(tc.p, crypto.MD5, "codec-pass", []byte("codec-engine"))
			var short *KeyError
			require.ErrorAs(t, err, &short)
			assert.Equal(t, tc.want, short)
		})
	}
	_, err := NewCache().PrivacyKey(Priv{}, crypto.MD5, "codec-pass", []byte("codec-engine"))
	require.ErrorIs(t, err, errNoCipher)
}

// TestCacheKeys checks that the cache keeps one password-to-key result per
// hash and passphrase: each lookup, first and repeated, returns the result
// computed without the cache.
func TestCacheKeys(t *testing.T) {
	c := NewCache()

	keys := []cacheKey{
		{hash: crypto.MD5, password: "codec-pass-one"},
		{hash: crypto.MD5, password: "codec-pass-two"},
		{hash: crypto.SHA1, password: "codec-pass-one"},
	}
	for range 2 {
		for _, k := range keys {
			want, err := passwordToKey(k.hash.New(), k.password)
			require.NoError(t, err)
			got, err := c.passwordToKey(k, k.hash.New)
			require.NoError(t, err)
			assert.Equal(t, want, got, "%v %s", k.hash, k.password)
		}
		assert.Equal(t, len(keys), c.Len(), "one result per hash and password")
	}
}

// countingHash counts the Write calls of a hash.
type countingHash struct {
	hash.Hash
	writes int
}

func (h *countingHash) Write(p []byte) (int, error) {
	h.writes++
	return h.Hash.Write(p)
}

// TestCacheHashes pins when a derivation hashes the passphrase: once, the
// first time; a derivation the cache answers creates no hash.
func TestCacheHashes(t *testing.T) {
	k := cacheKey{hash: crypto.MD5, password: "codec-count-pass"}
	c := NewCache()
	hashes := func() bool {
		var h *countingHash
		_, err := c.passwordToKey(k, func() hash.Hash {
			h = &countingHash{Hash: crypto.MD5.New()}
			return h
		})
		require.NoError(t, err)
		if h == nil {
			return false
		}
		assert.Positive(t, h.writes, "a created hash hashes the passphrase")
		return true
	}

	assert.True(t, hashes(), "first")
	assert.False(t, hashes(), "again")
}
