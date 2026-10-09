// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"crypto"
	"encoding/hex"
	"hash"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLocalizedKeyRFC3414 checks key localization against RFC 3414 appendix
// A.3.1 (MD5) and A.3.2 (SHA): passphrase "maplesyrup" localized to the
// engine ID 00 00 00 00 00 00 00 00 00 00 00 02.
func TestLocalizedKeyRFC3414(t *testing.T) {
	engineID := string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

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

// TestLocalizedKeyEmptyPassphrase pins a known bug: localizing an empty
// passphrase returns an empty key and no error.
func TestLocalizedKeyEmptyPassphrase(t *testing.T) {
	key, err := NewCache().LocalizedKey(crypto.SHA1, "", "codec-engine")
	require.NoError(t, err)
	assert.Equal(t, []byte{}, key)
}

// TestPrivacyKeyTooShort checks that a privacy key still shorter than its
// cipher key after the extension fails with a *ShortKeyError.
func TestPrivacyKeyTooShort(t *testing.T) {
	_, err := NewCache().PrivacyKey(Priv{Cipher: AESCFB, KeyLen: 32, Extension: Blumenthal}, crypto.SHA1, "", "codec-engine")
	var short *ShortKeyError
	require.ErrorAs(t, err, &short)
	assert.Equal(t, &ShortKeyError{Len: 20, KeyLen: 32}, short)
}

// TestCacheKeys checks that the cache keeps one password-to-key result per
// hash and passphrase: each lookup, first and repeated, returns the result
// computed without the cache, also after turning the cache off and on.
func TestCacheKeys(t *testing.T) {
	c := NewCache()
	c.SetEnabled(false)
	c.SetEnabled(true)

	keys := []cacheKey{
		{hash: crypto.MD5, password: "codec-pass-one"},
		{hash: crypto.MD5, password: "codec-pass-two"},
		{hash: crypto.SHA1, password: "codec-pass-one"},
	}
	for range 2 {
		for _, k := range keys {
			want, err := passwordToKey(k.hash.New(), k.password)
			require.NoError(t, err)
			got, err := c.passwordToKey(k.hash.New(), k)
			require.NoError(t, err)
			assert.Equal(t, want, got, "%v %s", k.hash, k.password)
		}
	}
}

// blockingHash holds its first Write until release is closed, after closing
// started.
type blockingHash struct {
	hash.Hash
	once             sync.Once
	started, release chan struct{}
}

func (h *blockingHash) Write(p []byte) (int, error) {
	h.once.Do(func() {
		close(h.started)
		<-h.release
	})
	return h.Hash.Write(p)
}

// TestCacheOffDuringDerivation turns the cache off while a derivation that
// found it on hashes the passphrase: the derivation returns the key without
// storing it, and the cache stays usable.
func TestCacheOffDuringDerivation(t *testing.T) {
	const pass = "codec-toggle-pass"
	k := cacheKey{hash: crypto.MD5, password: pass}
	c := NewCache()
	want, err := passwordToKey(crypto.MD5.New(), pass)
	require.NoError(t, err)

	h := &blockingHash{Hash: crypto.MD5.New(), started: make(chan struct{}), release: make(chan struct{})}
	type result struct {
		key      []byte
		err      error
		panicked any
	}
	done := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			r.panicked = recover()
			done <- r
		}()
		r.key, r.err = c.passwordToKey(h, k)
	}()

	select {
	case <-h.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the derivation did not hash the passphrase")
	}
	c.SetEnabled(false)
	close(h.release)
	r := <-done

	// A panic would leave the cache mutex locked, so stop before using it.
	require.Nil(t, r.panicked, "derivation panicked")
	require.NoError(t, r.err)
	assert.Equal(t, want, r.key)

	c.SetEnabled(true)
	key, err := c.passwordToKey(crypto.MD5.New(), k)
	require.NoError(t, err)
	assert.Equal(t, want, key, "derivation after re-enabling the cache")
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

// TestCacheHashes pins when a derivation hashes the passphrase: every time
// while the cache is off, once while it is on, and once again after it is
// turned back on, which resets it.
func TestCacheHashes(t *testing.T) {
	k := cacheKey{hash: crypto.MD5, password: "codec-count-pass"}
	c := NewCache()
	assert.True(t, c.Enabled(), "new")
	hashes := func() bool {
		h := &countingHash{Hash: crypto.MD5.New()}
		_, err := c.passwordToKey(h, k)
		require.NoError(t, err)
		return h.writes > 0
	}

	c.SetEnabled(false)
	assert.False(t, c.Enabled())
	assert.True(t, hashes(), "off")
	assert.True(t, hashes(), "off, again")
	c.SetEnabled(true)
	assert.True(t, c.Enabled())
	assert.True(t, hashes(), "on")
	assert.False(t, hashes(), "on, again")
	c.SetEnabled(true)
	assert.False(t, hashes(), "on twice keeps the cache")
	c.SetEnabled(false)
	assert.True(t, hashes(), "off after on")
	c.SetEnabled(true)
	assert.True(t, hashes(), "on after off")
	assert.False(t, hashes(), "on after off, again")
}
