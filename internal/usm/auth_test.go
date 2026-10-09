// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"crypto"
	"crypto/hmac"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAuths = map[string]Auth{
	"MD5":    {Hash: crypto.MD5, MACLen: 12},
	"SHA":    {Hash: crypto.SHA1, MACLen: 12},
	"SHA224": {Hash: crypto.SHA224, MACLen: 16},
	"SHA256": {Hash: crypto.SHA256, MACLen: 24},
	"SHA384": {Hash: crypto.SHA384, MACLen: 32},
	"SHA512": {Hash: crypto.SHA512, MACLen: MaxMACLen},
}

// TestDigest compares every digest with crypto/hmac cut to the MAC length,
// for keys of 0 to 100 octets. Known bug: HMAC-MD5-96 and HMAC-SHA-96 cut a
// key longer than the 64-octet block instead of hashing it (RFC 2104).
func TestDigest(t *testing.T) {
	msg := []byte("codec-message")
	for name, a := range testAuths {
		t.Run(name, func(t *testing.T) {
			for n := range 101 {
				key := make([]byte, n)
				for i := range key {
					key[i] = byte(i*7 + n)
				}
				hmacKey := key
				if (a.Hash == crypto.MD5 || a.Hash == crypto.SHA1) && n > 64 {
					hmacKey = key[:64]
				}
				h := hmac.New(a.Hash.New, hmacKey)
				h.Write(msg)

				got, err := a.Digest(key, msg)
				require.NoError(t, err)
				assert.Equal(t, h.Sum(nil)[:a.MACLen], got, "key of %d octets", n)
			}
		})
	}
}

// TestVerify checks that Verify accepts the digest only: not a changed or a
// shortened one.
func TestVerify(t *testing.T) {
	key, msg := []byte("codec-key"), []byte("codec-message")
	for name, a := range testAuths {
		t.Run(name, func(t *testing.T) {
			mac, err := a.Digest(key, msg)
			require.NoError(t, err)
			changed := append([]byte(nil), mac...)
			changed[len(changed)-1] ^= 1

			for _, tc := range []struct {
				mac  []byte
				want bool
			}{
				{mac: mac, want: true},
				{mac: changed},
				{mac: mac[:len(mac)-1]},
				{mac: nil},
			} {
				ok, err := a.Verify(key, msg, tc.mac)
				require.NoError(t, err)
				assert.Equal(t, tc.want, ok, "%x", tc.mac)
			}
		})
	}
}
