// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"bytes"
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

// TestDigest checks, for keys of 0 to 100 octets, that Digest takes only a key
// of the hash's size, whose digest is crypto/hmac's cut to the MAC length, and
// refuses any other with the rule's *KeyError; and that the zero Auth refuses
// every key.
func TestDigest(t *testing.T) {
	msg := []byte("codec-message")
	for name, a := range testAuths {
		t.Run(name, func(t *testing.T) {
			for n := range 101 {
				key := make([]byte, n)
				for i := range key {
					key[i] = byte(i*7 + n)
				}
				got, err := a.Digest(key, msg)
				if n != a.Hash.Size() {
					var ke *KeyError
					require.ErrorAs(t, err, &ke, "key of %d octets", n)
					assert.Equal(t, &KeyError{Kind: "authentication", Len: n, Want: a.Hash.Size()}, ke)
					assert.Nil(t, got)
					continue
				}
				require.NoError(t, err)
				h := hmac.New(a.Hash.New, key)
				h.Write(msg)
				assert.Equal(t, h.Sum(nil)[:a.MACLen], got, "key of %d octets", n)
			}
		})
	}
	_, err := Auth{}.Digest(make([]byte, 16), msg)
	require.ErrorIs(t, err, errNoAuth)
}

// TestVerify checks that Verify accepts the digest only: not a changed or a
// shortened one.
func TestVerify(t *testing.T) {
	msg := []byte("codec-message")
	for name, a := range testAuths {
		t.Run(name, func(t *testing.T) {
			key := bytes.Repeat([]byte{'k'}, a.Hash.Size())
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
