// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"slices"
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

// TestVerifyField checks that VerifyField accepts the digest of the message
// with the field zeroed only, in a field of the MAC's length, and writes
// nothing.
func TestVerifyField(t *testing.T) {
	for name, a := range testAuths {
		t.Run(name, func(t *testing.T) {
			key := bytes.Repeat([]byte{'k'}, a.Hash.Size())
			// msg carries its digest at off, computed with the field zeroed.
			const off = 6
			msg := slices.Concat([]byte("codec-"), make([]byte, a.MACLen), []byte("-message"))
			mac, err := a.Digest(key, msg)
			require.NoError(t, err)
			copy(msg[off:], mac)
			changed := func(i int) []byte {
				m := bytes.Clone(msg)
				m[i] ^= 1
				return m
			}

			for _, tc := range []struct {
				name   string
				msg    []byte
				off, n int
				want   bool
			}{
				{name: "the field", msg: msg, off: off, n: a.MACLen, want: true},
				{name: "a digest octet changed", msg: changed(off + a.MACLen - 1), off: off, n: a.MACLen},
				{name: "a message octet changed", msg: changed(0), off: off, n: a.MACLen},
				{name: "a shorter field", msg: msg, off: off, n: a.MACLen - 1},
				{name: "a longer field", msg: msg, off: off, n: a.MACLen + 1},
				{name: "a field longer than any MAC", msg: slices.Concat(msg, make([]byte, MaxMACLen)), off: off, n: MaxMACLen + 1},
				{name: "no field", msg: msg, off: -1, n: a.MACLen},
				{name: "past the message", msg: msg, off: len(msg) - a.MACLen + 1, n: a.MACLen},
			} {
				in := bytes.Clone(tc.msg)
				ok, verr := a.VerifyField(key, in, tc.off, tc.n)
				require.NoError(t, verr)
				assert.Equal(t, tc.want, ok, tc.name)
				assert.Equal(t, tc.msg, in, "%s: the message is not written", tc.name)
			}

			_, err = a.VerifyField(key[1:], msg, off, a.MACLen)
			assert.Error(t, err, "a key CheckKey refuses")
		})
	}
}
