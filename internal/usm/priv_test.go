// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrivRoundTrip checks that Decrypt undoes Encrypt for plaintexts of 0
// to 24 octets, and that DES pads with zeros to whole blocks, adding a whole
// block when the plaintext fills its last one. The netsnmp module compares
// the ciphertexts with net-snmp.
func TestPrivRoundTrip(t *testing.T) {
	key := []byte("codec-privacy-key-of-32-octets!!")
	salt := []byte("saltsalt")
	tests := map[string]struct {
		priv Priv
		key  []byte
	}{
		"DES":    {priv: Priv{Cipher: DESCBC, KeyLen: 16}, key: key[:16]},
		"AES":    {priv: Priv{Cipher: AESCFB, KeyLen: 16}, key: key[:16]},
		"AES192": {priv: Priv{Cipher: AESCFB, KeyLen: 24}, key: key[:24]},
		"AES256": {priv: Priv{Cipher: AESCFB, KeyLen: 32}, key: key},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for n := range 25 {
				plaintext := bytes.Repeat([]byte{0xa5}, n)
				ciphertext, err := tc.priv.Encrypt(tc.key, salt, 7, 1234, plaintext)
				require.NoError(t, err)
				want := plaintext
				if tc.priv.Cipher == DESCBC {
					want = append(bytes.Clone(plaintext), make([]byte, 8-n%8)...)
				}
				require.Len(t, ciphertext, len(want), "plaintext of %d octets", n)

				got, err := tc.priv.Decrypt(tc.key, salt, 7, 1234, ciphertext)
				require.NoError(t, err)
				assert.Equal(t, want, got, "plaintext of %d octets", n)
			}
		})
	}
}

// TestPrivErrors checks the inputs Encrypt and Decrypt reject.
func TestPrivErrors(t *testing.T) {
	key, salt := make([]byte, 16), make([]byte, 8)

	_, err := Priv{}.Encrypt(key, salt, 0, 0, []byte("plaintext"))
	require.ErrorIs(t, err, errNoCipher, "encrypt without a cipher")
	_, err = Priv{}.Decrypt(key, salt, 0, 0, make([]byte, 8))
	require.ErrorIs(t, err, errNoCipher, "decrypt without a cipher")

	_, err = Priv{Cipher: DESCBC, KeyLen: 16}.Decrypt(key, salt, 0, 0, make([]byte, 9))
	require.EqualError(t, err, "usm: decrypting: ciphertext of 9 octets, not whole DES blocks")
}

// TestPrivKeyAndSaltLengths checks the rule of Encrypt and Decrypt: a key of
// exactly the protocol's KeyLen and an 8-octet salt; anything else fails with
// an error naming it, before either is used, so no length makes DES index past
// its inputs or AES pick another key size.
func TestPrivKeyAndSaltLengths(t *testing.T) {
	aes128, des := Priv{Cipher: AESCFB, KeyLen: 16}, Priv{Cipher: DESCBC, KeyLen: 16}
	tests := map[string]struct {
		p         Priv
		key, salt int
		want      string // the error after "usm: encrypting: " and "usm: decrypting: ", "" for none
	}{
		"AES-128":                     {p: aes128, key: 16, salt: 8},
		"DES":                         {p: des, key: 16, salt: 8},
		"AES-128 with a 32-octet key": {p: aes128, key: 32, salt: 8, want: "privacy key of 32 octets, want 16"},
		"AES with a 9-octet salt":     {p: aes128, key: 16, salt: 9, want: "salt of 9 octets, want 8"},
		"AES with a 16-octet salt":    {p: aes128, key: 16, salt: 16, want: "salt of 16 octets, want 8"},
		"AES without a salt":          {p: aes128, key: 16, salt: 0, want: "salt of 0 octets, want 8"},
		"DES with a 20-octet key":     {p: des, key: 20, salt: 8, want: "privacy key of 20 octets, want 16"},
		"DES with a 12-octet key":     {p: des, key: 12, salt: 8, want: "privacy key of 12 octets, want 16"},
		"DES without a key":           {p: des, key: 0, salt: 8, want: "no privacy key, want 16 octets"},
		"DES with a 7-octet salt":     {p: des, key: 16, salt: 7, want: "salt of 7 octets, want 8"},
	}
	errText := func(err error) string {
		if err == nil {
			return ""
		}
		return err.Error()
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Inputs without spare capacity: a read past their length panics.
			key, salt := make([]byte, tc.key), make([]byte, tc.salt)
			_, encErr := tc.p.Encrypt(key[:tc.key:tc.key], salt[:tc.salt:tc.salt], 0, 0, make([]byte, 3))
			_, decErr := tc.p.Decrypt(key[:tc.key:tc.key], salt[:tc.salt:tc.salt], 0, 0, make([]byte, 16))
			want := [2]string{}
			if tc.want != "" {
				want = [2]string{"usm: encrypting: " + tc.want, "usm: decrypting: " + tc.want}
			}
			assert.Equal(t, want, [2]string{errText(encErr), errText(decErr)})
		})
	}
}
