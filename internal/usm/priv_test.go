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
		"DES":    {priv: Priv{Cipher: DESCBC}, key: key[:16]},
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

	_, err = Priv{Cipher: DESCBC}.Decrypt(key, salt, 0, 0, make([]byte, 9))
	require.EqualError(t, err, "error decrypting ScopedPDU: not multiple of des block size")
	_, err = Priv{Cipher: AESCFB, KeyLen: 16}.Decrypt(key[:15], salt, 0, 0, make([]byte, 9))
	require.EqualError(t, err, "crypto/aes: invalid key size 15")
}
