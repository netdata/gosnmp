// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"errors"
)

// Cipher is the cipher of a privacy protocol.
type Cipher uint8

// Privacy ciphers.
const (
	NoCipher Cipher = iota
	DESCBC          // CBC-DES (RFC 3414 section 8)
	AESCFB          // CFB128-AES (RFC 3826)
)

// Extension is how a privacy protocol extends a localized key shorter than
// its cipher key.
type Extension uint8

// Key extensions.
const (
	NoExtension Extension = iota
	Reeder                // draft-reeder-snmpv3-usm-3desede
	Blumenthal            // draft-blumenthal-aes-usm-04
)

// Priv describes a privacy protocol: its cipher, its key length and how a
// shorter localized key is extended. A key length of 0 keeps the whole
// localized key, which DES uses as its key and pre-IV. The zero value
// describes no protocol.
type Priv struct {
	Cipher    Cipher
	KeyLen    int
	Extension Extension
}

var errNoCipher = errors.New("usm: no privacy cipher")

// Encrypt returns the ciphertext of a scoped PDU. salt is msgPrivacyParameters;
// AES also takes the engine boots and time into its IV. DES pads the
// plaintext with zeros to whole blocks, with a whole block of padding when it
// is a multiple of the block size already.
func (p Priv) Encrypt(key, salt []byte, engineBoots, engineTime uint32, plaintext []byte) ([]byte, error) {
	switch p.Cipher {
	case AESCFB:
		iv := aesIV(engineBoots, engineTime, salt)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck // RFC3826 Section 3.1.1.1 specifies CFB-128 mode for AES
		stream := cipher.NewCFBEncrypter(block, iv[:])
		ciphertext := make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)
		return ciphertext, nil
	case DESCBC:
		iv := desIV(key, salt)
		block, err := des.NewCipher(key[:8]) //nolint:gosec
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, len(plaintext)+des.BlockSize-len(plaintext)%des.BlockSize)
		copy(ciphertext, plaintext)
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, ciphertext)
		return ciphertext, nil
	}
	return nil, errNoCipher
}

// Decrypt returns the plaintext of an encrypted scoped PDU, with the DES
// padding left in place. The arguments are those of Encrypt.
func (p Priv) Decrypt(key, salt []byte, engineBoots, engineTime uint32, ciphertext []byte) ([]byte, error) {
	switch p.Cipher {
	case AESCFB:
		iv := aesIV(engineBoots, engineTime, salt)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck // RFC3826 Section 3.1.1.1 specifies CFB-128 mode for AES
		stream := cipher.NewCFBDecrypter(block, iv[:])
		plaintext := make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
		return plaintext, nil
	case DESCBC:
		if len(ciphertext)%des.BlockSize != 0 {
			return nil, errors.New("error decrypting ScopedPDU: not multiple of des block size")
		}
		iv := desIV(key, salt)
		block, err := des.NewCipher(key[:8]) //nolint:gosec
		if err != nil {
			return nil, err
		}
		plaintext := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(plaintext, ciphertext)
		return plaintext, nil
	}
	return nil, errNoCipher
}

// aesIV returns the IV of CFB-AES (RFC 3826 section 3.1.2.1): the engine
// boots and time, then the 64-bit salt.
func aesIV(engineBoots, engineTime uint32, salt []byte) [16]byte {
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[:], engineBoots)
	binary.BigEndian.PutUint32(iv[4:], engineTime)
	copy(iv[8:], salt)
	return iv
}

// desIV returns the IV of CBC-DES (RFC 3414 section 8.1.1.1): the pre-IV, the
// key octets after the DES key, XORed with the salt. Known bug: a key shorter
// than 16 octets or a salt shorter than 8 panics here.
func desIV(key, salt []byte) [8]byte {
	preIV := key[8:]
	var iv [8]byte
	for i := range iv {
		iv[i] = preIV[i] ^ salt[i]
	}
	return iv
}
