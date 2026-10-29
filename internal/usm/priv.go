// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/fips140"
	"encoding/binary"
	"errors"
	"fmt"
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
// shorter localized key is extended. The key length is the AES key's, or the
// 16 octets of DES's key and pre-IV (RFC 3414 section 8.1.1.1). The zero value
// describes no protocol.
type Priv struct {
	Cipher    Cipher
	KeyLen    int
	Extension Extension
}

// SaltLen is the length of msgPrivacyParameters, the salt, for both ciphers
// (RFC 3414 section 8.1.1.1, RFC 3826 section 3.1.2.1).
const SaltLen = 8

var (
	errNoCipher      = errors.New("no privacy cipher")
	errCFBNotAllowed = errors.New("AES-CFB is not allowed in FIPS 140-only mode")
)

// CheckKey is the one rule for privacy keys: it returns an error for a
// protocol without a cipher, and a *KeyError unless key is exactly the
// protocol's KeyLen.
func (p Priv) CheckKey(key []byte) error {
	if p.Cipher != DESCBC && p.Cipher != AESCFB {
		return errNoCipher
	}
	if len(key) != p.KeyLen {
		return &KeyError{Kind: "privacy", Len: len(key), Want: p.KeyLen}
	}
	return nil
}

// CheckUse returns why the process cannot encrypt or decrypt with key, apart
// from what a message carries: a key CheckKey refuses, or AES-CFB in FIPS
// 140-only mode.
func (p Priv) CheckUse(key []byte) error {
	if err := p.CheckKey(key); err != nil {
		return err
	}
	return p.allowed()
}

// allowed returns the error of AES-CFB in FIPS 140-only mode.
func (p Priv) allowed() error {
	if p.Cipher == AESCFB && fips140.Enforced() {
		return errCFBNotAllowed
	}
	return nil
}

// check returns why Encrypt and Decrypt cannot take key and salt: a key
// CheckKey refuses, a salt of another length than SaltLen (RFC 3414 section
// 8.3.2, RFC 3826 section 3.3.2), or AES-CFB in FIPS 140-only mode.
func (p Priv) check(key, salt []byte) error {
	if err := p.CheckKey(key); err != nil {
		return err
	}
	if len(salt) != SaltLen {
		return fmt.Errorf("salt of %d octets, want %d", len(salt), SaltLen)
	}
	return p.allowed()
}

// Encrypt returns the ciphertext of a scoped PDU. salt is
// msgPrivacyParameters; AES also takes the engine boots and time into its IV.
// DES pads the plaintext with zeros to whole blocks, with a whole block of
// padding when it is a multiple of the block size already. It refuses what
// check refuses; its errors start with "usm: encrypting: ".
func (p Priv) Encrypt(key, salt []byte, engineBoots, engineTime uint32, plaintext []byte) ([]byte, error) {
	ciphertext, err := p.encrypt(key, salt, engineBoots, engineTime, plaintext)
	if err != nil {
		return nil, fmt.Errorf("usm: encrypting: %w", err)
	}
	return ciphertext, nil
}

func (p Priv) encrypt(key, salt []byte, engineBoots, engineTime uint32, plaintext []byte) ([]byte, error) {
	if err := p.check(key, salt); err != nil {
		return nil, err
	}
	if p.Cipher == AESCFB {
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
	}
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

// Decrypt returns the plaintext of an encrypted scoped PDU, with the DES
// padding left in place. The arguments are those of Encrypt, and it refuses
// what Encrypt refuses, and DES ciphertext that is not whole blocks; its
// errors start with "usm: decrypting: ".
func (p Priv) Decrypt(key, salt []byte, engineBoots, engineTime uint32, ciphertext []byte) ([]byte, error) {
	plaintext, err := p.decrypt(key, salt, engineBoots, engineTime, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("usm: decrypting: %w", err)
	}
	return plaintext, nil
}

func (p Priv) decrypt(key, salt []byte, engineBoots, engineTime uint32, ciphertext []byte) ([]byte, error) {
	if err := p.check(key, salt); err != nil {
		return nil, err
	}
	if p.Cipher == AESCFB {
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
	}
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext of %d octets, not whole DES blocks", len(ciphertext))
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
// 8 key octets after the DES key, XORed with the 8-octet salt (Encrypt and
// Decrypt check both lengths).
func desIV(key, salt []byte) [8]byte {
	preIV := key[8:]
	var iv [8]byte
	for i := range iv {
		iv[i] = preIV[i] ^ salt[i]
	}
	return iv
}
