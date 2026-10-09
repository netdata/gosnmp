// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Package usm implements the cryptography of the SNMPv3 User-based Security
// Model: message digests (RFC 3414, RFC 7860), localized keys and their
// extension for AES-192 and AES-256, and the CBC-DES (RFC 3414) and CFB-AES
// (RFC 3826) privacy ciphers. It knows nothing of SNMP messages; the root
// package maps its protocols to these descriptions and places the results.
package usm

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/md5"    // Register hash function #2 (MD5)
	_ "crypto/sha1"   // Register hash function #3 (SHA1)
	_ "crypto/sha256" // Register hash function #4 (SHA224), #5 (SHA256)
	_ "crypto/sha512" // Register hash function #6 (SHA384), #7 (SHA512)
	"crypto/subtle"
)

// Auth describes an authentication protocol: the hash of its key derivation
// and HMAC, and the length its HMAC is cut to, which is the length of
// msgAuthenticationParameters. The zero value describes no protocol.
type Auth struct {
	Hash   crypto.Hash
	MACLen int
}

// MaxMACLen is the longest MACLen, HMAC-SHA-512's.
const MaxMACLen = 48

// Digest returns the HMAC of msg keyed with key, cut to the MAC length:
// HMAC-MD5-96 and HMAC-SHA-96 as RFC 3414 sections 6.3.1 and 7.3.1 spell them
// out, the SHA-2 protocols with crypto/hmac (RFC 7860 section 4.2.1).
func (a Auth) Digest(key, msg []byte) ([]byte, error) {
	var mac []byte
	switch a.Hash {
	case crypto.MD5, crypto.SHA1:
		var err error
		if mac, err = hmacRFC3414(a.Hash, key, msg); err != nil {
			return nil, err
		}
	default:
		h := hmac.New(a.Hash.New, key)
		_, _ = h.Write(msg)
		mac = h.Sum(nil)
	}
	return mac[:a.MACLen], nil
}

// Verify reports whether mac is the digest of msg keyed with key, comparing
// in constant time.
func (a Auth) Verify(key, msg, mac []byte) (bool, error) {
	digest, err := a.Digest(key, msg)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(digest, mac) == 1, nil
}

// hmacRFC3414 computes the HMAC of RFC 3414 sections 6.3.1 and 7.3.1: the key
// zero-padded to the 64-octet block (a longer key is cut, not hashed as RFC
// 2104 does), XORed with ipad and opad around two hash passes. Unlike
// crypto/hmac, which panics, it returns the error a hash reports, as MD5 and
// SHA-1 do in FIPS 140-only mode.
func hmacRFC3414(hash crypto.Hash, key, msg []byte) ([]byte, error) {
	var ipad, opad [64]byte
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}

	inner := hash.New()
	if _, err := inner.Write(ipad[:]); err != nil {
		return nil, err
	}
	if _, err := inner.Write(msg); err != nil {
		return nil, err
	}
	outer := hash.New()
	if _, err := outer.Write(opad[:]); err != nil {
		return nil, err
	}
	if _, err := outer.Write(inner.Sum(nil)); err != nil {
		return nil, err
	}
	return outer.Sum(nil), nil
}
