// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"sync"
)

// Cache derives localized keys and memoizes their costly first step, the
// password-to-key hash of a megabyte of the passphrase (RFC 3414 appendix
// A.2.1), by hash and passphrase, for as long as it lives: the passphrases
// stay in memory meanwhile. Use NewCache.
type Cache struct {
	mu   sync.RWMutex
	keys map[cacheKey][]byte
}

type cacheKey struct {
	hash     crypto.Hash
	password string
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{keys: make(map[cacheKey][]byte)}
}

// Len returns the number of password-to-key results the cache holds.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys)
}

// LocalizedKey returns passphrase localized to engineID with hash h (RFC 3414
// appendix A.2.2): the hash of the password-to-key result, the engine ID and
// the password-to-key result again. An empty passphrase is an error.
func (c *Cache) LocalizedKey(h crypto.Hash, passphrase string, engineID []byte) ([]byte, error) {
	ku, err := c.passwordToKey(cacheKey{hash: h, password: passphrase}, h.New)
	if err != nil {
		return nil, err
	}

	local := h.New()
	if _, err := local.Write(ku); err != nil {
		return nil, err
	}
	if _, err := local.Write(engineID); err != nil {
		return nil, err
	}
	if _, err := local.Write(ku); err != nil {
		return nil, err
	}
	return local.Sum(nil), nil
}

// PrivacyKey returns the key of privacy protocol p: passphrase localized to
// engineID with hash h, extended once when it is shorter than the cipher key,
// and cut to the cipher key length; the result passes p's CheckKey, or fails
// with its error (a key still too short).
func (c *Cache) PrivacyKey(p Priv, h crypto.Hash, passphrase string, engineID []byte) ([]byte, error) {
	key, err := c.LocalizedKey(h, passphrase, engineID)
	if err != nil {
		return nil, err
	}

	if len(key) < p.KeyLen {
		switch p.Extension {
		case Reeder:
			if key, err = c.extendReeder(h, key, engineID); err != nil {
				return nil, err
			}
		case Blumenthal:
			key = extendBlumenthal(h, key)
		}
	}
	key = key[:min(len(key), p.KeyLen)]
	if err := p.CheckKey(key); err != nil {
		return nil, fmt.Errorf("usm: %w", err)
	}
	return key, nil
}

// extendReeder extends a localized key with the Reeder key extension
// (draft-reeder-snmpv3-usm-3desede, used by Cisco and others): the key
// followed by the key localized from it as a passphrase.
func (c *Cache) extendReeder(h crypto.Hash, key, engineID []byte) ([]byte, error) {
	next, err := c.LocalizedKey(h, string(key), engineID)
	if err != nil {
		return nil, err
	}
	return append(key, next...), nil
}

// extendBlumenthal extends a localized key with the Blumenthal key extension
// (draft-blumenthal-aes-usm-04 section 3.1.2.1): the key followed by its hash.
func extendBlumenthal(h crypto.Hash, key []byte) []byte {
	d := h.New()
	_, _ = d.Write(key)
	return d.Sum(key)
}

// passwordToKey returns the password-to-key result for k, hashing its password
// with a hash from newHash when the cache does not hold it.
func (c *Cache) passwordToKey(k cacheKey, newHash func() hash.Hash) ([]byte, error) {
	c.mu.RLock()
	key := c.keys[k]
	c.mu.RUnlock()
	if key != nil {
		return key, nil
	}

	key, err := passwordToKey(newHash(), k.password)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys[k] = key
	c.mu.Unlock()
	return key, nil
}

// passwordToKey hashes a megabyte of password repeated, 64 octets at a time
// (RFC 3414 appendix A.2.1).
func passwordToKey(h hash.Hash, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("usm: empty passphrase")
	}
	var block [64]byte
	var pi int // password index
	for range 1048576 / len(block) {
		for i := range block {
			block[i] = password[pi%len(password)]
			pi++
		}
		if _, err := h.Write(block[:]); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}
