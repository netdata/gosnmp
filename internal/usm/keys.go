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
// A.2.1), by hash and passphrase. NewCache returns a cache that is on; the zero
// Cache is off. While off, it stores nothing and derives every key from
// scratch.
type Cache struct {
	// mu guards keys, which is nil while the cache is off.
	mu   sync.RWMutex
	keys map[cacheKey][]byte
}

type cacheKey struct {
	hash     crypto.Hash
	password string
}

// NewCache returns an empty cache that is on.
func NewCache() *Cache {
	return &Cache{keys: make(map[cacheKey][]byte)}
}

// SetEnabled turns the cache on or off. Turning it off drops what it holds,
// so it is empty when turned back on.
func (c *Cache) SetEnabled(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch {
	case !enable:
		c.keys = nil
	case c.keys == nil:
		c.keys = make(map[cacheKey][]byte)
	}
}

// Enabled reports whether the cache is on.
func (c *Cache) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys != nil
}

// LocalizedKey returns passphrase localized to engineID with hash h (RFC 3414
// appendix A.2.2): the hash of the password-to-key result, the engine ID and
// the password-to-key result again. An empty passphrase is an error.
func (c *Cache) LocalizedKey(h crypto.Hash, passphrase, engineID string) ([]byte, error) {
	ku, err := c.passwordToKey(cacheKey{hash: h, password: passphrase}, h.New)
	if err != nil {
		return nil, err
	}

	local := h.New()
	if _, err := local.Write(ku); err != nil {
		return nil, err
	}
	if _, err := local.Write([]byte(engineID)); err != nil {
		return nil, err
	}
	if _, err := local.Write(ku); err != nil {
		return nil, err
	}
	return local.Sum(nil), nil
}

// PrivacyKey returns the key of privacy protocol p: passphrase localized to
// engineID with hash h, extended once when it is shorter than the cipher key,
// and cut to the cipher key length. A key still too short fails with p's
// CheckKey error.
func (c *Cache) PrivacyKey(p Priv, h crypto.Hash, passphrase, engineID string) ([]byte, error) {
	if p.Cipher == NoCipher {
		return nil, errNoCipher
	}
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
	if len(key) < p.KeyLen {
		return nil, fmt.Errorf("usm: %w", p.CheckKey(key))
	}
	return key[:p.KeyLen], nil
}

// extendReeder extends a localized key with the Reeder key extension
// (draft-reeder-snmpv3-usm-3desede, used by Cisco and others): the key
// followed by the key localized from it as a passphrase.
func (c *Cache) extendReeder(h crypto.Hash, key []byte, engineID string) ([]byte, error) {
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
// with a hash from newHash when the cache does not hold it. The cache may be
// turned off or on while the password is hashed.
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
	if c.keys != nil {
		c.keys[k] = key
	}
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
