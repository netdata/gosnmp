// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	crand "crypto/rand"
	"encoding/binary"
	"sync/atomic"
)

// SaltCounter draws the salts (msgPrivacyParameters) of encrypted messages:
// a 64-bit counter, so a salt repeats only after 2^64 messages (RFC 3826
// section 3.1.2.1; RFC 3414 section 8.1.1.1 leaves DES's integer to the
// implementation, and the receiver uses the eight octets as given). It is
// safe for concurrent use.
type SaltCounter struct {
	n atomic.Uint64
}

// Next returns the next salt.
func (c *SaltCounter) Next() [8]byte {
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], c.n.Add(1))
	return salt
}

// Set makes next the value of the next salt.
func (c *SaltCounter) Set(next uint64) {
	c.n.Store(next - 1)
}

// Salts is the process-wide salt counter, seeded from crypto/rand, which
// never fails (Go 1.24 and later), so that processes do not share a salt
// sequence.
var Salts = newSeededSaltCounter() //nolint:gochecknoglobals // one counter for every encoder in the process

func newSeededSaltCounter() *SaltCounter {
	var seed [8]byte
	_, _ = crand.Read(seed[:])
	c := new(SaltCounter)
	c.Set(binary.BigEndian.Uint64(seed[:]))
	return c
}
