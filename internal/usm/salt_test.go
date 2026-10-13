// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package usm

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSaltCounter checks that Set positions the next salt, that Next counts
// up in big-endian order and wraps after the largest value.
func TestSaltCounter(t *testing.T) {
	var c SaltCounter
	c.Set(0x1122334455667788)
	assert.Equal(t, [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, c.Next())
	assert.Equal(t, [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89}, c.Next())

	c.Set(math.MaxUint64)
	assert.Equal(t, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, c.Next())
	assert.Equal(t, [8]byte{}, c.Next(), "wraps")
}

// TestSaltCounterConcurrent checks that concurrent draws never return the
// same salt.
func TestSaltCounterConcurrent(t *testing.T) {
	var c SaltCounter
	const goroutines, draws = 8, 1000
	var mu sync.Mutex
	seen := make(map[[8]byte]bool, goroutines*draws)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			<-start
			got := make([][8]byte, 0, draws)
			for range draws {
				got = append(got, c.Next())
			}
			mu.Lock()
			defer mu.Unlock()
			for _, s := range got {
				assert.False(t, seen[s], "salt %x drawn twice", s)
				seen[s] = true
			}
		})
	}
	close(start)
	wg.Wait()
	assert.Len(t, seen, goroutines*draws)
}

// TestSaltsSeeded checks that counters start at random points: two seeded
// counters start apart, as constant or unread seeds would not, and the
// process-wide counter is seeded (each check has a 2^-64 chance of a false
// failure; no test of this package draws from Salts).
func TestSaltsSeeded(t *testing.T) {
	assert.NotEqual(t, newSeededSaltCounter().Next(), newSeededSaltCounter().Next())
	assert.NotZero(t, Salts.n.Load(), "the process-wide counter is not seeded")
}
