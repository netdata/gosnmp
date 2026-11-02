// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

const (
	// maxEngineValue is the largest engine boots and time (RFC 3414 section
	// 2.2.2); boots at it mean the engine must be reconfigured.
	maxEngineValue = 2147483647
	// timeWindow is the time window in seconds (RFC 3414 section 2.2.3).
	timeWindow = 150
)

// engineTimes holds a receiver's notion of the engine boots and time of the
// engines whose authenticated Unconfirmed-class messages (traps) it accepted,
// one record per engine and credential, and decides with it whether such a
// message is in the time window (RFC 3414 section 3.2 step 7 b, for the
// receiver of a message whose sender is the authoritative engine). Only the
// receiver's users authenticate a message, each for its own engine ID, so the
// records are at most one per user, of whom the receiver has a bounded number.
type engineTimes struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[engineTimeKey]*engineClock
}

// engineTimeKey identifies the records of one engine for one credential: the
// SHA-256 of the authentication protocol, the engine ID and the authentication
// key localized to it. Users sharing a protocol and a passphrase share a
// record; another credential, which may authenticate any engine ID, cannot
// change it.
type engineTimeKey [sha256.Size]byte

// engineClock is a non-authoritative engine's notion of an authoritative
// engine's time (RFC 3414 section 2.3): the boots and the latest engine time
// received (latestReceivedEngineTime), and when it was received, by the
// monotonic clock. The engine time then advances with the local clock. The
// zero clock is no notion.
type engineClock struct {
	boots, latest uint32
	received      time.Time
}

// known reports whether c is a notion of an engine's time.
func (c engineClock) known() bool { return !c.received.IsZero() }

// local returns c's notion of the engine time at now: the latest received
// time advanced by the whole seconds since, not wrapped.
func (c engineClock) local(now time.Time) int64 {
	return int64(c.latest) + int64(now.Sub(c.received)/time.Second)
}

// at returns c's notion of the engine boots and time at now, as a message
// carries them: past maxEngineValue the time wraps and the boots go up by one,
// unless they are at maxEngineValue (RFC 3414 section 2.2.2; net-snmp's
// get_enginetime).
func (c engineClock) at(now time.Time) (boots, engineTime uint32) {
	t := c.local(now)
	if t <= maxEngineValue {
		return c.boots, uint32(t) //nolint:gosec // within the range checked above
	}
	boots = c.boots
	if boots < maxEngineValue {
		boots++
	}
	return boots, uint32(t - maxEngineValue) //nolint:gosec // elapsed time below 68 years
}

// update applies RFC 3414 section 3.2 step 7 b(1) to c for an authenticated
// message with engine boots and time received at now: a message newer than
// the latest (greater boots, or equal boots and a greater time, with equal
// also an equal time) or the first one, without a notion, becomes the clock.
// It returns the clock after the step and whether it is the message's.
func (c engineClock) update(boots, engineTime uint32, now time.Time, equal bool) (engineClock, bool) {
	if !c.known() || boots > c.boots || boots == c.boots && (engineTime > c.latest || equal && engineTime == c.latest) {
		return engineClock{boots: boots, latest: engineTime, received: now}, true
	}
	return c, false
}

// inWindow applies RFC 3414 section 3.2 step 7 b(2) for a message with engine
// boots and time received at now to c, the clock after b(1): the message is
// outside the time window when c's boots are maxEngineValue, its boots are
// lower, or its time is more than timeWindow seconds behind c's notion of the
// engine time. The parse takes boots and time of at most maxEngineValue only.
func (c engineClock) inWindow(boots, engineTime uint32, now time.Time) bool {
	return c.boots != maxEngineValue && boots >= c.boots && int64(engineTime)+timeWindow >= c.local(now)
}

// admit applies RFC 3414 section 3.2 step 7 b to c for an authenticated
// message with engine boots and time received at now: b(1) updates c with a
// strictly newer message (an exact replay of the latest is no update) or an
// engine's first one, then b(2) decides on the updated clock, which keeps the
// update whatever it decides: a message at boots maxEngineValue leaves the
// clock there.
func (c *engineClock) admit(boots, engineTime uint32, now time.Time) error {
	*c, _ = c.update(boots, engineTime, now, false)
	if !c.inWindow(boots, engineTime, now) {
		return errNotInTime
	}
	return nil
}

func newEngineTimes(now func() time.Time) *engineTimes {
	return &engineTimes{now: now, records: make(map[engineTimeKey]*engineClock)}
}

// keyOf returns the key of the records of an engine and a credential: the
// engine ID and the authentication protocol and key localized to it.
func keyOf(engineID []byte, keys *usmKeys) engineTimeKey {
	var buf [128]byte
	b := append(buf[:0], byte(keys.authProtocol))
	b = binary.BigEndian.AppendUint32(b, uint32(len(engineID))) //nolint:gosec // a message is shorter
	b = append(b, engineID...)
	b = append(b, keys.auth...)
	return sha256.Sum256(b)
}

// admit applies step 7 b (engineClock.admit) to the record of key, a key of
// one of the receiver's users, made by the first message, under the lock.
func (s *engineTimes) admit(key engineTimeKey, boots, engineTime uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.records[key]
	if c == nil {
		c = new(engineClock)
		s.records[key] = c
	}
	return c.admit(boots, engineTime, s.now())
}

// probe applies step 7 b for a message of a user the receiver is learning,
// whose key may have no record yet: to the record of key when there is one,
// otherwise to a new clock, which it returns with made set, for install once
// the user is registered.
func (s *engineTimes) probe(key engineTimeKey, boots, engineTime uint32) (engineClock, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if c := s.records[key]; c != nil {
		return engineClock{}, false, c.admit(boots, engineTime, now)
	}
	var c engineClock
	err := c.admit(boots, engineTime, now)
	return c, true, err
}

// install makes clock the record of key, unless key has one already.
func (s *engineTimes) install(key engineTimeKey, clock engineClock) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.records[key] == nil {
		s.records[key] = &clock
	}
}
