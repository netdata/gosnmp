// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"container/list"
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
	// maxEngineTimes bounds the records of trapEngineTimes.
	maxEngineTimes = 65536
)

// trapEngineTimes holds the records of the trap paths of every client in the
// process, so that a receiver that decodes with tables or clients it builds
// per message keeps them. Tests replace it.
var trapEngineTimes = newEngineTimes(maxEngineTimes, time.Now) //nolint:gochecknoglobals // see above

// engineTimes holds a receiver's notion of the engine boots and time of the
// engines whose authenticated Unconfirmed-class messages (traps) it accepted,
// one record per engine and credential, and decides with it whether such a
// message is in the time window (RFC 3414 section 3.2 step 7 b, for the
// receiver of a message whose sender is the authoritative engine). It holds
// at most limit records: a new one then replaces the least recently updated,
// whose engine starts over with its next message.
type engineTimes struct {
	mu      sync.Mutex
	limit   int
	now     func() time.Time
	records map[engineTimeKey]*list.Element
	// updated orders the records, the most recently updated first.
	updated list.List
}

// engineTimeKey identifies the records of one engine for one credential: the
// SHA-256 of the authentication protocol, the engine ID and the
// authentication key localized to it. Parameter sets sharing a passphrase
// share a record; another credential, which may authenticate any engine ID,
// cannot change it.
type engineTimeKey [sha256.Size]byte

// engineTimeRecord is the receiver's notion of an engine's time: the boots
// and the latest engine time received (latestReceivedEngineTime), and when it
// was received, by the monotonic clock. The engine time then advances with the
// local clock (RFC 3414 section 2.3).
type engineTimeRecord struct {
	key          engineTimeKey
	boots        uint32
	latest       uint32
	receivedTime time.Time
}

func newEngineTimes(limit int, now func() time.Time) *engineTimes {
	return &engineTimes{limit: limit, now: now, records: make(map[engineTimeKey]*list.Element)}
}

// keyOf returns the key of the records of sp's engine and credential.
func keyOf(sp *UsmSecurityParameters) engineTimeKey {
	var buf [128]byte
	b := append(buf[:0], byte(sp.AuthenticationProtocol))
	b = binary.BigEndian.AppendUint32(b, uint32(len(sp.AuthoritativeEngineID))) //nolint:gosec // a message is shorter
	b = append(b, sp.AuthoritativeEngineID...)
	b = append(b, sp.SecretKey...)
	return sha256.Sum256(b)
}

// admit applies RFC 3414 section 3.2 step 7 b to an authenticated message
// with engine boots and time, as one update under the lock: a newer message
// than the latest (greater boots, or equal boots and a greater time) updates
// the record (b(1)), the first one of an engine creates it; then the message is
// outside the time window when the boots of the record are maxEngineValue,
// its boots are lower, or, with equal boots, its time is more than timeWindow
// seconds behind the latest received time advanced by the time since (b(2)).
// The parse takes boots and time of at most maxEngineValue only.
func (s *engineTimes) admit(key engineTimeKey, boots, engineTime uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	e, ok := s.records[key]
	if !ok {
		e = s.insert(key)
	}
	r := e.Value.(*engineTimeRecord) //nolint:forcetypeassert // the list holds only records
	if !ok || boots > r.boots || boots == r.boots && engineTime > r.latest {
		r.boots, r.latest, r.receivedTime = boots, engineTime, now
		s.updated.MoveToFront(e)
	}
	local := int64(r.latest) + int64(now.Sub(r.receivedTime)/time.Second)
	if r.boots == maxEngineValue || boots < r.boots || int64(engineTime)+timeWindow < local {
		return errNotInTime
	}
	return nil
}

// insert adds an empty record for key, removing the least recently updated
// one when the records are at the limit.
func (s *engineTimes) insert(key engineTimeKey) *list.Element {
	if len(s.records) >= s.limit {
		oldest := s.updated.Back()
		delete(s.records, oldest.Value.(*engineTimeRecord).key) //nolint:forcetypeassert // the list holds only records
		s.updated.Remove(oldest)
	}
	e := s.updated.PushFront(&engineTimeRecord{key: key})
	s.records[key] = e
	return e
}
