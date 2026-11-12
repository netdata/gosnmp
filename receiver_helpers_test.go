// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestReceiver returns the receiver of config, whose local engine time and
// time records run on a clock of their own, which starts at a fixed instant
// and moves only when the returned advance is called.
func newTestReceiver(tb testing.TB, config ReceiverConfig) (r *Receiver, advance func(time.Duration)) {
	tb.Helper()
	var mu sync.Mutex
	clock := time.Unix(1_000_000_000, 0)
	r, err := newReceiver(config, func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	})
	require.NoError(tb, err)
	return r, func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(d)
	}
}

// receiverAt returns a receiver (newTestReceiver) of users, each registered
// for engineID, in order.
func receiverAt(tb testing.TB, engineID []byte, users ...User) *Receiver {
	tb.Helper()
	config := ReceiverConfig{Users: make([]EngineUser, len(users))}
	for i, u := range users {
		config.Users[i] = EngineUser{EngineID: engineID, User: u}
	}
	r, _ := newTestReceiver(tb, config)
	return r
}

// receiverFor returns a receiver (receiverAt) of users registered for the
// engine ID datagram names, or for codecEngineID when its header does not
// read or names none, so that Receive reaches the users for any datagram that
// parses.
func receiverFor(tb testing.TB, datagram []byte, users ...User) *Receiver {
	tb.Helper()
	engineID := []byte(codecEngineID)
	if e, err := ReadEnvelope(datagram); err == nil && len(e.SecurityParameters.AuthoritativeEngineID) > 0 {
		engineID = e.SecurityParameters.AuthoritativeEngineID
	}
	return receiverAt(tb, engineID, users...)
}

// receiveMessage returns the message r accepted from datagram, or nil with
// the error.
func receiveMessage(r *Receiver, datagram []byte) (*Message, error) {
	n, _, err := r.Receive(datagram)
	if err != nil {
		return nil, err
	}
	return &n.Message, nil
}
