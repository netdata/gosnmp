// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"time"
)

// engineState is the client's notion of the agent's SNMPv3 engine, the local
// configuration datastore of a non-authoritative engine (RFC 3414 section
// 2.3): the engine ID, the user's keys localized to it and the engine boots
// and time; the context engine ID of requests is the engine ID. Every decision
// of a request reads it, and only a commit replaces it, whole, with a value
// validated first (commitEngine); startEngine takes the configuration into it
// when a request starts. It is internal: nothing exported shows it.
type engineState struct {
	// user is the user the keys derive from, as the last request started
	// with it; zero before the first SNMPv3 request.
	user User

	// engineID is the agent's engine ID, empty before discovery; a new value
	// is a new slice, never written.
	engineID []byte
	// clock is the notion of the engine's boots and time, none for a new
	// engine ID (RFC 3414 section 2.3).
	clock sourcedClock
	// keys are the user's keys localized to engineID; without one, the
	// protocols only.
	keys usmKeys
}

// clockSource is where an engine clock came from.
type clockSource uint8

const (
	// fromUnauthenticated: discovery, an unauthenticated answer, a Report
	// lent to a resend, or the caller.
	fromUnauthenticated clockSource = iota
	// fromTimeWindowReport: an unauthenticated notInTimeWindow Report lent
	// to a resend (exchange.settle).
	fromTimeWindowReport
	// fromAuthenticated: an authenticated message (RFC 3414 section 3.2 step
	// 7 b).
	fromAuthenticated
)

// sourcedClock is an engine clock and where it came from.
type sourcedClock struct {
	engineClock
	source clockSource
}

// clockOf returns the clock of engine boots and time received at now from
// source.
func clockOf(boots, engineTime uint32, now time.Time, source clockSource) sourcedClock {
	return sourcedClock{engineClock{boots: boots, latest: engineTime, received: now}, source}
}

// timeFor returns the engine boots and time a request carries when it is sent
// at now (RFC 3414 section 3.1 step 6): c's notion of them, whatever c's
// source, or zeros without a clock. Every request is a read request (send),
// which an on-path sender could replay only as itself, so a clock from
// discovery, an unauthenticated answer or the caller signs it as an
// authenticated clock does; a request without authentication carries the
// notion too, which no agent checks the time of (net-snmp sends its notion;
// section 3.1 step 6 c sends zeros). A request that changes the agent, which
// the client does not send, would need the rule back: authenticated, it
// carries zeros with a clock that is not authenticated, which the agent
// answers with an authenticated notInTimeWindow Report carrying its own
// (section 4).
func (c sourcedClock) timeFor(now time.Time) (boots, engineTime uint32) {
	if !c.known() {
		return 0, 0
	}
	return c.at(now)
}

// errAnswerNoEngineID is the error of an answer that names no engine ID where
// the client needs one, from discovery or to lend (RFC 3414 section 3.2 step 3:
// a zero-length engine ID is unknown).
var errAnswerNoEngineID = inCategory(ErrUnknownEngineID, errors.New("the answer names no engine ID"))

// contextEngineID returns the context engine ID of requests: the engine ID.
func (s *engineState) contextEngineID() []byte {
	return s.engineID
}

// withEngine returns the state for the engine engineID: the same state for its
// own engine ID, else one with the user's keys localized to engineID and no
// clock (RFC 3414 section 2.3: the next authentic message synchronizes it). An
// empty engine ID is an error, and so are keys that do not derive. The state
// keeps engineID, which its caller must not write.
func (s *engineState) withEngine(engineID []byte) (engineState, error) {
	next := *s
	switch {
	case len(engineID) == 0:
		return next, errAnswerNoEngineID
	case bytes.Equal(engineID, s.engineID):
		return next, nil
	}
	keys, err := s.user.localize(engineID)
	if err != nil {
		return next, err
	}
	next.engineID, next.keys, next.clock = engineID, keys, sourcedClock{}
	return next, nil
}

// startEngine takes the configuration into the engine state at the start of
// an SNMPv3 request (and of EncodeMessage): after ForgetEngine the state starts
// over, with no engine ID, so the request discovers the engine again; another
// User keeps the engine ID and clock and derives the keys again for the engine
// ID. Without an engine ID the keys must derive all the same, before
// discovery: FIPS 140-only mode, for one, refuses MD5 and SHA-1. An error ends
// the request and changes nothing.
func (x *Client) startEngine() error {
	next := x.engine
	if x.forgetEngine {
		next = engineState{}
	} else if next.user == x.User {
		return nil
	}
	next.user = x.User
	keys, err := next.user.localize(next.engineID)
	if err != nil {
		return err
	}
	if len(next.engineID) == 0 {
		// No keys before discovery, only their protocols: a message signed
		// or encrypted then (EncodeMessage) fails the key check.
		keys.auth, keys.priv = nil, nil
	}
	next.keys = keys
	x.engine, x.forgetEngine = next, false
	return nil
}

// ForgetEngine makes the client forget what it learned of the agent's SNMPv3
// engine: its engine ID, the keys localized to it, its engine boots and time
// and the context engine ID taken from it. The next request starts from the
// configuration and discovers the engine again (RFC 3414 section 4); a request
// that is running, the one a hook runs in included, keeps the state it has.
// Call it when a request fails with an error that matches ErrUnknownEngineID:
// the agent's engine ID changed (a replaced device), or a forged answer to the
// discovery gave the client another engine's. Like the configuration, it is
// not safe to call while a request runs on another goroutine.
func (x *Client) ForgetEngine() {
	x.forgetEngine = true
}

// commitEngine replaces the engine state with next, a state validated by its
// caller.
func (x *Client) commitEngine(next engineState) {
	x.engine = next
}

// stamp gives packet, a request, the engine state's engine ID and context
// engine ID; its attempts sign and encrypt it with the state's keys and give
// it the engine boots and time (exchange.encode).
func (s *engineState) stamp(packet *Message) {
	packet.SecurityParameters.AuthoritativeEngineID = s.engineID
	packet.ContextEngineID = s.contextEngineID()
}
