// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"slices"
	"time"
)

// engineState is the client's notion of the agent's SNMPv3 engine, the local
// configuration datastore of a non-authoritative engine (RFC 3414 section
// 2.3): the engine ID, the user's keys localized to it, the engine boots and
// time, and the context engine ID of requests. Every decision of a request
// reads it, and only a commit replaces it, whole, with a value validated
// first (commitEngine). The exported fields mirror it (mirrorEngine).
type engineState struct {
	// params is the SecurityParameters value the state follows; nil before
	// the first SNMPv3 request.
	params *UsmSecurityParameters

	engineID string
	// clock is the notion of the engine's boots and time, none for a new
	// engine ID (RFC 3414 section 2.3).
	clock sourcedClock

	// authKey and privKey are the keys localized to engineID. The exported
	// fields get copies, so that a write into them changes no request; the
	// packets of requests and their answers share these.
	authKey, privKey []byte
	// authGiven and privGiven mark keys the caller gave that their
	// passphrases do not derive, which no change of the credentials derives
	// again.
	authGiven, privGiven bool
	// cred are the credentials the keys the client derived come from.
	cred credentials

	// context is the context engine ID the caller configured; empty, requests
	// take engineID.
	context string
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

// timeFor returns the engine boots and time packet, a request, carries when
// it is sent at now (RFC 3414 section 3.1 step 6): c's notion of them when c
// is authenticated, when the request asks for no authentication, which no
// agent checks the time of (net-snmp sends its notion too; section 3.1 step 6
// c sends zeros), or when it is a read request, which an on-path sender could
// replay only as itself; else zeros, as without a clock, which an agent
// answers with an authenticated notInTimeWindow Report carrying its own
// (section 4).
func (c sourcedClock) timeFor(packet *SnmpPacket, now time.Time) (boots, engineTime uint32) {
	if !c.known() || c.source != fromAuthenticated && packet.MsgFlags.authFlag() && !packet.PDUType.read() {
		return 0, 0
	}
	return c.at(now)
}

// credentials are the parameters' fields the keys derive from.
type credentials struct {
	authProtocol   SnmpV3AuthProtocol
	authPassphrase string
	privProtocol   SnmpV3PrivProtocol
	privPassphrase string
}

// engineFields are the values of the exported fields that mirror an engine
// state.
type engineFields struct {
	engineID          string
	boots, engineTime uint32
	authKey, privKey  []byte
	contextEngineID   string
}

// errAnswerNoEngineID is the error of an answer that names no engine ID where
// the client needs one, from discovery or to lend (RFC 3414 section 3.2 step 3:
// a zero-length engine ID is unknown).
var errAnswerNoEngineID = inCategory(ErrUnknownEngineID, errors.New("the answer names no engine ID"))

// contextEngineID returns the context engine ID of requests: the configured
// one, else the engine ID.
func (s *engineState) contextEngineID() string {
	if s.context != "" {
		return s.context
	}
	return s.engineID
}

// fields returns the values the state's exported fields show.
func (s *engineState) fields() engineFields {
	return engineFields{
		engineID:        s.engineID,
		boots:           s.clock.boots,
		engineTime:      s.clock.latest,
		authKey:         s.authKey,
		privKey:         s.privKey,
		contextEngineID: s.contextEngineID(),
	}
}

// sp returns private parameters with the state's credentials, engine ID and
// keys, from which keysFor derives.
func (s *engineState) sp() *UsmSecurityParameters {
	return &UsmSecurityParameters{
		AuthoritativeEngineID:    s.engineID,
		AuthenticationProtocol:   s.cred.authProtocol,
		AuthenticationPassphrase: s.cred.authPassphrase,
		PrivacyProtocol:          s.cred.privProtocol,
		PrivacyPassphrase:        s.cred.privPassphrase,
		SecretKey:                s.authKey,
		PrivacyKey:               s.privKey,
	}
}

// withEngine returns the state for the engine engineID: the same state for its
// own engine ID, else one with the keys keysFor localizes to engineID (an
// error for keys given without a passphrase, which stay bound to their engine
// ID) and no clock (RFC 3414 section 2.3: the next authentic message
// synchronizes it). An empty engine ID is an error.
func (s *engineState) withEngine(engineID string) (engineState, error) {
	next := *s
	switch engineID {
	case "":
		return next, errAnswerNoEngineID
	case s.engineID:
		return next, nil
	}
	authKey, privKey, err := s.sp().keysFor(engineID)
	if err != nil {
		return next, err
	}
	next.engineID, next.authKey, next.privKey = engineID, authKey, privKey
	next.authGiven, next.privGiven = false, false
	next.clock = sourcedClock{}
	return next, nil
}

// reconcileEngine takes into the engine state, at the start of an SNMPv3
// request, what the caller changed since the client last wrote the exported
// fields: another SecurityParameters value is configuration whole; otherwise a
// field that no longer holds the state's value is the caller's from this
// request on (an empty engine ID discovers again, another one has no clock,
// boots and time are a clock, an empty key derives, an empty context engine ID
// follows the engine ID). Keys localize to the engine ID: the client derives
// the missing ones for a known engine ID, a key given for another engine ID
// again from its passphrase (none: an error, the key is bound, but a key
// given without an engine ID or passphrase serves the first one), and the
// ones it derived again after a change of the credentials; a key its passphrase
// derives is the client's, however it reached the field. Without an engine ID
// the keys must derive all the same, before discovery. An error ends the
// request and changes nothing.
func (x *GoSNMP) reconcileEngine() error {
	sp := usmOf(x.SecurityParameters)
	if sp == nil {
		return errors.New("SNMPV3 SecurityParameters must be set")
	}
	sp.mu.Lock()
	cur := engineFields{
		engineID:   sp.AuthoritativeEngineID,
		boots:      sp.AuthoritativeEngineBoots,
		engineTime: sp.AuthoritativeEngineTime,
		authKey:    sp.SecretKey,
		privKey:    sp.PrivacyKey,
	}
	cred := credentials{
		authProtocol:   sp.AuthenticationProtocol,
		authPassphrase: sp.AuthenticationPassphrase,
		privProtocol:   sp.PrivacyProtocol,
		privPassphrase: sp.PrivacyPassphrase,
	}
	sp.mu.Unlock()
	cur.contextEngineID = x.ContextEngineID

	prev := &x.engine
	same := prev.params == sp
	newClock := !same || cur.boots != prev.clock.boots || cur.engineTime != prev.clock.latest
	if same && cur.engineID == prev.engineID && !newClock &&
		bytes.Equal(cur.authKey, prev.authKey) && bytes.Equal(cur.privKey, prev.privKey) &&
		cred == prev.cred && cur.contextEngineID == prev.contextEngineID() {
		return nil
	}

	// A field that holds the state's value and one the caller changed both
	// give the field's value; the keys, the clock and the context engine ID
	// also need to know which it was.
	next := engineState{
		params:   sp,
		engineID: cur.engineID,
		cred:     cred,
		context:  prev.context,
	}
	if cur.contextEngineID != prev.contextEngineID() {
		next.context = cur.contextEngineID
	}
	newEngine, newCred := same && cur.engineID != prev.engineID, same && cred != prev.cred
	// The boots and time are one pair: one the caller set is an
	// unauthenticated clock received now, none for zeros (net-snmp takes
	// non-zero ones only); the state's clock stays for its engine ID.
	switch {
	case newClock && (cur.boots != 0 || cur.engineTime != 0):
		next.clock = clockOf(cur.boots, cur.engineTime, time.Now(), fromUnauthenticated)
	case !newClock && !newEngine:
		next.clock = prev.clock
	}
	fromNone := prev.engineID == ""
	var err error
	if next.authKey, next.authGiven, err = nextKey(cur.authKey, prev.authKey, prev.authGiven, same, newEngine, newCred,
		fromNone, cred.authProtocol > NoAuth && cred.authPassphrase == ""); err != nil {
		return errAuthKeyBoundToEngine
	}
	if next.privKey, next.privGiven, err = nextKey(cur.privKey, prev.privKey, prev.privGiven, same, newEngine, newCred,
		fromNone, cred.privProtocol > NoPriv && cred.privPassphrase == ""); err != nil {
		return errPrivKeyBoundToEngine
	}
	keys := next.sp()
	if err := keys.InitSecurityKeys(); err != nil {
		return err
	}
	if next.engineID == "" {
		// Supplied keys passing validation do not prove their passphrases can
		// derive keys for discovery. Check that too, keeping keys just derived
		// above and keys supplied without passphrases. With PasswordCaching
		// off, discovery hashes the passphrases again for its engine ID.
		if len(next.authKey) != 0 && cred.authPassphrase != "" {
			keys.SecretKey = nil
		}
		if len(next.privKey) != 0 && cred.privPassphrase != "" {
			keys.PrivacyKey = nil
		}
		if err := keys.deriveKeys(); err != nil {
			return err
		}
	} else {
		next.authKey, next.privKey = keys.SecretKey, keys.PrivacyKey
		if next.authGiven || next.privGiven {
			derived := next.sp()
			derived.SecretKey, derived.PrivacyKey = nil, nil
			if derived.deriveKeys() == nil {
				next.authGiven = next.authGiven && !bytes.Equal(next.authKey, derived.SecretKey)
				next.privGiven = next.privGiven && !bytes.Equal(next.privKey, derived.PrivacyKey)
			}
		}
	}
	*prev = next
	x.mirrorEngine(cur, prev)
	return nil
}

// errKeyBound is nextKey's error of a key given for another engine ID.
var errKeyBound = errors.New("key bound to another engine ID")

// nextKey returns a key of the state reconcileEngine builds, from the field's
// key and the state's key, whether the caller gave it, and what changed in
// the same SecurityParameters value (same): the field's key when the caller
// changed it or the value is another (empty: none, to derive); for another
// engine ID none, to derive again, but for a key the caller gave whose
// passphrase is empty (bound) the key itself when the state had no engine ID
// (fromNone: the key serves the first one), else errKeyBound; for other
// credentials none, to derive again, when the client derived it; else the
// state's key.
func nextKey(field, key []byte, given, same, newEngine, newCred, fromNone, bound bool) ([]byte, bool, error) {
	switch {
	case !same || !bytes.Equal(field, key):
		return slices.Clone(field), len(field) != 0, nil
	case newEngine && given && bound && fromNone:
		return key, given, nil
	case newEngine && given && bound:
		return nil, false, errKeyBound
	case newEngine, newCred && !given:
		return nil, false, nil
	}
	return key, given, nil
}

// commitEngine replaces the engine state with next, a state validated by its
// caller, and mirrors it into the exported fields.
func (x *GoSNMP) commitEngine(next engineState) {
	was := x.engine.fields()
	x.engine = next
	x.mirrorEngine(was, &x.engine)
}

// mirrorEngine writes the engine state s into the exported fields that still
// hold was, the values the client last wrote or read there: the fields of the
// SecurityParameters value the state follows, and ContextEngineID. A field a
// caller or a hook changed since keeps the change, which the next request
// takes (reconcileEngine). Keys are written as copies.
func (x *GoSNMP) mirrorEngine(was engineFields, s *engineState) {
	sp := s.params
	sp.mu.Lock()
	if sp.AuthoritativeEngineID == was.engineID {
		sp.AuthoritativeEngineID = s.engineID
	}
	if sp.AuthoritativeEngineBoots == was.boots && sp.AuthoritativeEngineTime == was.engineTime {
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = s.clock.boots, s.clock.latest
	}
	if !bytes.Equal(s.authKey, was.authKey) && bytes.Equal(sp.SecretKey, was.authKey) {
		sp.SecretKey = slices.Clone(s.authKey)
	}
	if !bytes.Equal(s.privKey, was.privKey) && bytes.Equal(sp.PrivacyKey, was.privKey) {
		sp.PrivacyKey = slices.Clone(s.privKey)
	}
	sp.mu.Unlock()
	if x.ContextEngineID == was.contextEngineID {
		x.ContextEngineID = s.contextEngineID()
	}
}

// stamp gives packet, a request's private copy of the parameters, the engine
// state's engine ID and keys, and its context engine ID; each attempt gives it
// the engine boots and time (exchange.encode).
func (s *engineState) stamp(packet *SnmpPacket) {
	sp := packet.SecurityParameters.usm()
	sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey = s.engineID, s.authKey, s.privKey
	packet.ContextEngineID = s.contextEngineID()
}
