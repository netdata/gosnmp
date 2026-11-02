// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Receiver decodes the notifications an SNMP manager receives: traps and
// informs of every version, each a datagram the caller read. It holds the
// SNMPv3 users of each engine (the usmUserTable of RFC 3414 section 2.1), the
// users it may learn for an engine it has none for, and the time records of
// the engines that sent it authenticated traps. It opens no socket and sends
// nothing. A Receiver is safe for concurrent use.
type Receiver struct {
	// mu guards users and learned: Receive reads them, learning adds to
	// them. A user name's slice is never changed once set, so it is used
	// after the lock is released.
	mu sync.RWMutex
	// users holds the users of each engine ID, by user name, in the order
	// added.
	users map[string]map[string][]*tableUser
	// learnable holds the users the receiver may learn, by name, in the
	// order configured; learned counts the user names it learned, at most
	// maxLearned.
	learnable           map[string][]User
	learned, maxLearned int
	// times holds the time records of the users' engines.
	times *engineTimes
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	// Users are the SNMPv3 users of each engine: an SNMPv3 message is
	// decoded with the users registered for its user name and engine ID,
	// tried in the order given. Several users may share a name and an
	// engine ID; the same user twice may not.
	Users []EngineUser

	// LearnUsers are the users the receiver may learn for any engine ID
	// (RFC 3414 section 3.2 step 3 lets a non-authoritative engine create the
	// entry of an engine it does not know; the receiver creates one per user
	// name, also at an engine it has users of other names for). A message
	// whose user name and engine ID have no user is decoded with the
	// LearnUsers of its name,
	// tried in the order given; once one accepts it, by the security
	// processing at the user's own level, the receiver registers every
	// LearnUser of the name for the engine ID. A message of the Confirmed
	// Class (an inform) is never learned: its engine is the receiver's. A
	// LearnUser without an authentication protocol learns from
	// unauthenticated messages, which anyone can send naming any engine ID.
	LearnUsers []User

	// MaxLearned is how many user names, each for one engine ID, the
	// receiver learns at most, every name counting against it; it must be at
	// least 1 when LearnUsers is set.
	MaxLearned int
}

// EngineUser is an SNMPv3 user registered for an engine ID: the
// authoritative engine of the messages the user sends, an agent's for its
// traps, the receiver's own for informs.
type EngineUser struct {
	EngineID []byte
	User     User
}

// Notification is a notification a Receiver accepted: the decoded message,
// which holds no secret, and whether its user was learned by it.
type Notification struct {
	Message Message

	// Learned reports that the message made the receiver learn its user
	// name for its engine ID (ReceiverConfig.LearnUsers).
	Learned bool
}

var errLearnWithoutMax = errors.New("ReceiverConfig.MaxLearned must be at least 1 when LearnUsers is set")

// NewReceiver returns a receiver of config's users, whose keys it derives
// for their engine IDs. A user with an empty engine ID or a name outside 1..32
// octets, the same user twice for an engine ID or in LearnUsers, a protocol out
// of its set and a key that does not derive (a protocol without a passphrase,
// or one FIPS 140-only mode refuses) fail.
func NewReceiver(config ReceiverConfig) (*Receiver, error) {
	r := &Receiver{
		users:      make(map[string]map[string][]*tableUser),
		learnable:  make(map[string][]User),
		maxLearned: config.MaxLearned,
		times:      newEngineTimes(time.Now),
	}
	for i, u := range config.Users {
		if err := r.add(u.EngineID, u.User); err != nil {
			return nil, fmt.Errorf("ReceiverConfig.Users[%d]: %w", i, err)
		}
	}
	if len(config.LearnUsers) > 0 && config.MaxLearned < 1 {
		return nil, errLearnWithoutMax
	}
	for i, u := range config.LearnUsers {
		if err := r.addLearnable(u); err != nil {
			return nil, fmt.Errorf("ReceiverConfig.LearnUsers[%d]: %w", i, err)
		}
	}
	return r, nil
}

// add registers user for engineID, with its keys localized to it.
func (r *Receiver) add(engineID []byte, user User) error {
	if len(engineID) == 0 {
		return errors.New("an engine ID is required")
	}
	if err := user.checkName(); err != nil {
		return err
	}
	byName := r.users[string(engineID)]
	for _, u := range byName[user.Name] {
		if u.user == user {
			return fmt.Errorf("user %s is registered twice for the engine ID", user.Name)
		}
	}
	keys, err := user.localize(engineID)
	if err != nil {
		return err
	}
	if byName == nil {
		byName = make(map[string][]*tableUser)
		r.users[string(engineID)] = byName
	}
	byName[user.Name] = append(byName[user.Name], &tableUser{user: user, keys: keys})
	return nil
}

// addLearnable adds user to the users the receiver may learn, after deriving
// its keys once, for the empty engine ID, so that a key that cannot derive
// (a protocol without a passphrase, or one FIPS 140-only mode refuses) fails
// here rather than every registration of its name.
func (r *Receiver) addLearnable(user User) error {
	if err := user.checkName(); err != nil {
		return err
	}
	if _, err := user.localize(nil); err != nil {
		return err
	}
	if slices.Contains(r.learnable[user.Name], user) {
		return fmt.Errorf("user %s is given twice", user.Name)
	}
	r.learnable[user.Name] = append(r.learnable[user.Name], user)
	return nil
}

// Receive decodes datagram, a notification of any version, and returns it,
// or no notification with an error. Receive decodes any PDU type and does not
// compare the community: check PDUType and Community.
//
// An SNMPv3 message goes through the security processing of RFC 3414 section
// 3.2, by its own flags, with the users registered for its user name and
// engine ID, tried in the order added until one accepts it, and each
// rejection unwraps (errors.Is) to the error named after the step's counter:
// it must name an engine ID (ErrUnknownEngineID); the receiver must have a
// user for the engine ID (ErrUnknownEngineID) and one of the user name for it
// (ErrUnknownUsername), unless it learns one (ReceiverConfig.LearnUsers); the
// user must have the protocols the message asks for
// (ErrUnknownSecurityLevel); a message that asks for authentication must
// carry a digest that checks with the user's key (ErrWrongDigest); a message
// is decrypted exactly when it asks for privacy, with the privacy key derived,
// for a user being learned, only once the digest checked (ErrDecryption); an
// authenticated message whose PDU is not a request or an inform, a trap, must
// be in the time window of its engine (ErrNotInTimeWindow, see the package
// documentation). Then the receiver's minimum level applies
// (ErrUnknownSecurityLevel): a user with an authentication protocol accepts
// only authenticated messages. When no user accepts the message, the error is
// the one of the user that got furthest through these steps, the first on
// ties. An inform is decoded with the users of the engine ID it names, as any
// message: Receive does not check that it names the receiver's own engine ID,
// an inform's authoritative engine (RFC 3414 section 1.5.1); the caller does.
//
// The notification's OctetString, Opaque and IPAddress values alias
// datagram (see the package documentation).
func (r *Receiver) Receive(datagram []byte) (*Notification, error) {
	n := new(Notification)
	cursor, w, err := unmarshalHeader(datagram, &n.Message)
	if err != nil {
		return nil, err
	}
	if n.Message.Version != Version3 {
		if err := unmarshalPayload(datagram, cursor, &n.Message); err != nil {
			return nil, err
		}
		return n, nil
	}
	h := &n.Message.SecurityParameters
	if len(h.AuthoritativeEngineID) == 0 {
		return nil, errNoEngineID
	}
	r.mu.RLock()
	byName, engineKnown := r.users[string(h.AuthoritativeEngineID)]
	users := byName[h.UserName]
	learnable := r.learned < r.maxLearned
	r.mu.RUnlock()
	switch {
	case len(users) > 0:
		return r.decodeWith(datagram, w, n, users)
	case learnable && len(r.learnable[h.UserName]) > 0:
		return r.learn(datagram, w, n, engineKnown)
	}
	return nil, unknownUser(h.UserName, engineKnown)
}

// unknownUser returns the error of a message whose user name the receiver
// has no user of for its engine ID: ErrUnknownEngineID when it has no user
// for the engine ID at all (RFC 3414 section 3.2 step 3), ErrUnknownUsername
// otherwise (step 4).
func unknownUser(name string, engineKnown bool) error {
	if !engineKnown {
		return errUnknownEngine
	}
	return inCategory(ErrUnknownUsername, fmt.Errorf("no user %s for the message's engine ID", name))
}

// decodeWith decodes the SNMPv3 message whose header is in n and w with
// users, in order; the first that accepts it wins, and when none does, the
// error wraps the one of the user that got furthest.
func (r *Receiver) decodeWith(datagram []byte, w v3Wire, n *Notification, users []*tableUser) (*Notification, error) {
	// The attempts share the header's USM fields: they run one after the
	// other, each on a copy of the header.
	header := n.Message
	var furthest error
	var reached trapStep
	for i, u := range users {
		if i > 0 {
			n.Message = header
		}
		step, err := decodeTrapV3(datagram, w, &n.Message, &u.user, &u.keys, r.times.admit)
		if err == nil {
			return n, nil
		}
		if furthest == nil || step > reached {
			furthest, reached = err, step
		}
	}
	return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", furthest)
}

// learn decodes the SNMPv3 message whose header is in n and w with the users
// the receiver may learn for its user name, in order, the keys derived for its
// engine ID; once one accepts a message that is not of the Confirmed Class, it
// registers them all for the engine ID (register). When none does, the error
// wraps the one of the user that got furthest.
func (r *Receiver) learn(datagram []byte, w v3Wire, n *Notification, engineKnown bool) (*Notification, error) {
	header := n.Message
	h := &header.SecurityParameters
	candidates := r.learnable[h.UserName]
	var furthest error
	var reached trapStep
	for i := range candidates {
		if i > 0 {
			n.Message = header
		}
		probe := learnProbe{now: r.times.now}
		step, err := decodeTrapV3(datagram, w, &n.Message, &candidates[i], nil, probe.admit)
		if err != nil {
			if furthest == nil || step > reached {
				furthest, reached = err, step
			}
			continue
		}
		if n.Message.PDUType.confirmed() {
			return nil, unknownUser(h.UserName, engineKnown)
		}
		learned, err := r.register(h.AuthoritativeEngineID, h.UserName, candidates, &probe)
		if err != nil {
			return nil, err
		}
		n.Learned = learned
		return n, nil
	}
	return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", furthest)
}

// register registers users, the users the receiver may learn for name, for
// engineID, with their keys localized to it, unless the name was registered
// for the engine ID meanwhile (learned false) or the receiver learned
// MaxLearned names (its error). An authenticated trap is decided again by step
// 7 b (engineTimes.admit) on the record of its engine and credential, made now
// when there is none: another user's message, or a concurrent one, may have
// made it since probe decided it, and step 7 b stays one update per message,
// in one order.
func (r *Receiver) register(engineID []byte, name string, users []User, probe *learnProbe) (bool, error) {
	entries := make([]*tableUser, len(users))
	for i, u := range users {
		keys, err := u.localize(engineID)
		if err != nil {
			return false, err
		}
		entries[i] = &tableUser{user: u, keys: keys}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	byName, engineKnown := r.users[string(engineID)]
	_, registered := byName[name]
	if !registered && r.learned >= r.maxLearned {
		return false, unknownUser(name, engineKnown)
	}
	if probe.checked {
		if err := r.times.admit(probe.key, probe.boots, probe.engineTime); err != nil {
			return false, err
		}
	}
	if registered {
		return false, nil
	}
	if byName == nil {
		byName = make(map[string][]*tableUser)
		r.users[string(engineID)] = byName
	}
	byName[name] = entries
	r.learned++
	return true, nil
}

// learnProbe applies RFC 3414 section 3.2 step 7 b for a message of a user
// being learned on a new clock, which rejects only an engine at the maximum
// boots: the message is not the receiver's yet, so it changes no record. It
// keeps what register needs to decide the message on the record.
type learnProbe struct {
	now               func() time.Time
	key               engineTimeKey
	boots, engineTime uint32
	checked           bool
}

func (p *learnProbe) admit(key engineTimeKey, boots, engineTime uint32) error {
	p.key, p.boots, p.engineTime, p.checked = key, boots, engineTime, true
	var c engineClock
	return c.admit(boots, engineTime, p.now())
}

// trapStep is how far an SNMPv3 trap got through decodeTrapV3 with one user:
// the steps of RFC 3414 section 3.2 from step 4 on (step 7 after step 8, which
// reveals the PDU type it depends on), the minimum level, the PDU. A local
// failure counts at the step it occurred in.
type trapStep uint8

const (
	stepUser trapStep = iota
	stepLevel
	stepDigest
	stepPrivacy
	stepTimeliness
	stepMinimum
	stepPDU
)

// decodeTrapV3 decodes the SNMPv3 trap whose header is in result and w for
// user, with keys, the user's keys localized to the message's engine ID (nil:
// they derive for it), and returns how far it got: the security processing from RFC 3414 section
// 3.2 step 4 on, by the message's level, with step 7 b by admit for a
// decrypted PDU not of the Confirmed Class (RFC 3412 section 6.4: the PDU
// type, not the reportable flag, decides once the PDU decodes), the user's
// minimum level, then the PDU.
func decodeTrapV3(trap []byte, w v3Wire, result *Message, user *User, keys *usmKeys, admit func(engineTimeKey, uint32, uint32) error) (trapStep, error) {
	in, err := receiveV3(trap, w, result, user, keys)
	if err != nil {
		if errors.Is(err, ErrUnknownSecurityLevel) {
			return stepLevel, err
		}
		return stepUser, err
	}
	flags := result.SecurityLevel
	if flags.authFlag() {
		if err = in.verify(); err != nil {
			return stepDigest, err
		}
	}
	scoped, cursor, err := in.scopedPDU(result)
	if err != nil {
		return stepPrivacy, err
	}
	// Step 7 b, for a message whose sender is the authoritative engine: any
	// but a Confirmed-class one (an inform), whose receiver is, and whose time
	// the library does not keep. A PDU that does not decode fails below.
	if flags.authFlag() && (cursor >= len(scoped) || !PDUType(scoped[cursor]).confirmed()) {
		h := &result.SecurityParameters
		if err = admit(keyOf(h.AuthoritativeEngineID, &in.keys), h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime); err != nil {
			return stepTimeliness, err
		}
	}
	if user.levelFloor().authFlag() && !flags.authFlag() {
		return stepMinimum, errBelowMinimum
	}
	return stepPDU, unmarshalPayload(scoped, cursor, result)
}

// Envelope is what a datagram's header says before any security processing:
// the version and, for SNMPv3, the msgID and the flags of msgGlobalData and
// the User-based Security Model's parameters. None of it is authenticated.
type Envelope struct {
	Version Version

	// The SNMPv3 msgID, the security level and the reportableFlag of
	// msgFlags (RFC 3412 section 6).
	MsgID         uint32
	SecurityLevel SecurityLevel
	Reportable    bool

	// SecurityParameters are the message's USM parameters (copies).
	SecurityParameters SecurityParameters
}

// ReadEnvelope reads the header of datagram, a message of any version, by the
// rules a decode reads it with and with the errors of their categories: the
// message's SEQUENCE, which must span datagram, the version and, for SNMPv1
// and SNMPv2c, the community (not returned), or, for SNMPv3, every header
// field up to the USM parameters. It returns no envelope with an error, also
// when the version read. It decodes no PDU, derives no key and checks no
// digest.
func ReadEnvelope(datagram []byte) (Envelope, error) {
	var m Message
	_, w, err := unmarshalHeader(datagram, &m)
	if err != nil {
		return Envelope{}, err
	}
	e := Envelope{Version: m.Version}
	if m.Version == Version3 {
		e.MsgID, e.SecurityLevel, e.Reportable = m.MsgID, m.SecurityLevel, w.reportable
		e.SecurityParameters = m.SecurityParameters
	}
	return e, nil
}
