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
// informs of every version, each a datagram the caller read, and makes the
// answers the RFCs give them, for the caller to send. It holds the SNMPv3
// users of each engine (the usmUserTable of RFC 3414 section 2.1), the users
// it may learn for an engine it has none for, the time records of the other
// engines that sent it authenticated messages, and its own engine, the
// authoritative engine of the informs it receives. It opens no socket and
// sends nothing. A Receiver is safe for concurrent use.
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
	// times holds the time records of the other engines.
	times *engineTimes
	// local is the receiver's own engine, nil without one.
	local *localEngine
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	// Users are the SNMPv3 users of each engine: an SNMPv3 message is
	// decoded with the users registered for its user name and engine ID,
	// tried in the order given. Several users may share a name and an
	// engine ID; the same user twice may not.
	Users []EngineUser

	// LearnUsers are the users the receiver may learn for any engine ID other
	// than its own (RFC 3414 section 3.2 step 3 lets a non-authoritative
	// engine create the entry of an engine it does not know; the receiver
	// creates one per user name, also at an engine it has users of other
	// names for). An unreportable message whose user name and engine ID have
	// no user is decoded with the LearnUsers of its name, tried in the order
	// given; once one accepts it, by the security processing at the user's own
	// level, the receiver registers every LearnUser of the name for the engine
	// ID. A message of the Confirmed Class (an inform) is never learned: its
	// engine is the receiver's. A LearnUser without an authentication protocol
	// learns from unauthenticated messages, which anyone can send naming any
	// engine ID.
	LearnUsers []User

	// MaxLearned is how many user names, each for one engine ID, the
	// receiver learns at most, every name counting against it; it must be at
	// least 1 when LearnUsers is set.
	MaxLearned int

	// EngineID is the receiver's own engine ID (snmpEngineID, 5..32 octets,
	// RFC 3411) and EngineBoots its engine boots (snmpEngineBoots,
	// 1..2147483647), which the caller keeps across restarts and raises by
	// one at each (RFC 3414 section 2.2.2); the receiver counts its engine
	// time in seconds from NewReceiver on, from 0 again with the boots one
	// higher past 2147483647 seconds. Both are set, or neither. The
	// receiver is the authoritative engine of the messages that name EngineID
	// (see the package documentation, Notifications): it decodes them with the
	// Users registered for EngineID, which it never learns, answers their
	// informs and the discovery and time synchronization of their senders.
	// Without them, it takes no SNMPv3 inform and sends no Report.
	EngineID    []byte
	EngineBoots uint32
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
// for their engine IDs. A local engine ID outside 5..32 octets or engine boots
// outside 1..2147483647 (or one without the other), a user with an empty
// engine ID or a name outside 1..32 octets, the same user twice for an engine
// ID or in LearnUsers, a protocol out of its set and a key that does not
// derive (a protocol without a passphrase, or one FIPS 140-only mode refuses)
// fail.
func NewReceiver(config ReceiverConfig) (*Receiver, error) {
	return newReceiver(config, time.Now)
}

// newReceiver is NewReceiver with now, the clock of the local engine's time
// and of the time records.
func newReceiver(config ReceiverConfig, now func() time.Time) (*Receiver, error) {
	r := &Receiver{
		users:      make(map[string]map[string][]*tableUser),
		learnable:  make(map[string][]User),
		maxLearned: config.MaxLearned,
		times:      newEngineTimes(now),
	}
	if err := checkLocalEngine(config.EngineID, config.EngineBoots); err != nil {
		return nil, err
	}
	if len(config.EngineID) > 0 {
		r.local = newLocalEngine(config.EngineID, config.EngineBoots, now)
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

// Sizes of snmpEngineID (SNMP-FRAMEWORK-MIB, RFC 3411).
const (
	minEngineIDLen = 5
	maxEngineIDLen = 32
)

// checkLocalEngine checks a receiver's own engine ID and boots: neither, or
// an snmpEngineID of 5..32 octets and snmpEngineBoots of 1..2147483647
// (SNMP-FRAMEWORK-MIB, RFC 3411).
func checkLocalEngine(id []byte, boots uint32) error {
	switch {
	case len(id) == 0 && boots == 0:
		return nil
	case len(id) < minEngineIDLen || len(id) > maxEngineIDLen:
		return fmt.Errorf("ReceiverConfig.EngineID is %d octets, not %d..%d", len(id), minEngineIDLen, maxEngineIDLen)
	case boots < 1 || boots > maxEngineValue:
		return fmt.Errorf("ReceiverConfig.EngineBoots %d is outside 1..%d", boots, maxEngineValue)
	}
	return nil
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
// or no notification with an error; and the response to send back to the
// datagram's sender, or nil: the Response to an inform it accepted, or the
// Report of a rejected SNMPv3 message that asked its authoritative engine for
// one (see the package documentation, Notifications), which comes with the
// rejection's error. Receive decodes any PDU type, answers only informs and
// does not compare the community: check PDUType and Community, and send the
// response only for a notification the caller accepts.
//
// An SNMPv3 message goes through the security processing of RFC 3414 section
// 3.2, by its own flags, with the users registered for its user name and engine
// ID, tried in the order added until one accepts it, and each rejection unwraps
// (errors.Is) to the error named after the step's counter: it must name an
// engine ID (ErrUnknownEngineID); the receiver must have a user for the engine
// ID (ErrUnknownEngineID) and one of the user name for it (ErrUnknownUsername),
// unless it learns one (ReceiverConfig.LearnUsers); the user must have the
// protocols the message asks for (ErrUnknownSecurityLevel); a message that asks
// for authentication must carry a digest that checks with the user's key
// (ErrWrongDigest) and be in the time window (ErrNotInTimeWindow): of the local
// engine for a message naming its ID, of the record of the message's engine
// otherwise (see the package documentation); a message is decrypted exactly
// when it asks for privacy, with the privacy key derived, for a user being
// learned, only once the digest checked (ErrDecryption). Then the receiver's
// minimum level applies (ErrUnknownSecurityLevel): a user with an
// authentication protocol accepts only authenticated messages. When no user
// accepts the message, the error is the one of the user that got furthest
// through these steps, the first on ties. A reportable message naming an engine
// ID the receiver has no user for, and any message naming one of another size
// than 5..32 octets it has no user for, is ErrUnknownEngineID before any key is
// used and never learned: the first asks its authoritative engine, which the
// receiver is not; the second names no engine (RFC 3414 section 3.2 step 3;
// with users of other names there, it is ErrUnknownUsername, still never
// learned). A request or an inform naming another engine ID than the receiver's
// own is ErrUnknownEngineID once decoded (RFC 3412 section 7.2 step 13 a): its
// answer would come from that engine.
//
// The notification's OctetString, Opaque and IPAddress values alias
// datagram (see the package documentation).
func (r *Receiver) Receive(datagram []byte) (*Notification, []byte, error) {
	n := new(Notification)
	cursor, w, err := unmarshalHeader(datagram, &n.Message)
	if err != nil {
		return nil, nil, err
	}
	if n.Message.Version != Version3 {
		if err = unmarshalPayload(datagram, cursor, &n.Message); err != nil {
			return nil, nil, err
		}
		return accept(n, datagram[cursor:], nil, nil)
	}
	h := &n.Message.SecurityParameters
	if r.local.is(h.AuthoritativeEngineID) {
		return r.receiveLocal(datagram, w, n)
	}
	if len(h.AuthoritativeEngineID) == 0 {
		return r.rejectUnknownEngine(datagram, w, n, errNoEngineID)
	}
	r.mu.RLock()
	byName, engineKnown := r.users[string(h.AuthoritativeEngineID)]
	users := byName[h.UserName]
	learnable := r.learned < r.maxLearned
	r.mu.RUnlock()
	// An engine ID of another size than snmpEngineID's is unknown unless the
	// caller registered users for it, and never learned (RFC 3414 section 3.2
	// step 3).
	legal := len(h.AuthoritativeEngineID) >= minEngineIDLen && len(h.AuthoritativeEngineID) <= maxEngineIDLen
	switch {
	case len(users) > 0:
		if _, _, err = r.decodeWith(datagram, w, n, users, r.times.admitMessage); err != nil {
			return nil, nil, err
		}
		if n.Message.PDUType.confirmed() {
			return nil, nil, errNotLocalEngine
		}
		return n, nil, nil
	case !w.reportable && legal && learnable && len(r.learnable[h.UserName]) > 0:
		if n, err = r.learn(datagram, w, n); err != nil {
			return nil, nil, err
		}
		return n, nil, nil
	case !engineKnown:
		return r.rejectUnknownEngine(datagram, w, n, errUnknownEngine)
	}
	return nil, nil, r.unknownUser(h.UserName, true)
}

// receiveLocal decodes the SNMPv3 message whose header is in n and w, which
// names the local engine ID: with the users registered for it, in the time
// window of the local engine (RFC 3414 section 3.2 step 7 a). An accepted
// inform gets its Response (accept), a message outside the time window its
// Report (report), signed by the user whose digest checked, as the step asks.
func (r *Receiver) receiveLocal(datagram []byte, w v3Wire, n *Notification) (*Notification, []byte, error) {
	header := n.Message
	r.mu.RLock()
	users := r.users[string(r.local.id)][header.SecurityParameters.UserName]
	r.mu.RUnlock()
	if len(users) == 0 {
		return nil, nil, r.unknownUser(header.SecurityParameters.UserName, true)
	}
	u, pdu, err := r.decodeWith(datagram, w, n, users, r.local.admitMessage)
	if err != nil {
		var report []byte
		if errors.Is(err, ErrNotInTimeWindow) {
			count := r.local.notInTimeWindows.Add(1)
			report = r.report(datagram, w, &header, usmStatsNotInTimeWindows, count, &u.keys)
		}
		return nil, report, err
	}
	return accept(n, pdu, u, r.local)
}

// rejectUnknownEngine returns err, the error of an SNMPv3 message whose engine
// ID the receiver has no user for (RFC 3414 section 3.2 step 3), counted, with
// its Report.
func (r *Receiver) rejectUnknownEngine(datagram []byte, w v3Wire, n *Notification, err error) (*Notification, []byte, error) {
	count := r.countUnknownEngine()
	if r.local == nil {
		return nil, nil, err
	}
	return nil, r.report(datagram, w, &n.Message, usmStatsUnknownEngineIDs, count, nil), err
}

// countUnknownEngine counts a message rejected for an unknown engine ID in
// usmStatsUnknownEngineIDs and returns the count; a receiver without a local
// engine reports nothing, so it counts nothing.
func (r *Receiver) countUnknownEngine() uint32 {
	if r.local == nil {
		return 0
	}
	return r.local.unknownEngineIDs.Add(1)
}

// unknownUser returns the error of a message whose user name the receiver
// has no user of for its engine ID: ErrUnknownEngineID, counted, when it has
// no user for the engine ID at all (RFC 3414 section 3.2 step 3),
// ErrUnknownUsername otherwise (step 4).
func (r *Receiver) unknownUser(name string, engineKnown bool) error {
	if !engineKnown {
		r.countUnknownEngine()
		return errUnknownEngine
	}
	return inCategory(ErrUnknownUsername, fmt.Errorf("no user %s for the message's engine ID", name))
}

// decodeWith decodes the SNMPv3 message whose header is in n and w with
// users, in order, deciding step 7 with admit; the first that accepts it wins
// and is returned, with the PDU (decodeV3). When none does, the error wraps
// the one of the user that got furthest, which is returned.
func (r *Receiver) decodeWith(datagram []byte, w v3Wire, n *Notification, users []*tableUser, admit timeliness) (*tableUser, []byte, error) {
	// The attempts share the header's USM fields: they run one after the
	// other, each on a copy of the header.
	header := n.Message
	var furthest error
	var reached v3Step
	var who *tableUser
	for i, u := range users {
		if i > 0 {
			n.Message = header
		}
		step, pdu, err := decodeV3(datagram, w, &n.Message, &u.user, &u.keys, admit)
		if err == nil {
			return u, pdu, nil
		}
		if furthest == nil || step > reached {
			furthest, reached, who = err, step, u
		}
	}
	return who, nil, noUserAccepted(furthest)
}

// noUserAccepted returns the error of a message no user accepted, err being
// the one of the user that got furthest.
func noUserAccepted(err error) error {
	return fmt.Errorf("no credentials successfully unmarshaled trap: %w", err)
}

// learn decodes the SNMPv3 message whose header is in n and w with the users
// the receiver may learn for its user name, in order, the keys derived for its
// engine ID; once one accepts a message that is not of the Confirmed Class, it
// registers them all for the engine ID (register). When none does, the error
// wraps the one of the user that got furthest.
func (r *Receiver) learn(datagram []byte, w v3Wire, n *Notification) (*Notification, error) {
	header := n.Message
	h := &header.SecurityParameters
	candidates := r.learnable[h.UserName]
	var furthest error
	var reached v3Step
	for i := range candidates {
		if i > 0 {
			n.Message = header
		}
		probe := learnProbe{times: r.times}
		step, _, err := decodeV3(datagram, w, &n.Message, &candidates[i], nil, probe.admitMessage)
		if err != nil {
			if furthest == nil || step > reached {
				furthest, reached = err, step
			}
			continue
		}
		if n.Message.PDUType.confirmed() {
			return nil, errNotLocalEngine
		}
		learned, err := r.register(h.AuthoritativeEngineID, h.UserName, candidates, &probe)
		if err != nil {
			return nil, err
		}
		n.Learned = learned
		return n, nil
	}
	return nil, noUserAccepted(furthest)
}

// register registers users, the users the receiver may learn for name, for
// engineID, with their keys localized to it, unless the name was registered
// for the engine ID meanwhile (learned false) or the receiver learned
// MaxLearned names (its error). An authenticated trap the
// probe decided on a new clock is decided again by step 7 b
// (engineTimes.admit) on the record of its engine and credential, made now
// when there is none: a concurrent message of the credential may have made it
// since, and step 7 b stays one update per message, in one order.
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
		return false, r.unknownUser(name, engineKnown)
	}
	if probe.made {
		if err := r.times.admit(probe.key, probe.boots, probe.engineTime); err != nil {
			return false, noUserAccepted(err)
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
// being learned (engineTimes.probe), and keeps what register needs to decide
// the message again when the probe had no record to decide it on (made).
type learnProbe struct {
	times             *engineTimes
	key               engineTimeKey
	boots, engineTime uint32
	made              bool
}

func (p *learnProbe) admitMessage(h *SecurityParameters, keys usmKeys) error {
	key := keyOf(h.AuthoritativeEngineID, &keys)
	made, err := p.times.probe(key, h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime)
	if made {
		p.key, p.boots, p.engineTime, p.made = key, h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime, true
	}
	return err
}

// timeliness decides RFC 3414 section 3.2 step 7 for an authenticated
// message whose USM header is h, processed with keys: step 7 a for the local
// engine (localEngine.admitMessage), 7 b for another (engineTimes.admitMessage,
// learnProbe.admitMessage).
type timeliness func(h *SecurityParameters, keys usmKeys) error

// v3Step is how far an SNMPv3 message got through decodeV3 with one user: the
// steps of RFC 3414 section 3.2 from step 4 on, in order, the minimum level,
// the PDU. A local failure counts at the step it occurred in.
type v3Step uint8

const (
	stepUser v3Step = iota
	stepLevel
	stepDigest
	stepTimeliness
	stepPrivacy
	stepMinimum
	stepPDU
)

// decodeV3 decodes the SNMPv3 message whose header is in result and w for
// user, with keys, the user's keys localized to the message's engine ID (nil:
// they derive for it), and returns how far it got: the security processing
// from RFC 3414 section 3.2 step 4 on, by the message's level and in the
// RFC's order, with step 7 by admit for an authenticated message, the user's
// minimum level, then the PDU, which it returns on success, decrypted.
func decodeV3(msg []byte, w v3Wire, result *Message, user *User, keys *usmKeys, admit timeliness) (v3Step, []byte, error) {
	in, err := receiveV3(msg, w, result, user, keys)
	if err != nil {
		if errors.Is(err, ErrUnknownSecurityLevel) {
			return stepLevel, nil, err
		}
		return stepUser, nil, err
	}
	flags := result.SecurityLevel
	if flags.authFlag() {
		if err = in.verify(); err != nil {
			return stepDigest, nil, err
		}
		if err = admit(&result.SecurityParameters, in.keys); err != nil {
			return stepTimeliness, nil, err
		}
	}
	scoped, cursor, err := in.scopedPDU(result)
	if err != nil {
		return stepPrivacy, nil, err
	}
	if user.levelFloor().authFlag() && !flags.authFlag() {
		return stepMinimum, nil, errBelowMinimum
	}
	if err = unmarshalPayload(scoped, cursor, result); err != nil {
		return stepPDU, nil, err
	}
	return stepPDU, scoped[cursor:], nil
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
