// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto/fips140"
	"crypto/hmac"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
)

const (
	lrEngineA = "\x80\x00\x1f\x88\x04learn-a"
	lrEngineB = "\x80\x00\x1f\x88\x04learn-b"
)

var (
	lrAuth   = User{Name: "lr-user", AuthProtocol: SHA, AuthPassphrase: "lr-auth-pass"}
	lrPriv   = User{Name: "lr-user", AuthProtocol: SHA, AuthPassphrase: "lr-auth-pass", PrivProtocol: AES, PrivPassphrase: "lr-priv-pass"}
	lrPlain  = User{Name: "lr-user"}
	lrOther  = User{Name: "lr-other", AuthProtocol: SHA, AuthPassphrase: "lr-other-pass"}
	lrInform = InformRequest
)

// lrMessage is a notification of a learning test: sent by user from
// engineID at level, with the PDU type, boots and time given.
type lrMessage struct {
	engineID    string
	user        User
	level       SecurityLevel
	pdu         PDUType
	boots, time uint32
}

// lrEncode encodes m, signed and encrypted with m.user's keys for its engine
// ID as its level asks, with an SNMPv2-Trap PDU unless m.pdu is set and boots
// and time 3 and 77 unless set.
func lrEncode(t *testing.T, m lrMessage) []byte {
	t.Helper()
	if m.pdu == 0 {
		m.pdu = SNMPv2Trap
	}
	if m.boots == 0 && m.time == 0 {
		m.boots, m.time = 3, 77
	}
	data, err := (&Message{
		Version:       Version3,
		SecurityLevel: m.level,
		SecurityParameters: SecurityParameters{
			AuthoritativeEngineID:    []byte(m.engineID),
			AuthoritativeEngineBoots: m.boots,
			AuthoritativeEngineTime:  m.time,
			UserName:                 m.user.Name,
		},
		ContextEngineID: []byte(m.engineID),
		PDUType:         m.pdu,
		MsgID:           21,
		RequestID:       42,
		VarBinds:        rtVarbinds,
	}).Encode(&m.user)
	require.NoError(t, err)
	return data
}

// TestNewReceiverConfig pins what NewReceiver accepts: users registered for a
// non-empty engine ID, several users of one name for one engine ID, the same
// user for several engine IDs, and LearnUsers with a MaxLearned of at least
// 1; and what it rejects, with the index of the user.
func TestNewReceiverConfig(t *testing.T) {
	at := func(engineID string, u User) EngineUser { return EngineUser{EngineID: []byte(engineID), User: u} }
	tests := map[string]struct {
		config  ReceiverConfig
		wantErr string
	}{
		"empty": {},
		"users of one name for one engine ID": {
			config: ReceiverConfig{Users: []EngineUser{at(lrEngineA, lrAuth), at(lrEngineA, lrPriv), at(lrEngineA, lrPlain)}},
		},
		"one user for two engine IDs": {
			config: ReceiverConfig{Users: []EngineUser{at(lrEngineA, lrAuth), at(lrEngineB, lrAuth)}},
		},
		"learnable users of one name": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth, lrPlain}, MaxLearned: 1},
		},
		"a user without a name": {
			config:  ReceiverConfig{Users: []EngineUser{at(lrEngineA, User{})}},
			wantErr: "ReceiverConfig.Users[0]: User.Name is required",
		},
		"a name of 33 octets": {
			config:  ReceiverConfig{Users: []EngineUser{at(lrEngineA, User{Name: strings.Repeat("n", 33)})}},
			wantErr: "ReceiverConfig.Users[0]: User.Name is 33 octets, more than 32",
		},
		"a learnable user without a name": {
			config:  ReceiverConfig{LearnUsers: []User{lrAuth, {}}, MaxLearned: 1},
			wantErr: "ReceiverConfig.LearnUsers[1]: User.Name is required",
		},
		"a user without an engine ID": {
			config:  ReceiverConfig{Users: []EngineUser{at(lrEngineA, lrAuth), {User: lrOther}}},
			wantErr: "ReceiverConfig.Users[1]: an engine ID is required",
		},
		"the same user twice for an engine ID": {
			config:  ReceiverConfig{Users: []EngineUser{at(lrEngineA, lrAuth), at(lrEngineB, lrAuth), at(lrEngineA, lrAuth)}},
			wantErr: "ReceiverConfig.Users[2]: user lr-user is registered twice for the engine ID",
		},
		"a protocol without a passphrase": {
			config:  ReceiverConfig{Users: []EngineUser{at(lrEngineA, User{Name: "u", AuthProtocol: SHA})}},
			wantErr: "ReceiverConfig.Users[0]: usm: no authentication key, want 20 octets",
		},
		"an unsupported protocol": {
			config:  ReceiverConfig{Users: []EngineUser{at(lrEngineA, User{Name: "u", AuthProtocol: AuthProtocol(99)})}},
			wantErr: "ReceiverConfig.Users[0]: User.AuthProtocol AuthProtocol(99) is not supported",
		},
		"learnable users without MaxLearned": {
			config:  ReceiverConfig{LearnUsers: []User{lrAuth}},
			wantErr: "ReceiverConfig.MaxLearned must be at least 1 when LearnUsers is set",
		},
		"a learnable user twice": {
			config:  ReceiverConfig{LearnUsers: []User{lrAuth, lrPlain, lrAuth}, MaxLearned: 1},
			wantErr: "ReceiverConfig.LearnUsers[2]: user lr-user is given twice",
		},
		"a learnable protocol without a passphrase": {
			config:  ReceiverConfig{LearnUsers: []User{{Name: "u", PrivProtocol: AES}}, MaxLearned: 1},
			wantErr: "ReceiverConfig.LearnUsers[0]: usm: no privacy key, want 16 octets",
		},
		"an unsupported learnable protocol": {
			config:  ReceiverConfig{LearnUsers: []User{{Name: "u", PrivProtocol: PrivProtocol(99)}}, MaxLearned: 1},
			wantErr: "ReceiverConfig.LearnUsers[0]: User.PrivProtocol PrivProtocol(99) is not supported",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := NewReceiver(tc.config)
			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.NotNil(t, r)
				return
			}
			require.EqualError(t, err, tc.wantErr)
			assert.Nil(t, r)
		})
	}
}

// TestNewReceiverFIPS140OnlyLearnUser pins, in FIPS 140-only mode, that a
// LearnUser whose keys the mode refuses (MD5) fails NewReceiver as a
// registered one does, instead of failing every registration of its name, and
// one it allows (SHA-256) does not.
func TestNewReceiverFIPS140OnlyLearnUser(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only")
	}
	md5 := User{Name: "lr-user", AuthProtocol: MD5, AuthPassphrase: "lr-auth-pass"}
	_, err := NewReceiver(ReceiverConfig{Users: []EngineUser{{EngineID: []byte(lrEngineA), User: md5}}})
	require.Error(t, err)
	sha256 := User{Name: "lr-user", AuthProtocol: SHA256, AuthPassphrase: "lr-auth-pass"}
	_, err = NewReceiver(ReceiverConfig{LearnUsers: []User{sha256}, MaxLearned: 1})
	require.NoError(t, err)
	_, err = NewReceiver(ReceiverConfig{LearnUsers: []User{sha256, md5}, MaxLearned: 1})
	require.ErrorContains(t, err, "ReceiverConfig.LearnUsers[1]: ")
	require.ErrorContains(t, err, "FIPS 140-only")
}

// lrStep is a message a learning test sends and what the receiver does with
// it: the error it unwraps to, or whether it learned the message's user.
type lrStep struct {
	msg     lrMessage
	wait    time.Duration
	wantErr error
	// wantText is the error's text, when set.
	wantText string
	learned  bool
}

// TestReceiveLearning pins how a receiver learns a user name for an engine ID
// (RFC 3414 section 3.2 step 3): with the first message a LearnUser of the
// name accepts at its own level, which registers every LearnUser of the name
// for the engine; never with an inform, a message no LearnUser accepts, or
// past MaxLearned; and afterwards, the registered users decode the engine's
// messages, as configured ones do.
func TestReceiveLearning(t *testing.T) {
	trap := func(engineID string, u User, level SecurityLevel) lrMessage {
		return lrMessage{engineID: engineID, user: u, level: level}
	}
	ok := func(m lrMessage, learned bool) lrStep { return lrStep{msg: m, learned: learned} }
	rejected := func(m lrMessage, err error) lrStep { return lrStep{msg: m, wantErr: err} }
	wrongPass := lrAuth
	wrongPass.AuthPassphrase = "lr-wrong-pass"
	wrongPriv := lrPriv
	wrongPriv.PrivPassphrase = "lr-wrong-priv"
	wrongPassPriv := wrongPriv
	wrongPassPriv.AuthPassphrase = "lr-wrong-pass"

	tests := map[string]struct {
		config ReceiverConfig
		steps  []lrStep
	}{
		"the first trap learns, the next is decoded": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 4},
			steps:  []lrStep{ok(trap(lrEngineA, lrAuth, AuthNoPriv), true), ok(trap(lrEngineA, lrAuth, AuthNoPriv), false)},
		},
		"every LearnUser of the name is registered": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth, lrPlain, lrOther}, MaxLearned: 4},
			steps: []lrStep{
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
				ok(trap(lrEngineA, lrPlain, NoAuthNoPriv), false),
				ok(trap(lrEngineA, lrOther, AuthNoPriv), true),
			},
		},
		"an unauthenticated trap for an authentication user": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 4},
			steps: []lrStep{
				rejected(trap(lrEngineA, lrPlain, NoAuthNoPriv), ErrUnknownSecurityLevel),
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
			},
		},
		"an unauthenticated trap for a no-auth user learns": {
			config: ReceiverConfig{LearnUsers: []User{lrPlain}, MaxLearned: 4},
			steps:  []lrStep{ok(trap(lrEngineA, lrPlain, NoAuthNoPriv), true)},
		},
		"a wrong digest learns nothing": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				rejected(trap(lrEngineA, wrongPass, AuthNoPriv), ErrWrongDigest),
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
			},
		},
		"an inform learns nothing": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				rejected(lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv, pdu: lrInform}, ErrUnknownEngineID),
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
			},
		},
		"a request learns nothing": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				rejected(lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv, pdu: GetRequest}, ErrUnknownEngineID),
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
			},
		},
		"the first error of the learnable users on a tie": {
			// Both fail RFC 3414 section 3.2 step 5, each with its own text.
			config: ReceiverConfig{LearnUsers: []User{lrPlain, lrAuth}, MaxLearned: 1},
			steps: []lrStep{{
				msg: trap(lrEngineA, lrPriv, AuthPriv), wantErr: ErrUnknownSecurityLevel,
				wantText: "no credentials successfully unmarshaled trap: " + errNoAuthForMsg.Error(),
			}},
		},
		"the furthest error of the learnable users": {
			// The first decrypts with the wrong key, the second fails the digest.
			config: ReceiverConfig{LearnUsers: []User{wrongPriv, wrongPassPriv}, MaxLearned: 1},
			steps:  []lrStep{rejected(trap(lrEngineA, lrPriv, AuthPriv), ErrDecryption)},
		},
		"a trap at the maximum boots leaves no record before learning": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				rejected(lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv, boots: maxEngineValue, time: 10}, ErrNotInTimeWindow),
				ok(lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv, boots: 3, time: 1}, true),
			},
		},
		"an inform to an engine with users learns nothing": {
			config: ReceiverConfig{Users: []EngineUser{{EngineID: []byte(lrEngineA), User: lrOther}}, LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				rejected(lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv, pdu: lrInform}, ErrUnknownUsername),
			},
		},
		"MaxLearned names": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth, lrOther}, MaxLearned: 1},
			steps: []lrStep{
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
				rejected(trap(lrEngineB, lrAuth, AuthNoPriv), ErrUnknownEngineID),
				rejected(trap(lrEngineA, lrOther, AuthNoPriv), ErrUnknownUsername),
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), false),
			},
		},
		"a name not learnable": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps:  []lrStep{rejected(trap(lrEngineA, lrOther, AuthNoPriv), ErrUnknownEngineID)},
		},
		"a learnable name at an engine with users": {
			config: ReceiverConfig{Users: []EngineUser{{EngineID: []byte(lrEngineA), User: lrOther}}, LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
				ok(trap(lrEngineA, lrOther, AuthNoPriv), false),
			},
		},
		"a configured user is not relearned": {
			config: ReceiverConfig{Users: []EngineUser{{EngineID: []byte(lrEngineA), User: lrAuth}}, LearnUsers: []User{lrPriv}, MaxLearned: 1},
			steps: []lrStep{
				rejected(trap(lrEngineA, lrPriv, AuthPriv), ErrUnknownSecurityLevel),
				ok(trap(lrEngineB, lrPriv, AuthPriv), true),
			},
		},
		"a learned trap's record": {
			config: ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 1},
			steps: []lrStep{
				ok(trap(lrEngineA, lrAuth, AuthNoPriv), true),
				{msg: trap(lrEngineA, lrAuth, AuthNoPriv), wait: 151 * time.Second, wantErr: ErrNotInTimeWindow},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r, advance := newTestReceiver(t, tc.config)
			for i, s := range tc.steps {
				advance(s.wait)
				n, err := r.Receive(lrEncode(t, s.msg))
				if s.wantErr != nil {
					require.ErrorIs(t, err, s.wantErr, "message %d", i)
					if s.wantText != "" {
						require.EqualError(t, err, s.wantText, "message %d", i)
					}
					assert.Nil(t, n, "message %d", i)
					continue
				}
				require.NoError(t, err, "message %d", i)
				assert.Equal(t, s.learned, n.Learned, "message %d learned", i)
				assert.Equal(t, rtVarbinds, n.Message.VarBinds, "message %d", i)
			}
		})
	}
}

// TestReceiveRecordsPerCredential pins that the receiver's time records are
// those of an engine and an authentication credential: users of one key that
// share it share the record, so that a replay the first rejects is not
// accepted by the next as a first contact; another credential has its own;
// another receiver has its own records.
func TestReceiveRecordsPerCredential(t *testing.T) {
	otherAuth := lrAuth
	otherAuth.AuthPassphrase = "lr-auth-pass-b"
	at := func(u User) EngineUser { return EngineUser{EngineID: []byte(lrEngineA), User: u} }
	msg := func(u User, boots, engineTime uint32) []byte {
		return lrEncode(t, lrMessage{engineID: lrEngineA, user: u, level: AuthNoPriv, boots: boots, time: engineTime})
	}

	t.Run("one authentication credential", func(t *testing.T) {
		// lrPriv authenticates lrAuth's authNoPriv traps too.
		r, _ := newTestReceiver(t, ReceiverConfig{Users: []EngineUser{at(lrAuth), at(lrPriv)}})
		_, err := r.Receive(msg(lrAuth, 5, 1000))
		require.NoError(t, err)
		_, err = r.Receive(msg(lrAuth, 4, 1))
		require.ErrorIs(t, err, ErrNotInTimeWindow)
		assert.Len(t, r.times.records, 1)
	})
	t.Run("another authentication credential", func(t *testing.T) {
		r, _ := newTestReceiver(t, ReceiverConfig{Users: []EngineUser{at(lrAuth), at(otherAuth)}})
		_, err := r.Receive(msg(lrAuth, 5, 1000))
		require.NoError(t, err)
		_, err = r.Receive(msg(otherAuth, 4, 1))
		require.NoError(t, err)
		assert.Len(t, r.times.records, 2)
	})
	t.Run("a learned user and a registered one", func(t *testing.T) {
		// lr-reg shares lrAuth's credential at the engine: the record its trap
		// made decides lrAuth's first trap there.
		reg := lrAuth
		reg.Name = "lr-reg"
		r, _ := newTestReceiver(t, ReceiverConfig{Users: []EngineUser{at(reg)}, LearnUsers: []User{lrAuth}, MaxLearned: 1})
		_, err := r.Receive(msg(reg, 5, 1000))
		require.NoError(t, err)
		_, err = r.Receive(msg(lrAuth, 4, 1))
		require.ErrorIs(t, err, ErrNotInTimeWindow)
		assert.Zero(t, r.learned)
		// A trap at the maximum boots locks the shared record, as reg's own would.
		_, err = r.Receive(msg(lrAuth, maxEngineValue, 1))
		require.ErrorIs(t, err, ErrNotInTimeWindow)
		_, err = r.Receive(msg(reg, 5, 1001))
		require.ErrorIs(t, err, ErrNotInTimeWindow)
	})
	t.Run("a learning trap that fails after step 7 b", func(t *testing.T) {
		r, _ := newTestReceiver(t, ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: 4})
		for i := range 3 {
			engineID := fmt.Sprintf("\x80\x00\x1f\x88\x04lr-bad-pdu-%d", i)
			trap := lrEncode(t, lrMessage{engineID: engineID, user: lrAuth, level: AuthNoPriv})
			_, err := r.Receive(lrWithPDUType(t, trap, &lrAuth, []byte(engineID), 0xaf))
			require.ErrorIs(t, err, ErrASNParse)
		}
		assert.Empty(t, r.times.records, "an unknown PDU type learns nothing and leaves no record")
		assert.Zero(t, r.learned)
	})
	t.Run("another receiver", func(t *testing.T) {
		config := ReceiverConfig{Users: []EngineUser{at(lrAuth)}}
		first, _ := newTestReceiver(t, config)
		_, err := first.Receive(msg(lrAuth, 5, 1000))
		require.NoError(t, err)
		second, _ := newTestReceiver(t, config)
		_, err = second.Receive(msg(lrAuth, 4, 1))
		require.NoError(t, err)
	})
}

// TestReceiverRegister pins register's own rules, which concurrent learners
// of one key reach in either order: a name is learned once (a lost race is no
// learning), MaxLearned holds for a new name, and an authenticated trap is
// decided again on the record as it is at registration, so step 7 b stays in
// one order: an older trap that registers first does not hide a newer one.
func TestReceiverRegister(t *testing.T) {
	key := keyOf([]byte(lrEngineA), &usmKeys{authProtocol: SHA, auth: []byte("k")})
	probed := func(r *Receiver, boots, engineTime uint32) *learnProbe {
		p := &learnProbe{times: r.times}
		require.NoError(t, p.admit(key, boots, engineTime))
		require.True(t, p.made)
		return p
	}
	newReceiver := func(t *testing.T) *Receiver {
		r, _ := newTestReceiver(t, ReceiverConfig{LearnUsers: []User{lrAuth, lrOther}, MaxLearned: 1})
		return r
	}

	t.Run("once, then the cap", func(t *testing.T) {
		r := newReceiver(t)
		learned, err := r.register([]byte(lrEngineA), "lr-user", []User{lrAuth}, &learnProbe{})
		require.NoError(t, err)
		assert.True(t, learned)
		learned, err = r.register([]byte(lrEngineA), "lr-user", []User{lrAuth}, &learnProbe{})
		require.NoError(t, err)
		assert.False(t, learned, "a lost race")
		_, err = r.register([]byte(lrEngineB), "lr-user", []User{lrAuth}, probed(r, 3, 77))
		require.ErrorIs(t, err, ErrUnknownEngineID)
		_, err = r.register([]byte(lrEngineA), "lr-other", []User{lrOther}, probed(r, 3, 77))
		require.ErrorIs(t, err, ErrUnknownUsername)
		assert.Equal(t, 1, r.learned)
		assert.Empty(t, r.times.records, "past the cap a trap makes no record")
	})
	t.Run("a lost race through learn", func(t *testing.T) {
		r := newReceiver(t)
		trap := lrEncode(t, lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv})
		first, err := r.Receive(trap)
		require.NoError(t, err)
		require.True(t, first.Learned)
		// The loser read the header before the winner registered the name.
		n := new(Notification)
		_, w, err := unmarshalHeader(trap, &n.Message)
		require.NoError(t, err)
		n, err = r.learn(trap, w, n, false)
		require.NoError(t, err)
		assert.False(t, n.Learned)
	})
	t.Run("an older trap registers first", func(t *testing.T) {
		r := newReceiver(t)
		older, newer := probed(r, 4, 500), probed(r, 5, 1)
		learned, err := r.register([]byte(lrEngineA), "lr-user", []User{lrAuth}, older)
		require.NoError(t, err)
		require.True(t, learned)
		learned, err = r.register([]byte(lrEngineA), "lr-user", []User{lrAuth}, newer)
		require.NoError(t, err, "the newer trap updates the record")
		require.False(t, learned)
		require.ErrorIs(t, r.times.admit(key, 4, 600), ErrNotInTimeWindow, "the record is the newer trap's")
	})
	t.Run("a newer trap registers first", func(t *testing.T) {
		r := newReceiver(t)
		older, newer := probed(r, 4, 500), probed(r, 5, 1)
		_, err := r.register([]byte(lrEngineA), "lr-user", []User{lrAuth}, newer)
		require.NoError(t, err)
		_, err = r.register([]byte(lrEngineA), "lr-user", []User{lrAuth}, older)
		require.ErrorIs(t, err, ErrNotInTimeWindow, "the older trap is decided on the newer's record")
	})
}

// TestReceiveLearningPastTheCapDerivesNoKey pins, with the size of the
// package's key cache, that once the receiver learned MaxLearned names a
// message of a learnable name derives no key: a user of a Reeder-extended
// protocol (AES-256 Cisco) caches one password-to-key result per engine ID
// its privacy key derives for. The learnable user's privacy passphrase differs
// from the sender's, whose keys are cached when its message is made.
func TestReceiveLearningPastTheCapDerivesNoKey(t *testing.T) {
	stamp := time.Now().UnixNano()
	receiver := User{
		Name: "lr-reeder", AuthProtocol: SHA, AuthPassphrase: "lr-auth-pass",
		PrivProtocol: AES256C, PrivPassphrase: fmt.Sprintf("lr-receiver-priv-%d", stamp),
	}
	sender := receiver
	sender.PrivPassphrase = "lr-sender-priv"
	r, _ := newTestReceiver(t, ReceiverConfig{LearnUsers: []User{lrAuth, receiver}, MaxLearned: 1})
	_, err := r.Receive(lrEncode(t, lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv}))
	require.NoError(t, err)

	newEngine := func() string { return fmt.Sprintf("\x80\x00\x1f\x88\x04lr-cap-%d", stamp) }
	trap := lrEncode(t, lrMessage{engineID: newEngine(), user: sender, level: AuthPriv})
	before := passwordCache.Len()
	_, err = r.Receive(trap)
	require.ErrorIs(t, err, ErrUnknownEngineID)
	assert.Equal(t, before, passwordCache.Len())
}

// lrWithPDUType returns the authNoPriv message data with its PDU's tag set to
// tag, signed again with user's key for engineID.
func lrWithPDUType(t *testing.T, data []byte, user *User, engineID []byte, tag byte) []byte {
	t.Helper()
	m := splitV3Message(t, data)
	r := ber.NewReader(m.scoped)
	for range 2 { // contextEngineID, contextName
		_, _, err := r.Next()
		require.NoError(t, err)
	}
	scoped := bytes.Clone(m.scoped)
	scoped[len(m.scoped)-r.Len()] = tag
	m.scoped = scoped
	key, err := user.authKey(engineID)
	require.NoError(t, err)
	m.usm[4] = make([]byte, len(m.usm[4]))
	mac := hmac.New(user.AuthProtocol.hash().New, key)
	mac.Write(m.bytes())
	m.usm[4] = mac.Sum(nil)[:user.AuthProtocol.spec().MACLen]
	return m.bytes()
}

// TestReceiveConcurrent receives traps from several goroutines, which learn
// and decode at once, for the race detector: one name per engine is learned
// once, by one message, and MaxLearned holds.
func TestReceiveConcurrent(t *testing.T) {
	const engines, goroutines = 8, 8
	r, _ := newTestReceiver(t, ReceiverConfig{LearnUsers: []User{lrAuth}, MaxLearned: engines - 2})
	traps := make([][]byte, engines)
	for i := range traps {
		traps[i] = lrEncode(t, lrMessage{engineID: fmt.Sprintf("\x80\x00\x1f\x88\x04learn-%d", i), user: lrAuth, level: AuthNoPriv})
	}
	var mu sync.Mutex
	learned := 0
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for _, trap := range traps {
				n, err := r.Receive(trap)
				if err != nil {
					assert.ErrorIs(t, err, ErrUnknownEngineID)
					continue
				}
				if n.Learned {
					mu.Lock()
					learned++
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	assert.Equal(t, engines-2, learned)
	assert.Equal(t, engines-2, r.learned)
	assert.Len(t, r.users, engines-2)
}

// TestReadEnvelope pins what ReadEnvelope returns: the version of any
// message, and for SNMPv3 the msgID, the level, the reportable flag and the
// USM header, as the wire has them; a header that does not parse is the
// error of its category, with no envelope.
func TestReadEnvelope(t *testing.T) {
	v2c, err := (&Message{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 1, VarBinds: rtVarbinds}).Encode(nil)
	require.NoError(t, err)
	inform := lrEncode(t, lrMessage{engineID: lrEngineA, user: lrPriv, level: AuthPriv, pdu: lrInform, boots: 7, time: 9})
	header := SecurityParameters{
		AuthoritativeEngineID: []byte(lrEngineA), AuthoritativeEngineBoots: 7, AuthoritativeEngineTime: 9, UserName: "lr-user",
	}
	got, err := ReadEnvelope(inform)
	require.NoError(t, err)
	// The digest and the salt are on the wire; the rest is compared whole.
	assert.Len(t, got.SecurityParameters.AuthenticationParameters, 12)
	assert.Len(t, got.SecurityParameters.PrivacyParameters, 8)
	got.SecurityParameters.AuthenticationParameters, got.SecurityParameters.PrivacyParameters = nil, nil
	assert.Equal(t, Envelope{Version: Version3, MsgID: 21, SecurityLevel: AuthPriv, Reportable: true, SecurityParameters: header}, got)

	trap := lrEncode(t, lrMessage{engineID: lrEngineA, user: lrPlain, level: NoAuthNoPriv})
	got, err = ReadEnvelope(trap)
	require.NoError(t, err)
	assert.False(t, got.Reportable)
	assert.Equal(t, NoAuthNoPriv, got.SecurityLevel)

	got, err = ReadEnvelope(v2c)
	require.NoError(t, err)
	assert.Equal(t, Envelope{Version: Version2c}, got)

	// The reportable flag alone (a discovery request's 0x04), and
	// authentication alone (an authNoPriv trap's 0x01).
	probe := lrEncode(t, lrMessage{engineID: lrEngineA, user: lrPlain, level: NoAuthNoPriv, pdu: GetRequest})
	got, err = ReadEnvelope(probe)
	require.NoError(t, err)
	assert.Equal(t, SecurityLevel(0x04), wireFlags(t, probe))
	assert.True(t, got.Reportable)
	assert.Equal(t, NoAuthNoPriv, got.SecurityLevel)
	signed := lrEncode(t, lrMessage{engineID: lrEngineA, user: lrAuth, level: AuthNoPriv})
	got, err = ReadEnvelope(signed)
	require.NoError(t, err)
	assert.Equal(t, SecurityLevel(0x01), wireFlags(t, signed))
	assert.False(t, got.Reportable)
	assert.Equal(t, AuthNoPriv, got.SecurityLevel)

	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"empty":           {in: nil, want: ErrASNParse},
		"version 2":       {in: []byte{0x30, 0x05, 0x02, 0x01, 0x02, 0x04, 0x00}, want: ErrBadVersion},
		"a broken header": {in: inform[:40], want: ErrASNParse},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ReadEnvelope(tc.in)
			require.ErrorIs(t, err, tc.want)
			assert.Equal(t, Envelope{}, got)
		})
	}
}
