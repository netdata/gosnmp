// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
)

// timelyMessage is a message of a timeliness sequence: a trap, or an inform,
// from user at the sequence's engine with the engine boots and time it
// carries, sent after wait.
type timelyMessage struct {
	user        string // codec-user when empty
	boots, time uint32
	inform      bool
	// flipped sends the reportable flag the other way than RFC 3412
	// section 6.4 sets it for the PDU (set for a trap, clear for an inform).
	flipped bool
	wait    time.Duration
	// want is the error a rejection unwraps to, nil for an accepted one.
	want error
}

// encodeTimely encodes m from engineID: codec-user and other-user at
// authPriv (SHA, AES) with their own passphrases, plain-user at noAuthNoPriv.
// What the encoder does not write (a flipped reportable flag, boots or time
// over 2147483647) is put on the wire afterwards (rewireV3).
func encodeTimely(t *testing.T, engineID string, m timelyMessage) []byte {
	t.Helper()
	user := User{Name: m.user}
	flags := AuthPriv
	switch m.user {
	case "", "codec-user":
		user = usmUser(SHA, "codec-auth-pass", AES, "codec-priv-pass")
	case "other-user":
		user.AuthProtocol, user.AuthPassphrase = SHA, "other-auth-pass"
		user.PrivProtocol, user.PrivPassphrase = AES, "other-priv-pass"
	default:
		flags = NoAuthNoPriv
	}
	header := SecurityParameters{
		UserName: user.Name, AuthoritativeEngineID: []byte(engineID),
		AuthoritativeEngineBoots: min(m.boots, maxEngineValue), AuthoritativeEngineTime: min(m.time, maxEngineValue),
	}
	// wire is the msgFlags octet the message carries.
	pdu, wire := SNMPv2Trap, flags
	if m.inform {
		pdu, wire = InformRequest, wire|reportableFlag
	}
	if m.flipped {
		wire ^= reportableFlag
	}
	data, err := (&Message{
		Version: Version3, SecurityLevel: flags, SecurityParameters: header,
		PDUType: pdu, RequestID: 1, VarBinds: usmPlainVars,
	}).Encode(&user)
	require.NoError(t, err)
	if m.flipped || m.boots != header.AuthoritativeEngineBoots || m.time != header.AuthoritativeEngineTime {
		data = rewireV3(t, data, &user, header.AuthoritativeEngineID, wire, m.boots, m.time)
	}
	// A flipped message must carry the flag the other way on the wire.
	require.Equal(t, wire&reportableFlag, wireFlags(t, data)&reportableFlag, "the wire's reportable flag")
	return data
}

// rewireV3 returns the SNMPv3 message data from engineID, signed with user's
// key for it when its flags ask for authentication, with the msgFlags octet
// flags and the engine boots and time given, and signed again: wire values
// the encoder does not write. An encrypted scoped PDU stays as encrypted with
// the encoded boots and time.
func rewireV3(t *testing.T, data []byte, user *User, engineID []byte, flags SecurityLevel, boots, engineTime uint32) []byte {
	t.Helper()
	m := splitV3Message(t, data)
	msgFlagsOctets(byte(flags))(&m)
	m.usm[1], m.usm[2] = ber.AppendUint64(nil, uint64(boots)), ber.AppendUint64(nil, uint64(engineTime))
	if !flags.authFlag() {
		return m.bytes()
	}
	key, err := user.authKey(engineID)
	require.NoError(t, err)
	m.usm[4] = make([]byte, len(m.usm[4]))
	mac := hmac.New(user.AuthProtocol.hash().New, key)
	mac.Write(m.bytes())
	m.usm[4] = mac.Sum(nil)[:user.AuthProtocol.spec().MACLen]
	return m.bytes()
}

// timelyReceivers are the trap receivers of the timeliness sequences, each
// with the three users of encodeTimely: registered for the sequence's engine
// ID, or to learn for it (informs, which are never learned, are left out).
var timelyReceivers = []struct {
	name    string
	config  func(engineID []byte) ReceiverConfig
	informs bool // the receiver takes informs
}{
	{"registered", func(engineID []byte) ReceiverConfig {
		var config ReceiverConfig
		for _, u := range timelyUsers() {
			config.Users = append(config.Users, EngineUser{EngineID: engineID, User: u})
		}
		return config
	}, true},
	{"learning", func([]byte) ReceiverConfig {
		return ReceiverConfig{LearnUsers: timelyUsers(), MaxLearned: 3}
	}, false},
}

// timelyUsers are the users of encodeTimely.
func timelyUsers() []User {
	other := usmUser(SHA, "other-auth-pass", AES, "other-priv-pass")
	other.Name = "other-user"
	return []User{usmUser(SHA, "codec-auth-pass", AES, "codec-priv-pass"), other, {Name: "plain-user"}}
}

// TestTrapTimeliness pins which traps and informs a receiver accepts by the
// engine boots and time they carry (RFC 3414 section 3.2 step 7 b), in
// sequences from one sender engine, each on its own engine ID: a trap newer
// than the latest updates the receiver's notion of the engine's time, which
// then advances with the receiver's clock, and is accepted; an older one more
// than 150 s behind that notion, one of lower boots, and one of an engine at
// the maximum boots are rejected; informs and unauthenticated traps are neither checked nor
// recorded, and each credential has its own records. A learned user's first
// trap starts its record.
func TestTrapTimeliness(t *testing.T) {
	const maxBoots = 2147483647
	ok := func(boots, time uint32) timelyMessage { return timelyMessage{boots: boots, time: time} }
	rejected := func(boots, time uint32) timelyMessage {
		return timelyMessage{boots: boots, time: time, want: ErrNotInTimeWindow}
	}
	// invalid boots or time fail the header parse (RFC 3414 section 3.2 step 1).
	invalid := func(boots, time uint32) timelyMessage {
		return timelyMessage{boots: boots, time: time, want: ErrASNParse}
	}
	after := func(wait time.Duration, m timelyMessage) timelyMessage { m.wait = wait; return m }
	inform := func(m timelyMessage) timelyMessage { m.inform = true; return m }
	flipped := func(m timelyMessage) timelyMessage { m.flipped = true; return m }
	from := func(user string, m timelyMessage) timelyMessage { m.user = user; return m }

	tests := map[string][]timelyMessage{
		"the latest again, at once":           {ok(3, 1000), ok(3, 1000)},
		"the latest again, 150 s later":       {ok(3, 1000), after(150*time.Second, ok(3, 1000))},
		"the latest again, 151 s later":       {ok(3, 1000), after(151*time.Second, rejected(3, 1000))},
		"lower boots":                         {ok(5, 100), rejected(4, 999)},
		"150 s older than the latest":         {ok(3, 1000), ok(3, 850)},
		"151 s older than the latest":         {ok(3, 1000), rejected(3, 849)},
		"100 s later, 50 s older":             {ok(3, 1000), after(100*time.Second, ok(3, 950))},
		"100 s later, 51 s older":             {ok(3, 1000), after(100*time.Second, rejected(3, 949))},
		"200 s later, newer":                  {ok(3, 1000), after(200*time.Second, ok(3, 1001))},
		"an older one updates nothing":        {ok(3, 1000), ok(3, 900), after(100*time.Second, rejected(3, 949))},
		"a reboot, then the old boots":        {ok(3, 1000), ok(4, 5), rejected(3, 2000)},
		"boots 2147483647, twice":             {rejected(maxBoots, 10), rejected(maxBoots, 20)},
		"boots 2147483647 after an update":    {ok(3, 1000), rejected(maxBoots, 10), rejected(3, 1001), rejected(4, 1)},
		"boots above 2147483647, then low":    {invalid(maxBoots+1, 10), ok(1, 1)},
		"time above 2147483647, then low":     {invalid(1, maxBoots+1), ok(1, 1)},
		"informs, then a trap":                {inform(ok(3, 1000)), inform(ok(2, 1)), ok(1, 1)},
		"reportable traps, 151 s later":       {flipped(ok(3, 1000)), after(151*time.Second, flipped(rejected(3, 1000)))},
		"a reportable trap, then lower boots": {flipped(ok(5, 100)), rejected(4, 999)},
		"unreportable informs, then a trap":   {flipped(inform(ok(3, 1000))), flipped(inform(ok(2, 1))), ok(1, 1)},
		"unauthenticated, then authenticated": {from("plain-user", ok(100, 100)), ok(3, 77)},
		"unauthenticated, 151 s later":        {from("plain-user", ok(3, 1000)), after(151*time.Second, from("plain-user", ok(3, 1000)))},
		"another credential, lower boots":     {ok(9, 9), from("other-user", ok(1, 1))},
	}

	var seq int
	for name, msgs := range tests {
		for _, r := range timelyReceivers {
			t.Run(name+"/"+r.name, func(t *testing.T) {
				for _, m := range msgs {
					if m.inform && !r.informs {
						t.Skip("informs are never learned")
					}
				}
				seq++
				engineID := fmt.Sprintf("\x80\x00\x1f\x88\x04tl-%d", seq)
				x, advance := newTestReceiver(t, r.config([]byte(engineID)))
				for i, m := range msgs {
					advance(m.wait)
					_, err := x.Receive(encodeTimely(t, engineID, m))
					if m.want == nil {
						assert.NoError(t, err, "message %d", i)
					} else {
						assert.ErrorIs(t, err, m.want, "message %d", i)
					}
				}
			})
		}
	}
}

// TestEngineTimesRecords pins the records' lifecycle: admit makes a key's
// record with its first message and keeps every record (no eviction).
func TestEngineTimesRecords(t *testing.T) {
	key := func(b byte) engineTimeKey { return engineTimeKey{b} }
	now := time.Unix(1_000_000_000, 0)

	t.Run("every record is kept", func(t *testing.T) {
		s := newEngineTimes(func() time.Time { return now })
		for b := range 200 {
			require.NoError(t, s.admit(key(byte(b)), 5, 100))
		}
		assert.Len(t, s.records, 200)
		for b := range 200 {
			require.ErrorIs(t, s.admit(key(byte(b)), 4, 1), ErrNotInTimeWindow, "record %d", b)
		}
	})
}

// TestEngineTimesKeys pins what the records of a trap's engine are keyed by:
// the authentication protocol, the engine ID and the localized key.
func TestEngineTimesKeys(t *testing.T) {
	type keyInput struct {
		engineID string
		keys     usmKeys
	}
	base := func() keyInput {
		return keyInput{engineID: "engine", keys: usmKeys{authProtocol: SHA, auth: []byte("key")}}
	}
	keyOfInput := func(k keyInput) engineTimeKey { return keyOf([]byte(k.engineID), &k.keys) }
	keys := map[engineTimeKey]string{keyOfInput(base()): "base"}
	for name, edit := range map[string]func(k *keyInput){
		"another protocol":           func(k *keyInput) { k.keys.authProtocol = SHA256 },
		"another engine ID":          func(k *keyInput) { k.engineID = "engine2" },
		"another key":                func(k *keyInput) { k.keys.auth = []byte("key2") },
		"an engine ID longer by 1":   func(k *keyInput) { k.engineID, k.keys.auth = "enginek", []byte("ey") },
		"another engine ID, as long": func(k *keyInput) { k.engineID = "engin2" },
		"an engine ID of 200 bytes":  func(k *keyInput) { k.engineID = string(make([]byte, 200)) },
	} {
		k := base()
		edit(&k)
		key := keyOfInput(k)
		require.NotContains(t, keys, key, name)
		keys[key] = name
	}
	assert.Equal(t, keyOfInput(base()), keyOfInput(base()))
}

// TestEngineTimesConcurrent runs admit from several goroutines, for the race
// detector: each update is one step under the lock.
func TestEngineTimesConcurrent(t *testing.T) {
	s := newEngineTimes(time.Now)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				_ = s.admit(engineTimeKey{byte(g % 6)}, 1, uint32(i))
			}
		})
	}
	wg.Wait()
	assert.Len(t, s.records, 6)
}

// TestTrapEncodedReplay pins that a trap the library's own encoder makes,
// unreportable as RFC 3412 section 6.4 asks, is checked against the time
// window: a copy of it a day later is outside it, for a registered user and
// for a learned one.
func TestTrapEncodedReplay(t *testing.T) {
	user := signedTestUser(SHA256, AES, "codec-user")
	for name, config := range map[string]ReceiverConfig{
		"registered": {Users: []EngineUser{{EngineID: []byte(usmCharEngineID), User: user}}},
		"learned":    {LearnUsers: []User{user}, MaxLearned: 1},
	} {
		t.Run(name, func(t *testing.T) {
			sender := &Client{Version: Version3, SecurityLevel: AuthPriv, User: user}
			seedEngine(usmCharEngineID, 3, 77)(sender)
			wire, err := sender.EncodeMessage(SNMPv2Trap, usmPlainVars, 0, 0)
			require.NoError(t, err)
			receiver, advance := newTestReceiver(t, config)
			got, err := receiver.Receive(bytes.Clone(wire))
			require.NoError(t, err)
			require.Equal(t, AuthPriv, got.Message.SecurityLevel)
			advance(24 * time.Hour)
			_, err = receiver.Receive(bytes.Clone(wire))
			require.ErrorIs(t, err, ErrNotInTimeWindow)
		})
	}
}

// TestPDUTypeConfirmed pins the Confirmed Class of RFC 3411 section 2.8.2,
// which the time window leaves out and the receiver never learns: requests
// and informs.
func TestPDUTypeConfirmed(t *testing.T) {
	want := map[PDUType]bool{
		GetRequest: true, GetNextRequest: true, GetBulkRequest: true, SetRequest: true, InformRequest: true,
		Response: false, Trap: false, SNMPv2Trap: false, Report: false, ber.Sequence: false,
	}
	got := make(map[PDUType]bool, len(want))
	for pdu := range want {
		got[pdu] = pdu.confirmed()
	}
	assert.Equal(t, want, got)
}
