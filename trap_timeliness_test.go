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

// timelyReceivers are the trap receivers of the timeliness sequences: a table
// with the three users of encodeTimely, and a single user, codec-user.
var timelyReceivers = []struct {
	name     string
	receiver func(t *testing.T) *Client
	users    []string // the users the receiver knows
}{
	{"table", func(t *testing.T) *Client {
		other := usmUser(SHA, "other-auth-pass", AES, "other-priv-pass")
		other.Name = "other-user"
		tb := NewSnmpV3SecurityParametersTable()
		require.NoError(t, tb.Add(usmUser(SHA, "codec-auth-pass", AES, "codec-priv-pass"), nil))
		require.NoError(t, tb.Add(other, nil))
		require.NoError(t, tb.Add(User{Name: "plain-user"}, nil))
		return &Client{Version: Version3, TrapSecurityParametersTable: tb}
	}, []string{"", "codec-user", "other-user", "plain-user"}},
	{"single", func(*testing.T) *Client {
		x := usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")()
		x.Version, x.SecurityLevel = Version3, AuthPriv
		return x
	}, []string{"", "codec-user"}},
}

// TestTrapTimeliness pins which traps and informs a receiver accepts by the
// engine boots and time they carry (RFC 3414 section 3.2 step 7 b), in
// sequences from one sender engine, each on its own engine ID: a trap newer
// than the latest updates the receiver's notion of the engine's time, which
// then advances with the receiver's clock, and is accepted; an older one more
// than 150 s behind that notion, one of lower boots, and one of an engine at
// the maximum boots are rejected; informs and unauthenticated traps are neither checked nor
// recorded, and each credential has its own records.
func TestTrapTimeliness(t *testing.T) {
	const maxBoots = 2147483647
	ok := func(boots, time uint32) timelyMessage { return timelyMessage{boots: boots, time: time} }
	rejected := func(boots, time uint32) timelyMessage {
		return timelyMessage{boots: boots, time: time, want: ErrNotInTimeWindow}
	}
	// invalid boots or time fail the header parse (RFC 3414 section 3.2 step 1).
	invalid := func(boots, time uint32) timelyMessage {
		return timelyMessage{boots: boots, time: time, want: ErrInvalidMsgs}
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
					known := false
					for _, u := range r.users {
						known = known || u == m.user
					}
					if !known {
						t.Skip("the receiver does not know " + m.user)
					}
				}
				seq++
				engineID := fmt.Sprintf("\x80\x00\x1f\x88\x04tl-%d", seq)
				advance := useEngineTimes(t)
				x := r.receiver(t)
				for i, m := range msgs {
					advance(m.wait)
					_, err := x.UnmarshalTrap(encodeTimely(t, engineID, m), false)
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

// useEngineTimes gives the test its own trap timeliness store, whose clock
// stands still until advance moves it, and restores the package's afterwards:
// tests decode messages of one engine with any boots and time.
func useEngineTimes(tb testing.TB) (advance func(time.Duration)) {
	tb.Helper()
	clock := time.Unix(1_000_000_000, 0)
	prev := trapEngineTimes
	trapEngineTimes = newEngineTimes(maxEngineTimes, func() time.Time { return clock })
	tb.Cleanup(func() { trapEngineTimes = prev })
	return func(d time.Duration) { clock = clock.Add(d) }
}

// TestEngineTimesRecords pins the bounds of the timeliness records: at the
// limit, a new engine replaces the least recently updated one, which then
// starts over (a message with lower boots is accepted again); a message that
// updates nothing does not count as an update, a newer one does.
func TestEngineTimesRecords(t *testing.T) {
	key := func(b byte) engineTimeKey { return engineTimeKey{b} }
	now := time.Unix(1_000_000_000, 0)

	t.Run("an older message is no update", func(t *testing.T) {
		s := newEngineTimes(2, func() time.Time { return now })
		require.NoError(t, s.admit(key(1), 5, 100))
		require.NoError(t, s.admit(key(2), 5, 100))
		require.NoError(t, s.admit(key(1), 5, 50))  // older: 1 stays the least recently updated
		require.NoError(t, s.admit(key(3), 5, 100)) // replaces 1
		assert.Len(t, s.records, 2)
		require.NoError(t, s.admit(key(1), 4, 1), "a replaced engine starts over")
		require.ErrorIs(t, s.admit(key(3), 4, 1), ErrNotInTimeWindow, "a kept engine keeps its record")
	})
	t.Run("a newer message is an update", func(t *testing.T) {
		s := newEngineTimes(2, func() time.Time { return now })
		require.NoError(t, s.admit(key(1), 5, 100))
		require.NoError(t, s.admit(key(2), 5, 100))
		require.NoError(t, s.admit(key(1), 5, 101)) // newer: 2 is the least recently updated
		require.NoError(t, s.admit(key(3), 5, 100)) // replaces 2
		require.ErrorIs(t, s.admit(key(1), 4, 1), ErrNotInTimeWindow, "a kept engine keeps its record")
		require.NoError(t, s.admit(key(2), 4, 1), "a replaced engine starts over")
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
	s := newEngineTimes(4, time.Now)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				_ = s.admit(engineTimeKey{byte(g % 6)}, 1, uint32(i))
			}
		})
	}
	wg.Wait()
	assert.LessOrEqual(t, len(s.records), 4)
	assert.Equal(t, len(s.records), s.updated.Len())
}

// TestTrapEncodedReplay pins that a trap the library's own encoder makes,
// unreportable as RFC 3412 section 6.4 asks, is checked against the time
// window: a copy of it a day later is outside it, on both trap paths.
func TestTrapEncodedReplay(t *testing.T) {
	for _, path := range []string{"single", "table"} {
		t.Run(path, func(t *testing.T) {
			advance := useEngineTimes(t)
			user := signedTestUser(SHA256, AES, "codec-user")
			sender := &Client{Version: Version3, SecurityLevel: AuthPriv, User: user}
			seedEngine(usmCharEngineID, 3, 77)(sender)
			wire, err := sender.EncodeMessage(SNMPv2Trap, usmPlainVars, 0, 0)
			require.NoError(t, err)
			receiver := &Client{Version: Version3, SecurityLevel: AuthPriv, User: user}
			if path == "table" {
				receiver.TrapSecurityParametersTable = NewSnmpV3SecurityParametersTable()
				require.NoError(t, receiver.TrapSecurityParametersTable.Add(user, []byte(usmCharEngineID)))
			}
			got, err := receiver.UnmarshalTrap(bytes.Clone(wire), false)
			require.NoError(t, err)
			require.Equal(t, AuthPriv, got.SecurityLevel)
			advance(24 * time.Hour)
			_, err = receiver.UnmarshalTrap(bytes.Clone(wire), false)
			require.ErrorIs(t, err, ErrNotInTimeWindow)
		})
	}
}

// TestPDUTypeConfirmed pins the Confirmed Class of RFC 3411 section 2.8.2,
// which the time window leaves to the API phase: requests and informs.
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
