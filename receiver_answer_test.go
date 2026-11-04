// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The receiver as the authoritative engine of the messages naming its own
// engine ID: step 7 a, the Response to an inform and the Reports.

const (
	ansLocalID = "\x80\x00\x1f\x88\x04local-engine"
	ansAgentID = "\x80\x00\x1f\x88\x04agent-engine"
	ansBoots   = 9
)

var (
	ansAuth = User{Name: "ans-user", AuthProtocol: SHA, AuthPassphrase: "ans-auth-pass"}
	ansPriv = User{
		Name: "ans-user", AuthProtocol: SHA, AuthPassphrase: "ans-auth-pass",
		PrivProtocol: AES, PrivPassphrase: "ans-priv-pass",
	}
	ansPlain = User{Name: "ans-user"}
)

// ansReceiver returns a receiver whose own engine is ansLocalID at boots
// ansBoots, with users registered for it, and the advance of its clock, at
// which its engine time starts at 0.
func ansReceiver(t *testing.T, users ...User) (*Receiver, func(time.Duration)) {
	t.Helper()
	config := ReceiverConfig{EngineID: []byte(ansLocalID), EngineBoots: ansBoots}
	for _, u := range users {
		config.Users = append(config.Users, EngineUser{EngineID: []byte(ansLocalID), User: u})
	}
	return newTestReceiver(t, config)
}

// ansMessage is an SNMPv3 message of the answer tests: from user, at level,
// naming engineID (ansLocalID when empty) with boots and time, msgID 21 and
// request ID 42, the PDU type pdu (InformRequest when zero) and rtVarbinds.
type ansMessage struct {
	user        User
	level       SecurityLevel
	engineID    string
	boots, time uint32
	pdu         PDUType
	maxSize     uint32
	varbinds    []VarBind
}

func ansEncode(t *testing.T, m ansMessage) []byte {
	t.Helper()
	if m.engineID == "" {
		m.engineID = ansLocalID
	}
	if m.pdu == 0 {
		m.pdu = InformRequest
	}
	if m.varbinds == nil {
		m.varbinds = rtVarbinds
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
		ContextName:     "inform-context",
		PDUType:         m.pdu,
		MsgID:           21,
		RequestID:       42,
		MsgMaxSize:      m.maxSize,
		VarBinds:        m.varbinds,
	}).Encode(&m.user)
	require.NoError(t, err)
	return data
}

// ansProbe encodes a discovery request (RFC 3414 section 4): an
// unauthenticated GetRequest, reportable, with msgID 99, request ID 42, no
// varbind and no engine ID, from user name.
func ansProbe(t *testing.T, name string) []byte {
	t.Helper()
	data, err := (&Message{
		Version: Version3, SecurityLevel: NoAuthNoPriv, SecurityParameters: SecurityParameters{UserName: name},
		PDUType: GetRequest, MsgID: 99, RequestID: 42,
	}).Encode(nil)
	require.NoError(t, err)
	return data
}

// decodeAnswer decodes an answer of the local engine as the inform's sender
// does: with user registered for ansLocalID by a receiver of its own engine,
// which checks the digest and step 7 b on a new record; an unauthenticated one
// (user nil) by DecodeMessage.
func decodeAnswer(t *testing.T, data []byte, user *User) *Message {
	t.Helper()
	if user == nil {
		m, err := new(Client).DecodeMessage(data)
		require.NoError(t, err)
		return m
	}
	m, err := receiveMessage(receiverAt(t, []byte(ansLocalID), *user), data)
	require.NoError(t, err)
	return m
}

// ansWant returns the message an answer of the local engine decodes to: at
// level, to name, at the local engine time engineTime, with msgID 21 and
// request ID 42, and the PDU type and varbinds given, with the digest and
// salt of got, whose values no test pins.
func ansWant(got *Message, level SecurityLevel, name string, engineTime uint32, pdu PDUType, contextName string, varbinds []VarBind) Message {
	return Message{
		Version:       Version3,
		SecurityLevel: level,
		SecurityParameters: SecurityParameters{
			AuthoritativeEngineID:    []byte(ansLocalID),
			AuthoritativeEngineBoots: ansBoots,
			AuthoritativeEngineTime:  engineTime,
			UserName:                 name,
			AuthenticationParameters: got.SecurityParameters.AuthenticationParameters,
			PrivacyParameters:        got.SecurityParameters.PrivacyParameters,
		},
		ContextEngineID: []byte(ansLocalID),
		ContextName:     contextName,
		PDUType:         pdu,
		MsgID:           21,
		RequestID:       42,
		MsgMaxSize:      rxBufSize,
		VarBinds:        varbinds,
	}
}

// TestInformResponse pins the Response to an accepted inform (RFC 3416
// section 4.2.7, RFC 3412 section 7.1 step 2): for SNMPv3, from the local
// engine (its ID, boots and time), with the inform's msgID, level, user name,
// context, request ID and varbinds, unreportable, signed and encrypted for the
// sender as the level asks; for SNMPv2c, with the community, also without a
// local engine, and no longer than the inform. The receiver answers nothing
// else.
func TestInformResponse(t *testing.T) {
	for name, user := range map[string]User{
		"noAuthNoPriv":      ansPlain,
		"authNoPriv":        ansAuth,
		"authPriv":          ansPriv,
		"authPriv, MD5 DES": {Name: "ans-user", AuthProtocol: MD5, AuthPassphrase: "ans-auth-pass", PrivProtocol: DES, PrivPassphrase: "ans-priv-pass"},
		"authPriv, SHA-512 Reeder AES-256": {
			Name: "ans-user", AuthProtocol: SHA512, AuthPassphrase: "ans-auth-pass", PrivProtocol: AES256C, PrivPassphrase: "ans-priv-pass",
		},
	} {
		t.Run(name, func(t *testing.T) {
			level := rtCredentials{auth: max(user.AuthProtocol, NoAuth), priv: max(user.PrivProtocol, NoPriv)}.flags()
			r, advance := ansReceiver(t, user)
			advance(40 * time.Second)
			n, response, err := r.Receive(ansEncode(t, ansMessage{user: user, level: level, boots: ansBoots, time: 30}))
			require.NoError(t, err)
			require.Equal(t, InformRequest, n.Message.PDUType)
			require.NotNil(t, response)
			assert.Zero(t, wireFlags(t, response)&reportableFlag, "a Response is unreportable")
			got := decodeAnswer(t, response, &user)
			assert.Equal(t, ansWant(got, level, "ans-user", 40, Response, "inform-context", rtVarbinds), *got)
		})
	}

	t.Run("a salt of its own", func(t *testing.T) {
		r, _ := ansReceiver(t, ansPriv)
		inform := ansEncode(t, ansMessage{user: ansPriv, level: AuthPriv, boots: ansBoots})
		salts := [][]byte{splitV3Message(t, inform).usm[5]}
		for range 2 {
			_, response, err := r.Receive(bytes.Clone(inform))
			require.NoError(t, err)
			salt := splitV3Message(t, response).usm[5]
			require.Len(t, salt, 8)
			for _, s := range salts {
				require.NotEqual(t, s, salt, "the inform's salt or another Response's")
			}
			salts = append(salts, salt)
		}
	})

	t.Run("by the user that accepted it", func(t *testing.T) {
		first, second := ansPriv, ansPriv
		second.AuthPassphrase, second.PrivPassphrase = "ans-auth-pass-2", "ans-priv-pass-2"
		r, _ := ansReceiver(t, first, second)
		_, response, err := r.Receive(ansEncode(t, ansMessage{user: second, level: AuthPriv, boots: ansBoots}))
		require.NoError(t, err)
		decodeAnswer(t, response, &second)
		_, err = receiveMessage(receiverAt(t, []byte(ansLocalID), first), response)
		require.ErrorIs(t, err, ErrWrongDigest, "signed by the first user")
	})

	t.Run("varbinds the encoder refuses, as they came", func(t *testing.T) {
		// An unknown value type and an empty IpAddress decode (see Values)
		// but do not encode: the Response repeats the inform's octets.
		quirky := craftedVBL(craftedVB(tlv(0x88, []byte("x"))), craftedVB(tlv(byte(IPAddress))))
		v2c, err := (&Message{Version: Version2c, Community: "public", PDUType: InformRequest, RequestID: 42, echoed: quirky}).Encode(nil)
		require.NoError(t, err)
		v3, err := (&Message{
			Version: Version3, SecurityLevel: AuthPriv, PDUType: InformRequest, MsgID: 21, RequestID: 42, echoed: quirky,
			SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(ansLocalID), AuthoritativeEngineBoots: ansBoots, UserName: "ans-user"},
		}).Encode(&ansPriv)
		require.NoError(t, err)
		for name, inform := range map[string][]byte{"SNMPv2c": v2c, "SNMPv3": v3} {
			t.Run(name, func(t *testing.T) {
				r, _ := ansReceiver(t, ansPriv)
				n, response, err := r.Receive(inform)
				require.NoError(t, err)
				require.NotNil(t, response)
				var got *Message
				if name == "SNMPv2c" {
					assert.True(t, bytes.Contains(response, quirky), "the varbind list's octets")
					got, err = new(Client).DecodeMessage(response)
					require.NoError(t, err)
				} else {
					got = decodeAnswer(t, response, &ansPriv)
				}
				assert.Equal(t, Response, got.PDUType)
				assert.Equal(t, n.Message.VarBinds, got.VarBinds)
			})
		}
	})

	t.Run("tooBig past the inform's msgMaxSize", func(t *testing.T) {
		r, _ := ansReceiver(t, ansAuth)
		big := []VarBind{{Name: ".1.3.6.1.4.1.20372.1.2.9", Value: OctetStringValue(bytes.Repeat([]byte{'x'}, 600))}}
		_, response, err := r.Receive(ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots, maxSize: 484, varbinds: big}))
		require.NoError(t, err)
		got := decodeAnswer(t, response, &ansAuth)
		want := ansWant(got, AuthNoPriv, "ans-user", 0, Response, "inform-context", []VarBind{})
		want.ErrorStatus = TooBig
		assert.Equal(t, want, *got)
		assert.LessOrEqual(t, len(response), 484)
	})

	t.Run("SNMPv2c", func(t *testing.T) {
		for name, config := range map[string]ReceiverConfig{
			"with a local engine":    {EngineID: []byte(ansLocalID), EngineBoots: ansBoots},
			"without a local engine": {},
		} {
			t.Run(name, func(t *testing.T) {
				inform, err := (&Message{
					Version: Version2c, Community: "public", PDUType: InformRequest, RequestID: 42, VarBinds: rtVarbinds,
				}).Encode(nil)
				require.NoError(t, err)
				r, _ := newTestReceiver(t, config)
				_, response, err := r.Receive(inform)
				require.NoError(t, err)
				got, err := new(Client).DecodeMessage(response)
				require.NoError(t, err)
				assert.Equal(t, Message{Version: Version2c, Community: "public", PDUType: Response, RequestID: 42, VarBinds: rtVarbinds}, *got)
				assert.LessOrEqual(t, len(response), len(inform))
			})
		}
	})

	t.Run("nothing else", func(t *testing.T) {
		v2Trap, err := (&Message{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, VarBinds: rtVarbinds}).Encode(nil)
		require.NoError(t, err)
		v1Inform, err := (&Message{Version: Version1, Community: "public", PDUType: InformRequest, VarBinds: rtVarbinds}).Encode(nil)
		require.NoError(t, err)
		for name, data := range map[string][]byte{
			"an SNMPv2c trap":          v2Trap,
			"an SNMPv1 InformRequest":  v1Inform,
			"a trap to the local one":  ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots, pdu: SNMPv2Trap}),
			"a request to the local":   ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots, pdu: GetRequest}),
			"a Report to the local":    ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots, pdu: Report}),
			"a Response to the local":  ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots, pdu: Response}),
			"an unauthenticated trap":  ansEncode(t, ansMessage{user: ansPlain, level: NoAuthNoPriv, pdu: SNMPv2Trap}),
			"a trap at another engine": ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, engineID: ansAgentID, pdu: SNMPv2Trap}),
		} {
			t.Run(name, func(t *testing.T) {
				r, _ := newTestReceiver(t, ReceiverConfig{
					EngineID: []byte(ansLocalID), EngineBoots: ansBoots,
					Users: []EngineUser{
						{EngineID: []byte(ansLocalID), User: ansAuth},
						{EngineID: []byte(ansLocalID), User: ansPlain},
						{EngineID: []byte(ansAgentID), User: ansAuth},
					},
				})
				n, response, err := r.Receive(data)
				require.NoError(t, err)
				require.NotNil(t, n)
				assert.Nil(t, response)
			})
		}
	})
}

// TestLocalEngineTimeliness pins RFC 3414 section 3.2 step 7 a for the
// authenticated messages naming the local engine ID, an inform or a trap: one
// whose boots differ from the local engine's, or whose time is more than 150 s
// off the local engine time, which counts from the receiver's construction,
// or any when the local boots are 2147483647, is outside the time window;
// unauthenticated messages are not checked; the local engine keeps no record.
// The step comes before decryption: a message outside the window that does
// not decrypt fails the window.
func TestLocalEngineTimeliness(t *testing.T) {
	at := func(user User, level SecurityLevel, pdu PDUType, boots, engineTime uint32) ansMessage {
		return ansMessage{user: user, level: level, pdu: pdu, boots: boots, time: engineTime}
	}
	inform := func(boots, engineTime uint32) ansMessage {
		return at(ansPriv, AuthPriv, InformRequest, boots, engineTime)
	}
	tests := map[string]struct {
		elapsed time.Duration
		msg     ansMessage
		boots   uint32 // the local boots, ansBoots when zero
		want    error
	}{
		"on time":                  {elapsed: 100 * time.Second, msg: inform(ansBoots, 100)},
		"150 s ahead":              {elapsed: 100 * time.Second, msg: inform(ansBoots, 250)},
		"151 s ahead":              {elapsed: 100 * time.Second, msg: inform(ansBoots, 251), want: ErrNotInTimeWindow},
		"150 s behind":             {elapsed: 200 * time.Second, msg: inform(ansBoots, 50)},
		"151 s behind":             {elapsed: 200 * time.Second, msg: inform(ansBoots, 49), want: ErrNotInTimeWindow},
		"lower boots":              {msg: inform(ansBoots-1, 0), want: ErrNotInTimeWindow},
		"higher boots":             {msg: inform(ansBoots+1, 0), want: ErrNotInTimeWindow},
		"boots and time zero":      {msg: inform(0, 0), want: ErrNotInTimeWindow},
		"local boots at the max":   {msg: inform(maxEngineValue, 0), boots: maxEngineValue, want: ErrNotInTimeWindow},
		"authNoPriv, lower boots":  {msg: at(ansAuth, AuthNoPriv, InformRequest, ansBoots-1, 0), want: ErrNotInTimeWindow},
		"unauthenticated, stale":   {msg: at(ansPlain, NoAuthNoPriv, InformRequest, 0, 0)},
		"a trap, on time":          {elapsed: time.Hour, msg: at(ansAuth, AuthNoPriv, SNMPv2Trap, ansBoots, 3600)},
		"a trap, lower boots":      {msg: at(ansAuth, AuthNoPriv, SNMPv2Trap, ansBoots-1, 0), want: ErrNotInTimeWindow},
		"a trap, 151 s ahead":      {msg: at(ansAuth, AuthNoPriv, SNMPv2Trap, ansBoots, 151), want: ErrNotInTimeWindow},
		"a request, lower boots":   {msg: at(ansAuth, AuthNoPriv, GetRequest, ansBoots-1, 0), want: ErrNotInTimeWindow},
		"a day later, on time":     {elapsed: 24 * time.Hour, msg: inform(ansBoots, 86400)},
		"a day later, a day stale": {elapsed: 24 * time.Hour, msg: inform(ansBoots, 0), want: ErrNotInTimeWindow},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			boots := tc.boots
			if boots == 0 {
				boots = ansBoots
			}
			r, advance := newTestReceiver(t, ReceiverConfig{
				EngineID: []byte(ansLocalID), EngineBoots: boots,
				Users: []EngineUser{
					{EngineID: []byte(ansLocalID), User: ansPriv},
					{EngineID: []byte(ansLocalID), User: ansAuth},
					{EngineID: []byte(ansLocalID), User: ansPlain},
				},
			})
			advance(tc.elapsed)
			n, _, err := r.Receive(ansEncode(t, tc.msg))
			if tc.want == nil {
				require.NoError(t, err)
				assert.NotNil(t, n)
			} else {
				require.ErrorIs(t, err, tc.want)
				assert.Nil(t, n)
			}
			assert.Empty(t, r.times.records, "the local engine keeps no record")
		})
	}

	t.Run("before decryption", func(t *testing.T) {
		r, _ := ansReceiver(t, ansPriv)
		m := splitV3Message(t, ansEncode(t, inform(ansBoots, 0)))
		m.scoped = bytes.Repeat([]byte{0x5a}, len(m.scoped))
		stale := rewireV3(t, m.bytes(), &ansPriv, []byte(ansLocalID), AuthPriv|reportableFlag, ansBoots-1, 0)
		_, _, err := r.Receive(stale)
		require.ErrorIs(t, err, ErrNotInTimeWindow)
		fresh := rewireV3(t, m.bytes(), &ansPriv, []byte(ansLocalID), AuthPriv|reportableFlag, ansBoots, 0)
		_, _, err = r.Receive(fresh)
		require.ErrorIs(t, err, ErrDecryption, "the same message in the window")
	})

	t.Run("before decryption, another engine", func(t *testing.T) {
		r := receiverAt(t, []byte(ansAgentID), ansPriv)
		trap := ansMessage{user: ansPriv, level: AuthPriv, engineID: ansAgentID, pdu: SNMPv2Trap, boots: 5, time: 100}
		_, _, err := r.Receive(ansEncode(t, trap))
		require.NoError(t, err)
		m := splitV3Message(t, ansEncode(t, trap))
		m.scoped = bytes.Repeat([]byte{0x5a}, len(m.scoped))
		stale := rewireV3(t, m.bytes(), &ansPriv, []byte(ansAgentID), AuthPriv, 4, 100)
		_, _, err = r.Receive(stale)
		require.ErrorIs(t, err, ErrNotInTimeWindow)
	})
}

// TestLocalEngineNeverLearned pins that a receiver learns no user for its own
// engine ID: a message naming it with a user name it has no user of there is
// ErrUnknownUsername, unanswered, whatever its LearnUsers.
func TestLocalEngineNeverLearned(t *testing.T) {
	r, _ := newTestReceiver(t, ReceiverConfig{
		EngineID: []byte(ansLocalID), EngineBoots: ansBoots, LearnUsers: []User{ansAuth}, MaxLearned: 4,
	})
	for _, pdu := range []PDUType{SNMPv2Trap, InformRequest} {
		n, data, err := r.Receive(ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots, pdu: pdu}))
		require.ErrorIs(t, err, ErrUnknownUsername, "%v", pdu)
		assert.Nil(t, n)
		assert.Nil(t, data)
	}
	assert.Zero(t, r.learned)
}

// TestReports pins the Reports of the local engine (RFC 3412 section 7.1
// step 3): usmStatsUnknownEngineIDs for a reportable message naming no engine
// ID (discovery) or one the receiver has no user for, before any key is used
// or a user learned, and usmStatsNotInTimeWindows for an authenticated one
// naming the local engine ID outside its time window (step 7 a), signed by
// the user whose digest checked; each from the local engine (its ID, boots
// and time now), to the message's user name, with its msgID, the request ID
// of a plaintext PDU (0 for an encrypted one), the local engine ID as
// contextEngineID, the default context and the receiver's count; unreportable
// itself. A sender resynchronizes from the notInTimeWindow Report.
func TestReports(t *testing.T) {
	unknownEngineIDs := func(count uint32) []VarBind {
		return []VarBind{{Name: usmStatsUnknownEngineIDs, Value: Counter32Value(count)}}
	}
	notInTimeWindows := func(count uint32) []VarBind {
		return []VarBind{{Name: usmStatsNotInTimeWindows, Value: Counter32Value(count)}}
	}
	// report returns what a Report decodes to: to name, at level, the
	// engine time 30, for msgID and request ID, with varbinds.
	report := func(got *Message, level SecurityLevel, name string, msgID, requestID uint32, varbinds []VarBind) Message {
		want := ansWant(got, level, name, 30, Report, "", varbinds)
		want.MsgID, want.RequestID = msgID, requestID
		return want
	}

	t.Run("discovery", func(t *testing.T) {
		r, advance := ansReceiver(t, ansAuth)
		advance(30 * time.Second)
		for i, name := range []string{"", "probe-user"} {
			n, data, err := r.Receive(ansProbe(t, name))
			require.ErrorIs(t, err, ErrUnknownEngineID)
			require.Nil(t, n)
			require.NotNil(t, data)
			assert.Zero(t, wireFlags(t, data)&reportableFlag, "a Report is unreportable")
			got := decodeAnswer(t, data, nil)
			assert.Equal(t, report(got, NoAuthNoPriv, name, 99, 42, unknownEngineIDs(uint32(i+1))), *got)
		}
	})

	t.Run("a stale engine ID", func(t *testing.T) {
		// A sender that cached another engine ID (the receiver's before its
		// state was lost) gets the Report whatever its credentials, and the
		// receiver learns nothing: the answer tells no user or key apart.
		wrong := ansPriv
		wrong.AuthPassphrase = "ans-wrong-pass"
		var errs []string
		for _, sender := range []User{ansPriv, wrong} {
			r, advance := newTestReceiver(t, ReceiverConfig{
				EngineID: []byte(ansLocalID), EngineBoots: ansBoots,
				LearnUsers: []User{ansPriv}, MaxLearned: 4,
			})
			advance(30 * time.Second)
			for _, tc := range []struct {
				level     SecurityLevel
				requestID uint32
			}{{AuthPriv, 0}, {AuthNoPriv, 42}} {
				_, data, err := r.Receive(ansEncode(t, ansMessage{user: sender, level: tc.level, engineID: ansAgentID, boots: 4, time: 5}))
				require.ErrorIs(t, err, ErrUnknownEngineID)
				errs = append(errs, err.Error())
				got := decodeAnswer(t, data, nil)
				count := uint32(1)
				if tc.level == AuthNoPriv {
					count = 2
				}
				assert.Equal(t, report(got, NoAuthNoPriv, "ans-user", 21, tc.requestID, unknownEngineIDs(count)), *got)
			}
			assert.Zero(t, r.learned)
		}
		assert.Equal(t, errs[:2], errs[2:], "the same errors for the right and the wrong credentials")
	})

	t.Run("notInTimeWindow", func(t *testing.T) {
		for name, tc := range map[string]struct {
			user        User
			level       SecurityLevel
			boots, time uint32
			requestID   uint32
		}{
			"authPriv, stale boots":       {ansPriv, AuthPriv, ansBoots - 1, 30, 0},
			"authNoPriv, stale boots":     {ansAuth, AuthNoPriv, ansBoots - 1, 30, 42},
			"time synchronization, zeros": {ansPriv, AuthPriv, 0, 0, 0},
			"time far ahead":              {ansAuth, AuthNoPriv, ansBoots, 30 + 151, 42},
		} {
			t.Run(name, func(t *testing.T) {
				r, advance := ansReceiver(t, tc.user)
				advance(30 * time.Second)
				_, data, err := r.Receive(ansEncode(t, ansMessage{user: tc.user, level: tc.level, boots: tc.boots, time: tc.time}))
				require.ErrorIs(t, err, ErrNotInTimeWindow)
				require.NotNil(t, data)
				got := decodeAnswer(t, data, &tc.user)
				assert.Equal(t, report(got, AuthNoPriv, "ans-user", 21, tc.requestID, notInTimeWindows(1)), *got)

				// The sender takes the boots and time of the authenticated
				// Report, and its inform is accepted.
				h := got.SecurityParameters
				n, response, err := r.Receive(ansEncode(t, ansMessage{
					user: tc.user, level: tc.level, boots: h.AuthoritativeEngineBoots, time: h.AuthoritativeEngineTime,
				}))
				require.NoError(t, err)
				require.NotNil(t, n)
				require.NotNil(t, response)
			})
		}
	})

	t.Run("signed by the user whose digest checked", func(t *testing.T) {
		first, second := ansAuth, ansAuth
		second.AuthPassphrase = "ans-auth-pass-2"
		r, _ := ansReceiver(t, first, second)
		_, data, err := r.Receive(ansEncode(t, ansMessage{user: second, level: AuthNoPriv, boots: 1}))
		require.ErrorIs(t, err, ErrNotInTimeWindow)
		decodeAnswer(t, data, &second)
	})

	t.Run("not answered", func(t *testing.T) {
		probe := ansProbe(t, "")
		with := func(data []byte, change func(*v3Message)) []byte {
			m := splitV3Message(t, bytes.Clone(data))
			change(&m)
			return m.bytes()
		}
		badDigest := splitV3Message(t, ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots}))
		badDigest.usm[4] = bytes.Repeat([]byte{0}, len(badDigest.usm[4]))
		badCipher := splitV3Message(t, ansEncode(t, ansMessage{user: ansPriv, level: AuthPriv, boots: ansBoots}))
		badCipher.scoped = bytes.Repeat([]byte{0x5a}, len(badCipher.scoped))
		tests := map[string]struct {
			data []byte
			want error
			// local are the users of the local engine ID, ansAuth when nil;
			// agent registers ansAuth for ansAgentID too; noLocal leaves the
			// receiver without a local engine.
			local          []User
			agent, noLocal bool
		}{
			"an unreportable probe": {data: with(probe, msgFlagsOctets(0)), want: ErrUnknownEngineID},
			"a reportable trap, no engine ID": {data: with(ansEncode(t, ansMessage{user: ansPlain, level: NoAuthNoPriv, engineID: "\x00", pdu: SNMPv2Trap}), func(m *v3Message) {
				m.usm[0] = nil
				msgFlagsOctets(reportableFlag)(m)
			}), want: ErrUnknownEngineID},
			"no msgData":                    {data: probeWithout(t, probe), want: ErrUnknownEngineID},
			"an empty plaintext scoped PDU": {data: with(probe, func(m *v3Message) { m.scoped = nil }), want: ErrUnknownEngineID},
			"a PDU that does not decode": {data: with(probe, func(m *v3Message) {
				m.scoped = append(append(tlv(byte(OctetString)), tlv(byte(OctetString))...), tlv(byte(GetRequest), []byte{0x02, 0x05, 0x01})...)
			}), want: ErrUnknownEngineID},
			"encrypted msgData without privacy": {data: with(probe, func(m *v3Message) { m.scopedTag = byte(OctetString) }), want: ErrUnknownEngineID},
			"plaintext msgData with privacy":    {data: with(probe, msgFlagsOctets(byte(AuthPriv)|reportableFlag)), want: ErrUnknownEngineID},
			"an invalid header":                 {data: with(probe, func(m *v3Message) { m.header[0] = byte(OctetString) }), want: ErrASNParse},
			"no local engine":                   {data: probe, want: ErrUnknownEngineID, noLocal: true},
			"a wrong digest":                    {data: badDigest.bytes(), want: ErrWrongDigest},
			"an unknown user":                   {data: ansEncode(t, ansMessage{user: lrAuth, level: AuthNoPriv, boots: ansBoots}), want: ErrUnknownUsername},
			"an unsupported level":              {data: ansEncode(t, ansMessage{user: ansPriv, level: AuthPriv, boots: ansBoots}), want: ErrUnknownSecurityLevel},
			"a decryption error": {
				data: rewireV3(t, badCipher.bytes(), &ansPriv, []byte(ansLocalID), AuthPriv|reportableFlag, ansBoots, 0),
				want: ErrDecryption, local: []User{ansPriv},
			},
			"an inform to an agent's engine": {data: ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, engineID: ansAgentID}), want: ErrUnknownEngineID, agent: true},
			"an unknown user at an agent":    {data: ansEncode(t, ansMessage{user: lrAuth, level: AuthNoPriv, engineID: ansAgentID}), want: ErrUnknownUsername, agent: true},
			"a stale reportable trap": {data: rewireV3(t, ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, pdu: SNMPv2Trap, boots: ansBoots}),
				&ansAuth, []byte(ansLocalID), AuthNoPriv|reportableFlag, 1, 0), want: ErrNotInTimeWindow},
			"a stale unreportable inform": {data: rewireV3(t, ansEncode(t, ansMessage{user: ansAuth, level: AuthNoPriv, boots: ansBoots}),
				&ansAuth, []byte(ansLocalID), AuthNoPriv, 1, 0), want: ErrNotInTimeWindow},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				config := ReceiverConfig{EngineID: []byte(ansLocalID), EngineBoots: ansBoots}
				if tc.noLocal {
					config = ReceiverConfig{}
				}
				if tc.local == nil {
					tc.local = []User{ansAuth}
				}
				for _, u := range tc.local {
					config.Users = append(config.Users, EngineUser{EngineID: []byte(ansLocalID), User: u})
				}
				if tc.agent {
					config.Users = append(config.Users, EngineUser{EngineID: []byte(ansAgentID), User: ansAuth})
				}
				r, _ := newTestReceiver(t, config)
				n, data, err := r.Receive(tc.data)
				require.ErrorIs(t, err, tc.want)
				assert.Nil(t, n)
				assert.Nil(t, data)
			})
		}
	})
}

// probeWithout returns probe, an SNMPv3 message, without its msgData.
func probeWithout(t *testing.T, probe []byte) []byte {
	t.Helper()
	m := splitV3Message(t, probe)
	var usm [][]byte
	for i, f := range m.usm {
		usm = append(usm, tlv(m.usmTags[i], f))
	}
	return tlv(0x30, tlv(byte(Integer), m.version), tlv(0x30, m.header), tlv(byte(OctetString), tlv(0x30, usm...)))
}

// TestNewReceiverLocalEngine pins the local engine's configuration: an
// engine ID of 5..32 octets and boots of 1..2147483647, both or neither, and
// the receiver keeps a copy of the engine ID.
func TestNewReceiverLocalEngine(t *testing.T) {
	tests := map[string]struct {
		id    []byte
		boots uint32
		want  string
	}{
		"neither":              {},
		"5 octets, boots 1":    {id: []byte("12345"), boots: 1},
		"32 octets, max boots": {id: bytes.Repeat([]byte{1}, 32), boots: maxEngineValue},
		"4 octets":             {id: []byte("1234"), boots: 1, want: "ReceiverConfig.EngineID is 4 octets, not 5..32"},
		"33 octets":            {id: bytes.Repeat([]byte{1}, 33), boots: 1, want: "ReceiverConfig.EngineID is 33 octets, not 5..32"},
		"boots 0":              {id: []byte(ansLocalID), want: "ReceiverConfig.EngineBoots 0 is outside 1..2147483647"},
		"boots past the max":   {id: []byte(ansLocalID), boots: maxEngineValue + 1, want: "ReceiverConfig.EngineBoots 2147483648 is outside 1..2147483647"},
		"boots without an ID":  {boots: 1, want: "ReceiverConfig.EngineID is 0 octets, not 5..32"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := NewReceiver(ReceiverConfig{EngineID: tc.id, EngineBoots: tc.boots})
			if tc.want != "" {
				require.EqualError(t, err, tc.want)
				assert.Nil(t, r)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.id != nil, r.local != nil)
		})
	}

	t.Run("a copy of the engine ID", func(t *testing.T) {
		id := []byte(ansLocalID)
		r, err := NewReceiver(ReceiverConfig{
			EngineID: id, EngineBoots: ansBoots,
			Users: []EngineUser{{EngineID: []byte(ansLocalID), User: ansPlain}},
		})
		require.NoError(t, err)
		copy(id, ansAgentID)
		_, response, err := r.Receive(ansEncode(t, ansMessage{user: ansPlain, level: NoAuthNoPriv}))
		require.NoError(t, err)
		assert.NotNil(t, response)
	})
}

// TestReceiveAnswersConcurrent runs the local engine's answers from several
// goroutines, for the race detector: informs answered, stale ones and probes
// reported, each answer for its own message.
func TestReceiveAnswersConcurrent(t *testing.T) {
	r, _ := ansReceiver(t, ansPriv)
	inform := ansEncode(t, ansMessage{user: ansPriv, level: AuthPriv, boots: ansBoots})
	stale := ansEncode(t, ansMessage{user: ansPriv, level: AuthPriv, boots: 1})
	probe := ansProbe(t, "")
	var probes atomic.Uint32
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 50 {
				switch (g + i) % 3 {
				case 0:
					_, response, err := r.Receive(inform)
					assert.NoError(t, err)
					assert.Equal(t, Response, decodeAnswer(t, response, &ansPriv).PDUType)
				case 1:
					_, report, err := r.Receive(stale)
					assert.ErrorIs(t, err, ErrNotInTimeWindow)
					assert.Equal(t, Report, decodeAnswer(t, report, &ansPriv).PDUType)
				default:
					probes.Add(1)
					_, report, err := r.Receive(probe)
					assert.ErrorIs(t, err, ErrUnknownEngineID)
					assert.Equal(t, Report, decodeAnswer(t, report, nil).PDUType)
				}
			}
		})
	}
	wg.Wait()
	assert.Equal(t, probes.Load(), r.local.unknownEngineIDs.Load(), "every probe counted once")
}
