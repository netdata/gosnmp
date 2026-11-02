// Copyright 2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"crypto/fips140"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
)

/**
 * This tests use hex dumps from real network traffic produced using net-snmp's snmpget with demo.snmplabs.com as SNMP agent.
 */

func authorativeEngineID(t *testing.T) []byte {
	// engine ID of demo.snmplabs.com
	engineID, err := hex.DecodeString("80004fb805636c6f75644dab22cc")
	require.NoError(t, err, "EngineId decoding failed.")

	return engineID
}

func correctKeySHA224(t *testing.T) []byte {
	correctKey, err := hex.DecodeString("f2a2ebaa9677ad286255596286ca4fb7ec22f52405cb0aac334c5f15")
	require.NoError(t, err, "Correct key initialization failed.")

	return correctKey
}

func packetSHA224NoAuthentication(t *testing.T) []byte {
	packet, err := hex.DecodeString("308184020103300e02025f84020205c0040105020103043f303d040e80004fb805636c6f75644dab22cc02012b0203203ea5040f7573722d7368613232342d6e6f6e650410000000000000000000000000000000000400302e040e80004fb805636c6f75644dab22cc0400a01a02023ced020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Non-authenticated packet data SHA224 decoding failed.")
	return packet
}

func packetSHA224Authenticated(t *testing.T) []byte {
	packet, err := hex.DecodeString("308184020103300e02025f84020205c0040105020103043f303d040e80004fb805636c6f75644dab22cc02012b0203203ea5040f7573722d7368613232342d6e6f6e65041066cd2d9b04cd48b02a9df0c77dc3415d0400302e040e80004fb805636c6f75644dab22cc0400a01a02023ced020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Authenticated packet data SHA224 decoding failed.")
	return packet
}

// TestTrapOtherUser pins that a single trap user does not take a message
// naming another user (RFC 3414 section 3.2 step 4), before its digest.
func TestTrapOtherUser(t *testing.T) {
	user := User{Name: "usr-sha224-none", AuthProtocol: SHA224, AuthPassphrase: "authkey1"}
	key, err := user.authKey(authorativeEngineID(t))
	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), key, "Wrong key generated")

	verifier := user
	verifier.Name = "foo"

	msg := packetSHA224Authenticated(t)
	res := new(Message)
	_, w, err := unmarshalHeader(msg, res)
	require.NoError(t, err)
	step, err := decodeTrapV3(msg, w, res, &verifier, nil, trapRule{singleUser: true})
	require.ErrorIs(t, err, ErrUnknownUsername)
	assert.Equal(t, stepUser, step)
}

func TestAuthenticationSHA224(t *testing.T) {
	user := User{Name: "usr-sha224-none", AuthProtocol: SHA224, AuthPassphrase: "authkey1"}
	keys, err := user.localize(authorativeEngineID(t))
	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), keys.auth, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)
	err = keys.sign(srcPacket, authParamsOffset(t, srcPacket))
	require.NoError(t, err, "Authentication of packet failed")

	require.Equal(t, packetSHA224Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA224(t *testing.T) {
	user := User{Name: "usr-sha224-none", AuthProtocol: SHA224, AuthPassphrase: "authkey1"}
	key, err := user.authKey(authorativeEngineID(t))
	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), key, "Wrong key generated")

	require.NoError(t, testInbound(t, packetSHA224Authenticated(t), &user).verify(), "Packet was not considered to be authentic")
}

func correctKeySHA512(t *testing.T) []byte {
	correctKey, err := hex.DecodeString("c336e5e6396926813d623984610e8f0cd7f419da75c82ac50927c84fd92027f7cdd849ce983036dca67bfb1e8fde2a8c2d45cd2f0d3e0b0b929f7dda462a58cf")
	require.NoError(t, err, "Correct key initialization failed.")

	return correctKey
}

func packetSHA512NoAuthentication(t *testing.T) []byte {
	packet, err := hex.DecodeString("3081a4020103300e0202366e020205c0040105020103045f305d040e80004fb805636c6f75644dab22cc02012b0203203eea040f7573722d7368613531322d6e6f6e6504300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400302e040e80004fb805636c6f75644dab22cc0400a01a020214d9020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Not-authenticated packet data SHA512 decoding failed.")
	return packet
}

func packetSHA512Authenticated(t *testing.T) []byte {
	packet, err := hex.DecodeString("3081a4020103300e0202366e020205c0040105020103045f305d040e80004fb805636c6f75644dab22cc02012b0203203eea040f7573722d7368613531322d6e6f6e65043026f8087ced336a394642b8698eba9810929a9bfa44afbf43975a7ad6c4cc55bd279b549a77ec56d791467612747d6f570400302e040e80004fb805636c6f75644dab22cc0400a01a020214d9020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Authenticated packet data SHA512 decoding failed.")
	return packet
}

func TestAuthenticationSHA512(t *testing.T) {
	user := User{Name: "usr-sha512-none", AuthProtocol: SHA512, AuthPassphrase: "authkey1"}
	keys, err := user.localize(authorativeEngineID(t))
	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), keys.auth, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)
	err = keys.sign(srcPacket, authParamsOffset(t, srcPacket))
	require.NoError(t, err, "Authentication of packet failed")

	require.Equal(t, packetSHA512Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA512(t *testing.T) {
	user := User{Name: "usr-sha512-none", AuthProtocol: SHA512, AuthPassphrase: "authkey1"}
	key, err := user.authKey(authorativeEngineID(t))
	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), key, "Wrong key generated")

	require.NoError(t, testInbound(t, packetSHA512Authenticated(t), &user).verify(), "Packet was not considered to be authentic")
}

// TestParseTruncatedUSMSequence verifies that the header parse returns an
// error rather than panicking when the USM SEQUENCE body is truncated.
func TestParseTruncatedUSMSequence(t *testing.T) {
	tests := map[string][]byte{
		"short-form length zero": {0x30, 0x00},
		// 0x81 signals long-form with 1 extra length byte; the body is
		// absent.
		"long-form length one extra byte truncated body": {0x30, 0x81, 0x05},
	}

	for name, usmParams := range tests {
		t.Run(name, func(t *testing.T) {
			msg := craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), usmParams, craftedScopedResp)
			require.NotPanics(t, func() {
				_, _, err := unmarshalHeader(msg, new(Message))
				require.Error(t, err)
			})
		})
	}
}

// testInbound returns the SNMPv3 message msg in security processing with
// user, whose keys derive for the message's engine ID (receiveV3).
func testInbound(t *testing.T, msg []byte, user *User) *inbound {
	t.Helper()
	res := new(Message)
	_, w, err := unmarshalHeader(msg, res)
	require.NoError(t, err)
	in, err := receiveV3(msg, w, res, user, nil)
	require.NoError(t, err)
	return &in
}

// TestUSMUnsupportedProtocols checks that protocol values outside the defined
// sets fail with an error on every path: validation, key derivation, a
// table's Add, encoding without validation, and decoding with a table entry
// whose protocol changed after Add.
func TestUSMUnsupportedProtocols(t *testing.T) {
	useEngineTimes(t)
	const (
		authErr = "User.AuthProtocol AuthProtocol(8) is not supported"
		privErr = "User.PrivProtocol PrivProtocol(8) is not supported"
	)
	user := func(auth AuthProtocol, priv PrivProtocol) User {
		return usmUser(auth, "codec-auth-pass", priv, "codec-priv-pass")
	}

	tests := map[string]struct {
		auth    AuthProtocol
		priv    PrivProtocol
		flags   SecurityLevel
		wantErr string
	}{
		"authentication": {auth: AuthProtocol(8), priv: NoPriv, flags: AuthNoPriv, wantErr: authErr},
		"privacy":        {auth: SHA, priv: PrivProtocol(8), flags: AuthPriv, wantErr: privErr},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Run("validate", func(t *testing.T) {
				x := &Client{Version: Version3, SecurityLevel: tc.flags, User: user(tc.auth, tc.priv)}
				// Validation runs before decoding, so an empty message reaches it.
				_, err := x.DecodeMessage(nil)
				assert.EqualError(t, err, tc.wantErr)
			})
			t.Run("keys", func(t *testing.T) {
				u := user(tc.auth, tc.priv)
				_, err := u.localize([]byte(usmCharEngineID))
				assert.EqualError(t, err, tc.wantErr)
			})
			t.Run("table", func(t *testing.T) {
				table := NewSnmpV3SecurityParametersTable()
				assert.EqualError(t, table.Add(user(tc.auth, tc.priv), []byte(usmCharEngineID)), tc.wantErr)
			})
			t.Run("encode", func(t *testing.T) {
				pkt := &Message{
					Version:            Version3,
					SecurityLevel:      tc.flags,
					SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), UserName: "codec-user"},
					PDUType:            SNMPv2Trap,
					VarBinds:           usmCharVarbinds,
				}
				u := user(tc.auth, tc.priv)
				var err error
				require.NotPanics(t, func() { _, err = pkt.Encode(&u) })
				assert.EqualError(t, err, tc.wantErr)
			})
			t.Run("decode", func(t *testing.T) {
				data := usmCharTrap(t, AES, usmCharVarbinds)
				table := NewSnmpV3SecurityParametersTable()
				require.NoError(t, table.Add(user(SHA, AES), []byte(usmCharEngineID)))
				entries, err := table.get("codec-user")
				require.NoError(t, err)
				entries[0].user.AuthProtocol, entries[0].user.PrivProtocol = tc.auth, tc.priv
				x := &Client{Version: Version3, TrapSecurityParametersTable: table}
				require.NotPanics(t, func() { _, err = x.UnmarshalTrap(data, true) })
				assert.EqualError(t, err, "no credentials successfully unmarshaled trap: "+tc.wantErr)
			})
		})
	}
}

// TestUSMEncodeSecurityLevel checks that encoding fails when the message
// flags ask for authentication or privacy without a protocol for it, instead
// of sending a message without the MAC or the encryption its flags claim.
func TestUSMEncodeSecurityLevel(t *testing.T) {
	const (
		authErr = "User.AuthProtocol is required"
		privErr = "User.PrivProtocol is required"
	)

	tests := map[string]struct {
		flags   SecurityLevel
		auth    AuthProtocol
		priv    PrivProtocol
		wantErr string
	}{
		"authentication, unset protocol": {flags: AuthNoPriv, wantErr: authErr},
		"authentication, NoAuth":         {flags: AuthNoPriv, auth: NoAuth, wantErr: authErr},
		"privacy, unset protocol":        {flags: AuthPriv, auth: SHA, wantErr: privErr},
		"privacy, NoPriv":                {flags: AuthPriv, auth: SHA, priv: NoPriv, wantErr: privErr},
		"privacy, no protocol at all":    {flags: AuthPriv, wantErr: authErr},
		"no authentication, unset":       {flags: NoAuthNoPriv},
		"authentication":                 {flags: AuthNoPriv, auth: SHA},
		"privacy":                        {flags: AuthPriv, auth: SHA, priv: AES},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user := usmUser(tc.auth, "codec-auth-pass", tc.priv, "codec-priv-pass")
			pkt := &Message{
				Version:            Version3,
				SecurityLevel:      tc.flags,
				SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), UserName: "codec-user"},
				PDUType:            SNMPv2Trap,
				VarBinds:           usmCharVarbinds,
			}
			var msg []byte
			var err error
			panicked, wroteStdout := observe(func() { msg, err = pkt.Encode(&user) })
			require.False(t, panicked)
			assert.False(t, wroteStdout)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				assert.NotEmpty(t, msg)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMDecodeSecurityLevel checks that decoding fails when the message
// flags ask for authentication or privacy and the decoder has no protocol
// for it: the decoding counterpart of TestUSMEncodeSecurityLevel.
func TestUSMDecodeSecurityLevel(t *testing.T) {
	const (
		authErr = "unable to decode packet header: error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message"
		privErr = "unable to decode packet header: error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message"
	)
	authNoPriv := usmCharTrap(t, NoPriv, usmCharVarbinds)
	authPriv := usmCharTrap(t, AES, usmCharVarbinds)

	tests := map[string]struct {
		in      []byte
		auth    AuthProtocol
		priv    PrivProtocol
		wantErr string
	}{
		"authentication, unset protocol": {in: authNoPriv, wantErr: authErr},
		"authentication, NoAuth":         {in: authNoPriv, auth: NoAuth, wantErr: authErr},
		"authentication":                 {in: authNoPriv, auth: SHA},
		"privacy, unset protocol":        {in: authPriv, auth: SHA, wantErr: privErr},
		"privacy, NoPriv":                {in: authPriv, auth: SHA, priv: NoPriv, wantErr: privErr},
		"privacy":                        {in: authPriv, auth: SHA, priv: AES},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := usmDecoder(tc.auth, "codec-auth-pass", tc.priv, "codec-priv-pass")()
			_, err := x.DecodeMessage(bytes.Clone(tc.in))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMTrapTableAttempts checks how the trap table path tries the users of
// a name, in the order they were added, on the one trap (no attempt writes
// it): the first that decodes wins, and when none does the error carries the
// one of the user that got furthest, whatever the order, the first on ties: a
// wrong digest after a local failure that comes before it, a level the user
// lacks protocols for after a local failure.
func TestUSMTrapTableAttempts(t *testing.T) {
	useEngineTimes(t)
	data := usmCharTrap(t, AES, usmCharVarbinds)
	user := func(authPass string) User { return usmUser(SHA, authPass, AES, "codec-priv-pass") }
	good := user("codec-auth-pass")
	wrongPass := user("wrong-auth-pass")
	noPriv := good
	noPriv.PrivProtocol = NoPriv
	add := func(u User) func(*SnmpV3SecurityParametersTable) {
		return func(tb *SnmpV3SecurityParametersTable) { require.NoError(t, tb.Add(u, []byte(usmCharEngineID))) }
	}
	// unsupported fails before decoding anything: the entry's protocol is
	// set after Add, which rejects it; edit sets it.
	unsupported := func(edit func(u *User)) func(*SnmpV3SecurityParametersTable) {
		return func(tb *SnmpV3SecurityParametersTable) {
			add(good)(tb)
			entries, err := tb.get("codec-user")
			require.NoError(t, err)
			edit(&entries[len(entries)-1].user)
		}
	}
	unsupportedAuth := unsupported(func(u *User) { u.AuthProtocol = AuthProtocol(8) })
	unsupportedPriv := unsupported(func(u *User) { u.PrivProtocol = PrivProtocol(8) })
	const (
		prefix         = "no credentials successfully unmarshaled trap: "
		notAuthentic   = "incoming packet is not authentic, discarding"
		notSupportedV8 = "User.AuthProtocol AuthProtocol(8) is not supported"
		privNotSupport = "User.PrivProtocol PrivProtocol(8) is not supported"
		noPrivProtocol = "error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message"
	)

	tests := map[string]struct {
		sets    []func(*SnmpV3SecurityParametersTable)
		wantErr string
	}{
		"wrong passphrase, then right":          {sets: []func(*SnmpV3SecurityParametersTable){add(wrongPass), add(good)}},
		"right passphrase first":                {sets: []func(*SnmpV3SecurityParametersTable){add(good), add(wrongPass)}},
		"unsupported, then not authentic":       {sets: []func(*SnmpV3SecurityParametersTable){unsupportedAuth, add(wrongPass)}, wantErr: prefix + notAuthentic},
		"not authentic, then unsupported":       {sets: []func(*SnmpV3SecurityParametersTable){add(wrongPass), unsupportedAuth}, wantErr: prefix + notAuthentic},
		"unsupported twice":                     {sets: []func(*SnmpV3SecurityParametersTable){unsupportedAuth, unsupportedAuth}, wantErr: prefix + notSupportedV8},
		"unsupported, then unsupported privacy": {sets: []func(*SnmpV3SecurityParametersTable){unsupportedAuth, unsupportedPriv}, wantErr: prefix + notSupportedV8},
		"unsupported privacy, then unsupported": {sets: []func(*SnmpV3SecurityParametersTable){unsupportedPriv, unsupportedAuth}, wantErr: prefix + privNotSupport},
		"unsupported privacy, then no privacy":  {sets: []func(*SnmpV3SecurityParametersTable){unsupportedPriv, add(noPriv)}, wantErr: prefix + noPrivProtocol},
		"no privacy, then unsupported privacy":  {sets: []func(*SnmpV3SecurityParametersTable){add(noPriv), unsupportedPriv}, wantErr: prefix + noPrivProtocol},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tb := NewSnmpV3SecurityParametersTable()
			for _, set := range tc.sets {
				set(tb)
			}
			x := &Client{Version: Version3, TrapSecurityParametersTable: tb}
			in := bytes.Clone(data)
			res, err := x.UnmarshalTrap(in, false)
			assert.Equal(t, data, in, "the caller's trap")
			if tc.wantErr != "" {
				assert.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, usmCharVarbinds, res.VarBinds)
		})
	}
}

// TestUSMReceivePassphrases pins the category of a receiver's user that has a
// protocol without a passphrase when the keys derive for a message's engine
// ID: its configuration error, of no RFC category, not an unknown user.
func TestUSMReceivePassphrases(t *testing.T) {
	data := usmCharTrap(t, AES, usmCharVarbinds)
	tests := map[string]User{
		"authentication protocol without passphrase": usmUser(SHA, "", AES, "codec-priv-pass"),
		"privacy protocol without passphrase":        usmUser(SHA, "codec-auth-pass", AES, ""),
	}
	for name, user := range tests {
		t.Run(name, func(t *testing.T) {
			res := new(Message)
			_, w, err := unmarshalHeader(data, res)
			require.NoError(t, err)
			_, err = receiveV3(data, w, res, &user, nil)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrUnknownUsername)
		})
	}
}

// TestUSMTrapMistypedFields pins that a trap whose user name or engine ID is
// not an OCTET STRING fails the header parse (RFC 3414 section 3.2 step 1),
// so a receiver without authentication, whose user name is its only
// credential, cannot take it as its own user's or from no engine.
func TestUSMTrapMistypedFields(t *testing.T) {
	useEngineTimes(t)
	trap := func(engineID, user []byte) []byte {
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(engineID, intTLV(1), intTLV(1), user, octets(""), octets("")),
			tlv(0x30, octets(""), octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5))))))
	}
	receivers := map[string]func() *Client{
		"single": func() *Client {
			return &Client{Version: Version3, User: User{Name: "secret-user"}}
		},
		"table": func() *Client {
			tb := NewSnmpV3SecurityParametersTable()
			require.NoError(t, tb.Add(User{Name: "secret-user"}, nil))
			return &Client{Version: Version3, TrapSecurityParametersTable: tb}
		},
	}
	tests := map[string]struct {
		in   []byte
		want error // nil: accepted
	}{
		"as sent":                 {in: trap(octets(usmCharEngineID), octets("secret-user"))},
		"user name as an INTEGER": {in: trap(octets(usmCharEngineID), intTLV(1)), want: ErrASNParse},
		"engine ID as an INTEGER": {in: trap(intTLV(1), octets("secret-user")), want: ErrASNParse},
	}
	for name, tc := range tests {
		for rname, receiver := range receivers {
			t.Run(name+"/"+rname, func(t *testing.T) {
				_, err := receiver().UnmarshalTrap(bytes.Clone(tc.in), false)
				if tc.want == nil {
					require.NoError(t, err)
					return
				}
				require.ErrorIs(t, err, tc.want)
			})
		}
	}
}

// TestUSMTrapTableSkipsV1V2c checks that a receiver with a trap table
// decodes SNMPv1 and SNMPv2c traps without it.
func TestUSMTrapTableSkipsV1V2c(t *testing.T) {
	useEngineTimes(t)
	vbl := craftedVBL(craftedVB(intTLV(5)))
	vars := []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: Integer, Value: 5}}
	tests := map[string]struct {
		in          []byte
		wantVersion Version
		wantPDUType PDUType
	}{
		"SNMPv1":  {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, vbl), wantVersion: Version1, wantPDUType: Trap},
		"SNMPv2c": {in: craftedMsg(1, craftedPDU(SNMPv2Trap, vbl)), wantVersion: Version2c, wantPDUType: SNMPv2Trap},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tb := NewSnmpV3SecurityParametersTable()
			require.NoError(t, tb.Add(User{Name: "codec-user"}, nil))
			x := &Client{Version: Version3, TrapSecurityParametersTable: tb}
			var res *Message
			var err error
			require.NotPanics(t, func() { res, err = x.UnmarshalTrap(tc.in, false) })
			require.NoError(t, err)
			assert.Equal(t, tc.wantVersion, res.Version)
			assert.Equal(t, tc.wantPDUType, res.PDUType)
			assert.Equal(t, vars, res.VarBinds)
		})
	}
}

// TestUSMReceiverAuthenticationWithoutProtocol checks that a single-user
// UnmarshalTrap receiver whose flags require authentication rejects an
// unauthenticated trap from its user as below its minimum level, whether or
// not its parameters have an authentication protocol, instead of panicking or
// accepting it; a trap from another user is rejected before.
func TestUSMReceiverAuthenticationWithoutProtocol(t *testing.T) {
	useEngineTimes(t)
	sender := &Message{
		Version:            Version3,
		SecurityLevel:      NoAuthNoPriv,
		SecurityParameters: SecurityParameters{UserName: "codec-user", AuthoritativeEngineID: []byte(usmCharEngineID)},
		PDUType:            SNMPv2Trap,
		VarBinds:           usmCharVarbinds,
	}
	data, err := sender.Encode(nil)
	require.NoError(t, err)

	tests := map[string]struct {
		receiver User
		wantErr  string
	}{
		"unset protocol": {
			receiver: User{Name: "codec-user"},
			wantErr:  "incoming packet has a lower security level than its user requires, discarding",
		},
		"NoAuth": {
			receiver: User{Name: "codec-user", AuthProtocol: NoAuth},
			wantErr:  "incoming packet has a lower security level than its user requires, discarding",
		},
		"authentication protocol": {
			receiver: User{Name: "codec-user", AuthProtocol: SHA, AuthPassphrase: "codec-auth-pass"},
			wantErr:  "incoming packet has a lower security level than its user requires, discarding",
		},
		"other user": {
			receiver: User{Name: "other-user"},
			wantErr:  "incoming packet is not authentic, discarding",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Version: Version3, SecurityLevel: AuthNoPriv, User: tc.receiver}
			var err error
			require.NotPanics(t, func() { _, err = x.UnmarshalTrap(bytes.Clone(data), false) })
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMFIPS140OnlyDigest checks, when run with GODEBUG=fips140=only, that
// HMAC-MD5-96 and HMAC-SHA-96 fail with the hash's error instead of
// panicking, when signing and when checking the digest of a message made with
// enforcement off.
func TestUSMFIPS140OnlyDigest(t *testing.T) {
	useEngineTimes(t)
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	for _, auth := range []AuthProtocol{MD5, SHA} {
		t.Run(auth.String(), func(t *testing.T) {
			user := User{Name: "codec-user", AuthProtocol: auth, AuthPassphrase: "codec-auth-pass"}
			trap := func() *Message {
				return &Message{
					Version:            Version3,
					SecurityLevel:      AuthNoPriv,
					SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), UserName: "codec-user"},
					PDUType:            SNMPv2Trap,
					VarBinds:           usmCharVarbinds,
				}
			}
			var data []byte
			var keys usmKeys
			tb := NewSnmpV3SecurityParametersTable()
			fips140.WithoutEnforcement(func() {
				var err error
				keys, err = user.localize([]byte(usmCharEngineID))
				require.NoError(t, err)
				data, err = trap().Encode(&user)
				require.NoError(t, err)
				require.NoError(t, tb.Add(user, []byte(usmCharEngineID)))
			})

			var err error
			panicked, wroteStdout := observe(func() { _, err = trap().marshalMsg(&keys) })
			assert.False(t, panicked, "encode panicked")
			assert.False(t, wroteStdout, "encode wrote to stdout")
			assert.ErrorContains(t, err, "not allowed in FIPS 140-only mode")

			// The table holds the keys for the trap's engine ID, so decoding
			// derives none.
			x := &Client{Version: Version3, TrapSecurityParametersTable: tb}
			require.NotPanics(t, func() { _, err = x.UnmarshalTrap(bytes.Clone(data), false) })
			assert.ErrorContains(t, err, "not allowed in FIPS 140-only mode")
		})
	}
}

// TestUSMFIPS140OnlyEncodeNoAuth pins that Message.Encode derives no key a
// message's level does not use: in FIPS 140-only mode, which refuses MD5 and
// SHA-1 keys, a user of those protocols encodes a noAuthNoPriv message.
func TestUSMFIPS140OnlyEncodeNoAuth(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	for _, auth := range []AuthProtocol{MD5, SHA} {
		t.Run(auth.String(), func(t *testing.T) {
			user := User{Name: "codec-user", AuthProtocol: auth, AuthPassphrase: "codec-auth-pass"}
			_, err := (&Message{
				Version: Version3, SecurityLevel: NoAuthNoPriv, PDUType: SNMPv2Trap,
				SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), UserName: "codec-user"},
			}).Encode(&user)
			require.NoError(t, err)
		})
	}
}

// TestUSMFIPS140OnlyDecrypt checks, when run with GODEBUG=fips140=only, that
// a receiver whose privacy cipher the mode refuses (DES, AES-CFB) rejects an
// authPriv message made with enforcement off with the refusal, a local
// failure that unwraps to no RFC 3414 error (not ErrDecryption: the message is
// not at fault), after checking its digest: on the trap paths, the raw decode
// and a reply, for every privacy protocol.
func TestUSMFIPS140OnlyDecrypt(t *testing.T) {
	useEngineTimes(t)
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	for _, priv := range usmPrivProtocols[1:] {
		t.Run(priv.String(), func(t *testing.T) {
			user := User{
				Name: "codec-user", AuthProtocol: SHA256, AuthPassphrase: "codec-auth-pass",
				PrivProtocol: priv, PrivPassphrase: "codec-priv-pass",
			}
			header := SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), UserName: "codec-user"}
			var trap, reply []byte
			var keys usmKeys
			fips140.WithoutEnforcement(func() {
				var err error
				keys, err = user.localize(header.AuthoritativeEngineID)
				require.NoError(t, err)
				trap, err = (&Message{
					Version: Version3, SecurityLevel: AuthPriv, SecurityParameters: header,
					PDUType: SNMPv2Trap, VarBinds: usmCharVarbinds,
				}).Encode(&user)
				require.NoError(t, err)
				reply, err = (&Message{
					Version: Version3, SecurityLevel: AuthPriv, SecurityParameters: header,
					MsgID: 7, PDUType: Response, RequestID: 1, VarBinds: usmCharVarbinds,
				}).Encode(&user)
				require.NoError(t, err)
			})
			client := func() *Client {
				return &Client{Version: Version3, SecurityLevel: AuthPriv, User: user}
			}
			paths := map[string]func() error{
				"single": func() error { _, err := client().UnmarshalTrap(bytes.Clone(trap), false); return err },
				"table": func() error {
					tb := NewSnmpV3SecurityParametersTable()
					require.NoError(t, tb.Add(user, header.AuthoritativeEngineID))
					_, err := (&Client{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(bytes.Clone(trap), false)
					return err
				},
				"raw": func() error { _, err := client().DecodeMessage(bytes.Clone(trap)); return err },
				"reply": func() error {
					req := &Message{Version: Version3, SecurityLevel: AuthPriv, SecurityParameters: header, MsgID: 7}
					e := exchange{x: client(), packet: req, sec: attemptSecurity{keys: keys}}
					_, _, err := e.decode(reply, nil)
					return err
				},
			}
			for name, decode := range paths {
				t.Run(name, func(t *testing.T) {
					err := decode()
					require.ErrorContains(t, err, "not allowed in FIPS 140-only mode")
					assert.Empty(t, categoriesOf(err), "a local failure is in no category")
				})
			}
		})
	}
}

// TestUSMFIPS140OnlyShortSHA2Key checks, when run with GODEBUG=fips140=only,
// that signing with an HMAC-SHA-2 key shorter than the hash, as one shorter
// than the 14 octets crypto/hmac accepts in that mode, where it panics, fails
// with the rule's error, without a panic or output, and that a key of the
// hash's size signs.
func TestUSMFIPS140OnlyShortSHA2Key(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	tests := map[string]struct {
		keyLen  int
		wantErr string
	}{
		"13-octet key": {keyLen: 13, wantErr: "usm: authentication key of 13 octets, want 32"},
		"14-octet key": {keyLen: 14, wantErr: "usm: authentication key of 14 octets, want 32"},
		"32-octet key": {keyLen: 32},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pkt := &Message{
				Version:            Version3,
				SecurityLevel:      AuthNoPriv,
				SecurityParameters: SecurityParameters{AuthoritativeEngineID: []byte(usmCharEngineID), UserName: "codec-user"},
				PDUType:            SNMPv2Trap,
				VarBinds:           usmCharVarbinds,
			}
			keys := usmKeys{authProtocol: SHA256, auth: bytes.Repeat([]byte{'k'}, tc.keyLen)}
			var msg []byte
			var err error
			panicked, wroteStdout := observe(func() { msg, err = pkt.marshalMsg(&keys) })
			assert.False(t, panicked, "encode panicked")
			assert.False(t, wroteStdout, "wrote to stdout")
			if tc.wantErr != "" {
				assert.EqualError(t, err, tc.wantErr)
				assert.Nil(t, msg)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, msg)
		})
	}
}

// TestUSMEmptyPassphraseKeys checks that an empty passphrase derives no key:
// localizing fails with the rule's error for the protocol left without one,
// so no authentication key, DES key or Blumenthal key extended from nothing
// is computed from it.
func TestUSMEmptyPassphraseKeys(t *testing.T) {
	tests := map[string]struct {
		auth     AuthProtocol
		authPass string
		priv     PrivProtocol
		wantErr  string
	}{
		"authentication": {auth: SHA, priv: NoPriv, wantErr: "usm: no authentication key, want 20 octets"},
		"DES":            {auth: SHA, authPass: "codec-auth-pass", priv: DES, wantErr: "usm: no privacy key, want 16 octets"},
		"Blumenthal":     {auth: SHA256, authPass: "codec-auth-pass", priv: AES256, wantErr: "usm: no privacy key, want 32 octets"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user := User{AuthProtocol: tc.auth, AuthPassphrase: tc.authPass, PrivProtocol: tc.priv}
			keys, err := user.localize([]byte(usmCharEngineID))
			require.EqualError(t, err, tc.wantErr)
			assert.Nil(t, keys.auth)
			assert.Nil(t, keys.priv)
			privKey, err := user.privKey([]byte(usmCharEngineID))
			require.NoError(t, err)
			assert.Nil(t, privKey)
		})
	}
}

// TestUSMKeyLengths checks the length of a derived DES key: an HMAC-SHA
// user's is the localized key's first 16 octets.
func TestUSMKeyLengths(t *testing.T) {
	user := usmUser(SHA, "codec-auth-pass", DES, "codec-priv-pass")
	keys, err := user.localize([]byte(usmCharEngineID))
	require.NoError(t, err)
	localized, err := passwordCache.LocalizedKey(crypto.SHA1, "codec-priv-pass", []byte(usmCharEngineID))
	require.NoError(t, err)
	assert.Equal(t, localized[:16], keys.priv, "derived DES key")
}

// TestUSMFIPS140OnlyKeyDerivation checks, when run with GODEBUG=fips140=only,
// that localizing returns the error of deriving a key with a hash the mode
// refuses, not the missing key it leaves.
func TestUSMFIPS140OnlyKeyDerivation(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	user := User{AuthProtocol: MD5, AuthPassphrase: "codec-auth-pass"}
	keys, err := user.localize([]byte(usmCharEngineID))
	require.EqualError(t, err, "crypto/md5: use of MD5 is not allowed in FIPS 140-only mode")
	assert.Nil(t, keys.auth)
}

// TestSignDigestOffset pins where an outgoing message's digest goes: into its
// msgAuthenticationParameters field, as the digest of the message with the
// field zeroed, for layouts whose lengths take the long form (a USM SEQUENCE
// over 127 and 255 octets, a security-parameters OCTET STRING of 127 and 128
// octets, messages over 255 and 65535 octets: the engine ID makes the USM
// SEQUENCE long, a user name has at most 32 octets), and when the user name or
// the engine ID holds the octets of the zero placeholder. The signed message
// differs from its unsigned layout only in that field and decodes as an
// authentic trap.
func TestSignDigestOffset(t *testing.T) {
	useEngineTimes(t)
	// usmLen is the length of the encoded USM SEQUENCE of a message from
	// engineID.
	usmLen := func(t *testing.T, auth AuthProtocol, priv PrivProtocol, engineID string) int {
		m := splitV3Message(t, signedTestTrap(t, auth, priv, engineID, "codec-user", nil))
		var usm [][]byte
		for i, f := range m.usm {
			usm = append(usm, tlv(m.usmTags[i], f))
		}
		return len(tlv(0x30, usm...))
	}
	// longEngineID returns an engine ID of n octets.
	longEngineID := func(n int) string { return usmCharEngineID[:5] + strings.Repeat("e", n-5) }
	// engineIDForUSMLen returns an engine ID that makes the USM SEQUENCE n
	// octets long (its content under 128 octets).
	engineIDForUSMLen := func(t *testing.T, auth AuthProtocol, priv PrivProtocol, n int) string {
		e := longEngineID(5 + n - usmLen(t, auth, priv, longEngineID(5)))
		require.Equal(t, n, usmLen(t, auth, priv, e))
		return e
	}
	value := func(n int) []VarBind {
		return []VarBind{{Name: ".1.3.6.1.2.1.1.1.0", Type: OctetString, Value: bytes.Repeat([]byte("v"), n)}}
	}
	// placeholder is the field as marshal appends it before signing.
	placeholder := func(auth AuthProtocol) string {
		return string(appendMACPlaceholder(nil, auth.spec().MACLen))
	}

	type layout = func(t *testing.T, auth AuthProtocol, priv PrivProtocol) string
	tests := map[string]struct {
		user      func(auth AuthProtocol) string
		engineID  layout
		variables []VarBind
		minLen    int // of the message
	}{
		"short": {},
		"USM SEQUENCE over 127 octets": {
			engineID: func(*testing.T, AuthProtocol, PrivProtocol) string { return longEngineID(100) },
		},
		"USM SEQUENCE over 255 octets": {
			engineID: func(*testing.T, AuthProtocol, PrivProtocol) string { return longEngineID(250) },
		},
		// The longest fields the decoder takes: a USM SEQUENCE over 127
		// octets but for MD5 without privacy.
		"longest engine ID and user name": {
			user:     func(AuthProtocol) string { return strings.Repeat("u", maxUserNameLen) },
			engineID: func(*testing.T, AuthProtocol, PrivProtocol) string { return longEngineID(maxDecodedEngineIDLen) },
		},
		"security parameters of 127 octets": {
			engineID: func(t *testing.T, auth AuthProtocol, priv PrivProtocol) string {
				return engineIDForUSMLen(t, auth, priv, 127)
			},
		},
		"security parameters of 128 octets": {
			engineID: func(t *testing.T, auth AuthProtocol, priv PrivProtocol) string {
				return engineIDForUSMLen(t, auth, priv, 128)
			},
		},
		"placeholder octets in the user name": {
			user: placeholder,
		},
		"placeholder octets in the engine ID": {
			engineID: func(_ *testing.T, auth AuthProtocol, _ PrivProtocol) string {
				return "\x80\x00\x1f\x88\x04" + placeholder(auth)
			},
		},
		"message over 255 octets":   {variables: value(300), minLen: 256},
		"message over 65535 octets": {variables: value(70000), minLen: 65536},
	}
	for name, tc := range tests {
		for _, auth := range []AuthProtocol{MD5, SHA512} {
			for _, priv := range []PrivProtocol{NoPriv, AES} {
				t.Run(fmt.Sprintf("%s/%s/%s", name, auth, priv), func(t *testing.T) {
					user, engineID := "codec-user", usmCharEngineID
					if tc.user != nil {
						if user = tc.user(auth); len(user) > maxUserNameLen {
							t.Skipf("the %d-octet placeholder does not fit a user name", len(user))
						}
					}
					if tc.engineID != nil {
						engineID = tc.engineID(t, auth, priv)
					}
					data := signedTestTrap(t, auth, priv, engineID, user, tc.variables)
					require.GreaterOrEqual(t, len(data), tc.minLen)

					m := splitV3Message(t, data)
					require.Equal(t, data, m.bytes(), "the message re-encodes as laid out")
					digest := m.usm[4]
					m.usm[4] = make([]byte, len(digest))
					unsigned := m.bytes()

					u := signedTestUser(auth, priv, user)
					key, err := u.authKey([]byte(engineID))
					require.NoError(t, err)
					mac := hmac.New(auth.hash().New, key)
					mac.Write(unsigned)
					assert.Equal(t, mac.Sum(nil)[:auth.spec().MACLen], digest, "the field holds the digest")

					x := &Client{Version: Version3, SecurityLevel: signedTestFlags(priv), User: u}
					res, err := x.UnmarshalTrap(bytes.Clone(data), false)
					if len(engineID) > maxDecodedEngineIDLen {
						require.ErrorIs(t, err, ErrInvalidMsgs, "an engine ID longer than the decoder takes")
						return
					}
					require.NoError(t, err)
					_, w, err := unmarshalHeader(data, new(Message))
					require.NoError(t, err)
					assert.Equal(t, [2]int{authParamsOffset(t, data), auth.spec().MACLen}, [2]int{w.authOff, w.authLen},
						"the parse finds the field where the encoder put it")
					h := &res.SecurityParameters
					assert.Equal(t, []string{engineID, user}, []string{string(h.AuthoritativeEngineID), h.UserName})
					if tc.variables != nil {
						require.Len(t, res.VarBinds, 1)
						assert.Equal(t, tc.variables[0].Value, res.VarBinds[0].Value)
					}
				})
			}
		}
	}
}

// authParamsOffset returns the offset of the msgAuthenticationParameters
// content in the SNMPv3 message data.
func authParamsOffset(t *testing.T, data []byte) int {
	t.Helper()
	r := ber.NewReader(data)
	enter := func() {
		_, header, err := ber.Length(r.Rest())
		require.NoError(t, err)
		r = ber.NewReader(r.Rest()[header:])
	}
	skip := func(n int) {
		for range n {
			_, _, err := r.Next()
			require.NoError(t, err)
		}
	}
	enter() // the message
	skip(2) // the version and msgGlobalData
	enter() // the security parameters' OCTET STRING
	enter() // the USM SEQUENCE
	skip(4) // the engine ID, boots, time and user name
	enter() // msgAuthenticationParameters
	return len(data) - r.Len()
}

// signedTestUser returns user with the protocols auth and priv and the codec
// passphrases.
func signedTestUser(auth AuthProtocol, priv PrivProtocol, user string) User {
	return User{
		Name: user, AuthProtocol: auth, AuthPassphrase: "codec-auth-pass",
		PrivProtocol: priv, PrivPassphrase: "codec-priv-pass",
	}
}

// signedTestHeader returns the USM header of a message from user at
// engineID, with engine boots 3 and time 77.
func signedTestHeader(engineID, user string) SecurityParameters {
	return SecurityParameters{
		AuthoritativeEngineID: []byte(engineID), AuthoritativeEngineBoots: 3, AuthoritativeEngineTime: 77,
		UserName: user,
	}
}

// signedTestFlags is authPriv with a privacy protocol, authNoPriv without.
func signedTestFlags(priv PrivProtocol) SecurityLevel {
	if priv > NoPriv {
		return AuthPriv
	}
	return AuthNoPriv
}

// signedTestTrap encodes a signed SNMPv2-Trap from user at engineID,
// encrypted with a privacy protocol, carrying variables (usmPlainVars when
// nil).
func signedTestTrap(t *testing.T, auth AuthProtocol, priv PrivProtocol, engineID, user string, variables []VarBind) []byte {
	t.Helper()
	if variables == nil {
		variables = usmPlainVars
	}
	u := signedTestUser(auth, priv, user)
	data, err := (&Message{
		Version: Version3, SecurityLevel: signedTestFlags(priv),
		SecurityParameters: signedTestHeader(engineID, user), PDUType: SNMPv2Trap, VarBinds: variables,
	}).Encode(&u)
	require.NoError(t, err)
	return data
}
