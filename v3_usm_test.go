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
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
)

/**
 * This tests use hex dumps from real network traffic produced using net-snmp's snmpget with demo.snmplabs.com as SNMP agent.
 */

func authorativeEngineID(t *testing.T) string {
	// engine ID of demo.snmplabs.com
	engineID, err := hex.DecodeString("80004fb805636c6f75644dab22cc")
	require.NoError(t, err, "EngineId decoding failed.")

	return string(engineID)
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

func packetSHA224AuthenticationParams(t *testing.T) string {
	params, err := hex.DecodeString("66cd2d9b04cd48b02a9df0c77dc3415d")

	require.NoError(t, err, "Authentication parameters SHA224 decoding failed.")
	return string(params)
}

// TestTrapOtherUser pins that a single trap user does not take a message
// naming another user (RFC 3414 section 3.2 step 4), before its digest.
func TestTrapOtherUser(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: packetSHA224AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}

	sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	verifier := sp.Copy().usm()
	verifier.UserName = "foo"

	msg := packetSHA224Authenticated(t)
	res := new(SnmpPacket)
	_, w, err := unmarshalHeader(msg, res)
	require.NoError(t, err)
	step, err := decodeTrapV3(msg, w, res, verifier, trapRule{singleUser: true})
	require.ErrorIs(t, err, ErrUnknownUsername)
	assert.Equal(t, stepUser, step)
}

func TestAuthenticationSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: "",
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
		PrivacyKey:               nil,
	}

	sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)
	err = sp.sign(srcPacket, authParamsOffset(t, srcPacket))
	require.NoError(t, err, "Authentication of packet failed")

	require.Equal(t, packetSHA224Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: packetSHA224AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}

	sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	require.NoError(t, testInbound(t, packetSHA224Authenticated(t), sp.Copy().usm()).verify(), "Packet was not considered to be authentic")
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

func packetSHA512AuthenticationParams(t *testing.T) string {
	params, err := hex.DecodeString("26f8087ced336a394642b8698eba9810929a9bfa44afbf43975a7ad6c4cc55bd279b549a77ec56d791467612747d6f57")

	require.NoError(t, err, "Authentication parameters SHA512 decoding failed.")
	return string(params)
}

func TestAuthenticationSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113258,
		UserName:                 "usr-sha512-none",
		AuthenticationParameters: "",
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA512,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}

	sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)
	err = sp.sign(srcPacket, authParamsOffset(t, srcPacket))
	require.NoError(t, err, "Generation of key failed")

	require.Equal(t, packetSHA512Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha512-none",
		AuthenticationParameters: packetSHA512AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA512,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
		PrivacyKey:               nil,
	}

	sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	require.NoError(t, testInbound(t, packetSHA512Authenticated(t), sp.Copy().usm()).verify(), "Packet was not considered to be authentic")
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
				_, _, err := unmarshalHeader(msg, new(SnmpPacket))
				require.Error(t, err)
			})
		})
	}
}

// testInbound returns the SNMPv3 message msg in security processing with sp
// (receiveV3).
func testInbound(t *testing.T, msg []byte, sp *UsmSecurityParameters) *inbound {
	t.Helper()
	res := new(SnmpPacket)
	_, w, err := unmarshalHeader(msg, res)
	require.NoError(t, err)
	in, err := receiveV3(msg, w, res, sp)
	require.NoError(t, err)
	return &in
}

// TestUSMUnsupportedProtocols checks that protocol values outside the defined
// sets fail with an error on every path: validation, key derivation,
// encoding without validation, and decoding with table parameters changed
// after Add.
func TestUSMUnsupportedProtocols(t *testing.T) {
	useEngineTimes(t)
	const (
		authErr = "securityParameters.AuthenticationProtocol SnmpV3AuthProtocol(8) is not supported"
		privErr = "securityParameters.PrivacyProtocol SnmpV3PrivProtocol(8) is not supported"
	)
	params := func(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) *UsmSecurityParameters {
		return &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthoritativeEngineID:    usmCharEngineID,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: "codec-auth-pass",
			PrivacyProtocol:          priv,
			PrivacyPassphrase:        "codec-priv-pass",
		}
	}

	tests := map[string]struct {
		auth    SnmpV3AuthProtocol
		priv    SnmpV3PrivProtocol
		flags   SnmpV3MsgFlags
		wantErr string
	}{
		"authentication": {auth: SnmpV3AuthProtocol(8), priv: NoPriv, flags: AuthNoPriv, wantErr: authErr},
		"privacy":        {auth: SHA, priv: SnmpV3PrivProtocol(8), flags: AuthPriv, wantErr: privErr},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Run("validate", func(t *testing.T) {
				x := &GoSNMP{
					Version:            Version3,
					MsgFlags:           tc.flags,
					SecurityModel:      UserSecurityModel,
					SecurityParameters: params(tc.auth, tc.priv),
				}
				// Validation runs before decoding, so an empty message reaches it.
				_, err := x.SnmpDecodePacket(nil)
				assert.EqualError(t, err, tc.wantErr)
			})
			t.Run("keys", func(t *testing.T) {
				assert.EqualError(t, params(tc.auth, tc.priv).InitSecurityKeys(), tc.wantErr)
			})
			t.Run("table", func(t *testing.T) {
				table := NewSnmpV3SecurityParametersTable(Logger{})
				assert.EqualError(t, table.Add("codec-user", params(tc.auth, tc.priv)), tc.wantErr)
			})
			t.Run("encode", func(t *testing.T) {
				pkt := &SnmpPacket{
					Version:            Version3,
					MsgFlags:           tc.flags,
					SecurityModel:      UserSecurityModel,
					SecurityParameters: params(tc.auth, tc.priv),
					PDUType:            SNMPv2Trap,
					Variables:          usmCharVarbinds,
				}
				var err error
				require.NotPanics(t, func() { _, err = pkt.MarshalMsg() })
				assert.EqualError(t, err, tc.wantErr)
			})
			t.Run("decode", func(t *testing.T) {
				data := usmCharTrap(t, AES, usmCharVarbinds)
				sp := params(SHA, AES)
				table := NewSnmpV3SecurityParametersTable(Logger{})
				require.NoError(t, table.Add("codec-user", sp))
				sp.AuthenticationProtocol, sp.PrivacyProtocol = tc.auth, tc.priv
				x := &GoSNMP{Version: Version3, TrapSecurityParametersTable: table}
				var err error
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
		authErr = "securityParameters.AuthenticationProtocol is required"
		privErr = "securityParameters.PrivacyProtocol is required"
	)

	tests := map[string]struct {
		flags   SnmpV3MsgFlags
		auth    SnmpV3AuthProtocol
		priv    SnmpV3PrivProtocol
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
			sp := &UsmSecurityParameters{
				UserName:                 "codec-user",
				AuthoritativeEngineID:    usmCharEngineID,
				AuthenticationProtocol:   tc.auth,
				AuthenticationPassphrase: "codec-auth-pass",
				PrivacyProtocol:          tc.priv,
				PrivacyPassphrase:        "codec-priv-pass",
			}
			require.NoError(t, sp.InitSecurityKeys())
			pkt := &SnmpPacket{
				Version:            Version3,
				MsgFlags:           tc.flags,
				SecurityModel:      UserSecurityModel,
				SecurityParameters: sp,
				PDUType:            SNMPv2Trap,
				Variables:          usmCharVarbinds,
			}
			var msg []byte
			var err error
			panicked, wroteStdout := observe(func() { msg, err = pkt.MarshalMsg() })
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
		auth    SnmpV3AuthProtocol
		priv    SnmpV3PrivProtocol
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
			_, err := x.SnmpDecodePacket(bytes.Clone(tc.in))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMTrapTableAttempts checks how the trap table path tries the
// parameter sets of a user, in the order they were added, on the one trap (no
// attempt writes it): the first that decodes wins, and when none does the
// error carries the one of the set that got furthest, whatever the order, the
// first on ties: a wrong digest after a local failure that comes before it, a
// level the set lacks protocols for after another engine ID.
func TestUSMTrapTableAttempts(t *testing.T) {
	useEngineTimes(t)
	data := usmCharTrap(t, AES, usmCharVarbinds)
	params := func(authPass string) *UsmSecurityParameters {
		return &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthoritativeEngineID:    usmCharEngineID,
			AuthenticationProtocol:   SHA,
			AuthenticationPassphrase: authPass,
			PrivacyProtocol:          AES,
			PrivacyPassphrase:        "codec-priv-pass",
		}
	}
	good := func() *UsmSecurityParameters { return params("codec-auth-pass") }
	wrongPass := func() *UsmSecurityParameters { return params("wrong-auth-pass") }
	// unsupported fails before decoding anything; its protocol is set after
	// Add, which rejects it.
	unsupported := func(tb *SnmpV3SecurityParametersTable) {
		sp := good()
		require.NoError(t, tb.Add("codec-user", sp))
		sp.AuthenticationProtocol = SnmpV3AuthProtocol(8)
	}
	// keysOnly holds keys for another engine ID, without passphrases: it
	// refuses the trap's engine ID (step 4); noPriv has no privacy protocol
	// for the authPriv trap (step 5).
	keysOnly := usmKeysOnly(good(), usmOtherEngineID)
	noPriv := good()
	noPriv.PrivacyProtocol = NoPriv
	add := func(sp *UsmSecurityParameters) func(*SnmpV3SecurityParametersTable) {
		return func(tb *SnmpV3SecurityParametersTable) { require.NoError(t, tb.Add("codec-user", sp)) }
	}
	const (
		prefix         = "no credentials successfully unmarshaled trap: "
		notAuthentic   = "incoming packet is not authentic, discarding"
		notSupportedV8 = "securityParameters.AuthenticationProtocol SnmpV3AuthProtocol(8) is not supported"
		otherEngine    = "usm: without a passphrase, the authentication key cannot be localized to another engine ID"
		noPrivProtocol = "error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message"
	)

	tests := map[string]struct {
		sets    []func(*SnmpV3SecurityParametersTable)
		wantErr string
	}{
		"wrong passphrase, then right":    {sets: []func(*SnmpV3SecurityParametersTable){add(wrongPass()), add(good())}},
		"right passphrase first":          {sets: []func(*SnmpV3SecurityParametersTable){add(good()), add(wrongPass())}},
		"unsupported, then not authentic": {sets: []func(*SnmpV3SecurityParametersTable){unsupported, add(wrongPass())}, wantErr: prefix + notAuthentic},
		"not authentic, then unsupported": {sets: []func(*SnmpV3SecurityParametersTable){add(wrongPass()), unsupported}, wantErr: prefix + notAuthentic},
		"unsupported twice":               {sets: []func(*SnmpV3SecurityParametersTable){unsupported, unsupported}, wantErr: prefix + notSupportedV8},
		"unsupported, then keys only":     {sets: []func(*SnmpV3SecurityParametersTable){unsupported, add(keysOnly)}, wantErr: prefix + notSupportedV8},
		"keys only, then unsupported":     {sets: []func(*SnmpV3SecurityParametersTable){add(keysOnly), unsupported}, wantErr: prefix + otherEngine},
		"keys only, then no privacy":      {sets: []func(*SnmpV3SecurityParametersTable){add(keysOnly), add(noPriv)}, wantErr: prefix + noPrivProtocol},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tb := NewSnmpV3SecurityParametersTable(Logger{})
			for _, set := range tc.sets {
				set(tb)
			}
			x := &GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}
			in := bytes.Clone(data)
			res, err := x.UnmarshalTrap(in, false)
			assert.Equal(t, data, in, "the caller's trap")
			if tc.wantErr != "" {
				assert.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, usmCharVarbinds, res.Variables)
		})
	}
}

// TestUSMReceiveEngineBinding pins the categories of the engine ID rule when a
// receiver takes a message from another engine ID: a key given without its
// passphrase is bound to its engine, so the user is unknown there
// (ErrUnknownUsername, RFC 3414 section 3.2 step 4), for either key; a
// protocol with neither key nor passphrase is the receiver's configuration
// error, of no RFC category.
func TestUSMReceiveEngineBinding(t *testing.T) {
	w := v3Wire{engineID: usmCharEngineID, has: hasEngineID}
	keysOnly := func(edit func(sp *UsmSecurityParameters)) *UsmSecurityParameters {
		sp := usmKeysOnly(usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")().SecurityParameters.usm(), usmOtherEngineID)
		edit(sp)
		return sp
	}
	tests := map[string]struct {
		sp      *UsmSecurityParameters
		wantErr error
		unknown bool // unwraps to ErrUnknownUsername
	}{
		"authentication key only": {
			sp: keysOnly(func(*UsmSecurityParameters) {}), wantErr: errAuthKeyBoundToEngine, unknown: true,
		},
		"privacy key only": {
			sp:      keysOnly(func(sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = "codec-auth-pass" }),
			wantErr: errPrivKeyBoundToEngine, unknown: true,
		},
		"privacy protocol without key or passphrase": {
			sp: keysOnly(func(sp *UsmSecurityParameters) {
				sp.AuthenticationPassphrase, sp.PrivacyKey = "codec-auth-pass", nil
			}),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tc.sp.receive(AuthPriv, &w, true)
			require.Error(t, err)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.unknown, errors.Is(err, ErrUnknownUsername))
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
	receivers := map[string]func() *GoSNMP{
		"single": func() *GoSNMP {
			return &GoSNMP{Version: Version3, SecurityModel: UserSecurityModel, SecurityParameters: &UsmSecurityParameters{UserName: "secret-user"}}
		},
		"table": func() *GoSNMP {
			tb := NewSnmpV3SecurityParametersTable(Logger{})
			require.NoError(t, tb.Add("secret-user", &UsmSecurityParameters{UserName: "secret-user"}))
			return &GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}
		},
	}
	tests := map[string]struct {
		in   []byte
		want error // nil: accepted
	}{
		"as sent":                 {in: trap(octets(usmCharEngineID), octets("secret-user"))},
		"user name as an INTEGER": {in: trap(octets(usmCharEngineID), intTLV(1)), want: ErrInvalidMsgs},
		"engine ID as an INTEGER": {in: trap(intTLV(1), octets("secret-user")), want: ErrInvalidMsgs},
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
	vars := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: Integer, Value: 5}}
	tests := map[string]struct {
		in          []byte
		wantVersion SnmpVersion
		wantPDUType PDUType
	}{
		"SNMPv1":  {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, vbl), wantVersion: Version1, wantPDUType: Trap},
		"SNMPv2c": {in: craftedMsg(1, craftedPDU(SNMPv2Trap, vbl)), wantVersion: Version2c, wantPDUType: SNMPv2Trap},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tb := NewSnmpV3SecurityParametersTable(Logger{})
			require.NoError(t, tb.Add("codec-user", &UsmSecurityParameters{UserName: "codec-user"}))
			x := &GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}
			var res *SnmpPacket
			var err error
			require.NotPanics(t, func() { res, err = x.UnmarshalTrap(tc.in, false) })
			require.NoError(t, err)
			assert.Equal(t, tc.wantVersion, res.Version)
			assert.Equal(t, tc.wantPDUType, res.PDUType)
			assert.Equal(t, vars, res.Variables)
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
	sender := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: "codec-user", AuthoritativeEngineID: usmCharEngineID},
		PDUType:            SNMPv2Trap,
		Variables:          usmCharVarbinds,
	}
	data, err := sender.MarshalMsg()
	require.NoError(t, err)

	tests := map[string]struct {
		receiver *UsmSecurityParameters
		wantErr  string
	}{
		"unset protocol": {
			receiver: &UsmSecurityParameters{UserName: "codec-user"},
			wantErr:  "incoming packet has a lower security level than its user requires, discarding",
		},
		"NoAuth": {
			receiver: &UsmSecurityParameters{UserName: "codec-user", AuthenticationProtocol: NoAuth},
			wantErr:  "incoming packet has a lower security level than its user requires, discarding",
		},
		"authentication protocol": {
			receiver: &UsmSecurityParameters{
				UserName:                 "codec-user",
				AuthenticationProtocol:   SHA,
				AuthenticationPassphrase: "codec-auth-pass",
			},
			wantErr: "incoming packet has a lower security level than its user requires, discarding",
		},
		"other user": {
			receiver: &UsmSecurityParameters{UserName: "other-user"},
			wantErr:  "incoming packet is not authentic, discarding",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &GoSNMP{
				Version:            Version3,
				MsgFlags:           AuthNoPriv,
				SecurityModel:      UserSecurityModel,
				SecurityParameters: tc.receiver,
			}
			var err error
			require.NotPanics(t, func() { _, err = x.UnmarshalTrap(bytes.Clone(data), false) })
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMFIPS140OnlyDigest checks, when run with GODEBUG=fips140=only, that
// HMAC-MD5-96 and HMAC-SHA-96 fail with the hash's error instead of
// panicking, when encoding and when decoding a message made with enforcement
// off.
func TestUSMFIPS140OnlyDigest(t *testing.T) {
	useEngineTimes(t)
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	for _, auth := range []SnmpV3AuthProtocol{MD5, SHA} {
		t.Run(auth.String(), func(t *testing.T) {
			sp := &UsmSecurityParameters{
				UserName:                 "codec-user",
				AuthoritativeEngineID:    usmCharEngineID,
				AuthenticationProtocol:   auth,
				AuthenticationPassphrase: "codec-auth-pass",
			}
			trap := func() *SnmpPacket {
				return &SnmpPacket{
					Version:            Version3,
					MsgFlags:           AuthNoPriv,
					SecurityModel:      UserSecurityModel,
					SecurityParameters: sp.Copy(),
					PDUType:            SNMPv2Trap,
					Variables:          usmCharVarbinds,
				}
			}
			var data []byte
			fips140.WithoutEnforcement(func() {
				require.NoError(t, sp.InitSecurityKeys())
				var err error
				data, err = trap().MarshalMsg()
				require.NoError(t, err)
			})

			var err error
			panicked, wroteStdout := observe(func() { _, err = trap().MarshalMsg() })
			assert.False(t, panicked, "encode panicked")
			assert.False(t, wroteStdout, "encode wrote to stdout")
			assert.ErrorContains(t, err, "not allowed in FIPS 140-only mode")

			// The receiver has the keys, so decoding derives none.
			x := &GoSNMP{Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy()}
			require.NotPanics(t, func() { _, err = x.UnmarshalTrap(bytes.Clone(data), false) })
			assert.ErrorContains(t, err, "not allowed in FIPS 140-only mode")
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
			sp := &UsmSecurityParameters{
				UserName: "codec-user", AuthoritativeEngineID: usmCharEngineID,
				AuthenticationProtocol: SHA256, AuthenticationPassphrase: "codec-auth-pass",
				PrivacyProtocol: priv, PrivacyPassphrase: "codec-priv-pass",
			}
			var trap, reply []byte
			fips140.WithoutEnforcement(func() {
				require.NoError(t, sp.InitSecurityKeys())
				var err error
				trap, err = (&SnmpPacket{
					Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(),
					PDUType: SNMPv2Trap, Variables: usmCharVarbinds,
				}).MarshalMsg()
				require.NoError(t, err)
				reply, err = (&SnmpPacket{
					Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(),
					MsgID: 7, PDUType: GetResponse, RequestID: 1, Variables: usmCharVarbinds,
				}).MarshalMsg()
				require.NoError(t, err)
			})
			client := func() *GoSNMP {
				return &GoSNMP{Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy()}
			}
			paths := map[string]func() error{
				"single": func() error { _, err := client().UnmarshalTrap(bytes.Clone(trap), false); return err },
				"table": func() error {
					tb := NewSnmpV3SecurityParametersTable(Logger{})
					require.NoError(t, tb.Add("codec-user", sp.Copy()))
					_, err := (&GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(bytes.Clone(trap), false)
					return err
				},
				"raw": func() error { _, err := client().SnmpDecodePacket(bytes.Clone(trap)); return err },
				"reply": func() error {
					req := &SnmpPacket{Version: Version3, MsgFlags: AuthPriv | Reportable, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(), MsgID: 7}
					_, _, err := (&exchange{x: client(), packet: req}).decode(reply, nil)
					return err
				},
			}
			for name, decode := range paths {
				t.Run(name, func(t *testing.T) {
					err := decode()
					require.ErrorContains(t, err, "not allowed in FIPS 140-only mode")
					for _, category := range []error{ErrDecryption, ErrWrongDigest, ErrInvalidMsgs} {
						assert.NotErrorIs(t, err, category)
					}
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
			pkt := &SnmpPacket{
				Version:       Version3,
				MsgFlags:      AuthNoPriv,
				SecurityModel: UserSecurityModel,
				SecurityParameters: &UsmSecurityParameters{
					UserName:               "codec-user",
					AuthoritativeEngineID:  usmCharEngineID,
					AuthenticationProtocol: SHA256,
					SecretKey:              bytes.Repeat([]byte{'k'}, tc.keyLen),
				},
				PDUType:   SNMPv2Trap,
				Variables: usmCharVarbinds,
			}
			var msg []byte
			var err error
			panicked, wroteStdout := observe(func() { msg, err = pkt.MarshalMsg() })
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
// InitSecurityKeys fails with the rule's error for the protocol left without
// one, so no authentication key, DES key or Blumenthal key extended from
// nothing is computed from it.
func TestUSMEmptyPassphraseKeys(t *testing.T) {
	tests := map[string]struct {
		auth     SnmpV3AuthProtocol
		authPass string
		priv     SnmpV3PrivProtocol
		wantErr  string
	}{
		"authentication": {auth: SHA, priv: NoPriv, wantErr: "usm: no authentication key, want 20 octets"},
		"DES":            {auth: SHA, authPass: "codec-auth-pass", priv: DES, wantErr: "usm: no privacy key, want 16 octets"},
		"Blumenthal":     {auth: SHA256, authPass: "codec-auth-pass", priv: AES256, wantErr: "usm: no privacy key, want 32 octets"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sp := &UsmSecurityParameters{
				AuthoritativeEngineID:    usmCharEngineID,
				AuthenticationProtocol:   tc.auth,
				AuthenticationPassphrase: tc.authPass,
				PrivacyProtocol:          tc.priv,
			}
			require.EqualError(t, sp.InitSecurityKeys(), tc.wantErr)
			if tc.authPass == "" {
				assert.Nil(t, sp.SecretKey)
			}
			assert.Nil(t, sp.PrivacyKey)
		})
	}
}

// TestUSMKeyLengths checks the key lengths InitSecurityKeys leaves and takes:
// an HMAC-SHA user's derived DES key is the localized key's first 16 octets,
// and keys given with another length than the protocol's fail, at
// InitSecurityKeys and at a table's Add.
func TestUSMKeyLengths(t *testing.T) {
	derived := &UsmSecurityParameters{
		AuthoritativeEngineID:    usmCharEngineID,
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        "codec-priv-pass",
	}
	require.NoError(t, derived.InitSecurityKeys())
	localized, err := passwordCache.LocalizedKey(crypto.SHA1, "codec-priv-pass", usmCharEngineID)
	require.NoError(t, err)
	assert.Equal(t, localized[:16], derived.PrivacyKey, "derived DES key")

	tests := map[string]struct {
		auth         SnmpV3AuthProtocol
		priv         SnmpV3PrivProtocol
		key, privKey []byte
		want         string // the error of InitSecurityKeys and of Add, "" for none
	}{
		"SHA key of 16 octets":     {auth: SHA, key: make([]byte, 16), want: "usm: authentication key of 16 octets, want 20"},
		"SHA-256 key of 20 octets": {auth: SHA256, key: make([]byte, 20), want: "usm: authentication key of 20 octets, want 32"},
		"AES key of 32 octets":     {auth: SHA, key: make([]byte, 20), priv: AES, privKey: make([]byte, 32), want: "usm: privacy key of 32 octets, want 16"},
		"DES key of 8 octets":      {auth: SHA, key: make([]byte, 20), priv: DES, privKey: make([]byte, 8), want: "usm: privacy key of 8 octets, want 16"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sp := func() *UsmSecurityParameters {
				return &UsmSecurityParameters{
					UserName:               "codec-user",
					AuthoritativeEngineID:  usmCharEngineID,
					AuthenticationProtocol: tc.auth,
					PrivacyProtocol:        tc.priv,
					SecretKey:              tc.key,
					PrivacyKey:             tc.privKey,
				}
			}
			initErr := sp().InitSecurityKeys()
			addErr := NewSnmpV3SecurityParametersTable(Logger{}).Add("codec-user", sp())
			got := [2]string{}
			for i, err := range []error{initErr, addErr} {
				if err != nil {
					got[i] = err.Error()
				}
			}
			assert.Equal(t, [2]string{tc.want, tc.want}, got)
		})
	}
}

// TestUSMFIPS140OnlyKeyDerivation checks, when run with GODEBUG=fips140=only,
// that InitSecurityKeys returns the error of deriving a key with a hash the
// mode refuses, not the missing key it leaves.
func TestUSMFIPS140OnlyKeyDerivation(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("run with GODEBUG=fips140=only")
	}
	sp := &UsmSecurityParameters{
		AuthoritativeEngineID:    usmCharEngineID,
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: "codec-auth-pass",
	}
	require.EqualError(t, sp.InitSecurityKeys(), "crypto/md5: use of MD5 is not allowed in FIPS 140-only mode")
	assert.Nil(t, sp.SecretKey)
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
	usmLen := func(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol, engineID string) int {
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
	engineIDForUSMLen := func(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol, n int) string {
		e := longEngineID(5 + n - usmLen(t, auth, priv, longEngineID(5)))
		require.Equal(t, n, usmLen(t, auth, priv, e))
		return e
	}
	value := func(n int) []SnmpPDU {
		return []SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: OctetString, Value: bytes.Repeat([]byte("v"), n)}}
	}
	// placeholder is the field as marshal appends it before signing.
	placeholder := func(auth SnmpV3AuthProtocol) string {
		return string(appendMACPlaceholder(nil, auth.spec().MACLen))
	}

	type layout = func(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) string
	tests := map[string]struct {
		user      func(auth SnmpV3AuthProtocol) string
		engineID  layout
		variables []SnmpPDU
		minLen    int // of the message
	}{
		"short": {},
		"USM SEQUENCE over 127 octets": {
			engineID: func(*testing.T, SnmpV3AuthProtocol, SnmpV3PrivProtocol) string { return longEngineID(100) },
		},
		"USM SEQUENCE over 255 octets": {
			engineID: func(*testing.T, SnmpV3AuthProtocol, SnmpV3PrivProtocol) string { return longEngineID(250) },
		},
		"security parameters of 127 octets": {
			engineID: func(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) string {
				return engineIDForUSMLen(t, auth, priv, 127)
			},
		},
		"security parameters of 128 octets": {
			engineID: func(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) string {
				return engineIDForUSMLen(t, auth, priv, 128)
			},
		},
		"placeholder octets in the user name": {
			user: placeholder,
		},
		"placeholder octets in the engine ID": {
			engineID: func(_ *testing.T, auth SnmpV3AuthProtocol, _ SnmpV3PrivProtocol) string {
				return "\x80\x00\x1f\x88\x04" + placeholder(auth)
			},
		},
		"message over 255 octets":   {variables: value(300), minLen: 256},
		"message over 65535 octets": {variables: value(70000), minLen: 65536},
	}
	for name, tc := range tests {
		for _, auth := range []SnmpV3AuthProtocol{MD5, SHA512} {
			for _, priv := range []SnmpV3PrivProtocol{NoPriv, AES} {
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

					_, w, err := unmarshalHeader(data, new(SnmpPacket))
					require.NoError(t, err)
					assert.Equal(t, [2]int{authParamsOffset(t, data), auth.spec().MACLen}, [2]int{w.authOff, w.authLen},
						"the parse finds the field where the encoder put it")

					sp := signedTestUSM(t, auth, priv, engineID, user)
					mac := hmac.New(auth.HashType().New, sp.SecretKey)
					mac.Write(unsigned)
					assert.Equal(t, mac.Sum(nil)[:auth.spec().MACLen], digest, "the field holds the digest")

					x := &GoSNMP{Version: Version3, MsgFlags: signedTestFlags(priv), SecurityModel: UserSecurityModel, SecurityParameters: sp}
					res, err := x.UnmarshalTrap(bytes.Clone(data), false)
					require.NoError(t, err)
					usp := res.SecurityParameters.usm()
					assert.Equal(t, []string{engineID, user}, []string{usp.AuthoritativeEngineID, usp.UserName})
					if tc.variables != nil {
						require.Len(t, res.Variables, 1)
						assert.Equal(t, tc.variables[0].Value, res.Variables[0].Value)
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

// signedTestUSM returns parameters for user with keys localized to engineID.
func signedTestUSM(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol, engineID, user string) *UsmSecurityParameters {
	t.Helper()
	sp := &UsmSecurityParameters{
		UserName: user, AuthenticationProtocol: auth, AuthenticationPassphrase: "codec-auth-pass",
		PrivacyProtocol: priv, PrivacyPassphrase: "codec-priv-pass",
		AuthoritativeEngineID: engineID, AuthoritativeEngineBoots: 3, AuthoritativeEngineTime: 77,
	}
	require.NoError(t, sp.InitSecurityKeys())
	return sp
}

// signedTestFlags is authPriv with a privacy protocol, authNoPriv without.
func signedTestFlags(priv SnmpV3PrivProtocol) SnmpV3MsgFlags {
	if priv > NoPriv {
		return AuthPriv
	}
	return AuthNoPriv
}

// signedTestTrap encodes a signed SNMPv2-Trap from user at engineID,
// encrypted with a privacy protocol, carrying variables (usmPlainVars when
// nil).
func signedTestTrap(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol, engineID, user string, variables []SnmpPDU) []byte {
	t.Helper()
	if variables == nil {
		variables = usmPlainVars
	}
	data, err := (&SnmpPacket{
		Version: Version3, MsgFlags: signedTestFlags(priv), SecurityModel: UserSecurityModel,
		SecurityParameters: signedTestUSM(t, auth, priv, engineID, user), PDUType: SNMPv2Trap, Variables: variables,
	}).MarshalMsg()
	require.NoError(t, err)
	return data
}
