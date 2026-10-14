// Copyright 2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"crypto/fips140"
	"encoding/hex"
	"io"
	"log"
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

func TestIsAuthenticWrongUsername(t *testing.T) {
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

	srcPacket := packetSHA224NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: sp.Copy(),
	}
	snmpPacket.SecurityParameters.(*UsmSecurityParameters).UserName = "foo"

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.False(t, authentic, "Packet was considered to be authentic")
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
	err = sp.sign(srcPacket)
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

	srcPacket := packetSHA224NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: &sp,
	}

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.True(t, authentic, "Packet was not considered to be authentic")
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
	err = sp.sign(srcPacket)
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

	srcPacket := packetSHA512NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: &sp,
	}

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.True(t, authentic, "Packet was not considered to be authentic")
}

// TestUnmarshalTruncatedUSMSequence verifies that unmarshal returns an error
// rather than panicking when the USM SEQUENCE body is truncated.
func TestUnmarshalTruncatedUSMSequence(t *testing.T) {
	sp := &UsmSecurityParameters{
		Logger: NewLogger(log.New(io.Discard, "", 0)),
	}

	tests := []struct {
		name   string
		packet []byte
		cursor int
	}{
		{
			name:   "short-form length zero",
			packet: []byte{0x30, 0x00},
			cursor: 0,
		},
		{
			name: "long-form length one extra byte truncated body",
			// 0x81 signals long-form with 1 extra length byte; the body is
			// absent, so the first field read finds no bytes left.
			packet: []byte{0x30, 0x81, 0x05},
			cursor: 0,
		},
		{
			name:   "long-form with non-zero starting cursor",
			packet: []byte{0xff, 0xff, 0x30, 0x81, 0x05},
			cursor: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				r := ber.NewReader(tt.packet[tt.cursor:])
				require.Error(t, sp.unmarshal(NoAuthNoPriv, &r))
			})
		})
	}
}

// TestUSMUnsupportedProtocols checks that protocol values outside the defined
// sets fail with an error on every path: validation, key derivation,
// encoding without validation, and decoding with table parameters changed
// after Add.
func TestUSMUnsupportedProtocols(t *testing.T) {
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
// parameter sets of a user, in the order they were added: each on its own
// copy of the trap (a failed attempt zeroes the copy's digest), the first that
// decodes wins, and when none does the error carries the last attempt's.
func TestUSMTrapTableAttempts(t *testing.T) {
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
	add := func(sp *UsmSecurityParameters) func(*SnmpV3SecurityParametersTable) {
		return func(tb *SnmpV3SecurityParametersTable) { require.NoError(t, tb.Add("codec-user", sp)) }
	}
	const (
		prefix         = "no credentials successfully unmarshaled trap: "
		notAuthentic   = "incoming packet is not authentic, discarding"
		notSupportedV8 = "securityParameters.AuthenticationProtocol SnmpV3AuthProtocol(8) is not supported"
	)

	tests := map[string]struct {
		sets    []func(*SnmpV3SecurityParametersTable)
		wantErr string
	}{
		"wrong passphrase, then right":    {sets: []func(*SnmpV3SecurityParametersTable){add(wrongPass()), add(good())}},
		"right passphrase first":          {sets: []func(*SnmpV3SecurityParametersTable){add(good()), add(wrongPass())}},
		"unsupported, then not authentic": {sets: []func(*SnmpV3SecurityParametersTable){unsupported, add(wrongPass())}, wantErr: prefix + notAuthentic},
		"not authentic, then unsupported": {sets: []func(*SnmpV3SecurityParametersTable){add(wrongPass()), unsupported}, wantErr: prefix + notSupportedV8},
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

// TestUSMTrapTableSkipsV1V2c checks that a receiver with a trap table
// decodes SNMPv1 and SNMPv2c traps without it.
func TestUSMTrapTableSkipsV1V2c(t *testing.T) {
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
// UnmarshalTrap receiver whose flags require authentication, but whose
// parameters have no authentication protocol, rejects a trap from its user
// instead of panicking or accepting it unauthenticated.
func TestUSMReceiverAuthenticationWithoutProtocol(t *testing.T) {
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
			wantErr:  "securityParameters.AuthenticationProtocol is required",
		},
		"NoAuth": {
			receiver: &UsmSecurityParameters{UserName: "codec-user", AuthenticationProtocol: NoAuth},
			wantErr:  "securityParameters.AuthenticationProtocol is required",
		},
		"authentication protocol": {
			receiver: &UsmSecurityParameters{
				UserName:                 "codec-user",
				AuthenticationProtocol:   SHA,
				AuthenticationPassphrase: "codec-auth-pass",
			},
			wantErr: "incoming packet is not authentic, discarding",
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
