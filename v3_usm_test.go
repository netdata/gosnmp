// Copyright 2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
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
		localAESSalt:             0,
		localDESSalt:             0,
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

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
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
		localAESSalt:             0,
		localDESSalt:             0,
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

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)
	err = sp.authenticate(srcPacket)
	require.NoError(t, err, "Authentication of packet failed")

	require.Equal(t, packetSHA224Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
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

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
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
		localAESSalt:             0,
		localDESSalt:             0,
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

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)
	err = sp.authenticate(srcPacket)
	require.NoError(t, err, "Generation of key failed")

	require.Equal(t, packetSHA512Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
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

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
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
				data := usmCharTrap(t, AES, usmCharSalt(AES), usmCharVarbinds)
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
