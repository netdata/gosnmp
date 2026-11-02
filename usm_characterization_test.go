// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// The USM characterization tests pin the observable behavior of the
// User-based Security Model: key derivation for every protocol pair and
// passphrase/engine ID shape, decryption of malformed privacy fields, salts,
// the password cache, user validation and the hash of each protocol.
// TestUSM in the netsnmp module checks the same keys, ciphertexts and digests
// against net-snmp.

var (
	usmAuthProtocols = []AuthProtocol{NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512}
	usmPrivProtocols = []PrivProtocol{NoPriv, DES, AES, AES192, AES256, AES192C, AES256C}
)

const (
	usmCharEngineID  = "\x80\x00\x1f\x88\x04codec-engine"
	usmOtherEngineID = "\x80\x00\x1f\x88\x04other-engine"
)

// usmKeyCase is one set of credentials whose localized keys are pinned.
type usmKeyCase struct {
	name     string
	auth     AuthProtocol
	priv     PrivProtocol
	authPass string
	privPass string
	engineID string
}

func usmKeyCases() []usmKeyCase {
	var cases []usmKeyCase
	for _, a := range usmAuthProtocols {
		for _, p := range usmPrivProtocols {
			cases = append(cases, usmKeyCase{
				name: "protocols/" + usmPairName(a, p), auth: a, priv: p,
				authPass: "codec-auth-pass", privPass: "codec-priv-pass", engineID: usmCharEngineID,
			})
		}
	}

	// MD5 with DES, SHA with both AES-256 key extensions, SHA-512 whose key
	// needs no extension.
	pairs := []struct {
		auth AuthProtocol
		priv PrivProtocol
	}{{MD5, DES}, {SHA, AES256}, {SHA, AES256C}, {SHA512, AES}}

	passphrases := []struct{ name, value string }{
		{"empty", ""},
		{"1", "a"},
		{"7", "abcdefg"},
		{"8", "abcdefgh"},
		{"64", strings.Repeat("p", 64)},
		{"65", strings.Repeat("p", 65)},
		{"binary", "\x00\xff\x80\xc3\xa9"},
	}
	engineIDs := []struct{ name, value string }{
		{"empty", ""},
		{"1", "\x80"},
		{"5", "\x80\x00\x1f\x88\x00"},
		{"32", "\x80\x00\x1f\x88\x05" + strings.Repeat("\xa5", 27)},
		{"64", strings.Repeat("\x5a", 64)},
	}
	for _, pair := range pairs {
		name := usmPairName(pair.auth, pair.priv)
		for _, pass := range passphrases {
			cases = append(cases, usmKeyCase{
				name: "passphrase-" + pass.name + "/" + name, auth: pair.auth, priv: pair.priv,
				authPass: pass.value, privPass: pass.value, engineID: usmCharEngineID,
			})
		}
		cases = append(cases,
			usmKeyCase{
				name: "auth-passphrase-empty/" + name, auth: pair.auth, priv: pair.priv,
				authPass: "", privPass: "codec-priv-pass", engineID: usmCharEngineID,
			},
			usmKeyCase{
				name: "priv-passphrase-empty/" + name, auth: pair.auth, priv: pair.priv,
				authPass: "codec-auth-pass", privPass: "", engineID: usmCharEngineID,
			},
		)
		for _, id := range engineIDs {
			cases = append(cases, usmKeyCase{
				name: "engine-id-" + id.name + "/" + name, auth: pair.auth, priv: pair.priv,
				authPass: "codec-auth-pass", privPass: "codec-priv-pass", engineID: id.value,
			})
		}
	}
	return cases
}

func usmPairName(auth AuthProtocol, priv PrivProtocol) string {
	return strings.ToLower(auth.String() + "-" + priv.String())
}

// TestUSMKeysCharacterization pins the keys a user localizes to an engine ID.
func TestUSMKeysCharacterization(t *testing.T) {
	var results []goldenCase
	for _, c := range usmKeyCases() {
		results = append(results, goldenCase{name: c.name, dump: dumpUSMKeys(c)})
	}
	usmGolden.check(t, "keys", results)
}

// dumpUSMKeys dumps whether c's user localizes to c's engine ID and the key
// each of its passphrases derives, also when the other one fails.
func dumpUSMKeys(c usmKeyCase) string {
	user := User{AuthProtocol: c.auth, AuthPassphrase: c.authPass, PrivProtocol: c.priv, PrivPassphrase: c.privPass}
	engineID := []byte(c.engineID)
	var keys usmKeys
	var err error
	var authKey, privKey []byte
	panicked, wroteStdout := observe(func() {
		keys, err = user.localize(engineID)
		authKey, _ = user.authKey(engineID)
		privKey, _ = user.privKey(engineID)
	})

	var d dumpWriter
	switch {
	case panicked:
		d.line("init: panic")
	case err != nil:
		d.line("init: " + dumpError(err))
	default:
		d.line("init: ok")
		if !bytes.Equal(keys.auth, authKey) || !bytes.Equal(keys.priv, privKey) {
			d.line("localized keys: differ")
		}
	}
	if wroteStdout {
		d.line("stdout: written")
	}
	d.line("auth-key: " + dumpBytes(authKey))
	d.line("priv-key: " + dumpBytes(privKey))
	return d.String()
}

// usmCharTrap encodes usmCharPacket for usmCharUser with the salt
// usmCharSalt.
func usmCharTrap(t testing.TB, priv PrivProtocol, variables []VarBind) []byte {
	t.Helper()
	usm.Salts.Set(usmCharSalt(priv))
	user := usmCharUser(priv)
	data, err := usmCharPacket(t, priv, variables).Encode(&user)
	require.NoError(t, err)
	return data
}

// usmCharUser is codec-user, the credentials usmDecoder configures, with SHA
// and the given privacy protocol.
func usmCharUser(priv PrivProtocol) User {
	return usmUser(SHA, "codec-auth-pass", priv, "codec-priv-pass")
}

// usmCharPacket is an authPriv (authNoPriv without a privacy protocol)
// SNMPv2-Trap from codec-user at usmCharEngineID, engine boots 3 and time 77,
// for usmCharUser(priv) to encode.
func usmCharPacket(t testing.TB, priv PrivProtocol, variables []VarBind) *Message {
	t.Helper()

	flags := AuthPriv
	if priv == NoPriv {
		flags = AuthNoPriv
	}
	return &Message{
		Version:       Version3,
		SecurityLevel: flags,

		SecurityParameters: SecurityParameters{
			AuthoritativeEngineID:    []byte(usmCharEngineID),
			AuthoritativeEngineBoots: 3,
			AuthoritativeEngineTime:  77,
			UserName:                 "codec-user",
		},
		ContextEngineID: []byte(usmCharEngineID),
		ContextName:     "ctx",
		PDUType:         SNMPv2Trap,
		MsgID:           21,
		RequestID:       42,
		VarBinds:        variables,
	}
}

var usmCharVarbinds = []VarBind{
	{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(12345)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.2.3.0.1"},
}

// usmCharSalt is the salt of usmCharTrap's message, the one the USM goldens
// were recorded with.
func usmCharSalt(priv PrivProtocol) uint64 {
	if priv == DES {
		return 0x000000030a0b0c0d
	}
	return 0x1122334455667788
}

// v3Message is an SNMPv3 message split into the parts the USM tests change.
type v3Message struct {
	version, header []byte // contents
	usmTags         [6]byte
	usm             [6][]byte // USM field contents; 5 is msgPrivacyParameters
	scopedTag       byte
	scoped          []byte // scoped PDU content, the ciphertext when encrypted
}

func splitV3Message(t testing.TB, data []byte) v3Message {
	t.Helper()
	m, err := parseV3Message(data)
	require.NoError(t, err)
	return m
}

// parseV3Message splits an SNMPv3 message into its parts, without decoding
// the field contents.
func parseV3Message(data []byte) (v3Message, error) {
	var m v3Message
	var err error
	next := func(r *ber.Reader) (byte, []byte) {
		if err != nil {
			return 0, nil
		}
		var tag byte
		var content []byte
		tag, content, err = r.Next()
		return tag, content
	}
	r := ber.NewReader(data)
	_, body := next(&r)
	mr := ber.NewReader(body)
	_, m.version = next(&mr)
	_, m.header = next(&mr)
	_, usmOctets := next(&mr)
	m.scopedTag, m.scoped = next(&mr)
	ur := ber.NewReader(usmOctets)
	_, usm := next(&ur)
	fr := ber.NewReader(usm)
	for i := range m.usm {
		m.usmTags[i], m.usm[i] = next(&fr)
	}
	return m, err
}

func (m v3Message) bytes() []byte {
	var usm [][]byte
	for i, f := range m.usm {
		usm = append(usm, tlv(m.usmTags[i], f))
	}
	return tlv(0x30,
		tlv(byte(Integer), m.version),
		tlv(0x30, m.header),
		tlv(byte(OctetString), tlv(0x30, usm...)),
		tlv(m.scopedTag, m.scoped))
}

// TestUSMDecryptCharacterization pins what DecodeMessage (which decrypts
// without checking the digest) and UnmarshalTrap (which checks it first) make
// of an authPriv trap whose privacy parameters, ciphertext or msgFlags are
// changed, or whose receiver has other privacy settings. Both derive the
// user's keys for the message's engine ID.
func TestUSMDecryptCharacterization(t *testing.T) {
	var results []goldenCase
	for _, priv := range usmPrivProtocols[1:] {
		data := usmCharTrap(t, priv, usmCharVarbinds)
		msg := splitV3Message(t, data)
		require.Equal(t, data, msg.bytes(), "splitV3Message does not round-trip")

		with := func(change func(*v3Message)) []byte {
			m := msg
			change(&m)
			return m.bytes()
		}
		other := DES
		if priv == DES {
			other = AES
		}
		decoder := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")
		name := "decrypt/" + usmPairName(SHA, priv)

		cases := []decodeCase{
			{name: name + "/ok", in: data, decoder: decoder},
			{name: name + "/salt-empty", in: with(func(m *v3Message) { m.usm[5] = nil }), decoder: decoder},
			{name: name + "/salt-7", in: with(func(m *v3Message) { m.usm[5] = m.usm[5][:7] }), decoder: decoder},
			{name: name + "/salt-9", in: with(func(m *v3Message) { m.usm[5] = append(bytes.Clone(m.usm[5]), 0x99) }), decoder: decoder},
			{name: name + "/ciphertext-empty", in: with(func(m *v3Message) { m.scoped = nil }), decoder: decoder},
			{name: name + "/ciphertext-minus-1", in: with(func(m *v3Message) { m.scoped = m.scoped[:len(m.scoped)-1] }), decoder: decoder},
			{name: name + "/ciphertext-minus-8", in: with(func(m *v3Message) { m.scoped = m.scoped[:len(m.scoped)-8] }), decoder: decoder},
			{name: name + "/flags-no-auth-no-priv", in: with(func(m *v3Message) { *m = m.withFlags(t, NoAuthNoPriv) }), decoder: decoder},
			{name: name + "/flags-auth-no-priv", in: with(func(m *v3Message) { *m = m.withFlags(t, AuthNoPriv) }), decoder: decoder},
			{name: name + "/flags-privacy-only", in: with(func(m *v3Message) { *m = m.withFlags(t, usmPrivacyFlag) }), decoder: decoder},
			{name: name + "/engine-id-empty", in: with(func(m *v3Message) { m.usm[0] = nil }), decoder: decoder},
			{name: name + "/receiver-" + strings.ToLower(other.String()), in: data, decoder: usmDecoder(SHA, "codec-auth-pass", other, "codec-priv-pass")},
			{name: name + "/receiver-priv-pass-empty", in: data, decoder: usmDecoder(SHA, "codec-auth-pass", priv, "")},
		}
		for _, c := range cases {
			results = append(results, goldenCase{name: c.name, dump: dumpDecode(t, c)})
		}
	}
	usmGolden.check(t, "decrypt", results)
}

// usmPrivacyFlag is the msgFlags privacy bit without the authentication bit,
// an invalid combination (RFC 3412 section 7.2 step 5d).
const usmPrivacyFlag SecurityLevel = 0x02

// withFlags returns the message with other msgFlags.
func (m v3Message) withFlags(t testing.TB, flags SecurityLevel) v3Message {
	t.Helper()
	old := []byte{byte(OctetString), 1, byte(AuthPriv)}
	require.Equal(t, 1, bytes.Count(m.header, old), "authPriv msgFlags not found once in the header")
	m.header = bytes.Replace(m.header, old, []byte{byte(OctetString), 1, byte(flags)}, 1)
	return m
}

// withModel returns the message with another msgSecurityModel.
func (m v3Message) withModel(t testing.TB, model byte) v3Message {
	t.Helper()
	usm := []byte{byte(Integer), 1, usmSecurityModel}
	require.True(t, bytes.HasSuffix(m.header, usm), "the header does not end with the USM security model")
	m.header = append(bytes.Clone(m.header[:len(m.header)-1]), model)
	return m
}

// usmFlagsTrap is usmCharTrap, still encrypted, with other msgFlags and the
// first saltLen octets of its privacy parameters.
func usmFlagsTrap(t testing.TB, priv PrivProtocol, flags SecurityLevel, saltLen int) []byte {
	t.Helper()
	m := splitV3Message(t, usmCharTrap(t, priv, usmCharVarbinds)).withFlags(t, flags)
	m.usm[5] = m.usm[5][:saltLen]
	return m.bytes()
}

// usmMalformedV3Header is an SNMPv3 message whose header is not a SEQUENCE.
var usmMalformedV3Header = tlv(0x30, intTLV(3), tlv(0x31, intTLV(1)))

// usmPlainVars are the variable bindings of usmPlainTrap.
var usmPlainVars = []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: Integer, Value: 5}}

// usmPlainTrap is a noAuthNoPriv SNMPv2-Trap with a plaintext scoped PDU,
// the given security model, engine ID and user name, and no digest or salt.
func usmPlainTrap(model int64, engineID, user string) []byte {
	usm := craftedUSM(octets(engineID), intTLV(0), intTLV(0), octets(user), octets(""), octets(""))
	scoped := tlv(0x30, octets(""), octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5)))))
	return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(model), usm, scoped)
}

// TestUSMTrapUnauthenticated pins what UnmarshalTrap does, for a single user
// requiring authPriv and through a credentials table, with messages that
// carry no digest it can check or ask for less than their user needs: each is
// rejected at its step of the security processing (RFC 3412 section 7.2, RFC
// 3414 section 3.2), whose error it unwraps to. Privacy without
// authentication fails the header parse, a scoped PDU whose type does not
// match the privacy flag is invalid, and nothing is decrypted without a
// checked digest; an empty user name and engine ID, as in engine discovery,
// name no engine.
func TestUSMTrapUnauthenticated(t *testing.T) {
	useEngineTimes(t)
	// wrappedTrap carries the plaintext scoped PDU's fields in an OCTET
	// STRING, where an encrypted scoped PDU goes.
	wrappedTrap := func() []byte {
		usm := craftedUSM(octets(usmCharEngineID), intTLV(0), intTLV(0), octets("codec-user"), octets(""), octets(""))
		scoped := tlv(byte(OctetString), octets(""), octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5)))))
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), usm, scoped)
	}
	encryptedWithModel := func(priv PrivProtocol, model byte, saltLen int) []byte {
		m := splitV3Message(t, usmCharTrap(t, priv, usmCharVarbinds)).withModel(t, model)
		m.usm[5] = m.usm[5][:saltLen]
		return m.bytes()
	}

	// emptyKeyTrap is an authNoPriv trap from usmCharEngineID with the digest
	// of the empty key, which anyone can compute. The library does not sign
	// with the empty key; HMAC pads a key with zeros, so a key of 20 zero
	// octets gives the same digest.
	emptyKeyTrap := func() []byte {
		data, err := (&Message{
			Version: Version3, SecurityLevel: AuthNoPriv,
			SecurityParameters: SecurityParameters{UserName: "codec-user", AuthoritativeEngineID: []byte(usmCharEngineID)},
			PDUType:            SNMPv2Trap, VarBinds: usmPlainVars,
		}).marshalMsg(&usmKeys{authProtocol: SHA, auth: make([]byte, 20)})
		require.NoError(t, err)
		return data
	}

	type receiverKind int
	const (
		single receiverKind = iota
		table
	)
	receiver := func(priv PrivProtocol, kind receiverKind) *Client {
		user := usmUser(SHA, "codec-auth-pass", priv, "codec-priv-pass")
		if kind == single {
			return &Client{Version: Version3, SecurityLevel: AuthPriv, User: user}
		}
		tb := NewSnmpV3SecurityParametersTable()
		require.NoError(t, tb.Add(user, []byte(usmCharEngineID)))
		return &Client{Version: Version3, TrapSecurityParametersTable: tb}
	}

	tests := map[string]struct {
		in       func() []byte
		priv     PrivProtocol
		receiver receiverKind
		is       error // the exported error the rejection unwraps to
	}{
		"privacy-only DES, single user": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 8) }, priv: DES, is: ErrInvalidMsgs,
		},
		"privacy-only DES, table": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 8) }, priv: DES, receiver: table, is: ErrInvalidMsgs,
		},
		"privacy-only AES, table": {
			in: func() []byte { return usmFlagsTrap(t, AES, usmPrivacyFlag, 8) }, priv: AES, receiver: table, is: ErrInvalidMsgs,
		},
		"noAuthNoPriv flags, encrypted AES, table": {
			in: func() []byte { return usmFlagsTrap(t, AES, NoAuthNoPriv, 8) }, priv: AES, receiver: table, is: ErrInvalidMsgs,
		},
		"noAuthNoPriv flags, encrypted AES, single user": {
			in: func() []byte { return usmFlagsTrap(t, AES, NoAuthNoPriv, 8) }, priv: AES, is: ErrInvalidMsgs,
		},
		"noAuthNoPriv flags, OCTET STRING scoped PDU, table without privacy": {
			in: wrappedTrap, priv: NoPriv, receiver: table, is: ErrInvalidMsgs,
		},
		"privacy-only DES with a 7-octet salt, single user": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 7) }, priv: DES, is: ErrInvalidMsgs,
		},
		"privacy-only DES with a 7-octet salt, table": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 7) }, priv: DES, receiver: table, is: ErrInvalidMsgs,
		},
		"noAuthNoPriv flags, encrypted DES with a 7-octet salt, table": {
			in: func() []byte { return usmFlagsTrap(t, DES, NoAuthNoPriv, 7) }, priv: DES, receiver: table, is: ErrInvalidMsgs,
		},
		"privacy-only AES with a 7-octet salt, table": {
			in: func() []byte { return usmFlagsTrap(t, AES, usmPrivacyFlag, 7) }, priv: AES, receiver: table, is: ErrInvalidMsgs,
		},
		"authNoPriv signed with the empty key, table": {
			in: emptyKeyTrap, priv: NoPriv, receiver: table, is: ErrWrongDigest,
		},
		"noAuthNoPriv plaintext, AES table": {
			in: func() []byte { return usmPlainTrap(3, usmCharEngineID, "codec-user") }, priv: AES, receiver: table, is: ErrUnknownSecurityLevel,
		},
		"security model 2, plaintext, single user": {
			in: func() []byte { return usmPlainTrap(2, usmCharEngineID, "codec-user") }, priv: AES, is: ErrUnknownSecurityModels,
		},
		"security model 2, authPriv flags, table": {
			in: func() []byte { return encryptedWithModel(AES, 2, 8) }, priv: AES, receiver: table, is: ErrUnknownSecurityModels,
		},
		"security model 2, encrypted DES with a 7-octet salt, single user": {
			in: func() []byte { return encryptedWithModel(DES, 2, 7) }, priv: DES, is: ErrUnknownSecurityModels,
		},
		"empty user name and engine ID, single user": {
			in: func() []byte { return usmPlainTrap(3, "", "") }, priv: AES, is: ErrUnknownEngineID,
		},
		"empty user name and engine ID, table": {
			in: func() []byte { return usmPlainTrap(3, "", "") }, priv: AES, receiver: table, is: ErrUnknownEngineID,
		},
		"empty user name, engine ID set, single user": {
			in: func() []byte { return usmPlainTrap(3, usmCharEngineID, "") }, priv: AES, is: ErrUnknownUsername,
		},
		"malformed header, single user": {
			in: func() []byte { return usmMalformedV3Header }, priv: AES, is: ErrInvalidMsgs,
		},
		"malformed header, table": {
			in: func() []byte { return usmMalformedV3Header }, priv: AES, receiver: table, is: ErrInvalidMsgs,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := receiver(tc.priv, tc.receiver)
			var err error
			v, _ := recoverPanic(func() { _, err = x.UnmarshalTrap(tc.in(), false) })
			require.Nil(t, v, "UnmarshalTrap panicked")
			require.ErrorIs(t, err, tc.is)
		})
	}
}

// TestUSMAuthFieldEmpty pins that an authNoPriv message with an empty
// msgAuthenticationParameters, shorter than the 12-octet SHA digest, decodes
// without a write, whether or not the input has spare capacity:
// DecodeMessage checks no digest, and UnmarshalTrap finds it not
// authentic.
func TestUSMAuthFieldEmpty(t *testing.T) {
	useEngineTimes(t)
	usm := craftedUSM(octets(usmCharEngineID), intTLV(0), intTLV(0), octets("codec-user"), octets(""), octets(""))
	msg := craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), usm, craftedScopedResp)
	decoder := usmDecoder(SHA, "codec-auth-pass", NoPriv, "")
	trapDecoder := func() *Client {
		x := decoder()
		x.Version, x.SecurityLevel = Version3, AuthNoPriv
		return x
	}

	for name, spare := range map[string]int{"no spare capacity": 0, "spare capacity": 16} {
		t.Run(name, func(t *testing.T) {
			buf := append(bytes.Clone(msg), bytes.Repeat([]byte{0xaa}, spare)...)
			in := buf[:len(msg):len(buf)]
			_, err := decoder().DecodeMessage(in)
			require.NoError(t, err, "DecodeMessage")
			_, err = trapDecoder().UnmarshalTrap(in, false)
			assert.ErrorIs(t, err, errNotAuthentic, "UnmarshalTrap")
			assert.Equal(t, append(bytes.Clone(msg), bytes.Repeat([]byte{0xaa}, spare)...), buf, "the input and the octets after it")
		})
	}
}

// TestUSMPrivacyPadding pins the ciphertext length: DES pads the scoped PDU
// to the next 8-octet block, with a whole block when it is already aligned;
// the AES protocols do not pad.
func TestUSMPrivacyPadding(t *testing.T) {
	for _, priv := range usmPrivProtocols[1:] {
		for n := range 16 {
			vbs := []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: bytes.Repeat([]byte{'x'}, n)}}
			plain := splitV3Message(t, usmCharTrap(t, NoPriv, vbs))
			secured := splitV3Message(t, usmCharTrap(t, priv, vbs))

			plainLen := len(tlv(plain.scopedTag, plain.scoped))
			want := plainLen
			if priv == DES {
				want = plainLen + 8 - plainLen%8
			}
			assert.Equal(t, want, len(secured.scoped), "%v, scoped PDU of %d octets", priv, plainLen)
		}
	}
}

// TestUSMSalts pins how the encoder fills msgPrivacyParameters: a message
// the flags encrypt carries the next value of usm.Salts, one 64-bit counter
// for DES and the AES protocols (RFC 3826 section 3.1.2.1; RFC 3414 section
// 8.1.1.1 leaves DES's integer to the implementation); a message without
// privacy draws none and carries an empty salt. The packet's own
// PrivacyParameters are neither used nor written.
func TestUSMSalts(t *testing.T) {
	packetSalt := func() []byte { return bytes.Repeat([]byte{0xee}, 8) }
	tests := map[string]struct {
		priv  PrivProtocol
		next  uint64
		flags []SecurityLevel
		want  []string
	}{
		"aes": {
			priv: AES256, next: 0x0000000700000001,
			flags: []SecurityLevel{AuthPriv, AuthNoPriv, AuthPriv, NoAuthNoPriv, AuthPriv},
			want:  []string{"0000000700000001", "empty", "0000000700000002", "empty", "0000000700000003"},
		},
		"des counts in 64 bits": {
			priv: DES, next: 0x00000001ffffffff,
			flags: []SecurityLevel{AuthPriv, AuthNoPriv, AuthPriv},
			want:  []string{"00000001ffffffff", "empty", "0000000200000000"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			usm.Salts.Set(tc.next)
			var got []string
			user := codecUser(SHA, tc.priv)
			for _, flags := range tc.flags {
				pkt := &Message{Version: Version3, SecurityLevel: flags, SecurityParameters: codecHeader(), PDUType: GetRequest}
				pkt.SecurityParameters.PrivacyParameters = packetSalt()
				data, err := pkt.Encode(&user)
				require.NoError(t, err)
				got = append(got, dumpBytes(splitV3Message(t, data).usm[5]))
				assert.Equal(t, packetSalt(), pkt.SecurityParameters.PrivacyParameters, "the packet's salt")
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestUSMPasswordCache pins that the password-to-key cache does not change
// the keys: on cache hits and with concurrent users. The cache itself is
// tested in internal/usm.
func TestUSMPasswordCache(t *testing.T) {
	keys := func() []string {
		var out []string
		for _, a := range usmAuthProtocols[1:] {
			for _, p := range usmPrivProtocols[1:] {
				user := usmUser(a, "codec-auth-pass", p, "codec-priv-pass")
				keys, err := user.localize([]byte(usmCharEngineID))
				require.NoError(t, err)
				out = append(out, fmt.Sprintf("%x/%x", keys.auth, keys.priv))
			}
		}
		return out
	}

	cached := keys()
	assert.Equal(t, cached, keys(), "cache hits")

	var wg sync.WaitGroup
	results := make([][]string, 4)
	for i := range results {
		wg.Go(func() { results[i] = keys() })
	}
	wg.Wait()
	for _, r := range results {
		assert.Equal(t, cached, r, "concurrent users")
	}
}

// TestUSMValidate pins which SNMPv3 users a Client rejects before decoding or
// encoding, and the messages it rejects them with. The users that pass decode
// a noAuthNoPriv message.
func TestUSMValidate(t *testing.T) {
	msg := craftedV3NoAuth(craftedScopedResp)

	tests := map[string]struct {
		flags   SecurityLevel
		user    User
		wantErr string
	}{
		"noAuthNoPriv": {
			flags: NoAuthNoPriv, user: User{Name: "u"},
		},
		"noAuthNoPriv without user": {
			flags: NoAuthNoPriv, user: User{},
			wantErr: "User.Name is required",
		},
		"noAuthNoPriv with a user name of 32 octets": {
			flags: NoAuthNoPriv, user: User{Name: strings.Repeat("u", 32)},
		},
		"noAuthNoPriv with a user name of 33 octets": {
			flags: NoAuthNoPriv, user: User{Name: strings.Repeat("u", 33)},
			wantErr: "User.Name is 33 octets, more than 32",
		},
		"authNoPriv": {
			flags: AuthNoPriv, user: User{Name: "u", AuthProtocol: SHA, AuthPassphrase: "p"},
		},
		"authNoPriv without protocol": {
			flags: AuthNoPriv, user: User{Name: "u", AuthPassphrase: "p"},
			wantErr: "User.AuthProtocol is required",
		},
		"authNoPriv without passphrase": {
			flags: AuthNoPriv, user: User{Name: "u", AuthProtocol: SHA},
			wantErr: "User.AuthPassphrase is required when an authentication protocol is specified",
		},
		"authNoPriv without user": {
			flags: AuthNoPriv, user: User{AuthProtocol: SHA, AuthPassphrase: "p"},
			wantErr: "User.Name is required",
		},
		"authPriv": {
			flags: AuthPriv, user: User{
				Name: "u", AuthProtocol: SHA, AuthPassphrase: "p",
				PrivProtocol: AES, PrivPassphrase: "q",
			},
		},
		"authPriv without privacy protocol": {
			flags: AuthPriv, user: User{Name: "u", AuthProtocol: SHA, AuthPassphrase: "p"},
			wantErr: "User.PrivProtocol is required",
		},
		"authPriv without authentication protocol": {
			flags: AuthPriv, user: User{Name: "u", PrivProtocol: AES, PrivPassphrase: "q"},
			wantErr: "User.AuthProtocol is required",
		},
		"authPriv without privacy passphrase": {
			flags: AuthPriv, user: User{Name: "u", AuthProtocol: SHA, AuthPassphrase: "p", PrivProtocol: AES},
			wantErr: "User.PrivPassphrase is required when a privacy protocol is specified",
		},
		"authPriv without either passphrase": {
			flags: AuthPriv, user: User{Name: "u", AuthProtocol: SHA, PrivProtocol: AES},
			wantErr: "User.PrivPassphrase is required when a privacy protocol is specified",
		},
		"noAuthNoPriv with a privacy protocol and no passphrase": {
			flags: NoAuthNoPriv, user: User{Name: "u", PrivProtocol: AES},
			wantErr: "User.PrivPassphrase is required when a privacy protocol is specified",
		},
		"privacy flag without authentication flag": {
			flags: 0x2, user: User{Name: "u"},
			wantErr: "validate: SecurityLevel must be populated with an appropriate security level",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Version: Version3, SecurityLevel: tc.flags, User: tc.user}
			_, err := x.DecodeMessage(bytes.Clone(msg))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMAuthHash pins the hash of every authentication protocol value: MD5
// for NoAuth, unset and unknown values.
func TestUSMAuthHash(t *testing.T) {
	want := map[AuthProtocol]crypto.Hash{
		0:      crypto.MD5,
		NoAuth: crypto.MD5,
		MD5:    crypto.MD5,
		SHA:    crypto.SHA1,
		SHA224: crypto.SHA224,
		SHA256: crypto.SHA256,
		SHA384: crypto.SHA384,
		SHA512: crypto.SHA512,
		8:      crypto.MD5,
	}
	for auth, hash := range want {
		assert.Equal(t, hash, auth.hash(), "%v", auth)
	}
}
