// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// The USM characterization tests pin the observable behavior of the
// User-based Security Model, known bugs included, before it is restructured:
// key derivation for every protocol pair and passphrase/engine ID shape,
// decryption of malformed privacy fields, salts, Copy, the password cache,
// parameter validation and the string forms. TestUSM in the netsnmp module
// checks the same keys, ciphertexts and digests against net-snmp.

var (
	usmAuthProtocols = []SnmpV3AuthProtocol{NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512}
	usmPrivProtocols = []SnmpV3PrivProtocol{NoPriv, DES, AES, AES192, AES256, AES192C, AES256C}
)

const (
	usmCharEngineID  = "\x80\x00\x1f\x88\x04codec-engine"
	usmOtherEngineID = "\x80\x00\x1f\x88\x04other-engine"
)

// usmKeysOnly localizes the keys of sp to engineID and drops the passphrases
// they were derived from, as a user configured with keys instead of
// passphrases.
func usmKeysOnly(sp *UsmSecurityParameters, engineID string) *UsmSecurityParameters {
	sp.AuthoritativeEngineID = engineID
	if err := sp.InitSecurityKeys(); err != nil {
		panic(err)
	}
	sp.AuthenticationPassphrase, sp.PrivacyPassphrase = "", ""
	return sp
}

// usmKeyCase is one set of credentials whose localized keys are pinned.
type usmKeyCase struct {
	name     string
	auth     SnmpV3AuthProtocol
	priv     SnmpV3PrivProtocol
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
		auth SnmpV3AuthProtocol
		priv SnmpV3PrivProtocol
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

func usmPairName(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) string {
	return strings.ToLower(auth.String() + "-" + priv.String())
}

// TestUSMKeysCharacterization pins the keys InitSecurityKeys derives.
func TestUSMKeysCharacterization(t *testing.T) {
	var results []goldenCase
	for _, c := range usmKeyCases() {
		results = append(results, goldenCase{name: c.name, dump: dumpUSMKeys(c)})
	}
	usmGolden.check(t, "keys", results)
}

func dumpUSMKeys(c usmKeyCase) string {
	sp := &UsmSecurityParameters{
		AuthenticationProtocol:   c.auth,
		AuthenticationPassphrase: c.authPass,
		PrivacyProtocol:          c.priv,
		PrivacyPassphrase:        c.privPass,
		AuthoritativeEngineID:    c.engineID,
	}
	var err error
	panicked, wroteStdout := observe(func() { err = sp.InitSecurityKeys() })

	var d dumpWriter
	switch {
	case panicked:
		d.line("init: panic")
	case err != nil:
		d.line("init: " + dumpError(err))
	default:
		d.line("init: ok")
	}
	if wroteStdout {
		d.line("stdout: written")
	}
	d.line("auth-key: " + dumpBytes(sp.SecretKey))
	d.line("priv-key: " + dumpBytes(sp.PrivacyKey))
	return d.String()
}

// usmCharTrap encodes usmCharPacket with the salt usmCharSalt.
func usmCharTrap(t testing.TB, priv SnmpV3PrivProtocol, variables []SnmpPDU) []byte {
	t.Helper()
	usm.Salts.Set(usmCharSalt(priv))
	data, err := usmCharPacket(t, priv, variables).MarshalMsg()
	require.NoError(t, err)
	return data
}

// usmCharPacket is an authPriv (authNoPriv without a privacy protocol)
// SNMPv2-Trap from codec-user, the credentials usmDecoder configures, with
// the given privacy protocol and its keys initialized.
func usmCharPacket(t testing.TB, priv SnmpV3PrivProtocol, variables []SnmpPDU) *SnmpPacket {
	t.Helper()

	sp := &UsmSecurityParameters{
		UserName:                 "codec-user",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyProtocol:          priv,
		PrivacyPassphrase:        "codec-priv-pass",
		AuthoritativeEngineID:    usmCharEngineID,
		AuthoritativeEngineBoots: 3,
		AuthoritativeEngineTime:  77,
	}
	require.NoError(t, sp.InitSecurityKeys())
	flags := AuthPriv
	if priv == NoPriv {
		flags = AuthNoPriv
	}
	return &SnmpPacket{
		Version:            Version3,
		MsgFlags:           flags,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		ContextEngineID:    usmCharEngineID,
		ContextName:        "ctx",
		PDUType:            SNMPv2Trap,
		MsgID:              21,
		RequestID:          42,
		Variables:          variables,
	}
}

var usmCharVarbinds = []SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(12345)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.2.3.0.1"},
}

// usmCharSalt is the salt of usmCharTrap's message, the one the USM goldens
// were recorded with.
func usmCharSalt(priv SnmpV3PrivProtocol) uint64 {
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

// TestUSMDecryptCharacterization pins what SnmpDecodePacket (which decrypts
// without checking the digest) and UnmarshalTrap (which checks it first) make
// of an authPriv trap whose privacy parameters, ciphertext or msgFlags are
// changed (an OCTET STRING scoped PDU is decrypted whatever the flags say),
// or whose receiver has other privacy settings or keys localized to another
// engine ID (a message from a new engine ID replaces the keys with ones
// derived from the passphrases before the digest is checked). SnmpDecodePacket
// derives keys only for a new engine ID, so a message with the receiver's
// (empty) engine ID is decrypted with keys never derived.
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

		// localized returns a receiver whose keys are localized to engineID,
		// optionally without the passphrases they were derived from.
		localized := func(engineID string, keepPassphrases bool) func() *GoSNMP {
			return func() *GoSNMP {
				x := decoder()
				sp := x.SecurityParameters.(*UsmSecurityParameters)
				if !keepPassphrases {
					usmKeysOnly(sp, engineID)
					return x
				}
				sp.AuthoritativeEngineID = engineID
				if err := sp.InitSecurityKeys(); err != nil {
					panic(err)
				}
				return x
			}
		}

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
			{name: name + "/receiver-keys-other-engine", in: data, decoder: localized(usmOtherEngineID, true)},
			{name: name + "/receiver-keys-only", in: data, decoder: localized(usmCharEngineID, false)},
			{name: name + "/receiver-keys-only-other-engine", in: data, decoder: localized(usmOtherEngineID, false)},
		}
		for _, c := range cases {
			results = append(results, goldenCase{name: c.name, dump: dumpDecode(t, c)})
		}
	}
	usmGolden.check(t, "decrypt", results)
}

// usmPrivacyFlag is the msgFlags privacy bit without the authentication bit,
// an invalid combination (RFC 3412 section 7.2 step 5d).
const usmPrivacyFlag SnmpV3MsgFlags = 0x02

// withFlags returns the message with other msgFlags.
func (m v3Message) withFlags(t testing.TB, flags SnmpV3MsgFlags) v3Message {
	t.Helper()
	old := []byte{byte(OctetString), 1, byte(AuthPriv)}
	require.Equal(t, 1, bytes.Count(m.header, old), "authPriv msgFlags not found once in the header")
	m.header = bytes.Replace(m.header, old, []byte{byte(OctetString), 1, byte(flags)}, 1)
	return m
}

// withModel returns the message with another msgSecurityModel.
func (m v3Message) withModel(t testing.TB, model byte) v3Message {
	t.Helper()
	usm := []byte{byte(Integer), 1, byte(UserSecurityModel)}
	require.True(t, bytes.HasSuffix(m.header, usm), "the header does not end with the USM security model")
	m.header = append(bytes.Clone(m.header[:len(m.header)-1]), model)
	return m
}

// usmFlagsTrap is usmCharTrap, still encrypted, with other msgFlags and the
// first saltLen octets of its privacy parameters.
func usmFlagsTrap(t testing.TB, priv SnmpV3PrivProtocol, flags SnmpV3MsgFlags, saltLen int) []byte {
	t.Helper()
	m := splitV3Message(t, usmCharTrap(t, priv, usmCharVarbinds)).withFlags(t, flags)
	m.usm[5] = m.usm[5][:saltLen]
	return m.bytes()
}

// usmMalformedV3Header is an SNMPv3 message whose header is not a SEQUENCE.
var usmMalformedV3Header = tlv(0x30, intTLV(3), tlv(0x31, intTLV(1)))

// usmPlainVars are the variable bindings of usmPlainTrap.
var usmPlainVars = []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: Integer, Value: 5}}

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
	encryptedWithModel := func(priv SnmpV3PrivProtocol, model byte, saltLen int) []byte {
		m := splitV3Message(t, usmCharTrap(t, priv, usmCharVarbinds)).withModel(t, model)
		m.usm[5] = m.usm[5][:saltLen]
		return m.bytes()
	}

	// emptyKeyTrap is an authNoPriv trap from usmCharEngineID with the digest
	// of the empty key, which anyone can compute. The library does not sign
	// with the empty key; HMAC pads a key with zeros, so a key of 20 zero
	// octets gives the same digest.
	emptyKeyTrap := func() []byte {
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel,
			SecurityParameters: &UsmSecurityParameters{
				UserName: "codec-user", AuthoritativeEngineID: usmCharEngineID, AuthenticationProtocol: SHA,
				SecretKey: make([]byte, 20),
			},
			PDUType: SNMPv2Trap, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		return data
	}

	type receiverKind int
	const (
		single receiverKind = iota
		table
		tableKeysOnly  // keys localized to another engine ID, no passphrases
		singleKeysOnly // the same, for a single user at authNoPriv
	)
	receiver := func(priv SnmpV3PrivProtocol, kind receiverKind) *GoSNMP {
		sp := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")().SecurityParameters.(*UsmSecurityParameters)
		switch kind {
		case single:
			return &GoSNMP{Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp}
		case singleKeysOnly:
			usmKeysOnly(sp, usmOtherEngineID)
			return &GoSNMP{Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp}
		case tableKeysOnly:
			usmKeysOnly(sp, usmOtherEngineID)
		}
		tb := NewSnmpV3SecurityParametersTable(Logger{})
		require.NoError(t, tb.Add("codec-user", sp))
		return &GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}
	}

	tests := map[string]struct {
		in       func() []byte
		priv     SnmpV3PrivProtocol
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
		"privacy-only DES, table with keys only": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 8) }, priv: DES, receiver: tableKeysOnly, is: ErrInvalidMsgs,
		},
		"authNoPriv signed with the empty key, table with keys only": {
			in: emptyKeyTrap, priv: NoPriv, receiver: tableKeysOnly, is: ErrUnknownUsername,
		},
		"authNoPriv signed with the empty key, single user with keys only": {
			in: emptyKeyTrap, priv: NoPriv, receiver: singleKeysOnly, is: ErrUnknownUsername,
		},
		"authNoPriv signed with the empty key, table": {
			in: emptyKeyTrap, priv: NoPriv, receiver: table, is: ErrWrongDigest,
		},
		"noAuthNoPriv plaintext, AES table with keys only": {
			in: func() []byte { return usmPlainTrap(3, usmCharEngineID, "codec-user") }, priv: AES, receiver: tableKeysOnly, is: ErrUnknownUsername,
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

// TestUSMKeysBoundToEngine pins that parameters with keys given without
// passphrases decode only messages naming the engine ID the keys are
// localized to, for every protocol pair: on the trap table path, for a single
// trap user with its own or the message's flags, and with SnmpDecodePacket. A
// message naming another engine ID is rejected whatever its security level or
// user name, with the error of adopting another engine ID, which unwraps to
// ErrUnknownUsername (the trap paths reject an empty engine ID before; a
// message of another security model fails the header parse first), and the
// parameters keep their engine ID and keys.
func TestUSMKeysBoundToEngine(t *testing.T) {
	useEngineTimes(t)
	type receiverKind int
	const (
		table receiverKind = iota
		single
		singleMessageFlags // useResponseSecurityParameters
		decodePacket       // SnmpDecodePacket
	)
	receivers := map[receiverKind]string{
		table: "table", single: "single", singleMessageFlags: "single, message flags", decodePacket: "SnmpDecodePacket",
	}
	const boundEngineID = usmOtherEngineID

	// keysOnly is the user's parameters: keys localized to boundEngineID, no
	// passphrases.
	keysOnly := func(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) *UsmSecurityParameters {
		return usmKeysOnly(&UsmSecurityParameters{
			UserName: "codec-user", AuthenticationProtocol: auth, AuthenticationPassphrase: "codec-auth-pass",
			PrivacyProtocol: priv, PrivacyPassphrase: "codec-priv-pass",
		}, boundEngineID)
	}
	level := func(priv SnmpV3PrivProtocol) SnmpV3MsgFlags {
		if priv > NoPriv {
			return AuthPriv
		}
		return AuthNoPriv
	}
	// signedTrap is a trap from boundEngineID at the user's level, signed and
	// encrypted with the user's keys.
	signedTrap := func(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) []byte {
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: level(priv), SecurityModel: UserSecurityModel,
			SecurityParameters: keysOnly(auth, priv), PDUType: SNMPv2Trap, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		return data
	}
	plainTrap := func(model int64, engineID, user string) func(SnmpV3AuthProtocol, SnmpV3PrivProtocol) []byte {
		return func(SnmpV3AuthProtocol, SnmpV3PrivProtocol) []byte { return usmPlainTrap(model, engineID, user) }
	}

	tests := map[string]struct {
		in       func(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) []byte
		accepted bool
		noEngine bool  // the trap paths reject the empty engine ID first
		wantErr  error // instead of the error of adopting another engine ID
	}{
		"authenticated, from the keys' engine":  {in: signedTrap, accepted: true},
		"noAuthNoPriv, from another engine":     {in: plainTrap(3, usmCharEngineID, "codec-user")},
		"security model 2, from another engine": {in: plainTrap(2, usmCharEngineID, "codec-user"), wantErr: errNotUSM},
		"empty user name and engine ID":         {in: plainTrap(3, "", ""), noEngine: true},
	}

	for name, tc := range tests {
		for _, auth := range usmAuthProtocols[1:] {
			for _, priv := range usmPrivProtocols {
				for rk, receiver := range receivers {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", name, auth, priv, receiver), func(t *testing.T) {
						sp, want := keysOnly(auth, priv), keysOnly(auth, priv)
						x := &GoSNMP{Version: Version3, MsgFlags: level(priv), SecurityModel: UserSecurityModel, SecurityParameters: sp}
						if rk == table {
							tb := NewSnmpV3SecurityParametersTable(Logger{})
							require.NoError(t, tb.Add("codec-user", sp))
							x.SecurityParameters, x.TrapSecurityParametersTable = nil, tb
						}

						var res *SnmpPacket
						var err error
						if rk == decodePacket {
							res, err = x.SnmpDecodePacket(tc.in(auth, priv))
						} else {
							res, err = x.UnmarshalTrap(tc.in(auth, priv), rk == singleMessageFlags)
						}
						switch {
						case tc.accepted:
							require.NoError(t, err)
							assert.Equal(t, usmPlainVars, res.Variables)
						case rk != decodePacket && tc.noEngine:
							require.ErrorIs(t, err, ErrUnknownEngineID)
						case tc.wantErr != nil:
							require.ErrorIs(t, err, tc.wantErr)
						default:
							require.ErrorIs(t, err, errAuthKeyBoundToEngine)
							require.ErrorIs(t, err, ErrUnknownUsername)
						}
						assert.Equal(t, []any{want.AuthoritativeEngineID, want.SecretKey, want.PrivacyKey},
							[]any{sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey}, "the user's engine ID and keys")
					})
				}
			}
		}
	}
}

// TestUSMAdoptEngineID pins the rule of adopting an engine ID: keys localize
// to one engine ID, so another one takes keys derived for it from the
// passphrases, and parameters with a protocol whose passphrase is empty, with
// a key given without it or none, refuse it with that protocol's error and
// stay unchanged; the same engine ID changes nothing.
func TestUSMAdoptEngineID(t *testing.T) {
	// params returns SHA/AES parameters localized to usmOtherEngineID, with
	// edit applied.
	params := func(edit func(sp *UsmSecurityParameters)) *UsmSecurityParameters {
		sp := usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")().SecurityParameters.(*UsmSecurityParameters)
		sp.AuthoritativeEngineID = usmOtherEngineID
		require.NoError(t, sp.InitSecurityKeys())
		if edit != nil {
			edit(sp)
		}
		return sp
	}
	keysFor := func(engineID string) []any {
		sp := params(nil)
		sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey = engineID, nil, nil
		require.NoError(t, sp.InitSecurityKeys())
		return []any{engineID, sp.SecretKey, sp.PrivacyKey}
	}

	tests := map[string]struct {
		edit     func(sp *UsmSecurityParameters)
		engineID string
		wantErr  error // the parameters then stay unchanged
	}{
		"passphrases":                     {engineID: usmCharEngineID},
		"passphrases, no keys yet":        {edit: func(sp *UsmSecurityParameters) { sp.SecretKey, sp.PrivacyKey = nil, nil }, engineID: usmCharEngineID},
		"passphrases, the same engine ID": {engineID: usmOtherEngineID},
		"keys only, the same engine ID": {
			edit: func(sp *UsmSecurityParameters) { usmKeysOnly(sp, usmOtherEngineID) }, engineID: usmOtherEngineID,
		},
		"keys only": {
			edit: func(sp *UsmSecurityParameters) { usmKeysOnly(sp, usmOtherEngineID) }, engineID: usmCharEngineID,
			wantErr: errAuthKeyBoundToEngine,
		},
		"authentication key only": {
			edit: func(sp *UsmSecurityParameters) { sp.AuthenticationPassphrase = "" }, engineID: usmCharEngineID,
			wantErr: errAuthKeyBoundToEngine,
		},
		"privacy key only": {
			edit: func(sp *UsmSecurityParameters) { sp.PrivacyPassphrase = "" }, engineID: usmCharEngineID,
			wantErr: errPrivKeyBoundToEngine,
		},
		"no authentication key or passphrase": {
			edit:     func(sp *UsmSecurityParameters) { sp.AuthenticationPassphrase, sp.SecretKey = "", nil },
			engineID: usmCharEngineID, wantErr: errAuthKeyBoundToEngine,
		},
		"no privacy key or passphrase": {
			edit:     func(sp *UsmSecurityParameters) { sp.PrivacyPassphrase, sp.PrivacyKey = "", nil },
			engineID: usmCharEngineID, wantErr: errPrivKeyBoundToEngine,
		},
		"noAuthNoPriv": {
			edit: func(sp *UsmSecurityParameters) {
				sp.AuthenticationProtocol, sp.PrivacyProtocol = NoAuth, NoPriv
				sp.AuthenticationPassphrase, sp.PrivacyPassphrase, sp.SecretKey, sp.PrivacyKey = "", "", nil, nil
			},
			engineID: usmCharEngineID,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sp := params(tc.edit)
			before := []any{sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey}

			err := sp.adoptEngineID(tc.engineID)
			got := []any{sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey}
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
				assert.Equal(t, before, got)
			case tc.engineID == usmOtherEngineID:
				require.NoError(t, err)
				assert.Equal(t, before, got)
			case sp.AuthenticationProtocol == NoAuth:
				require.NoError(t, err)
				assert.Equal(t, []any{tc.engineID, []byte(nil), []byte(nil)}, got)
			default:
				require.NoError(t, err)
				assert.Equal(t, keysFor(tc.engineID), got)
			}
		})
	}
}

// TestUSMAuthFieldEmpty pins that an authNoPriv message with an empty
// msgAuthenticationParameters, shorter than the 12-octet SHA digest, decodes
// without a write, whether or not the input has spare capacity:
// SnmpDecodePacket checks no digest, and UnmarshalTrap finds it not
// authentic.
func TestUSMAuthFieldEmpty(t *testing.T) {
	useEngineTimes(t)
	usm := craftedUSM(octets(usmCharEngineID), intTLV(0), intTLV(0), octets("codec-user"), octets(""), octets(""))
	msg := craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), usm, craftedScopedResp)
	decoder := usmDecoder(SHA, "codec-auth-pass", NoPriv, "")
	trapDecoder := func() *GoSNMP {
		x := decoder()
		x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, AuthNoPriv
		return x
	}

	for name, spare := range map[string]int{"no spare capacity": 0, "spare capacity": 16} {
		t.Run(name, func(t *testing.T) {
			buf := append(bytes.Clone(msg), bytes.Repeat([]byte{0xaa}, spare)...)
			in := buf[:len(msg):len(buf)]
			_, err := decoder().SnmpDecodePacket(in)
			require.NoError(t, err, "SnmpDecodePacket")
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
			vbs := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: bytes.Repeat([]byte{'x'}, n)}}
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
// PrivacyParameters are neither used nor written, and InitPacket does
// nothing.
func TestUSMSalts(t *testing.T) {
	packetSalt := func() []byte { return bytes.Repeat([]byte{0xee}, 8) }
	tests := map[string]struct {
		priv  SnmpV3PrivProtocol
		next  uint64
		flags []SnmpV3MsgFlags
		want  []string
	}{
		"aes": {
			priv: AES256, next: 0x0000000700000001,
			flags: []SnmpV3MsgFlags{AuthPriv, AuthNoPriv, AuthPriv, NoAuthNoPriv, AuthPriv},
			want:  []string{"0000000700000001", "empty", "0000000700000002", "empty", "0000000700000003"},
		},
		"des counts in 64 bits": {
			priv: DES, next: 0x00000001ffffffff,
			flags: []SnmpV3MsgFlags{AuthPriv, AuthNoPriv, AuthPriv},
			want:  []string{"00000001ffffffff", "empty", "0000000200000000"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			usm.Salts.Set(tc.next)
			var got []string
			for _, flags := range tc.flags {
				sp := codecUSM(t, SHA, tc.priv)
				sp.PrivacyParameters = packetSalt()
				pkt := &SnmpPacket{
					Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp,
					PDUType: GetRequest,
				}
				data, err := pkt.MarshalMsg()
				require.NoError(t, err)
				got = append(got, dumpBytes(splitV3Message(t, data).usm[5]))
				assert.Equal(t, packetSalt(), sp.PrivacyParameters, "the packet's salt")
			}
			assert.Equal(t, tc.want, got)
		})
	}
	t.Run("a message without security parameters is an error", func(t *testing.T) {
		for name, sp := range map[string]SnmpV3SecurityParameters{"nil": nil, "typed nil": (*UsmSecurityParameters)(nil)} {
			for _, flags := range []SnmpV3MsgFlags{NoAuthNoPriv, AuthPriv} {
				pkt := &SnmpPacket{Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp}
				_, err := pkt.MarshalMsg()
				assert.EqualError(t, err, "SNMPv3 message without security parameters", "%s, %v", name, flags)
			}
		}
	})
	t.Run("InitPacket does nothing", func(t *testing.T) {
		usm.Salts.Set(5)
		sp := &UsmSecurityParameters{PrivacyProtocol: AES}
		pkt := &SnmpPacket{Version: Version3, MsgFlags: AuthPriv, SecurityParameters: sp}
		require.NoError(t, (&UsmSecurityParameters{PrivacyProtocol: DES}).InitPacket(pkt))
		assert.Equal(t, &UsmSecurityParameters{PrivacyProtocol: AES}, sp)
		assert.Equal(t, [8]byte{7: 5}, usm.Salts.Next(), "no salt drawn")
	})
}

// TestUSMCopy pins Copy: every field is copied, but the key and salt slices
// are shared with the original.
func TestUSMCopy(t *testing.T) {
	sp := &UsmSecurityParameters{
		AuthoritativeEngineID:    usmCharEngineID,
		AuthoritativeEngineBoots: 3,
		AuthoritativeEngineTime:  77,
		UserName:                 "codec-user",
		AuthenticationParameters: "auth-params",
		PrivacyParameters:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
		AuthenticationProtocol:   SHA,
		PrivacyProtocol:          AES,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyPassphrase:        "codec-priv-pass",
		Logger:                   NewLogger(&testLogger{}),
	}
	require.NoError(t, sp.InitSecurityKeys())

	cp, ok := sp.Copy().(*UsmSecurityParameters)
	require.True(t, ok)
	assert.Equal(t, sp, cp)

	t.Run("slices are shared", func(t *testing.T) {
		cp.SecretKey[0] ^= 0xff
		cp.PrivacyKey[0] ^= 0xff
		cp.PrivacyParameters[0] ^= 0xff
		assert.Equal(t, cp.SecretKey, sp.SecretKey)
		assert.Equal(t, cp.PrivacyKey, sp.PrivacyKey)
		assert.Equal(t, cp.PrivacyParameters, sp.PrivacyParameters)
	})
}

type testLogger struct{}

func (testLogger) Print(...any)          {}
func (testLogger) Printf(string, ...any) {}

// usmCacheOnAtInit is whether the password cache is on before any test
// toggles it.
var usmCacheOnAtInit = passwordCache.Enabled()

// TestUSMPasswordCaching pins that the password-to-key cache is on by default
// and that PasswordCaching turns it on and off, and that the cache does not
// change the keys: with caching on, off, re-enabled, and with concurrent
// users. The cache itself is tested in internal/usm.
func TestUSMPasswordCaching(t *testing.T) {
	require.True(t, usmCacheOnAtInit, "on by default")
	t.Cleanup(func() { PasswordCaching(true) })

	keys := func() []string {
		var out []string
		for _, a := range usmAuthProtocols[1:] {
			for _, p := range usmPrivProtocols[1:] {
				sp := &UsmSecurityParameters{
					AuthenticationProtocol:   a,
					AuthenticationPassphrase: "codec-auth-pass",
					PrivacyProtocol:          p,
					PrivacyPassphrase:        "codec-priv-pass",
					AuthoritativeEngineID:    usmCharEngineID,
				}
				require.NoError(t, sp.InitSecurityKeys())
				out = append(out, fmt.Sprintf("%x/%x", sp.SecretKey, sp.PrivacyKey))
			}
		}
		return out
	}

	PasswordCaching(true)
	require.True(t, passwordCache.Enabled())
	cached := keys()
	assert.Equal(t, cached, keys(), "cache hits")

	PasswordCaching(false)
	require.False(t, passwordCache.Enabled())
	assert.Equal(t, cached, keys(), "caching disabled")

	PasswordCaching(true)
	require.True(t, passwordCache.Enabled())
	assert.Equal(t, cached, keys(), "caching re-enabled")

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

// TestUSMValidate pins which SNMPv3 settings GoSNMP rejects before decoding
// or encoding, and the messages it rejects them with. The settings that pass
// decode a noAuthNoPriv message; keys given without passphrases are localized
// to its engine ID, since a new engine ID replaces them (decrypt golden).
func TestUSMValidate(t *testing.T) {
	msg := craftedV3NoAuth(craftedScopedResp)
	key := []byte("0123456789abcdefghij") // of the SHA hash's size

	tests := map[string]struct {
		flags   SnmpV3MsgFlags
		model   SnmpV3SecurityModel
		sp      SnmpV3SecurityParameters
		wantErr string
	}{
		"noAuthNoPriv": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{UserName: "u"},
		},
		"noAuthNoPriv without user": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{},
			wantErr: "securityParameters.UserName is required",
		},
		"noAuthNoPriv with a user name of 32 octets": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{UserName: strings.Repeat("u", 32)},
		},
		"noAuthNoPriv with a user name of 33 octets": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{UserName: strings.Repeat("u", 33)},
			wantErr: "securityParameters.UserName is 33 octets, more than 32",
		},
		"authNoPriv": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p"},
		},
		"authNoPriv without protocol": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationPassphrase: "p"},
			wantErr: "securityParameters.AuthenticationProtocol is required",
		},
		"authNoPriv without passphrase": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA},
			wantErr: "securityParameters.AuthenticationPassphrase is required when an authentication protocol is specified",
		},
		"authNoPriv with a key instead of a passphrase": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, SecretKey: key, AuthoritativeEngineID: usmCharEngineID,
			},
		},
		"authNoPriv without user": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{AuthenticationProtocol: SHA, AuthenticationPassphrase: "p"},
			wantErr: "securityParameters.UserName is required",
		},
		"authPriv": {
			flags: AuthPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p",
				PrivacyProtocol: AES, PrivacyPassphrase: "q",
			},
		},
		"authPriv without privacy protocol": {
			flags: AuthPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p"},
			wantErr: "securityParameters.PrivacyProtocol is required",
		},
		"authPriv without authentication protocol": {
			flags: AuthPriv, sp: &UsmSecurityParameters{UserName: "u", PrivacyProtocol: AES, PrivacyPassphrase: "q"},
			wantErr: "securityParameters.AuthenticationProtocol is required",
		},
		"authPriv without privacy passphrase": {
			flags: AuthPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p", PrivacyProtocol: AES,
			},
			wantErr: "securityParameters.PrivacyPassphrase is required when a privacy protocol is specified",
		},
		"authPriv without either passphrase": {
			flags: AuthPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA, PrivacyProtocol: AES},
			wantErr: "securityParameters.PrivacyPassphrase is required when a privacy protocol is specified",
		},
		"authPriv with keys instead of passphrases": {
			flags: AuthPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, SecretKey: key, PrivacyProtocol: AES, PrivacyKey: key,
				AuthoritativeEngineID: usmCharEngineID,
			},
		},
		"noAuthNoPriv with a privacy protocol and no passphrase": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", PrivacyProtocol: AES},
			wantErr: "securityParameters.PrivacyPassphrase is required when a privacy protocol is specified",
		},
		"privacy flag without authentication flag": {
			flags: 0x2, sp: &UsmSecurityParameters{UserName: "u"},
			wantErr: "validate: MsgFlags must be populated with an appropriate security level",
		},
		"no security parameters": {
			flags:   NoAuthNoPriv,
			wantErr: "SNMPV3 SecurityParameters must be set",
		},
		"other security model": {
			flags: NoAuthNoPriv, model: 2, sp: &UsmSecurityParameters{UserName: "u"},
			wantErr: "the SNMPV3 User Security Model is the only SNMPV3 security model currently implemented",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			model := tc.model
			if model == 0 {
				model = UserSecurityModel
			}
			x := &GoSNMP{Version: Version3, MsgFlags: tc.flags, SecurityModel: model, SecurityParameters: tc.sp}
			_, err := x.SnmpDecodePacket(bytes.Clone(msg))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMStrings pins SafeString and Description, which go to logs.
func TestUSMStrings(t *testing.T) {
	sp := &UsmSecurityParameters{
		AuthoritativeEngineID:    "\x80\x00\x1f\x88\x04e",
		AuthoritativeEngineBoots: 3,
		AuthoritativeEngineTime:  77,
		UserName:                 "codec-user",
		AuthenticationParameters: "",
		PrivacyParameters:        []byte{1, 2},
		AuthenticationProtocol:   SHA256,
		PrivacyProtocol:          AES192C,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyPassphrase:        "codec-priv-pass",
	}
	assert.Equal(t, "AuthoritativeEngineID:\x80\x00\x1f\x88\x04e, AuthoritativeEngineBoots:3, AuthoritativeEngineTimes:77, "+
		"UserName:codec-user, AuthenticationParameters:, PrivacyParameters:[1 2], AuthenticationProtocol:SHA256, PrivacyProtocol:AES192C",
		sp.SafeString())
	assert.Equal(t, "user=codec-user,engine=(80001f880465),auth=sha256,authPass=codec-auth-pass,priv=AES192C,privPass=codec-priv-pass",
		sp.Description())

	for _, a := range usmAuthProtocols {
		for _, p := range usmPrivProtocols {
			s := (&UsmSecurityParameters{AuthenticationProtocol: a, PrivacyProtocol: p}).Description()
			assert.Contains(t, s, ",auth="+strings.ToLower(a.String())+",", "%v", a)
			assert.Contains(t, s, ",priv="+p.String()+",", "%v", p)
		}
	}
	// Unset and unknown protocols have no name.
	for _, v := range []uint8{0, 8} {
		s := (&UsmSecurityParameters{AuthenticationProtocol: SnmpV3AuthProtocol(v), PrivacyProtocol: SnmpV3PrivProtocol(v)}).Description()
		assert.Equal(t, "user=,engine=(),authPass=,privPass=", s, "protocol value %d", v)
	}
}

// TestUSMLog pins that Log writes SafeString to the client's Logger, which
// prepare hands to the security parameters.
func TestUSMLog(t *testing.T) {
	var buf bytes.Buffer
	x := &GoSNMP{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: "codec-user"},
		Logger:             NewLogger(log.New(&buf, "", 0)),
	}
	require.NoError(t, x.prepare())
	x.SecurityParameters.Log()
	assert.Equal(t, "SECURITY PARAMETERS:"+x.SecurityParameters.SafeString()+"\n", buf.String())
}

// TestUSMHashType pins the hash of every authentication protocol value: MD5
// for NoAuth, unset and unknown values.
func TestUSMHashType(t *testing.T) {
	want := map[SnmpV3AuthProtocol]crypto.Hash{
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
		assert.Equal(t, hash, auth.HashType(), "%v", auth)
	}
}
