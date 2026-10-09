// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
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

// usmCharTrap encodes usmCharPacket.
func usmCharTrap(t testing.TB, priv SnmpV3PrivProtocol, salt []byte, variables []SnmpPDU) []byte {
	t.Helper()
	data, err := usmCharPacket(t, priv, salt, variables).MarshalMsg()
	require.NoError(t, err)
	return data
}

// usmCharPacket is an authPriv (authNoPriv without a privacy protocol)
// SNMPv2-Trap from codec-user, the credentials usmDecoder configures, with
// the given privacy protocol and salt and its keys initialized.
func usmCharPacket(t testing.TB, priv SnmpV3PrivProtocol, salt []byte, variables []SnmpPDU) *SnmpPacket {
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
		PrivacyParameters:        salt,
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

func usmCharSalt(priv SnmpV3PrivProtocol) []byte {
	if priv == DES {
		return []byte{0, 0, 0, 3, 0x0a, 0x0b, 0x0c, 0x0d}
	}
	return []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
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

	next := func(r *ber.Reader) (byte, []byte) {
		tag, content, err := r.Next()
		require.NoError(t, err)
		return tag, content
	}
	var m v3Message
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
	return m
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
		data := usmCharTrap(t, priv, usmCharSalt(priv), usmCharVarbinds)
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
			results = append(results, goldenCase{name: c.name, dump: dumpDecode(c)})
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
	m := splitV3Message(t, usmCharTrap(t, priv, usmCharSalt(priv), usmCharVarbinds)).withFlags(t, flags)
	m.usm[5] = m.usm[5][:saltLen]
	return m.bytes()
}

// usmMalformedV3Header is an SNMPv3 message whose header is not a SEQUENCE.
var usmMalformedV3Header = tlv(0x30, intTLV(3), tlv(0x31, intTLV(1)))

// TestUSMTrapUnauthenticated pins what UnmarshalTrap does, for a single user
// requiring authPriv and through a credentials table, with messages it
// decodes without checking a digest:
//
//   - the table path takes the security level from the message
//     (TestTrapSecurityOutcomes);
//   - both paths check the digest only for the User-based Security Model;
//   - testAuthentication skips it for any message with an empty user name and
//     engine ID: of the conditions of its engine discovery exception (RFC 3414
//     section 4), the flags test always holds (NoAuthNoPriv is 0) and the
//     varbind list is always empty there, since the payload is decoded later.
//
// Decryption follows the scoped PDU's tag (an OCTET STRING is decrypted)
// whatever the flags say. Cases with a knownBug note record wrong behavior
// that the bug-fix phase changes.
func TestUSMTrapUnauthenticated(t *testing.T) {
	plainVars := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: Integer, Value: 5}}
	plainTrap := func(model int64, engineID, user string) []byte {
		usm := craftedUSM(octets(engineID), intTLV(0), intTLV(0), octets(user), octets(""), octets(""))
		scoped := tlv(0x30, octets(""), octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5)))))
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(model), usm, scoped)
	}
	// wrappedTrap carries the plaintext scoped PDU's fields in an OCTET
	// STRING, where an encrypted scoped PDU goes.
	wrappedTrap := func() []byte {
		usm := craftedUSM(octets(usmCharEngineID), intTLV(0), intTLV(0), octets("codec-user"), octets(""), octets(""))
		scoped := tlv(byte(OctetString), octets(""), octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5)))))
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), usm, scoped)
	}
	encryptedWithModel := func(priv SnmpV3PrivProtocol, model byte, saltLen int) []byte {
		m := splitV3Message(t, usmCharTrap(t, priv, usmCharSalt(priv), usmCharVarbinds)).withModel(t, model)
		m.usm[5] = m.usm[5][:saltLen]
		return m.bytes()
	}

	type receiverKind int
	const (
		single receiverKind = iota
		table
		tableKeysOnly // keys localized to another engine ID, no passphrases
	)
	receiver := func(priv SnmpV3PrivProtocol, kind receiverKind) *GoSNMP {
		sp := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")().SecurityParameters.(*UsmSecurityParameters)
		if kind == single {
			return &GoSNMP{Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp}
		}
		if kind == tableKeysOnly {
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
		want     string    // accepted, rejected or panic
		vars     []SnmpPDU // of an accepted trap
		knownBug string
	}{
		"privacy-only DES, single user": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 8) }, priv: DES, want: "rejected",
		},
		"privacy-only DES, table": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 8) }, priv: DES, receiver: table,
			want: "accepted", vars: usmCharVarbinds, knownBug: "decrypted and accepted without checking the digest",
		},
		"privacy-only AES, table": {
			in: func() []byte { return usmFlagsTrap(t, AES, usmPrivacyFlag, 8) }, priv: AES, receiver: table,
			want: "accepted", vars: usmCharVarbinds, knownBug: "decrypted and accepted without checking the digest",
		},
		"noAuthNoPriv flags, encrypted AES, table": {
			in: func() []byte { return usmFlagsTrap(t, AES, NoAuthNoPriv, 8) }, priv: AES, receiver: table,
			want: "accepted", vars: usmCharVarbinds, knownBug: "decrypted and accepted without checking the digest",
		},
		"noAuthNoPriv flags, encrypted AES, single user": {
			in: func() []byte { return usmFlagsTrap(t, AES, NoAuthNoPriv, 8) }, priv: AES, want: "rejected",
		},
		"noAuthNoPriv flags, OCTET STRING scoped PDU, table without privacy": {
			in: wrappedTrap, priv: NoPriv, receiver: table,
			want: "accepted", vars: plainVars, knownBug: "without a privacy protocol an OCTET STRING scoped PDU is read as plaintext",
		},
		"privacy-only DES with a 7-octet salt, single user": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 7) }, priv: DES, want: "rejected",
		},
		"privacy-only DES with a 7-octet salt, table": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 7) }, priv: DES, receiver: table,
			want: "panic", knownBug: "DES builds its IV from 8 octets of a shorter salt",
		},
		"noAuthNoPriv flags, encrypted DES with a 7-octet salt, table": {
			in: func() []byte { return usmFlagsTrap(t, DES, NoAuthNoPriv, 7) }, priv: DES, receiver: table,
			want: "panic", knownBug: "DES builds its IV from 8 octets of a shorter salt",
		},
		"privacy-only AES with a 7-octet salt, table": {
			in: func() []byte { return usmFlagsTrap(t, AES, usmPrivacyFlag, 7) }, priv: AES, receiver: table, want: "rejected",
		},
		"privacy-only DES, table with keys only": {
			in: func() []byte { return usmFlagsTrap(t, DES, usmPrivacyFlag, 8) }, priv: DES, receiver: tableKeysOnly,
			want: "panic", knownBug: "a new engine ID replaces the keys with the empty keys of the empty passphrases",
		},
		"security model 2, plaintext, single user": {
			in: func() []byte { return plainTrap(2, usmCharEngineID, "codec-user") }, priv: AES,
			want: "accepted", vars: plainVars, knownBug: "the digest is checked only for the User-based Security Model",
		},
		"security model 2, authPriv flags, table": {
			in: func() []byte { return encryptedWithModel(AES, 2, 8) }, priv: AES, receiver: table,
			want: "accepted", vars: usmCharVarbinds, knownBug: "the digest is checked only for the User-based Security Model",
		},
		"security model 2, encrypted DES with a 7-octet salt, single user": {
			in: func() []byte { return encryptedWithModel(DES, 2, 7) }, priv: DES,
			want: "panic", knownBug: "DES builds its IV from 8 octets of a shorter salt",
		},
		"empty user name and engine ID, single user": {
			in: func() []byte { return plainTrap(3, "", "") }, priv: AES,
			want: "accepted", vars: plainVars, knownBug: "the engine discovery exception skips the digest for any message",
		},
		"empty user name, engine ID set, single user": {
			in: func() []byte { return plainTrap(3, usmCharEngineID, "") }, priv: AES, want: "rejected",
		},
		"malformed header, single user": {
			in: func() []byte { return usmMalformedV3Header }, priv: AES, want: "rejected",
		},
		"malformed header, table": {
			in: func() []byte { return usmMalformedV3Header }, priv: AES, receiver: table,
			want: "panic", knownBug: "getTrapIdentifier reads the user name from nil SecurityParameters",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := receiver(tc.priv, tc.receiver)
			var res *SnmpPacket
			var err error
			got := "accepted"
			switch v, _ := recoverPanic(func() { res, err = x.UnmarshalTrap(tc.in(), false) }); {
			case v != nil:
				got = "panic"
			case err != nil:
				got = "rejected"
			}
			require.Equal(t, tc.want, got, "known bug: %q", tc.knownBug)
			if got == "accepted" {
				assert.Equal(t, tc.vars, res.Variables)
			}
		})
	}
}

// TestUSMAuthFieldZeroing pins that, before checking any digest, USM
// unmarshal zeroes the expected digest length (12 octets for SHA) after the
// first two octets of msgAuthenticationParameters, whatever the field's
// length. In an authNoPriv message that ends with an empty field this panics
// when the input has no spare capacity (known bug), and otherwise writes the
// zeros past the end of the input.
func TestUSMAuthFieldZeroing(t *testing.T) {
	usm := craftedUSM(octets(usmCharEngineID), intTLV(0), intTLV(0), octets("codec-user"), octets(""), nil)
	msg := craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), usm, nil)
	decoder := usmDecoder(SHA, "codec-auth-pass", NoPriv, "")

	t.Run("no spare capacity", func(t *testing.T) {
		in := bytes.Clone(msg)[:len(msg):len(msg)]
		v, _ := recoverPanic(func() { _, _ = decoder().SnmpDecodePacket(in) })
		assert.NotNil(t, v, "SnmpDecodePacket did not panic (known bug: zeroes past the end of the packet)")

		x := decoder()
		x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, AuthNoPriv
		in = bytes.Clone(msg)[:len(msg):len(msg)]
		v, _ = recoverPanic(func() { _, _ = x.UnmarshalTrap(in, false) })
		assert.NotNil(t, v, "UnmarshalTrap did not panic (known bug: zeroes past the end of the packet)")
	})
	t.Run("spare capacity", func(t *testing.T) {
		buf := append(bytes.Clone(msg), bytes.Repeat([]byte{0xaa}, 16)...)
		in := buf[:len(msg)]
		_, err := decoder().SnmpDecodePacket(in)
		assert.Error(t, err)
		assert.Equal(t, append(make([]byte, 12), bytes.Repeat([]byte{0xaa}, 4)...), buf[len(msg):], "octets after the input")
	})
}

// TestUSMPrivacyPadding pins the ciphertext length: DES pads the scoped PDU
// to the next 8-octet block, with a whole block when it is already aligned;
// the AES protocols do not pad.
func TestUSMPrivacyPadding(t *testing.T) {
	for _, priv := range usmPrivProtocols[1:] {
		for n := range 16 {
			vbs := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: bytes.Repeat([]byte{'x'}, n)}}
			plain := splitV3Message(t, usmCharTrap(t, NoPriv, nil, vbs))
			secured := splitV3Message(t, usmCharTrap(t, priv, usmCharSalt(priv), vbs))

			plainLen := len(tlv(plain.scopedTag, plain.scoped))
			want := plainLen
			if priv == DES {
				want = plainLen + 8 - plainLen%8
			}
			assert.Equal(t, want, len(secured.scoped), "%v, scoped PDU of %d octets", priv, plainLen)
		}
	}
}

// TestUSMSalts pins how InitPacket allocates msgPrivacyParameters: a counter
// of the parameters it is called on, incremented on every call (also for
// packets without privacy), written to the packet's own parameters; DES
// prefixes the packet's engine boots (RFC 3414 section 8.1.1.1), the AES
// protocols use the 64-bit counter (RFC 3826 section 3.1.2.1); a counter of
// one family cannot fill the parameters of the other. The counters start at
// zero until GoSNMP initializes them with random values.
func TestUSMSalts(t *testing.T) {
	newPacket := func(sp *UsmSecurityParameters, flags SnmpV3MsgFlags) *SnmpPacket {
		return &SnmpPacket{Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp}
	}
	salts := func(t *testing.T, sp *UsmSecurityParameters, flags ...SnmpV3MsgFlags) []string {
		t.Helper()
		var out []string
		for _, f := range flags {
			pktSP := &UsmSecurityParameters{PrivacyProtocol: sp.PrivacyProtocol, AuthoritativeEngineBoots: 9}
			require.NoError(t, sp.InitPacket(newPacket(pktSP, f)))
			out = append(out, dumpBytes(pktSP.PrivacyParameters))
		}
		return out
	}

	tests := map[string]struct {
		sp    *UsmSecurityParameters
		flags []SnmpV3MsgFlags
		want  []string
	}{
		"aes counter": {
			sp:    &UsmSecurityParameters{PrivacyProtocol: AES256, AuthoritativeEngineBoots: 5},
			flags: []SnmpV3MsgFlags{AuthPriv, AuthNoPriv, AuthPriv, NoAuthNoPriv, AuthPriv},
			want:  []string{"0000000000000001", "nil", "0000000000000003", "nil", "0000000000000005"},
		},
		"des counter and boots of the packet": {
			sp:    &UsmSecurityParameters{PrivacyProtocol: DES, AuthoritativeEngineBoots: 5},
			flags: []SnmpV3MsgFlags{AuthPriv, AuthNoPriv, AuthPriv},
			want:  []string{"0000000900000001", "nil", "0000000900000003"},
		},
		"aes wraps": {
			sp:    &UsmSecurityParameters{PrivacyProtocol: AES, localAESSalt: math.MaxUint64 - 1},
			flags: []SnmpV3MsgFlags{AuthPriv, AuthPriv},
			want:  []string{"ffffffffffffffff", "0000000000000000"},
		},
		"des wraps": {
			sp:    &UsmSecurityParameters{PrivacyProtocol: DES, localDESSalt: math.MaxUint32 - 1},
			flags: []SnmpV3MsgFlags{AuthPriv, AuthPriv},
			want:  []string{"00000009ffffffff", "0000000900000000"},
		},
		"no privacy protocol uses the DES layout": {
			sp:    &UsmSecurityParameters{PrivacyProtocol: NoPriv},
			flags: []SnmpV3MsgFlags{AuthPriv},
			want:  []string{"0000000900000001"},
		},
		"unset privacy protocol uses the DES layout": {
			sp:    &UsmSecurityParameters{},
			flags: []SnmpV3MsgFlags{AuthPriv},
			want:  []string{"0000000900000001"},
		},
		"unknown privacy protocol uses the DES layout": {
			sp:    &UsmSecurityParameters{PrivacyProtocol: SnmpV3PrivProtocol(8)},
			flags: []SnmpV3MsgFlags{AuthPriv},
			want:  []string{"0000000900000001"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, salts(t, tc.sp, tc.flags...))
			assert.Nil(t, tc.sp.PrivacyParameters, "the counter's own parameters")
		})
	}
	t.Run("the counter's protocol family must match the packet's", func(t *testing.T) {
		tests := map[string]struct {
			counter, packet SnmpV3PrivProtocol
			wantErr         string
		}{
			"aes counter, des packet": {
				counter: AES192, packet: DES,
				wantErr: "salt provided to usmSetSalt is not the correct type for the DES privacy protocol",
			},
			"aes counter, no privacy packet": {
				counter: AES, packet: NoPriv,
				wantErr: "salt provided to usmSetSalt is not the correct type for the DES privacy protocol",
			},
			"des counter, aes packet": {
				counter: DES, packet: AES256C,
				wantErr: "salt provided to usmSetSalt is not the correct type for the AES privacy protocol",
			},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				pktSP := &UsmSecurityParameters{PrivacyProtocol: tc.packet}
				err := (&UsmSecurityParameters{PrivacyProtocol: tc.counter}).InitPacket(newPacket(pktSP, AuthPriv))
				assert.EqualError(t, err, tc.wantErr)
				assert.Nil(t, pktSP.PrivacyParameters)
			})
		}
	})
	t.Run("packet without security parameters", func(t *testing.T) {
		tests := map[string]struct {
			pktSP   SnmpV3SecurityParameters
			flags   SnmpV3MsgFlags
			wantErr string
		}{
			"nil, privacy": {
				flags: AuthPriv, wantErr: "param SnmpV3SecurityParameters is not of type *UsmSecurityParameters",
			},
			"typed nil, privacy": {
				pktSP: (*UsmSecurityParameters)(nil), flags: AuthPriv,
				wantErr: "param SnmpV3SecurityParameters is not of type *UsmSecurityParameters",
			},
			"nil, no privacy": {flags: AuthNoPriv},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				pkt := &SnmpPacket{Version: Version3, MsgFlags: tc.flags, SecurityParameters: tc.pktSP}
				err := (&UsmSecurityParameters{PrivacyProtocol: AES}).InitPacket(pkt)
				if tc.wantErr == "" {
					assert.NoError(t, err)
					return
				}
				assert.EqualError(t, err, tc.wantErr)
			})
		}
	})
	t.Run("init seeds the counter of the AES or the DES protocols only", func(t *testing.T) {
		for _, priv := range []SnmpV3PrivProtocol{0, NoPriv, DES, AES, AES192, AES256, AES192C, AES256C, 8} {
			sp := &UsmSecurityParameters{PrivacyProtocol: priv}
			require.NoError(t, sp.init(Logger{}))
			aes := priv >= AES && priv <= AES256C
			assert.Equal(t, aes, sp.localAESSalt != 0, "%v AES counter", priv)
			assert.Equal(t, priv == DES, sp.localDESSalt != 0, "%v DES counter", priv)
		}
	})
	t.Run("GoSNMP starts the counter at a random value", func(t *testing.T) {
		encode := func() string {
			x := &GoSNMP{
				Version:       Version3,
				MsgFlags:      AuthPriv,
				SecurityModel: UserSecurityModel,
				SecurityParameters: &UsmSecurityParameters{
					UserName:                 "codec-user",
					AuthenticationProtocol:   SHA,
					AuthenticationPassphrase: "codec-auth-pass",
					PrivacyProtocol:          AES,
					PrivacyPassphrase:        "codec-priv-pass",
					AuthoritativeEngineID:    usmCharEngineID,
				},
			}
			require.NoError(t, x.SecurityParameters.InitSecurityKeys())
			data, err := x.SnmpEncodePacket(GetRequest, nil, 0, 0)
			require.NoError(t, err)
			return string(splitV3Message(t, data).usm[5])
		}
		assert.NotEqual(t, encode(), encode())
	})
}

// TestUSMCopy pins Copy: every field is copied, the salt counters too, but
// the key and salt slices are shared with the original.
func TestUSMCopy(t *testing.T) {
	sp := &UsmSecurityParameters{
		localAESSalt:             11,
		localDESSalt:             12,
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
	t.Run("salt counters are independent", func(t *testing.T) {
		pkt := &SnmpPacket{MsgFlags: AuthPriv, SecurityParameters: &UsmSecurityParameters{PrivacyProtocol: AES}}
		require.NoError(t, cp.InitPacket(pkt))
		assert.Equal(t, uint64(12), cp.localAESSalt)
		assert.Equal(t, uint64(11), sp.localAESSalt)
	})
}

type testLogger struct{}

func (testLogger) Print(...any)          {}
func (testLogger) Printf(string, ...any) {}

// TestUSMPasswordCaching pins that PasswordCaching turns the password-to-key
// cache on and off, and that the cache does not change the keys: with caching
// on, off, re-enabled, and with concurrent users. The cache itself is tested
// in internal/usm.
func TestUSMPasswordCaching(t *testing.T) {
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
	key := []byte("0123456789abcdef")

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
