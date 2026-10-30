// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA-96, the protocol under test
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/usm"
)

// decodeV3ParseCases are SNMPv3 messages that pin how the header and the USM
// parameters are read: the security model, the extents of msgGlobalData, the
// security parameters and the USM SEQUENCE, and the msgAuthenticationParameters
// field the digest is checked over. The authenticated ones are signed for
// codec-user with the key usmDecoderLocalized(SHA, NoPriv) holds.
func decodeV3ParseCases() []decodeCase {
	globalData := cat(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3))
	usm := craftedNoAuthUSM
	scoped := craftedScopedResp
	// msg builds a message from its parts as they go on the wire.
	msg := func(parts ...[]byte) []byte { return tlv(0x30, append([][]byte{intTLV(3)}, parts...)...) }
	withModel := func(model []byte) []byte {
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), model, usm, scoped)
	}
	// header is a TLV header declaring n content octets, for misdeclared
	// lengths.
	header := buildTLVHeader
	usmFields := cat(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets(""))
	localized := usmDecoderLocalized(SHA, NoPriv)
	localizedPriv := usmDecoderLocalized(SHA, AES)
	// encryptedData returns msgData: the ciphertext in an OCTET STRING whose
	// declared length is off octets more than the ciphertext's.
	encryptedData := func(off int) func([]byte) []byte {
		return func(ciphertext []byte) []byte {
			return cat(header(byte(OctetString), len(ciphertext)+off), ciphertext)
		}
	}

	return []decodeCase{
		// The security model as the wire sends it: an INTEGER that the
		// header's one-octet field cuts, another field type, none.
		{name: "crafted/v3/parse/security-model-259", in: withModel(intTLV(259))},
		{name: "crafted/v3/parse/security-model-minus-253", in: withModel(intTLV(-253))},
		{name: "crafted/v3/parse/security-model-0", in: withModel(intTLV(0))},
		{name: "crafted/v3/parse/security-model-octet-string", in: withModel(octets("\x03"))},
		{name: "crafted/v3/parse/security-model-null", in: withModel(tlv(byte(Null)))},
		{name: "crafted/v3/parse/security-model-absent", in: msg(tlv(0x30, intTLV(42), intTLV(65507), octets("\x00")), tlv(byte(OctetString), usm), scoped)},
		// Another model and privacy without authentication: the model is
		// checked first (RFC 3412 section 7.2 step 4 before step 5).
		{name: "crafted/v3/parse/security-model-2-privacy-only", in: craftedV3(intTLV(42), intTLV(65507), octets("\x02"), intTLV(2), usm, scoped)},
		// An authNoPriv trap whose model is an OCTET STRING, with a digest
		// nobody computed.
		{
			name: "crafted/v3/parse/security-model-octet-string-auth",
			in: craftedV3(intTLV(42), intTLV(65507), octets("\x01"), octets("\x03"),
				craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(string(bytes.Repeat([]byte{0xaa}, 12))), octets("")), scoped),
			decoder: localized,
		},

		// Extents: what net-snmp v5.9.4 reads too (a msgGlobalData declared
		// shorter than its fields, security parameters declared to cover the
		// scoped PDU), what it rejects (lengths past the message, a USM field
		// crossing its SEQUENCE, a SEQUENCE longer than its OCTET STRING), and
		// trailing data in each container.
		{name: "crafted/v3/parse/global-data-under-declared", in: msg(cat(header(0x30, 3), globalData), tlv(byte(OctetString), usm), scoped)},
		{name: "crafted/v3/parse/global-data-over-declared", in: msg(cat(header(0x30, 200), globalData), tlv(byte(OctetString), usm), scoped)},
		{name: "crafted/v3/parse/global-data-extra-field", in: msg(tlv(0x30, globalData, intTLV(0)), tlv(byte(OctetString), usm), scoped)},
		{name: "crafted/v3/parse/security-parameters-cover-scoped-pdu", in: msg(tlv(0x30, globalData), cat(header(byte(OctetString), len(usm)+len(scoped)), usm), scoped)},
		{name: "crafted/v3/parse/security-parameters-over-declared", in: msg(tlv(0x30, globalData), cat(header(byte(OctetString), len(usm)+len(scoped)+10), usm), scoped)},
		{name: "crafted/v3/parse/security-parameters-trailing-data", in: msg(tlv(0x30, globalData), tlv(byte(OctetString), usm, intTLV(0)), scoped)},
		{name: "crafted/v3/parse/usm-extra-field", in: msg(tlv(0x30, globalData), tlv(byte(OctetString), tlv(0x30, usmFields, intTLV(0))), scoped)},
		{name: "crafted/v3/parse/usm-under-declared", in: msg(tlv(0x30, globalData), tlv(byte(OctetString), cat(header(0x30, len(usmFields)-2), usmFields)), scoped)},
		{name: "crafted/v3/parse/usm-over-declared", in: msg(tlv(0x30, globalData), tlv(byte(OctetString), cat(header(0x30, len(usmFields)+2), usmFields)), scoped)},

		// msgAuthenticationParameters of an authNoPriv message, signed over
		// the field's content zeroed: a long-form length, another length than
		// the 12-octet MAC, empty.
		{name: "crafted/v3/parse/auth-params-long-form-length", in: signedAuthField([]byte{0x04, 0x81, 0x0c}, 12), decoder: localized},
		{name: "crafted/v3/parse/auth-params-11-octets", in: signedAuthField([]byte{0x04, 0x0b}, 11), decoder: localized},
		{name: "crafted/v3/parse/auth-params-13-octets", in: signedAuthField([]byte{0x04, 0x0d}, 13), decoder: localized},
		{name: "crafted/v3/parse/auth-params-empty", in: signedAuthField([]byte{0x04, 0x00}, 0), decoder: localized},
		{name: "crafted/v3/parse/auth-params-short-form", in: signedAuthField([]byte{0x04, 0x0c}, 12), decoder: localized},

		// The encrypted scoped PDU: as sent, its OCTET STRING declared past the
		// message or short of the ciphertext, and a context field of another
		// type once decrypted.
		{name: "crafted/v3/parse/encrypted-scoped-pdu", in: encryptedV3(scoped, encryptedData(0)), decoder: localizedPriv},
		{name: "crafted/v3/parse/encrypted-scoped-pdu-over-declared", in: encryptedV3(scoped, encryptedData(5)), decoder: localizedPriv},
		{name: "crafted/v3/parse/encrypted-scoped-pdu-under-declared", in: encryptedV3(scoped, encryptedData(-5)), decoder: localizedPriv},
		{
			name: "crafted/v3/parse/encrypted-scoped-pdu-trailing-octets",
			in: encryptedV3(scoped, func(ciphertext []byte) []byte {
				return cat(header(byte(OctetString), len(ciphertext)), ciphertext, bytes.Repeat([]byte{0x5a}, 16))
			}),
			decoder: localizedPriv,
		},
		{
			name:    "crafted/v3/parse/encrypted-scoped-pdu-not-sequence",
			in:      encryptedV3(tlv(byte(OctetString), craftedEngineID, octets("ctx"), craftedPDU(GetResponse, craftedVBL(craftedVB(intTLV(5))))), encryptedData(0)),
			decoder: localizedPriv,
		},
		{
			name:    "crafted/v3/parse/encrypted-context-engine-id-integer",
			in:      encryptedV3(tlv(0x30, intTLV(1), octets("ctx"), craftedPDU(GetResponse, craftedVBL(craftedVB(intTLV(5))))), encryptedData(0)),
			decoder: localizedPriv,
		},
	}
}

// signedAuthField returns an authNoPriv GetResponse from codec-user whose
// msgAuthenticationParameters is fieldHeader followed by n content octets:
// the HMAC-SHA-96 digest of the message with those octets zeroed, cut or
// zero-padded to n.
func signedAuthField(fieldHeader []byte, n int) []byte {
	marker := bytes.Repeat([]byte{0xa5}, n)
	usmParams := craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), cat(fieldHeader, marker), octets(""))
	data := craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), usmParams, craftedScopedResp)
	if n == 0 {
		return data
	}
	return signedAt(data, marker)
}

// signedReply returns an authNoPriv message of codec-user with msgID 42 and
// msgData scoped, signed.
func signedReply(scoped []byte) []byte {
	marker := bytes.Repeat([]byte{0xa5}, 12)
	usmParams := craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(string(marker)), octets(""))
	return signedAt(craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), usmParams, scoped), marker)
}

// signedAt returns data with the HMAC-SHA-96 digest of codec-user written over
// marker, the content of its msgAuthenticationParameters, computed with those
// octets zeroed and cut or zero-padded to the marker's length.
func signedAt(data, marker []byte) []byte {
	off, n := bytes.Index(data, marker), len(marker)
	clear(data[off : off+n])
	key, err := passwordCache.LocalizedKey(crypto.SHA1, "codec-auth-pass", string(craftedEngineID[2:]))
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	copy(data[off:off+n], mac.Sum(nil)[:12])
	return data
}

// encryptedV3 returns an authPriv (SHA, AES) message from codec-user whose
// msgData is msgData(the ciphertext of scoped), encrypted and signed with the
// keys usmDecoderLocalized(SHA, AES) holds.
func encryptedV3(scoped []byte, msgData func(ciphertext []byte) []byte) []byte {
	sp := usmDecoderLocalized(SHA, AES)().SecurityParameters.usm()
	sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = 7, 1234
	salt := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	ciphertext, err := sp.encryptPacket(scoped, salt)
	if err != nil {
		panic(err)
	}
	marker := bytes.Repeat([]byte{0xa5}, 12)
	usmParams := craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), tlv(byte(OctetString), marker), tlv(byte(OctetString), salt))
	return signedAt(craftedV3(intTLV(42), intTLV(65507), octets("\x03"), intTLV(3), usmParams, msgData(ciphertext)), marker)
}

// withWrongDigest returns data, an authenticated message, with the first
// octet of its digest inverted.
func withWrongDigest(t testing.TB, data []byte) []byte {
	m := splitV3Message(t, data)
	m.usm[4] = bytes.Clone(m.usm[4])
	m.usm[4][0] ^= 0xff
	return m.bytes()
}

// TestV3ReceiverRules pins, for each SNMPv3 decode path, which message a
// receiver's parameters refuse, with which text and the exported errors it
// unwraps to, and whether the decoder writes into its input. Results are in
// testdata/usm/receiver-rules.golden.
func TestV3ReceiverRules(t *testing.T) {
	useEngineTimes(t)
	discoveryAuth := craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3),
		craftedUSM(octets(""), intTLV(0), intTLV(0), octets(""), octets(string(make([]byte, 12))), octets("")),
		tlv(0x30, octets(""), octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5))))))
	messages := []struct {
		name string
		in   func() []byte
	}{
		{"authNoPriv", func() []byte { return signedTestTrap(t, SHA, NoPriv, usmCharEngineID, "codec-user", nil) }},
		{"authPriv", func() []byte { return signedTestTrap(t, SHA, AES, usmCharEngineID, "codec-user", nil) }},
		{"noAuthNoPriv", func() []byte { return usmPlainTrap(3, usmCharEngineID, "codec-user") }},
		{"authNoPriv, empty user name and engine ID", func() []byte { return discoveryAuth }},
		{"authPriv, INTEGER privacy parameters", func() []byte {
			// A fixed salt: a receiver without privacy reads the ciphertext.
			usm.Salts.Set(usmCharSalt(AES))
			m := splitV3Message(t, signedTestTrap(t, SHA, AES, usmCharEngineID, "codec-user", nil))
			// An INTEGER where the OCTET STRING goes.
			m.usmTags[5], m.usm[5] = byte(Integer), []byte{0x05}
			return m.bytes()
		}},
		{"authNoPriv, long-form digest field length", func() []byte { return signedAuthField([]byte{0x04, 0x81, 0x0c}, 12) }},
		{"authNoPriv, another user", func() []byte { return signedTestTrap(t, SHA, NoPriv, usmCharEngineID, "other-user", nil) }},
	}
	sets := []struct {
		name string
		sp   func() *UsmSecurityParameters
	}{
		{"no protocols", func() *UsmSecurityParameters { return &UsmSecurityParameters{UserName: "codec-user"} }},
		{"SHA", func() *UsmSecurityParameters {
			return usmDecoder(SHA, "codec-auth-pass", NoPriv, "")().SecurityParameters.usm()
		}},
		{"SHA-AES", func() *UsmSecurityParameters {
			return usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")().SecurityParameters.usm()
		}},
		{"unknown authentication protocol", func() *UsmSecurityParameters {
			return &UsmSecurityParameters{UserName: "codec-user", AuthenticationProtocol: 99, AuthenticationPassphrase: "codec-auth-pass"}
		}},
	}
	type path struct {
		name   string
		decode func(sp *UsmSecurityParameters, in []byte) error
	}
	level := func(sp *UsmSecurityParameters) SnmpV3MsgFlags {
		switch {
		case sp.PrivacyProtocol > NoPriv:
			return AuthPriv
		case sp.AuthenticationProtocol > NoAuth:
			return AuthNoPriv
		}
		return NoAuthNoPriv
	}
	paths := []path{
		{"table", func(sp *UsmSecurityParameters, in []byte) error {
			tb := NewSnmpV3SecurityParametersTable(Logger{})
			if err := tb.Add("codec-user", sp); err != nil {
				return fmt.Errorf("add: %w", err)
			}
			_, err := (&GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(in, false)
			return err
		}},
		{"single", func(sp *UsmSecurityParameters, in []byte) error {
			x := &GoSNMP{Version: Version3, MsgFlags: level(sp), SecurityModel: UserSecurityModel, SecurityParameters: sp}
			_, err := x.UnmarshalTrap(in, false)
			return err
		}},
		{"single, message flags", func(sp *UsmSecurityParameters, in []byte) error {
			x := &GoSNMP{Version: Version3, MsgFlags: level(sp), SecurityModel: UserSecurityModel, SecurityParameters: sp}
			_, err := x.UnmarshalTrap(in, true)
			return err
		}},
		{"SnmpDecodePacket", func(sp *UsmSecurityParameters, in []byte) error {
			_, err := (&GoSNMP{SecurityParameters: sp}).SnmpDecodePacket(in)
			return err
		}},
	}

	var results []goldenCase
	record := func(name string, in []byte, decode func(in []byte) error) {
		useEngineTimes(t)
		buf := bytes.Clone(in)
		var d dumpWriter
		if err := decode(buf); err != nil {
			d.line(dumpError(err) + ": " + err.Error())
		} else {
			d.line("ok")
		}
		if !bytes.Equal(buf, in) {
			d.line("input: modified")
		}
		results = append(results, goldenCase{name: name, dump: d.String()})
	}
	for _, m := range messages {
		for _, s := range sets {
			for _, p := range paths {
				record(m.name+"/"+s.name+"/"+p.name, m.in(), func(in []byte) error { return p.decode(s.sp(), in) })
			}
		}
		// A client without SNMPv3 parameters (Netdata decodes so when no
		// SNMPv3 user is configured) and one whose version is not SNMPv3.
		record(m.name+"/no parameters/single", m.in(), func(in []byte) error {
			_, err := (&GoSNMP{Version: Version3}).UnmarshalTrap(in, false)
			return err
		})
		record(m.name+"/SHA-AES/single, version unset", m.in(), func(in []byte) error {
			sp := sets[2].sp()
			_, err := (&GoSNMP{MsgFlags: AuthPriv, SecurityParameters: sp}).UnmarshalTrap(in, false)
			return err
		})
	}
	// A table with two sets for one user: keys given without passphrases for
	// another engine ID, and passphrases; messages from either engine, and one
	// whose digest neither set checks, which each set rejects at another step.
	keysOnly := func() *UsmSecurityParameters {
		return usmKeysOnly(usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")().SecurityParameters.usm(), usmOtherEngineID)
	}
	passphrases := sets[2].sp
	mixedMessages := []struct {
		name string
		in   []byte
	}{
		{"from " + usmCharEngineID[5:], signedTestTrap(t, SHA, AES, usmCharEngineID, "codec-user", nil)},
		{"from " + usmOtherEngineID[5:], signedTestTrap(t, SHA, AES, usmOtherEngineID, "codec-user", nil)},
		{"from " + usmCharEngineID[5:] + ", wrong digest", withWrongDigest(t, signedTestTrap(t, SHA, AES, usmCharEngineID, "codec-user", nil))},
	}
	for _, order := range []struct {
		name string
		sets []func() *UsmSecurityParameters
	}{
		{"keys only, then passphrases", []func() *UsmSecurityParameters{keysOnly, passphrases}},
		{"passphrases, then keys only", []func() *UsmSecurityParameters{passphrases, keysOnly}},
	} {
		for _, m := range mixedMessages {
			name := "mixed sets/" + order.name + "/" + m.name
			record(name, m.in, func(in []byte) error {
				tb := NewSnmpV3SecurityParametersTable(Logger{})
				for _, sp := range order.sets {
					if err := tb.Add("codec-user", sp()); err != nil {
						return err
					}
				}
				_, err := (&GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(in, false)
				return err
			})
		}
	}
	usmGolden.check(t, "receiver-rules", results)
}

// TestV3DecodeKeyDerivation pins, with the size of the package's key cache,
// which messages from new engine IDs make a receiver derive a privacy key: a
// user of a Reeder-extended protocol (AES-256 Cisco) caches one
// password-to-key result per engine ID it localizes a privacy key to. Only a
// message whose digest checked is decrypted, whatever the receiver's level.
// The receiver's privacy passphrase differs from the sender's, whose own keys
// are cached when its messages are made.
func TestV3DecodeKeyDerivation(t *testing.T) {
	useEngineTimes(t)
	if !passwordCache.Enabled() {
		t.Skip("the key cache is off")
	}
	var seq int
	newEngine := func() string {
		seq++
		return fmt.Sprintf("\x80\x00\x1f\x88\x04kd-%d-%d", time.Now().UnixNano(), seq)
	}
	reeder := func() *UsmSecurityParameters {
		return usmDecoder(SHA, "codec-auth-pass", AES256C, "receiver-priv-pass")().SecurityParameters.usm()
	}
	// The passphrases' own cache entries, and a single user's keys for its
	// empty engine ID, are made once, before any count.
	require.NoError(t, reeder().InitSecurityKeys())
	wrongDigest := func(data []byte) []byte { return withWrongDigest(t, data) }
	signed := func(engineID string) []byte { return signedTestTrap(t, SHA, AES256C, engineID, "codec-user", nil) }

	// single is a single-user receiver with flags, its keys derived for
	// its own (empty) engine ID beforehand.
	single := func(flags SnmpV3MsgFlags, useResponse bool) func([]byte) (*SnmpPacket, error) {
		return func(in []byte) (*SnmpPacket, error) {
			x := &GoSNMP{Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: reeder()}
			require.NoError(t, x.SecurityParameters.InitSecurityKeys())
			return x.UnmarshalTrap(in, useResponse)
		}
	}
	table := func(in []byte) (*SnmpPacket, error) {
		tb := NewSnmpV3SecurityParametersTable(Logger{})
		require.NoError(t, tb.Add("codec-user", reeder()))
		return (&GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(in, false)
	}
	privacyOnly := func(e string) []byte { return splitV3Message(t, signed(e)).withFlags(t, usmPrivacyFlag).bytes() }
	noAuthEncrypted := func(e string) []byte { return splitV3Message(t, signed(e)).withFlags(t, NoAuthNoPriv).bytes() }

	tests := map[string]struct {
		in       func(engineID string) []byte
		receiver func(in []byte) (*SnmpPacket, error) // the table by default
		want     int                                  // cache entries added
	}{
		"authPriv, signed":       {in: signed, want: 1},
		"authPriv, wrong digest": {in: func(e string) []byte { return wrongDigest(signed(e)) }},
		"noAuthNoPriv plaintext": {in: func(e string) []byte { return usmPlainTrap(3, e, "codec-user") }},
		"authPriv, wrong digest, single user at authPriv": {
			in: func(e string) []byte { return wrongDigest(signed(e)) }, receiver: single(AuthPriv, false),
		},
		"privacy only":                  {in: privacyOnly},
		"noAuthNoPriv flags, encrypted": {in: noAuthEncrypted},
		"authPriv, wrong digest, single user at noAuthNoPriv": {
			in: func(e string) []byte { return wrongDigest(signed(e)) }, receiver: single(NoAuthNoPriv, false),
		},
		"noAuthNoPriv flags, encrypted, single user, message flags": {
			in: noAuthEncrypted, receiver: single(AuthPriv, true),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			receiver := tc.receiver
			if receiver == nil {
				receiver = table
			}
			in := tc.in(newEngine())
			before := passwordCache.Len()
			_, _ = receiver(in)
			assert.Equal(t, tc.want, passwordCache.Len()-before)
		})
	}

	// A client's request, answered by an unauthenticated Report naming a new
	// engine ID.
	t.Run("reply/unauthenticated Report from a new engine", func(t *testing.T) {
		sp := signedTestUSM(t, SHA, AES256C, usmCharEngineID, "codec-user")
		sp.PrivacyPassphrase = "receiver-priv-pass"
		x := &GoSNMP{Version: Version3, MsgFlags: AuthPriv | Reportable, SecurityModel: UserSecurityModel, SecurityParameters: sp}
		req := &SnmpPacket{Version: Version3, MsgFlags: AuthPriv | Reportable, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(), MsgID: 7, PDUType: GetRequest}
		engineID := newEngine()
		report := craftedV3(intTLV(7), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(octets(engineID), intTLV(1), intTLV(2), octets("codec-user"), octets(""), octets("")),
			tlv(0x30, octets(engineID), octets(""), craftedPDU(Report, craftedVBL(craftedVB(intTLV(5))))))
		before := passwordCache.Len()
		_, _, _ = (&exchange{x: x, packet: req}).decode(report)
		assert.Zero(t, passwordCache.Len()-before)
	})
}

// TestV3ReplyDecode pins how a client decodes replies to an SNMPv3 request:
// the reply's own msgFlags and the engine boots and time it carries.
func TestV3ReplyDecode(t *testing.T) {
	request := func(flags SnmpV3MsgFlags, priv SnmpV3PrivProtocol) (*exchange, *UsmSecurityParameters) {
		sp := signedTestUSM(t, SHA, priv, usmCharEngineID, "codec-user")
		x := &GoSNMP{Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp}
		req := &SnmpPacket{Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(), MsgID: 7, PDUType: GetRequest}
		return &exchange{x: x, packet: req}, sp
	}

	t.Run("empty msgFlags, Report to an authNoPriv request", func(t *testing.T) {
		e, _ := request(AuthNoPriv|Reportable, NoPriv)
		report := craftedV3(intTLV(7), intTLV(65507), octets(""), intTLV(3),
			craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(string(make([]byte, 12))), octets("")),
			tlv(0x30, octets(usmCharEngineID), octets(""), craftedPDU(Report, craftedVBL(craftedVB(intTLV(5))))))
		reply, verified, err := e.decode(report)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(7), reply.MsgID)
		assert.False(t, verified)
		require.ErrorIs(t, err, errMsgFlags)
	})

	t.Run("header that fails before its msgID", func(t *testing.T) {
		e, _ := request(AuthNoPriv|Reportable, NoPriv)
		report := craftedV3(intTLV(-1), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(""), octets("")),
			tlv(0x30, octets(usmCharEngineID), octets(""), craftedPDU(Report, craftedVBL(craftedVB(intTLV(5))))))
		reply, verified, err := e.decode(report)
		assert.Nil(t, reply, "no msgID was read")
		assert.False(t, verified)
		require.ErrorIs(t, err, ErrInvalidMsgs)
	})

	t.Run("authNoPriv reply, long-form digest field length", func(t *testing.T) {
		e, _ := request(AuthNoPriv|Reportable, NoPriv)
		reply, verified, err := e.decode(signedAuthField([]byte{0x04, 0x81, 0x0c}, 12))
		require.NoError(t, err)
		assert.True(t, verified)
		assert.NotNil(t, reply)
	})

	// An authentic reply that does not decode further reports its digest
	// checked: the discard ranks it above an unauthenticated one.
	t.Run("authentic reply whose scoped PDU does not decode", func(t *testing.T) {
		e, _ := request(AuthNoPriv|Reportable, NoPriv)
		reply, verified, err := e.decode(signedReply(tlv(0x30, craftedEngineID)))
		require.ErrorIs(t, err, ErrInvalidMsgs)
		assert.True(t, verified)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(42), reply.MsgID)
	})
	t.Run("authentic reply whose PDU does not decode", func(t *testing.T) {
		e, _ := request(AuthNoPriv|Reportable, NoPriv)
		reply, verified, err := e.decode(signedReply(tlv(0x30, craftedEngineID, octets("ctx"), tlv(0xaf, intTLV(1)))))
		require.Error(t, err)
		assert.True(t, verified)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(42), reply.MsgID)
	})

	// A msgID means nothing to an SNMPv2c request.
	t.Run("SNMPv3 message to an SNMPv2c request", func(t *testing.T) {
		e := &exchange{x: &GoSNMP{Version: Version2c}, packet: &SnmpPacket{Version: Version2c, PDUType: GetRequest}}
		msg := craftedV3(intTLV(7), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(""), octets("")),
			tlv(0x30, octets(usmCharEngineID), octets(""), craftedPDU(GetResponse, craftedVBL(craftedVB(intTLV(5))))))
		reply, _, err := e.decode(msg)
		require.Error(t, err)
		assert.Nil(t, reply)
	})

	// A reply naming another engine ID carries none of the request's keys
	// and derives none for that engine.
	t.Run("unauthenticated Report from another engine, the reply's keys", func(t *testing.T) {
		e, _ := request(AuthPriv|Reportable, AES)
		other := signedTestUSM(t, SHA, AES, usmOtherEngineID, "codec-user")
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: NoAuthNoPriv, SecurityModel: UserSecurityModel, SecurityParameters: other,
			MsgID: 7, PDUType: Report, Variables: []SnmpPDU{{Name: ".1.3.6.1.6.3.15.1.1.4.0", Type: Counter32, Value: uint32(1)}},
		}).MarshalMsg()
		require.NoError(t, err)
		reply, verified, err := e.decode(data)
		require.NoError(t, err)
		assert.False(t, verified)
		usp := reply.SecurityParameters.usm()
		assert.Equal(t, []any{usmOtherEngineID, []byte(nil), []byte(nil)}, []any{usp.AuthoritativeEngineID, usp.SecretKey, usp.PrivacyKey})
	})

	// A reply that asks for authentication is checked whatever the request's
	// level: one from another engine has none of the request's keys.
	t.Run("encrypted reply from another engine to a noAuthNoPriv request", func(t *testing.T) {
		e, _ := request(NoAuthNoPriv|Reportable, AES)
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel,
			SecurityParameters: signedTestUSM(t, SHA, AES, usmOtherEngineID, "codec-user"),
			MsgID:              7, PDUType: GetResponse, RequestID: 1, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		reply, _, err := e.decode(data)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(7), reply.MsgID)
		require.ErrorIs(t, err, ErrUnknownUsername)
	})

	// A request without authentication checks the digest of a reply that
	// asks for authentication, with its user's key; a user without an
	// authentication protocol takes no such reply.
	t.Run("authNoPriv reply with a wrong digest to a noAuthNoPriv request", func(t *testing.T) {
		e, sp := request(NoAuthNoPriv|Reportable, NoPriv)
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(),
			MsgID: 7, PDUType: GetResponse, RequestID: 1, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		reply, verified, err := e.decode(withWrongDigest(t, data))
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(7), reply.MsgID)
		assert.False(t, verified)
		require.ErrorIs(t, err, ErrWrongDigest)

		reply, verified, err = e.decode(data)
		require.NoError(t, err)
		assert.True(t, verified)
		assert.Equal(t, usmPlainVars, reply.Variables)
	})

	t.Run("authNoPriv reply to a noAuthNoPriv request of a user without protocols", func(t *testing.T) {
		sp := &UsmSecurityParameters{UserName: "codec-user", AuthoritativeEngineID: usmCharEngineID}
		x := &GoSNMP{Version: Version3, MsgFlags: NoAuthNoPriv | Reportable, SecurityModel: UserSecurityModel, SecurityParameters: sp}
		req := &SnmpPacket{Version: Version3, MsgFlags: NoAuthNoPriv | Reportable, SecurityModel: UserSecurityModel, SecurityParameters: sp.Copy(), MsgID: 7, PDUType: GetRequest}
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel,
			SecurityParameters: signedTestUSM(t, SHA, NoPriv, usmCharEngineID, "codec-user"),
			MsgID:              7, PDUType: GetResponse, RequestID: 1, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		reply, _, err := (&exchange{x: x, packet: req}).decode(data)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(7), reply.MsgID)
		require.ErrorIs(t, err, ErrUnknownSecurityLevel)
	})

	// The empty user of discovery has no protocols: a reply naming it takes
	// no authentication, even signed with the request's key.
	t.Run("authNoPriv reply naming the empty user", func(t *testing.T) {
		e, _ := request(AuthNoPriv|Reportable, NoPriv)
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel,
			SecurityParameters: signedTestUSM(t, SHA, NoPriv, usmCharEngineID, ""),
			MsgID:              7, PDUType: GetResponse, RequestID: 1, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		reply, _, err := e.decode(data)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(7), reply.MsgID)
		require.ErrorIs(t, err, ErrUnknownSecurityLevel)
	})

	t.Run("authPriv reply, another engine time", func(t *testing.T) {
		e, sp := request(AuthPriv|Reportable, AES)
		agent := sp.Copy().(*UsmSecurityParameters)
		agent.AuthoritativeEngineBoots, agent.AuthoritativeEngineTime = 9, 5000
		data, err := (&SnmpPacket{
			Version: Version3, MsgFlags: AuthPriv, SecurityModel: UserSecurityModel, SecurityParameters: agent,
			MsgID: 7, PDUType: GetResponse, RequestID: 1, Variables: usmPlainVars,
		}).MarshalMsg()
		require.NoError(t, err)
		reply, verified, err := e.decode(data)
		require.NoError(t, err)
		assert.True(t, verified)
		usp := reply.SecurityParameters.usm()
		assert.Equal(t, []any{uint32(9), uint32(5000), usmPlainVars},
			[]any{usp.AuthoritativeEngineBoots, usp.AuthoritativeEngineTime, reply.Variables})
	})
}

// TestV3InformResponse pins the round trip Netdata's trap receiver makes for
// an inform: it decodes the InformRequest through its table, copies the
// decoded security parameters into the response and marshals it; the sender
// must decode the response as authentic. The table's set has passphrases, or
// keys already localized to the sender's engine ID.
func TestV3InformResponse(t *testing.T) {
	useEngineTimes(t)
	tests := map[string]struct {
		priv       SnmpV3PrivProtocol
		configured bool // the set is localized to the sender's engine ID
	}{
		"authNoPriv":                     {priv: NoPriv},
		"authPriv":                       {priv: AES},
		"authPriv, configured engine ID": {priv: AES, configured: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sender := signedTestUSM(t, SHA, tc.priv, usmOtherEngineID, "codec-user")
			inform, err := (&SnmpPacket{
				Version: Version3, MsgFlags: signedTestFlags(tc.priv) | Reportable, SecurityModel: UserSecurityModel,
				SecurityParameters: sender.Copy(), MsgID: 11, PDUType: InformRequest, RequestID: 12, Variables: usmPlainVars,
			}).MarshalMsg()
			require.NoError(t, err)

			set := usmDecoder(SHA, "codec-auth-pass", tc.priv, "codec-priv-pass")().SecurityParameters.usm()
			if tc.configured {
				set = signedTestUSM(t, SHA, tc.priv, usmOtherEngineID, "codec-user")
			}
			tb := NewSnmpV3SecurityParametersTable(Logger{})
			require.NoError(t, tb.Add("codec-user", set))
			got, err := (&GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(bytes.Clone(inform), false)
			require.NoError(t, err)

			resp, err := (&SnmpPacket{
				Version: Version3, MsgFlags: got.MsgFlags &^ Reportable, SecurityModel: UserSecurityModel,
				SecurityParameters: got.SecurityParameters.Copy(), MsgID: got.MsgID, PDUType: GetResponse,
				RequestID: got.RequestID, Variables: got.Variables,
			}).MarshalMsg()
			require.NoError(t, err)

			x := &GoSNMP{Version: Version3, MsgFlags: signedTestFlags(tc.priv), SecurityModel: UserSecurityModel, SecurityParameters: sender}
			back, err := x.UnmarshalTrap(resp, false)
			require.NoError(t, err)
			assert.Equal(t, usmPlainVars, back.Variables)
		})
	}
}

// TestV3ParseErrorTexts pins the words of the header parse's new errors that
// Netdata's trap receiver maps to labels: a message of another security model
// is a USM failure, a malformed msgFlags a decode failure.
func TestV3ParseErrorTexts(t *testing.T) {
	labelWords := []string{"BER:", "authentication", "decrypt", "USM", "no credentials", "engine ID"}
	words := func(err error) []string {
		var found []string
		for _, w := range labelWords {
			if strings.Contains(err.Error(), w) {
				found = append(found, w)
			}
		}
		return found
	}
	assert.Equal(t, []string{"USM"}, words(errNotUSM))
	assert.Empty(t, words(errMsgFlags))
}

// TestV3DigestField pins that the digest is read only from an OCTET STRING
// msgAuthenticationParameters of the MAC's length: the right digest in a field
// of another type (an OBJECT IDENTIFIER) fails the header parse, and a field
// longer than any MAC is not authentic.
func TestV3DigestField(t *testing.T) {
	useEngineTimes(t)
	localized := usmDecoderLocalized(SHA, NoPriv)
	trapDecoder := func() *GoSNMP {
		x := localized()
		x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, AuthNoPriv
		return x
	}
	// signedWith returns an authNoPriv message whose authentication field has
	// the tag and n content octets, signed over them zeroed: for an OCTET
	// STRING, with the first message ID that makes it decode.
	signedWith := func(tag byte, n int) []byte {
		for id := int64(1); id < 64; id++ {
			marker := bytes.Repeat([]byte{0xa5}, n)
			usmParams := craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), tlv(tag, marker), octets(""))
			data := craftedV3(intTLV(id), intTLV(65507), octets("\x01"), intTLV(3), usmParams, craftedScopedResp)
			off := bytes.Index(data, marker)
			clear(data[off : off+n])
			key, err := passwordCache.LocalizedKey(crypto.SHA1, "codec-auth-pass", string(craftedEngineID[2:]))
			require.NoError(t, err)
			mac := hmac.New(sha1.New, key)
			mac.Write(data)
			copy(data[off:off+n], mac.Sum(nil))
			if _, err := localized().SnmpDecodePacket(bytes.Clone(data)); err == nil || tag != byte(OctetString) {
				return data
			}
		}
		t.Fatalf("no message ID gives a field of tag %#x that decodes", tag)
		return nil
	}

	tests := map[string]struct {
		in   []byte
		want error
	}{
		"the digest in an OBJECT IDENTIFIER": {signedWith(byte(ObjectIdentifier), 12), ErrInvalidMsgs},
		"a field of 64 octets":               {signedWith(byte(OctetString), 64), errNotAuthentic},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := trapDecoder().UnmarshalTrap(tc.in, false)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// TestV3SingleUserWithoutParameters pins a single-user receiver whose flags ask
// for authentication but which has no security parameters: its user is the
// empty one, without protocols, so it takes no message of another user and
// none of its own, which cannot have the level its flags require; decoding
// does not panic.
func TestV3SingleUserWithoutParameters(t *testing.T) {
	useEngineTimes(t)
	for name, tc := range map[string]struct {
		in []byte
		is error
	}{
		"noAuthNoPriv":          {usmPlainTrap(3, usmCharEngineID, "codec-user"), ErrUnknownUsername},
		"noAuthNoPriv, no user": {usmPlainTrap(3, usmCharEngineID, ""), ErrUnknownSecurityLevel},
	} {
		t.Run(name, func(t *testing.T) {
			x := &GoSNMP{Version: Version3, MsgFlags: AuthNoPriv, SecurityModel: UserSecurityModel}
			var err error
			v, _ := recoverPanic(func() { _, err = x.UnmarshalTrap(bytes.Clone(tc.in), false) })
			require.Nil(t, v, "UnmarshalTrap panicked")
			require.ErrorIs(t, err, tc.is)
		})
	}
}
