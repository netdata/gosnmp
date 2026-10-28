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

	return []decodeCase{
		// The security model as the wire sends it: an INTEGER that the
		// header's one-octet field cuts, another field type, none.
		{name: "crafted/v3/parse/security-model-259", in: withModel(intTLV(259))},
		{name: "crafted/v3/parse/security-model-minus-253", in: withModel(intTLV(-253))},
		{name: "crafted/v3/parse/security-model-0", in: withModel(intTLV(0))},
		{name: "crafted/v3/parse/security-model-octet-string", in: withModel(octets("\x03"))},
		{name: "crafted/v3/parse/security-model-absent", in: msg(tlv(0x30, intTLV(42), intTLV(65507), octets("\x00")), tlv(byte(OctetString), usm), scoped)},
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
	off := bytes.Index(data, marker)
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

// TestV3ReceiverRules pins, for each SNMPv3 decode path, which message a
// receiver's parameters refuse before the digest is checked and with which
// text (Netdata's trap receiver maps the texts to labels), whether the
// discovery exception (an empty user name and engine ID) comes first, and
// whether the decoder writes into its input. Results are in
// testdata/usm/receiver-rules.golden.
func TestV3ReceiverRules(t *testing.T) {
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
		buf := bytes.Clone(in)
		var d dumpWriter
		if err := decode(buf); err != nil {
			d.line("error: " + err.Error())
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
	// another engine ID, and passphrases; messages from either engine.
	keysOnly := func() *UsmSecurityParameters {
		return usmKeysOnly(usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")().SecurityParameters.usm(), usmOtherEngineID)
	}
	passphrases := sets[2].sp
	for _, order := range []struct {
		name string
		sets []func() *UsmSecurityParameters
	}{
		{"keys only, then passphrases", []func() *UsmSecurityParameters{keysOnly, passphrases}},
		{"passphrases, then keys only", []func() *UsmSecurityParameters{passphrases, keysOnly}},
	} {
		for _, engineID := range []string{usmCharEngineID, usmOtherEngineID} {
			name := "mixed sets/" + order.name + "/from " + engineID[5:]
			record(name, signedTestTrap(t, SHA, AES, engineID, "codec-user", nil), func(in []byte) error {
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
// password-to-key result per engine ID it localizes a privacy key to. The
// receiver's privacy passphrase differs from the sender's, whose own keys are
// cached when its messages are made.
func TestV3DecodeKeyDerivation(t *testing.T) {
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
	wrongDigest := func(data []byte) []byte {
		m := splitV3Message(t, data)
		m.usm[4] = bytes.Clone(m.usm[4])
		m.usm[4][0] ^= 0xff
		return m.bytes()
	}
	signed := func(engineID string) []byte { return signedTestTrap(t, SHA, AES256C, engineID, "codec-user", nil) }

	tests := map[string]struct {
		in   func(engineID string) []byte
		want int // cache entries added
	}{
		"authPriv, signed":       {in: signed, want: 1},
		"authPriv, wrong digest": {in: func(e string) []byte { return wrongDigest(signed(e)) }},
		"noAuthNoPriv plaintext": {in: func(e string) []byte { return usmPlainTrap(3, e, "codec-user") }},
		// Known bug: the table path decrypts these without a digest check, so
		// they derive the privacy key.
		"privacy only":                  {in: func(e string) []byte { return splitV3Message(t, signed(e)).withFlags(t, usmPrivacyFlag).bytes() }, want: 1},
		"noAuthNoPriv flags, encrypted": {in: func(e string) []byte { return splitV3Message(t, signed(e)).withFlags(t, NoAuthNoPriv).bytes() }, want: 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tb := NewSnmpV3SecurityParametersTable(Logger{})
			require.NoError(t, tb.Add("codec-user", reeder()))
			in := tc.in(newEngine())
			before := passwordCache.Len()
			_, _ = (&GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(in, false)
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
		assert.Nil(t, reply)
		assert.False(t, verified)
		require.ErrorIs(t, err, errMsgFlags)
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
// of another type (an OBJECT IDENTIFIER, which decodes as text) is not
// authentic, nor is a field longer than any MAC.
func TestV3DigestField(t *testing.T) {
	localized := usmDecoderLocalized(SHA, NoPriv)
	trapDecoder := func() *GoSNMP {
		x := localized()
		x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, AuthNoPriv
		return x
	}
	// signedWith returns an authNoPriv message whose authentication field has
	// the tag and n content octets, signed over them zeroed, for the first
	// message ID that makes it decode.
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
			if _, err := localized().SnmpDecodePacket(bytes.Clone(data)); err == nil {
				return data
			}
		}
		t.Fatalf("no message ID gives a field of tag %#x that decodes", tag)
		return nil
	}

	tests := map[string][]byte{
		"the digest in an OBJECT IDENTIFIER": signedWith(byte(ObjectIdentifier), 12),
		"a field of 64 octets":               signedWith(byte(OctetString), 64),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := trapDecoder().UnmarshalTrap(in, false)
			require.ErrorIs(t, err, errNotAuthentic)
		})
	}
}
