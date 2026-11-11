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
// codec-user with the key of usmDecoder(SHA, NoPriv) for the codec engine ID.
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
	authDecoder := usmDecoder(SHA, "codec-auth-pass", NoPriv, "")
	privDecoder := usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")
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
			decoder: authDecoder,
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
		{name: "crafted/v3/parse/auth-params-long-form-length", in: signedAuthField([]byte{0x04, 0x81, 0x0c}, 12), decoder: authDecoder},
		{name: "crafted/v3/parse/auth-params-11-octets", in: signedAuthField([]byte{0x04, 0x0b}, 11), decoder: authDecoder},
		{name: "crafted/v3/parse/auth-params-13-octets", in: signedAuthField([]byte{0x04, 0x0d}, 13), decoder: authDecoder},
		{name: "crafted/v3/parse/auth-params-empty", in: signedAuthField([]byte{0x04, 0x00}, 0), decoder: authDecoder},
		{name: "crafted/v3/parse/auth-params-short-form", in: signedAuthField([]byte{0x04, 0x0c}, 12), decoder: authDecoder},

		// The encrypted scoped PDU: as sent, its OCTET STRING declared past the
		// message or short of the ciphertext, and a context field of another
		// type once decrypted.
		{name: "crafted/v3/parse/encrypted-scoped-pdu", in: encryptedV3(scoped, encryptedData(0)), decoder: privDecoder},
		{name: "crafted/v3/parse/encrypted-scoped-pdu-over-declared", in: encryptedV3(scoped, encryptedData(5)), decoder: privDecoder},
		{name: "crafted/v3/parse/encrypted-scoped-pdu-under-declared", in: encryptedV3(scoped, encryptedData(-5)), decoder: privDecoder},
		{
			name: "crafted/v3/parse/encrypted-scoped-pdu-trailing-octets",
			in: encryptedV3(scoped, func(ciphertext []byte) []byte {
				return cat(header(byte(OctetString), len(ciphertext)), ciphertext, bytes.Repeat([]byte{0x5a}, 16))
			}),
			decoder: privDecoder,
		},
		{
			name:    "crafted/v3/parse/encrypted-scoped-pdu-not-sequence",
			in:      encryptedV3(tlv(byte(OctetString), craftedEngineID, octets("ctx"), craftedPDU(Response, craftedVBL(craftedVB(intTLV(5))))), encryptedData(0)),
			decoder: privDecoder,
		},
		{
			name:    "crafted/v3/parse/encrypted-context-engine-id-integer",
			in:      encryptedV3(tlv(0x30, intTLV(1), octets("ctx"), craftedPDU(Response, craftedVBL(craftedVB(intTLV(5))))), encryptedData(0)),
			decoder: privDecoder,
		},
	}
}

// signedAuthField returns an authNoPriv Response from codec-user whose
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
	key, err := passwordCache.LocalizedKey(crypto.SHA1, "codec-auth-pass", craftedEngineID[2:])
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
// keys of usmDecoder(SHA, AES) for the codec engine ID.
func encryptedV3(scoped []byte, msgData func(ciphertext []byte) []byte) []byte {
	user := usmUser(SHA, "codec-auth-pass", AES, "codec-priv-pass")
	keys, err := user.localize(craftedEngineID[2:])
	if err != nil {
		panic(err)
	}
	salt := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	ciphertext, err := keys.encrypt(&SecurityParameters{AuthoritativeEngineBoots: 7, AuthoritativeEngineTime: 1234}, scoped, salt)
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
// unwraps to, and whether the decoder writes into its input: a receiver with
// the user registered for the engine ID the message names (receiverFor), and
// DecodeMessage. Results are in testdata/usm/receiver-rules.golden.
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
		{"SNMPv2c", func() []byte {
			return mustMarshal(&Message{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 1})
		}},
	}
	sets := []struct {
		name string
		user User
	}{
		{"no protocols", User{Name: "codec-user"}},
		{"SHA", usmUser(SHA, "codec-auth-pass", NoPriv, "")},
		{"SHA-AES", usmUser(SHA, "codec-auth-pass", AES, "codec-priv-pass")},
		{"unknown authentication protocol", User{Name: "codec-user", AuthProtocol: 99, AuthPassphrase: "codec-auth-pass"}},
		{"SHA without a passphrase", User{Name: "codec-user", AuthProtocol: SHA}},
	}
	type path struct {
		name   string
		decode func(u User, in []byte) error
	}
	paths := []path{
		{"receiver", func(u User, in []byte) error {
			// A user NewReceiver refuses is refused for every engine ID.
			if _, err := NewReceiver(ReceiverConfig{Users: []EngineUser{{EngineID: []byte(codecEngineID), User: u}}}); err != nil {
				return err
			}
			_, _, err := receiverFor(t, in, u).Receive(in)
			return err
		}},
		{"DecodeMessage", func(u User, in []byte) error {
			_, err := mustClient(Config{User: u}).DecodeMessage(in)
			return err
		}},
	}

	var results []goldenCase
	record := func(name string, in []byte, decode func(in []byte) error) {
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
				record(m.name+"/"+s.name+"/"+p.name, m.in(), func(in []byte) error { return p.decode(s.user, in) })
			}
		}
	}
	usmGolden.check(t, "receiver-rules", results)
}

// TestV3DecodeKeyDerivation pins, with the size of the package's key cache,
// which messages from new engine IDs make a receiver derive a privacy key: a
// receiver that may learn its user (ReceiverConfig.LearnUsers) derives the
// user's keys for the message's engine ID, and a user of a Reeder-extended
// protocol (AES-256 Cisco) caches one password-to-key result per engine ID it
// localizes a privacy key to. Only a message whose digest checked is
// decrypted. The receiver's privacy passphrase differs from the sender's,
// whose own keys are cached when its messages are made, so no message is
// learned.
func TestV3DecodeKeyDerivation(t *testing.T) {
	var seq int
	newEngine := func() string {
		seq++
		return fmt.Sprintf("\x80\x00\x1f\x88\x04kd-%d-%d", time.Now().UnixNano(), seq)
	}
	reeder := usmUser(SHA, "codec-auth-pass", AES256C, "receiver-priv-pass")
	// The passphrases' own cache entries, and the keys for the empty engine
	// ID, are made once, before any count.
	_, err := reeder.localize(nil)
	require.NoError(t, err)
	wrongDigest := func(data []byte) []byte { return withWrongDigest(t, data) }
	signed := func(engineID string) []byte { return signedTestTrap(t, SHA, AES256C, engineID, "codec-user", nil) }
	privacyOnly := func(e string) []byte { return splitV3Message(t, signed(e)).withFlags(t, usmPrivacyFlag).bytes() }
	noAuthEncrypted := func(e string) []byte { return splitV3Message(t, signed(e)).withFlags(t, NoAuthNoPriv).bytes() }

	tests := map[string]struct {
		in   func(engineID string) []byte
		want int // cache entries added
	}{
		"authPriv, signed":              {in: signed, want: 1},
		"authPriv, wrong digest":        {in: func(e string) []byte { return wrongDigest(signed(e)) }},
		"noAuthNoPriv plaintext":        {in: func(e string) []byte { return usmPlainTrap(3, e, "codec-user") }},
		"privacy only":                  {in: privacyOnly},
		"noAuthNoPriv flags, encrypted": {in: noAuthEncrypted},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := newTestReceiver(t, ReceiverConfig{LearnUsers: []User{reeder}, MaxLearned: 1})
			in := tc.in(newEngine())
			before := passwordCache.Len()
			_, _, _ = r.Receive(in)
			assert.Equal(t, tc.want, passwordCache.Len()-before)
		})
	}

	// A client's request, answered by an unauthenticated Report naming a new
	// engine ID.
	t.Run("reply/unauthenticated Report from a new engine", func(t *testing.T) {
		user := signedTestUser(SHA, AES256C, "codec-user")
		user.PrivPassphrase = "receiver-priv-pass"
		keys, err := user.localize([]byte(usmCharEngineID))
		require.NoError(t, err)
		x := mustClient(Config{Version: Version3, SecurityLevel: AuthPriv, User: user})
		req := &Message{
			Version: Version3, SecurityLevel: AuthPriv, SecurityParameters: signedTestHeader(usmCharEngineID, "codec-user"),
			MsgID: 7, PDUType: GetRequest,
		}
		engineID := newEngine()
		report := craftedV3(intTLV(7), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(octets(engineID), intTLV(1), intTLV(2), octets("codec-user"), octets(""), octets("")),
			tlv(0x30, octets(engineID), octets(""), craftedPDU(Report, craftedVBL(craftedVB(intTLV(5))))))
		before := passwordCache.Len()
		_, _, _ = (&exchange{x: x, packet: req, sec: attemptSecurity{keys: keys}}).decode(report, nil)
		assert.Zero(t, passwordCache.Len()-before)
	})
}

// TestV3ReplyDecode pins how a client decodes replies to an SNMPv3 request:
// the reply's own msgFlags and the engine boots and time it carries. The
// request's msgID is 7; signedAuthField and signedReply carry 42, the msgID of
// an earlier attempt.
func TestV3ReplyDecode(t *testing.T) {
	// request returns the exchange of a request of codec-user at flags, with
	// the user's keys for usmCharEngineID, and the user.
	request := func(flags SecurityLevel, priv PrivProtocol) (*exchange, User) {
		user := signedTestUser(SHA, priv, "codec-user")
		keys, err := user.localize([]byte(usmCharEngineID))
		require.NoError(t, err)
		x := mustClient(Config{Version: Version3, SecurityLevel: flags, User: user})
		req := &Message{
			Version: Version3, SecurityLevel: flags, SecurityParameters: signedTestHeader(usmCharEngineID, "codec-user"),
			MsgID: 7, PDUType: GetRequest,
		}
		return &exchange{x: x, packet: req, sec: attemptSecurity{keys: keys}}, user
	}
	// reply encodes a message from codec-user at usmCharEngineID, for user's
	// keys unless user is nil.
	reply := func(p *Message, user *User) []byte {
		p.Version, p.MsgID = Version3, 7
		data, err := p.Encode(user)
		require.NoError(t, err)
		return data
	}
	earlier := []sentIDs{{msgID: 42}}

	t.Run("empty msgFlags, Report to an authNoPriv request", func(t *testing.T) {
		e, _ := request(AuthNoPriv, NoPriv)
		report := craftedV3(intTLV(7), intTLV(65507), octets(""), intTLV(3),
			craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(string(make([]byte, 12))), octets("")),
			tlv(0x30, octets(usmCharEngineID), octets(""), craftedPDU(Report, craftedVBL(craftedVB(intTLV(5))))))
		reply, verified, err := e.decode(report, nil)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(7), reply.MsgID)
		assert.False(t, verified)
		require.ErrorIs(t, err, errMsgFlags)
	})

	t.Run("header that fails before its msgID", func(t *testing.T) {
		e, _ := request(AuthNoPriv, NoPriv)
		report := craftedV3(intTLV(-1), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(""), octets("")),
			tlv(0x30, octets(usmCharEngineID), octets(""), craftedPDU(Report, craftedVBL(craftedVB(intTLV(5))))))
		reply, verified, err := e.decode(report, nil)
		assert.Nil(t, reply, "no msgID was read")
		assert.False(t, verified)
		require.ErrorIs(t, err, ErrASNParse)
	})

	// A message naming no attempt, or of another version, is discarded before
	// security processing: no digest is checked.
	t.Run("authentic reply naming no attempt", func(t *testing.T) {
		e, _ := request(AuthNoPriv, NoPriv)
		reply, verified, err := e.decode(signedAuthField([]byte{0x04, 0x0c}, 12), nil)
		require.ErrorIs(t, err, errOtherMessage)
		assert.False(t, verified)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(42), reply.MsgID)
	})
	t.Run("SNMPv2c message to an SNMPv3 request", func(t *testing.T) {
		e, _ := request(NoAuthNoPriv, NoPriv)
		reply, verified, err := e.decode(craftedMsg(1, craftedPDU(Response, craftedVBL(craftedVB(intTLV(5))))), earlier)
		require.ErrorIs(t, err, errOtherVersion)
		assert.False(t, verified)
		assert.Nil(t, reply, "no msgID was read")
	})

	t.Run("authNoPriv reply, long-form digest field length", func(t *testing.T) {
		e, _ := request(AuthNoPriv, NoPriv)
		reply, verified, err := e.decode(signedAuthField([]byte{0x04, 0x81, 0x0c}, 12), earlier)
		require.NoError(t, err)
		assert.True(t, verified)
		assert.NotNil(t, reply)
	})

	// An authentic reply that does not decode further reports its digest
	// checked: the discard ranks it above an unauthenticated one.
	t.Run("authentic reply whose scoped PDU does not decode", func(t *testing.T) {
		e, _ := request(AuthNoPriv, NoPriv)
		reply, verified, err := e.decode(signedReply(tlv(0x30, craftedEngineID)), earlier)
		require.ErrorIs(t, err, ErrASNParse)
		assert.True(t, verified)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(42), reply.MsgID)
	})
	t.Run("authentic reply whose PDU does not decode", func(t *testing.T) {
		e, _ := request(AuthNoPriv, NoPriv)
		reply, verified, err := e.decode(signedReply(tlv(0x30, craftedEngineID, octets("ctx"), tlv(0xaf, intTLV(1)))), earlier)
		require.Error(t, err)
		assert.True(t, verified)
		require.NotNil(t, reply, "the message as far as decode read it")
		assert.Equal(t, uint32(42), reply.MsgID)
	})

	// A msgID means nothing to an SNMPv2c request.
	t.Run("SNMPv3 message to an SNMPv2c request", func(t *testing.T) {
		e := &exchange{x: mustClient(Config{Version: Version2c}), packet: &Message{Version: Version2c, PDUType: GetRequest}}
		msg := craftedV3(intTLV(7), intTLV(65507), octets("\x00"), intTLV(3),
			craftedUSM(octets(usmCharEngineID), intTLV(3), intTLV(77), octets("codec-user"), octets(""), octets("")),
			tlv(0x30, octets(usmCharEngineID), octets(""), craftedPDU(Response, craftedVBL(craftedVB(intTLV(5))))))
		reply, _, err := e.decode(msg, nil)
		require.Error(t, err)
		assert.Nil(t, reply)
	})

	// A reply naming another engine ID derives no keys for that engine.
	t.Run("unauthenticated Report from another engine", func(t *testing.T) {
		e, _ := request(AuthPriv, AES)
		data := reply(&Message{
			SecurityLevel: NoAuthNoPriv, SecurityParameters: signedTestHeader(usmOtherEngineID, "codec-user"),
			PDUType: Report, VarBinds: []VarBind{{Name: ".1.3.6.1.6.3.15.1.1.4.0", Value: Counter32Value(1)}},
		}, nil)
		before := passwordCache.Len()
		got, verified, err := e.decode(data, nil)
		require.NoError(t, err)
		assert.False(t, verified)
		assert.Equal(t, []byte(usmOtherEngineID), got.SecurityParameters.AuthoritativeEngineID)
		assert.Zero(t, passwordCache.Len()-before, "keys derived")
	})

	// A reply that asks for authentication is checked whatever the request's
	// level: one from another engine has none of the request's keys.
	t.Run("encrypted reply from another engine to a noAuthNoPriv request", func(t *testing.T) {
		e, user := request(NoAuthNoPriv, AES)
		data := reply(&Message{
			SecurityLevel: AuthPriv, SecurityParameters: signedTestHeader(usmOtherEngineID, "codec-user"),
			PDUType: Response, RequestID: 1, VarBinds: usmPlainVars,
		}, &user)
		got, _, err := e.decode(data, nil)
		require.NotNil(t, got, "the message as far as decode read it")
		assert.Equal(t, uint32(7), got.MsgID)
		require.ErrorIs(t, err, ErrUnknownUsername)
	})

	// A request without authentication checks the digest of a reply that
	// asks for authentication, with its user's key; a user without an
	// authentication protocol takes no such reply.
	t.Run("authNoPriv reply with a wrong digest to a noAuthNoPriv request", func(t *testing.T) {
		e, user := request(NoAuthNoPriv, NoPriv)
		data := reply(&Message{
			SecurityLevel: AuthNoPriv, SecurityParameters: signedTestHeader(usmCharEngineID, "codec-user"),
			PDUType: Response, RequestID: 1, VarBinds: usmPlainVars,
		}, &user)
		got, verified, err := e.decode(withWrongDigest(t, data), nil)
		require.NotNil(t, got, "the message as far as decode read it")
		assert.Equal(t, uint32(7), got.MsgID)
		assert.False(t, verified)
		require.ErrorIs(t, err, ErrWrongDigest)

		got, verified, err = e.decode(data, nil)
		require.NoError(t, err)
		assert.True(t, verified)
		assert.Equal(t, usmPlainVars, got.VarBinds)
	})

	t.Run("authNoPriv reply to a noAuthNoPriv request of a user without protocols", func(t *testing.T) {
		x := mustClient(Config{Version: Version3, SecurityLevel: NoAuthNoPriv, User: User{Name: "codec-user"}})
		req := &Message{
			Version: Version3, SecurityLevel: NoAuthNoPriv, SecurityParameters: signedTestHeader(usmCharEngineID, "codec-user"),
			MsgID: 7, PDUType: GetRequest,
		}
		sender := signedTestUser(SHA, NoPriv, "codec-user")
		data := reply(&Message{
			SecurityLevel: AuthNoPriv, SecurityParameters: signedTestHeader(usmCharEngineID, "codec-user"),
			PDUType: Response, RequestID: 1, VarBinds: usmPlainVars,
		}, &sender)
		got, _, err := (&exchange{x: x, packet: req}).decode(data, nil)
		require.NotNil(t, got, "the message as far as decode read it")
		assert.Equal(t, uint32(7), got.MsgID)
		require.ErrorIs(t, err, ErrUnknownSecurityLevel)
	})

	// The empty user of discovery has no protocols: a reply naming it takes
	// no authentication, even signed with the request's key.
	t.Run("authNoPriv reply naming the empty user", func(t *testing.T) {
		e, user := request(AuthNoPriv, NoPriv)
		data := reply(&Message{
			SecurityLevel: AuthNoPriv, SecurityParameters: signedTestHeader(usmCharEngineID, ""),
			PDUType: Response, RequestID: 1, VarBinds: usmPlainVars,
		}, &user)
		got, _, err := e.decode(data, nil)
		require.NotNil(t, got, "the message as far as decode read it")
		assert.Equal(t, uint32(7), got.MsgID)
		require.ErrorIs(t, err, ErrUnknownSecurityLevel)
	})

	t.Run("authPriv reply, another engine time", func(t *testing.T) {
		e, user := request(AuthPriv, AES)
		agent := signedTestHeader(usmCharEngineID, "codec-user")
		agent.AuthoritativeEngineBoots, agent.AuthoritativeEngineTime = 9, 5000
		data := reply(&Message{
			SecurityLevel: AuthPriv, SecurityParameters: agent,
			PDUType: Response, RequestID: 1, VarBinds: usmPlainVars,
		}, &user)
		got, verified, err := e.decode(data, nil)
		require.NoError(t, err)
		assert.True(t, verified)
		h := &got.SecurityParameters
		assert.Equal(t, []any{uint32(9), uint32(5000), usmPlainVars},
			[]any{h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime, got.VarBinds})
	})
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
	decoder := usmDecoder(SHA, "codec-auth-pass", NoPriv, "")
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
			key, err := passwordCache.LocalizedKey(crypto.SHA1, "codec-auth-pass", craftedEngineID[2:])
			require.NoError(t, err)
			mac := hmac.New(sha1.New, key)
			mac.Write(data)
			copy(data[off:off+n], mac.Sum(nil))
			if _, err := decoder().DecodeMessage(bytes.Clone(data)); err == nil || tag != byte(OctetString) {
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
		"the digest in an OBJECT IDENTIFIER": {signedWith(byte(ObjectIdentifier), 12), ErrASNParse},
		"a field of 64 octets":               {signedWith(byte(OctetString), 64), errNotAuthentic},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := receiverFor(t, tc.in, decoder().config.User).Receive(tc.in)
			require.ErrorIs(t, err, tc.want)
		})
	}
}
