// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA-96, the protocol under test
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
