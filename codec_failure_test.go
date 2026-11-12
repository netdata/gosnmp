// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDecodeFailureNoMessage pins, for a field of each decoder failing in
// turn, the error text, and that DecodeMessage returns no message with it,
// also when the failure comes after the header and the varbinds before it.
func TestDecodeFailureNoMessage(t *testing.T) {
	bad := tlv(0x05) // a NULL where a field goes: a field of another tag
	vbl := craftedVBL(craftedVB(intTLV(5)))
	secondVB := func(vb []byte) []byte {
		return craftedMsg(1, tlv(byte(Response), intTLV(7), intTLV(2), intTLV(3), craftedVBL(craftedVB(intTLV(5)), vb)))
	}
	v3 := func(flags, model, usm []byte) []byte {
		return craftedV3(intTLV(42), intTLV(65507), flags, model, usm, nil)
	}
	usmWith := func(engineID, boots, engineTime, user, authParams, privParams []byte) []byte {
		return v3(octets("\x04"), intTLV(3), craftedUSM(engineID, boots, engineTime, user, authParams, privParams))
	}
	const (
		header = "unable to decode packet header: "
		body   = "unable to decode packet body: error in the PDU: "
		trapV1 = "unable to decode packet body: error in the SNMPv1 trap PDU: error parsing SNMPv1 trap "
		usm    = header + "error parsing SNMPV3 User Security Model "
		notInt = ": not an INTEGER"
		notStr = ": not an OCTET STRING"
	)

	tests := map[string]struct {
		in      []byte
		wantErr string
	}{
		// Message header.
		"empty input":    {in: []byte{}, wantErr: header + "invalid packet length: cannot unmarshal empty packet"},
		"one octet":      {in: []byte{0x30}, wantErr: header + "invalid packet length: cannot unmarshal empty packet"},
		"not a sequence": {in: cat([]byte{0x31}, craftedValue(intTLV(5))[1:]), wantErr: header + "invalid packet header"},
		"version":        {in: tlv(0x30, bad, octets("public"), vbl), wantErr: header + "error parsing SNMP packet version" + notInt},
		"community":      {in: tlv(0x30, intTLV(1), bad, vbl), wantErr: header + "error parsing community string" + notStr},
		"octet after the message": {
			in: cat(craftedMsg(1, craftedPDU(Response, vbl)), []byte{0x00}), wantErr: header + "error verifying packet sanity: 1 bytes after the TLV",
		},

		// PDU header.
		"request ID":      {in: craftedMsg(1, tlv(byte(Response), bad, intTLV(2), intTLV(3), vbl)), wantErr: body + "error parsing SNMP packet request ID" + notInt},
		"error status":    {in: craftedMsg(1, tlv(byte(Response), intTLV(7), bad, intTLV(3), vbl)), wantErr: body + "error parsing SNMP packet error" + notInt},
		"error index":     {in: craftedMsg(1, tlv(byte(Response), intTLV(7), intTLV(2), bad, vbl)), wantErr: body + "error parsing SNMP packet error index" + notInt},
		"non-repeaters":   {in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(7), bad, intTLV(9), vbl)), wantErr: body + "error parsing SNMP packet non repeaters" + notInt},
		"max-repetitions": {in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(7), intTLV(3), bad, vbl)), wantErr: body + "error parsing SNMP packet max repetitions" + notInt},

		// Varbind list.
		"no varbind list":              {in: craftedMsg(1, tlv(byte(Response), intTLV(7), intTLV(2), intTLV(3))), wantErr: body + "truncated packet when unmarshalling a VBL"},
		"varbind list not a sequence":  {in: craftedMsg(1, tlv(byte(Response), intTLV(7), intTLV(2), intTLV(3), intTLV(1))), wantErr: body + "expected a sequence when unmarshalling a VBL, got 2"},
		"varbind not a sequence":       {in: secondVB(intTLV(1)), wantErr: body + "expected a sequence when unmarshalling a VB, got 2"},
		"varbind past the list":        {in: secondVB([]byte{0x30, 0x10, 0x06}), wantErr: body + "error reading varbind: invalid packet length: TLV length exceeds the remaining input"},
		"varbind name":                 {in: secondVB(tlv(0x30, bad, intTLV(6))), wantErr: body + "error parsing OID Value" + ": not an OBJECT IDENTIFIER or text"},
		"varbind name not text":        {in: secondVB(tlv(0x30, intTLV(1), intTLV(6))), wantErr: body + "error parsing OID Value: not an OBJECT IDENTIFIER or text"},
		"varbind without a value":      {in: secondVB(tlv(0x30, craftedOID)), wantErr: body + "error decoding value: zero byte buffer"},
		"varbind value shorter":        {in: secondVB(tlv(0x30, craftedOID, intTLV(6), intTLV(7))), wantErr: body + "value TLV length mismatch in varbind (TLV 3, remaining 6)"},
		"varbind value not decodable":  {in: secondVB(tlv(0x30, craftedOID, tlv(byte(Integer)))), wantErr: body + "error decoding value: invalid Integer: zero length integer"},
		"varbind value unknown length": {in: secondVB(tlv(0x30, craftedOID, []byte{0x02, 0x85})), wantErr: body + "error parsing value TLV in varbind: invalid packet length"},

		// SNMPv1 trap header.
		"v1 trap enterprise":    {in: craftedV1Trap(bad, craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, vbl), wantErr: trapV1 + "enterprise" + ": not an OBJECT IDENTIFIER"},
		"v1 trap agent address": {in: craftedV1Trap(craftedEnterprise, bad, intTLV(6), intTLV(1), craftedTimestamp, vbl), wantErr: trapV1 + "agent address" + ": not an IpAddress or OCTET STRING"},
		"v1 trap generic trap":  {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, bad, intTLV(1), craftedTimestamp, vbl), wantErr: trapV1 + "generic trap" + notInt},
		"v1 trap specific trap": {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), bad, craftedTimestamp, vbl), wantErr: trapV1 + "specific trap" + notInt},
		"v1 trap timestamp":     {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), bad, vbl), wantErr: trapV1 + "timestamp" + ": not TimeTicks or another unsigned type"},

		// SNMPv3 header.
		"v3 message ID":     {in: craftedV3(bad, intTLV(65507), octets("\x04"), intTLV(3), craftedNoAuthUSM, nil), wantErr: header + "error parsing SNMPV3 message ID" + notInt},
		"v3 max size":       {in: craftedV3(intTLV(42), bad, octets("\x04"), intTLV(3), craftedNoAuthUSM, nil), wantErr: header + "error parsing SNMPV3 msgMaxSize" + notInt},
		"v3 flags":          {in: v3(bad, intTLV(3), craftedNoAuthUSM), wantErr: header + "error parsing SNMPV3 msgFlags: not an OCTET STRING of one octet"},
		"v3 security model": {in: v3(octets("\x04"), bad, craftedNoAuthUSM), wantErr: header + "error parsing SNMPV3 msgSecModel" + notInt},
		"v3 nothing after the security model": {
			in:      tlv(0x30, intTLV(3), tlv(0x30, intTLV(42), intTLV(65507), octets("\x04"), intTLV(3))),
			wantErr: header + "error parsing SNMPV3: nothing after the security model",
		},
		"v3 security parameters not an OCTET STRING": {
			in:      tlv(0x30, intTLV(3), tlv(0x30, intTLV(42), intTLV(65507), octets("\x04"), intTLV(3)), intTLV(1)),
			wantErr: header + "invalid SNMPV3 Security Parameters",
		},

		// USM security parameters.
		"usm engine ID":                 {in: usmWith(bad, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets("")), wantErr: usm + "msgAuthoritativeEngineID" + notStr},
		"usm boots":                     {in: usmWith(craftedEngineID, bad, intTLV(1234), octets("codec-user"), octets(""), octets("")), wantErr: usm + "msgAuthoritativeEngineBoots" + notInt},
		"usm engine time":               {in: usmWith(craftedEngineID, intTLV(7), bad, octets("codec-user"), octets(""), octets("")), wantErr: usm + "msgAuthoritativeEngineTime" + notInt},
		"usm user name":                 {in: usmWith(craftedEngineID, intTLV(7), intTLV(1234), bad, octets(""), octets("")), wantErr: usm + "msgUserName" + notStr},
		"usm authentication parameters": {in: usmWith(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), bad, octets("")), wantErr: usm + "msgAuthenticationParameters" + notStr},
		"usm privacy parameters":        {in: usmWith(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), bad), wantErr: usm + "msgPrivacyParameters" + notStr},
		// Flags asking for authentication, which the decoder has no protocol
		// for: after a header error, and as the error (step 5).
		"usm privacy parameters, authenticated": {
			in:      v3(octets("\x05"), intTLV(3), craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), bad)),
			wantErr: usm + "msgPrivacyParameters" + notStr,
		},
		"security level without a protocol": {
			in:      v3(octets("\x05"), intTLV(3), craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets(""))),
			wantErr: header + "error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message",
		},

		// SNMPv3 scoped PDU.
		"context engine ID": {in: craftedV3NoAuth(tlv(0x30, bad, octets("ctx"), craftedPDU(Response, vbl))), wantErr: "error parsing SNMPV3 contextEngineID" + notStr},
		"context name":      {in: craftedV3NoAuth(tlv(0x30, craftedEngineID, bad, craftedPDU(Response, vbl))), wantErr: "error parsing SNMPV3 contextName" + notStr},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := mustClient(Config{}).DecodeMessage(tc.in)
			if assert.Error(t, err) {
				assert.Equal(t, tc.wantErr, err.Error())
			}
			assert.Nil(t, p)
		})
	}
}

// TestDecodeUSMFields pins RFC 3414 section 3.2 step 1: each USM field must
// be of its type, and the engine boots and time within 0..2147483647, never
// cut to 32 bits (TestHeaderIntegers); anything else fails the header parse
// with ErrASNParse, on the raw path too.
func TestDecodeUSMFields(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x04codec-engine"
	// usm builds a message whose USM parameters are the fields, edited, in a
	// container of tag, a SEQUENCE as sent.
	usm := func(tag byte, edit func(f [][]byte)) []byte {
		f := [][]byte{octets(engineID), intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets("")}
		edit(f)
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), tlv(tag, f...), craftedScopedResp)
	}
	fields := func(edit func(f [][]byte)) []byte { return usm(0x30, edit) }
	in := func(tag byte) []byte { return usm(tag, func([][]byte) {}) }
	tests := map[string]struct {
		in      []byte
		invalid bool
	}{
		"as sent":                       {in: fields(func([][]byte) {})},
		"engine ID as an INTEGER":       {in: fields(func(f [][]byte) { f[0] = intTLV(1) }), invalid: true},
		"engine ID as an OID":           {in: fields(func(f [][]byte) { f[0] = tlv(byte(ObjectIdentifier), []byte{0x2b, 6}) }), invalid: true},
		"boots as an OCTET STRING":      {in: fields(func(f [][]byte) { f[1] = octets("boots") }), invalid: true},
		"time as TimeTicks":             {in: fields(func(f [][]byte) { f[2] = tlv(byte(TimeTicks), []byte{1}) }), invalid: true},
		"user name as an INTEGER":       {in: fields(func(f [][]byte) { f[3] = intTLV(2) }), invalid: true},
		"auth parameters as an INTEGER": {in: fields(func(f [][]byte) { f[4] = intTLV(3) }), invalid: true},
		"priv parameters as an INTEGER": {in: fields(func(f [][]byte) { f[5] = intTLV(4) }), invalid: true},
		"boots 2147483647":              {in: fields(func(f [][]byte) { f[1] = intTLV(2147483647) })},
		// 2^32+5, whose low 32 bits are 5.
		"boots 4294967301": {in: fields(func(f [][]byte) { f[1] = intTLV(4294967301) }), invalid: true},
		"boots -1":         {in: fields(func(f [][]byte) { f[1] = intTLV(-1) }), invalid: true},
		"time -2147483648": {in: fields(func(f [][]byte) { f[2] = intTLV(-2147483648) }), invalid: true},
		// The fields in another container than a SEQUENCE (RFC 3414 section 2.4).
		"fields in an OCTET STRING": {in: in(byte(OctetString)), invalid: true},
		"fields in a SET":           {in: in(0x31), invalid: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := mustClient(Config{}).DecodeMessage(tc.in)
			if tc.invalid {
				assert.ErrorIs(t, err, ErrASNParse)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestUnknownPDUTypeError checks the error for a PDU type the package does not
// know, from DecodeMessage (SNMPv2c and SNMPv3) and Receiver.Receive.
func TestUnknownPDUTypeError(t *testing.T) {
	nullVB := craftedVB(tlv(byte(Null)))
	pdu := func(tag byte) []byte { return tlv(tag, intTLV(1), intTLV(0), intTLV(0), craftedVBL(nullVB)) }
	tests := map[string]struct {
		tag  byte
		want string
	}{
		"undefined context tag": {tag: 0xaf, want: "unknown PDUType 0xaf"},
		"Sequence":              {tag: 0x30, want: "unknown PDUType 0x30"},
		"universal tag":         {tag: 0x04, want: "unknown PDUType 0x4"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := mustClient(Config{Version: Version2c}).DecodeMessage(craftedMsg(1, pdu(tc.tag)))
			assert.EqualError(t, err, "unable to decode packet body: "+tc.want, "SNMPv2c")

			v3 := mustClient(Config{Version: Version3, User: User{Name: "codec-user"}})
			_, err = v3.DecodeMessage(craftedV3NoAuth(tlv(0x30, craftedEngineID, octets("ctx"), pdu(tc.tag))))
			assert.EqualError(t, err, "unable to decode packet body: "+tc.want, "SNMPv3")

			r, _ := newTestReceiver(t, ReceiverConfig{})
			_, _, err = r.Receive(craftedMsg(1, pdu(tc.tag)))
			assert.EqualError(t, err, tc.want, "Receive")
		})
	}
}

// TestHeaderIntegers pins the one rule of the INTEGER header fields of every
// message, PDU and SNMPv1 trap: the field is read whole, up to 64 bits, and
// must lie in its range, which the decoded field holds without a cut; a value
// outside it fails the message (ErrASNParse), also one whose low 32 bits lie
// in the range. The probes are each field's bounds, the values next to them,
// and the bounds moved by 2^32.
func TestHeaderIntegers(t *testing.T) {
	nullVBL := craftedVBL(craftedVB(tlv(byte(Null))))
	pdu := func(tag PDUType, a, b, c int64) []byte {
		return craftedMsg(1, tlv(byte(tag), intTLV(a), intTLV(b), intTLV(c), nullVBL))
	}
	trap := func(generic, specific int64) []byte {
		return craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(generic), intTLV(specific), craftedTimestamp, nullVBL)
	}
	v3 := func(msgID, maxSize, boots, engineTime int64) []byte {
		usm := craftedUSM(craftedEngineID, intTLV(boots), intTLV(engineTime), octets("codec-user"), octets(""), octets(""))
		return craftedV3(intTLV(msgID), intTLV(maxSize), octets("\x00"), intTLV(3), usm, craftedScopedResp)
	}
	sat := func(v int64) int64 { return min(v, 255) } // the counts read above 255 as 255
	fields := map[string]struct {
		msg    func(v int64) []byte
		get    func(m *Message) int64
		lo, hi int64
		// held is the value the field holds for v in the range; nil: v.
		held func(v int64) int64
	}{
		// The request ID keeps its 32 bits, sent as an Integer32 or unsigned.
		"request ID": {
			msg: func(v int64) []byte { return pdu(Response, v, 0, 0) }, get: func(m *Message) int64 { return int64(m.RequestID) },
			lo: math.MinInt32, hi: math.MaxUint32, held: func(v int64) int64 { return int64(uint32(v)) }, //nolint:gosec // the two's complement
		},
		"error status": {
			msg: func(v int64) []byte { return pdu(Response, 1, v, 0) }, get: func(m *Message) int64 { return int64(m.ErrorStatus) },
			lo: 0, hi: 255,
		},
		"error index": {
			msg: func(v int64) []byte { return pdu(Response, 1, 0, v) }, get: func(m *Message) int64 { return int64(m.ErrorIndex) },
			lo: 0, hi: math.MaxInt32, held: sat,
		},
		"non-repeaters": {
			msg: func(v int64) []byte { return pdu(GetBulkRequest, 1, v, 10) }, get: func(m *Message) int64 { return int64(m.NonRepeaters) },
			lo: 0, hi: math.MaxInt32, held: sat,
		},
		"max-repetitions": {
			msg: func(v int64) []byte { return pdu(GetBulkRequest, 1, 0, v) }, get: func(m *Message) int64 { return int64(m.MaxRepetitions) },
			lo: 0, hi: math.MaxInt32,
		},
		"generic trap": {
			msg: func(v int64) []byte { return trap(v, 1) }, get: func(m *Message) int64 { return int64(m.GenericTrap) },
			lo: math.MinInt32, hi: math.MaxInt32,
		},
		"specific trap": {
			msg: func(v int64) []byte { return trap(6, v) }, get: func(m *Message) int64 { return int64(m.SpecificTrap) },
			lo: math.MinInt32, hi: math.MaxInt32,
		},
		"msgID": {
			msg: func(v int64) []byte { return v3(v, 65507, 7, 1234) }, get: func(m *Message) int64 { return int64(m.MsgID) },
			lo: 0, hi: math.MaxInt32,
		},
		"msgMaxSize": {
			msg: func(v int64) []byte { return v3(42, v, 7, 1234) }, get: func(m *Message) int64 { return int64(m.MsgMaxSize) },
			lo: 484, hi: math.MaxInt32,
		},
		"msgAuthoritativeEngineBoots": {
			msg: func(v int64) []byte { return v3(42, 65507, v, 1234) },
			get: func(m *Message) int64 { return int64(m.SecurityParameters.AuthoritativeEngineBoots) },
			lo:  0, hi: math.MaxInt32,
		},
		"msgAuthoritativeEngineTime": {
			msg: func(v int64) []byte { return v3(42, 65507, 7, v) },
			get: func(m *Message) int64 { return int64(m.SecurityParameters.AuthoritativeEngineTime) },
			lo:  0, hi: math.MaxInt32,
		},
	}
	type result struct {
		value int64
		err   error // the error's category
	}
	for name, f := range fields {
		probes := []int64{f.lo, f.hi, f.lo - 1, f.hi + 1, f.lo + 1<<32, f.hi - 1<<32}
		slices.Sort(probes)
		for _, v := range slices.Compact(probes) {
			t.Run(fmt.Sprintf("%s/%d", name, v), func(t *testing.T) {
				want := result{err: ErrASNParse}
				if f.lo <= v && v <= f.hi {
					want = result{value: v}
					if f.held != nil {
						want.value = f.held(v)
					}
				}
				m, err := mustClient(Config{}).DecodeMessage(f.msg(v))
				var got result
				if err != nil {
					got.err = headerCategory(err)
					assert.Nil(t, m)
				} else {
					got.value = f.get(m)
				}
				assert.Equal(t, want, got)
			})
		}
	}

	// The version and the security model, whose values are a set: any other
	// version is a bad version (RFC 3412 section 4.2.1), any other model in
	// 1..2147483647 another security model.
	tests := map[string]struct {
		in   []byte
		want result
	}{
		"version 1":                 {in: craftedMsg(1, craftedPDU(Response, nullVBL)), want: result{value: 1}},
		"version 0 (SNMPv1)":        {in: craftedMsg(0, craftedPDU(Response, nullVBL)), want: result{value: 0}},
		"version 2^32":              {in: craftedMsg(1<<32, craftedPDU(Response, nullVBL)), want: result{err: ErrBadVersion}},
		"version 2^32+1":            {in: craftedMsg(1<<32+1, craftedPDU(Response, nullVBL)), want: result{err: ErrBadVersion}},
		"version -2^32+1":           {in: craftedMsg(-1<<32+1, craftedPDU(Response, nullVBL)), want: result{err: ErrBadVersion}},
		"version 2^32+3":            {in: craftedMsg(1<<32+3, craftedPDU(Response, nullVBL)), want: result{err: ErrBadVersion}},
		"security model 3":          {in: v3Model(3), want: result{value: 3}},
		"security model 2147483647": {in: v3Model(math.MaxInt32), want: result{err: ErrUnknownSecurityModels}},
		"security model 0":          {in: v3Model(0), want: result{err: ErrASNParse}},
		"security model 2^31":       {in: v3Model(1 << 31), want: result{err: ErrASNParse}},
		"security model 2^32+3":     {in: v3Model(1<<32 + 3), want: result{err: ErrASNParse}},
		"security model -2^32+3":    {in: v3Model(-1<<32 + 3), want: result{err: ErrASNParse}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := mustClient(Config{}).DecodeMessage(tc.in)
			var got result
			switch {
			case err != nil:
				got.err = headerCategory(err)
				assert.Nil(t, m)
			case m.Version == Version3:
				got.value = 3 // the only model that decodes
			default:
				got.value = int64(m.Version)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// v3Model returns an SNMPv3 message whose security model is model.
func v3Model(model int64) []byte {
	return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(model), craftedNoAuthUSM, craftedScopedResp)
}

// headerCategory returns the category of a header field's error: the first of
// ErrASNParse, ErrBadVersion and ErrUnknownSecurityModels it matches, else
// err.
func headerCategory(err error) error {
	for _, c := range []error{ErrASNParse, ErrBadVersion, ErrUnknownSecurityModels} {
		if errors.Is(err, c) {
			return c
		}
	}
	return err
}
