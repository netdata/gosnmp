// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// decodedFields are the packet fields a decode sets, so a failed decode's
// partial packet can be compared whole.
type decodedFields struct {
	version                      SnmpVersion
	community                    string
	msgID, msgMaxSize            uint32
	msgFlags                     SnmpV3MsgFlags
	securityModel                SnmpV3SecurityModel
	usmEngineID, usmUser         string
	usmBoots, usmTime            uint32
	contextEngineID, contextName string
	pduType                      PDUType
	requestID                    uint32
	errorStatus                  SNMPError
	errorIndex, nonRepeaters     uint8
	maxRepetitions               uint32
	enterprise, agentAddress     string
	genericTrap, specificTrap    int
	timestamp                    uint
	variables                    []SnmpPDU
}

func fieldsOf(p *SnmpPacket) decodedFields {
	d := decodedFields{
		version:         p.Version,
		community:       p.Community,
		msgID:           p.MsgID,
		msgMaxSize:      p.MsgMaxSize,
		msgFlags:        p.MsgFlags,
		securityModel:   p.SecurityModel,
		contextEngineID: p.ContextEngineID,
		contextName:     p.ContextName,
		pduType:         p.PDUType,
		requestID:       p.RequestID,
		errorStatus:     p.Error,
		errorIndex:      p.ErrorIndex,
		nonRepeaters:    p.NonRepeaters,
		maxRepetitions:  p.MaxRepetitions,
		enterprise:      p.Enterprise,
		agentAddress:    p.AgentAddress,
		genericTrap:     p.GenericTrap,
		specificTrap:    p.SpecificTrap,
		timestamp:       p.Timestamp,
		variables:       p.Variables,
	}
	if sp := usmOf(p.SecurityParameters); sp != nil {
		d.usmEngineID, d.usmUser = sp.AuthoritativeEngineID, sp.UserName
		d.usmBoots, d.usmTime = sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime
	}
	return d
}

// TestDecodeFailurePartialResults pins, for a field of each decoder failing
// in turn, the error text and the packet SnmpDecodePacket returns with it:
// the fields read before the failure are set, the later ones are not. Known
// bug: the variables are an empty list, not nil, for any input of two octets
// or more, decoded or not.
func TestDecodeFailurePartialResults(t *testing.T) {
	bad := tlv(0x05) // a NULL where a field goes: a field of another tag
	vbl := craftedVBL(craftedVB(intTLV(5)))
	firstVB := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: Integer, Value: 5}}
	secondVB := func(vb []byte) []byte {
		return craftedMsg(1, tlv(byte(GetResponse), intTLV(7), intTLV(2), intTLV(3), craftedVBL(craftedVB(intTLV(5)), vb)))
	}
	with := func(d decodedFields, set func(*decodedFields)) decodedFields {
		d.variables = []SnmpPDU{}
		set(&d)
		return d
	}
	v2c := decodedFields{version: Version2c, community: "public"}
	resp := with(v2c, func(d *decodedFields) { d.pduType = GetResponse })
	respFields := with(resp, func(d *decodedFields) { d.requestID, d.errorStatus, d.errorIndex = 7, 2, 3 })
	bulk := with(v2c, func(d *decodedFields) { d.pduType = GetBulkRequest; d.requestID = 7 })
	v1Trap := with(decodedFields{version: Version1, community: "public"}, func(d *decodedFields) { d.pduType = Trap })
	v3Header := with(decodedFields{version: Version3}, func(d *decodedFields) {
		d.msgID, d.msgMaxSize, d.msgFlags, d.securityModel = 42, 65507, Reportable, UserSecurityModel
	})
	v3USM := with(v3Header, func(d *decodedFields) {
		d.msgFlags = NoAuthNoPriv
		d.usmEngineID, d.usmBoots, d.usmTime, d.usmUser = "\x80\x00\x1f\x88\x04codec-engine", 7, 1234, "codec-user"
	})
	v3 := func(flags, model, usm []byte) []byte {
		return craftedV3(intTLV(42), intTLV(65507), flags, model, usm, nil)
	}
	usmWith := func(engineID, boots, engineTime, user, authParams, privParams []byte) []byte {
		return v3(octets("\x04"), intTLV(3), craftedUSM(engineID, boots, engineTime, user, authParams, privParams))
	}
	const (
		header = "unable to decode packet header: "
		body   = "unable to decode packet body: error in unmarshalResponse: "
		trapV1 = "unable to decode packet body: error in unmarshalTrapV1: error parsing SNMPv1 trap "
		usm    = header + "error parsing SNMPV3 User Security Model "
		notInt = ": not an INTEGER"
		notStr = ": not an OCTET STRING"
	)

	tests := map[string]struct {
		in      []byte
		wantErr string
		want    decodedFields
	}{
		// Message header.
		"empty input":    {in: []byte{}, wantErr: header + "invalid packet length: cannot unmarshal empty packet"},
		"one octet":      {in: []byte{0x30}, wantErr: header + "invalid packet length: cannot unmarshal empty packet"},
		"not a sequence": {in: cat([]byte{0x31}, craftedValue(intTLV(5))[1:]), wantErr: header + "invalid packet header", want: with(decodedFields{}, func(*decodedFields) {})},
		"version":        {in: tlv(0x30, bad, octets("public"), vbl), wantErr: header + "error parsing SNMP packet version" + notInt, want: with(decodedFields{}, func(*decodedFields) {})},
		"community":      {in: tlv(0x30, intTLV(1), bad, vbl), wantErr: header + "error parsing community string" + notStr, want: with(decodedFields{version: Version2c}, func(*decodedFields) {})},

		// PDU header.
		"request ID":      {in: craftedMsg(1, tlv(byte(GetResponse), bad, intTLV(2), intTLV(3), vbl)), wantErr: body + "error parsing SNMP packet request ID" + notInt, want: resp},
		"error status":    {in: craftedMsg(1, tlv(byte(GetResponse), intTLV(7), bad, intTLV(3), vbl)), wantErr: body + "error parsing SNMP packet error" + notInt, want: with(resp, func(d *decodedFields) { d.requestID = 7 })},
		"error index":     {in: craftedMsg(1, tlv(byte(GetResponse), intTLV(7), intTLV(2), bad, vbl)), wantErr: body + "error parsing SNMP packet error index" + notInt, want: with(resp, func(d *decodedFields) { d.requestID, d.errorStatus = 7, 2 })},
		"non-repeaters":   {in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(7), bad, intTLV(9), vbl)), wantErr: body + "error parsing SNMP packet non repeaters" + notInt, want: bulk},
		"max-repetitions": {in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(7), intTLV(3), bad, vbl)), wantErr: body + "error parsing SNMP packet max repetitions" + notInt, want: with(bulk, func(d *decodedFields) { d.nonRepeaters = 3 })},

		// Varbind list.
		"no varbind list":              {in: craftedMsg(1, tlv(byte(GetResponse), intTLV(7), intTLV(2), intTLV(3))), wantErr: body + "truncated packet when unmarshalling a VBL", want: respFields},
		"varbind list not a sequence":  {in: craftedMsg(1, tlv(byte(GetResponse), intTLV(7), intTLV(2), intTLV(3), intTLV(1))), wantErr: body + "expected a sequence when unmarshalling a VBL, got 2", want: respFields},
		"varbind not a sequence":       {in: secondVB(intTLV(1)), wantErr: body + "expected a sequence when unmarshalling a VB, got 2", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind past the list":        {in: secondVB([]byte{0x30, 0x10, 0x06}), wantErr: body + "error reading varbind: invalid packet length: TLV length exceeds the remaining input", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind name":                 {in: secondVB(tlv(0x30, bad, intTLV(6))), wantErr: body + "error parsing OID Value" + ": not an OBJECT IDENTIFIER or text", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind name not text":        {in: secondVB(tlv(0x30, intTLV(1), intTLV(6))), wantErr: body + "error parsing OID Value: not an OBJECT IDENTIFIER or text", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind without a value":      {in: secondVB(tlv(0x30, craftedOID)), wantErr: body + "error decoding value: zero byte buffer", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind value shorter":        {in: secondVB(tlv(0x30, craftedOID, intTLV(6), intTLV(7))), wantErr: body + "value TLV length mismatch in varbind (TLV 3, remaining 6)", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind value not decodable":  {in: secondVB(tlv(0x30, craftedOID, tlv(byte(Integer)))), wantErr: body + "error decoding value: invalid Integer: zero length integer", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},
		"varbind value unknown length": {in: secondVB(tlv(0x30, craftedOID, []byte{0x02, 0x85})), wantErr: body + "error parsing value TLV in varbind: invalid packet length", want: with(respFields, func(d *decodedFields) { d.variables = firstVB })},

		// SNMPv1 trap header.
		"v1 trap enterprise":    {in: craftedV1Trap(bad, craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, vbl), wantErr: trapV1 + "enterprise" + ": not an OBJECT IDENTIFIER", want: v1Trap},
		"v1 trap agent address": {in: craftedV1Trap(craftedEnterprise, bad, intTLV(6), intTLV(1), craftedTimestamp, vbl), wantErr: trapV1 + "agent address" + ": not an IpAddress or OCTET STRING", want: with(v1Trap, func(d *decodedFields) { d.enterprise = ".1.3.6.1.4.1.20372" })},
		"v1 trap generic trap": {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, bad, intTLV(1), craftedTimestamp, vbl), wantErr: trapV1 + "generic trap" + notInt, want: with(v1Trap, func(d *decodedFields) {
			d.enterprise, d.agentAddress = ".1.3.6.1.4.1.20372", "192.0.2.1"
		})},
		"v1 trap specific trap": {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), bad, craftedTimestamp, vbl), wantErr: trapV1 + "specific trap" + notInt, want: with(v1Trap, func(d *decodedFields) {
			d.enterprise, d.agentAddress, d.genericTrap = ".1.3.6.1.4.1.20372", "192.0.2.1", 6
		})},
		"v1 trap timestamp": {in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), bad, vbl), wantErr: trapV1 + "timestamp" + ": not TimeTicks or another unsigned type", want: with(v1Trap, func(d *decodedFields) {
			d.enterprise, d.agentAddress, d.genericTrap, d.specificTrap = ".1.3.6.1.4.1.20372", "192.0.2.1", 6, 1
		})},

		// SNMPv3 header.
		"v3 message ID":     {in: craftedV3(bad, intTLV(65507), octets("\x04"), intTLV(3), craftedNoAuthUSM, nil), wantErr: header + "error parsing SNMPV3 message ID" + notInt, want: with(decodedFields{version: Version3}, func(*decodedFields) {})},
		"v3 max size":       {in: craftedV3(intTLV(42), bad, octets("\x04"), intTLV(3), craftedNoAuthUSM, nil), wantErr: header + "error parsing SNMPV3 msgMaxSize" + notInt, want: with(decodedFields{version: Version3}, func(d *decodedFields) { d.msgID = 42 })},
		"v3 flags":          {in: v3(bad, intTLV(3), craftedNoAuthUSM), wantErr: header + "error parsing SNMPV3 msgFlags: not an OCTET STRING of one octet", want: with(decodedFields{version: Version3}, func(d *decodedFields) { d.msgID, d.msgMaxSize = 42, 65507 })},
		"v3 security model": {in: v3(octets("\x04"), bad, craftedNoAuthUSM), wantErr: header + "error parsing SNMPV3 msgSecModel" + notInt, want: with(v3Header, func(d *decodedFields) { d.securityModel = 0 })},
		"v3 nothing after the security model": {
			in:      tlv(0x30, intTLV(3), tlv(0x30, intTLV(42), intTLV(65507), octets("\x04"), intTLV(3))),
			wantErr: header + "error parsing SNMPV3: nothing after the security model",
			want:    with(v3Header, func(d *decodedFields) { d.securityModel = 0 }),
		},
		"v3 security parameters not an OCTET STRING": {
			in:      tlv(0x30, intTLV(3), tlv(0x30, intTLV(42), intTLV(65507), octets("\x04"), intTLV(3)), intTLV(1)),
			wantErr: header + "invalid SNMPV3 Security Parameters",
			want:    v3Header,
		},

		// USM security parameters.
		"usm engine ID":   {in: usmWith(bad, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets("")), wantErr: usm + "msgAuthoritativeEngineID" + notStr, want: v3Header},
		"usm boots":       {in: usmWith(craftedEngineID, bad, intTLV(1234), octets("codec-user"), octets(""), octets("")), wantErr: usm + "msgAuthoritativeEngineBoots" + notInt, want: with(v3Header, func(d *decodedFields) { d.usmEngineID = "\x80\x00\x1f\x88\x04codec-engine" })},
		"usm engine time": {in: usmWith(craftedEngineID, intTLV(7), bad, octets("codec-user"), octets(""), octets("")), wantErr: usm + "msgAuthoritativeEngineTime" + notInt, want: with(v3Header, func(d *decodedFields) { d.usmEngineID, d.usmBoots = "\x80\x00\x1f\x88\x04codec-engine", 7 })},
		"usm user name": {in: usmWith(craftedEngineID, intTLV(7), intTLV(1234), bad, octets(""), octets("")), wantErr: usm + "msgUserName" + notStr, want: with(v3Header, func(d *decodedFields) {
			d.usmEngineID, d.usmBoots, d.usmTime = "\x80\x00\x1f\x88\x04codec-engine", 7, 1234
		})},
		"usm authentication parameters": {in: usmWith(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), bad, octets("")), wantErr: usm + "msgAuthenticationParameters" + notStr, want: with(v3USM, func(d *decodedFields) { d.msgFlags = Reportable })},
		"usm privacy parameters":        {in: usmWith(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), bad), wantErr: usm + "msgPrivacyParameters" + notStr, want: with(v3USM, func(d *decodedFields) { d.msgFlags = Reportable })},
		// Flags asking for authentication, which the decoder has no protocol
		// for: after a header error, and as the error (step 5).
		"usm privacy parameters, authenticated": {
			in:      v3(octets("\x05"), intTLV(3), craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), bad)),
			wantErr: usm + "msgPrivacyParameters" + notStr,
			want:    with(v3USM, func(d *decodedFields) { d.msgFlags = Reportable | AuthNoPriv }),
		},
		"security level without a protocol": {
			in:      v3(octets("\x05"), intTLV(3), craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets(""))),
			wantErr: header + "error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message",
			want:    with(v3USM, func(d *decodedFields) { d.msgFlags = Reportable | AuthNoPriv }),
		},

		// SNMPv3 scoped PDU.
		"context engine ID": {in: craftedV3NoAuth(tlv(0x30, bad, octets("ctx"), craftedPDU(GetResponse, vbl))), wantErr: "error parsing SNMPV3 contextEngineID" + notStr, want: v3USM},
		"context name": {in: craftedV3NoAuth(tlv(0x30, craftedEngineID, bad, craftedPDU(GetResponse, vbl))), wantErr: "error parsing SNMPV3 contextName" + notStr, want: with(v3USM, func(d *decodedFields) {
			d.contextEngineID = "\x80\x00\x1f\x88\x04codec-engine"
		})},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := (&GoSNMP{}).SnmpDecodePacket(tc.in)
			if assert.Error(t, err) {
				assert.Equal(t, tc.wantErr, err.Error())
			}
			if assert.NotNil(t, p) {
				assert.Equal(t, tc.want, fieldsOf(p))
			}
		})
	}
}

// TestDecodeUSMFields pins RFC 3414 section 3.2 step 1: each USM field must
// be of its type, and the engine boots and time within 0..2147483647 once cut
// to 32 bits (as net-snmp v5.9.4 reads them); anything else fails the header
// parse with ErrInvalidMsgs, on the raw path too.
func TestDecodeUSMFields(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x04codec-engine"
	fields := func(edit func(f [][]byte)) []byte {
		f := [][]byte{octets(engineID), intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets("")}
		edit(f)
		return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), tlv(0x30, f...), craftedScopedResp)
	}
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
		// 2^32+5, cut to 5 on every platform.
		"boots 4294967301": {in: fields(func(f [][]byte) { f[1] = intTLV(4294967301) })},
		"boots -1":         {in: fields(func(f [][]byte) { f[1] = intTLV(-1) }), invalid: true},
		"time -2147483648": {in: fields(func(f [][]byte) { f[2] = intTLV(-2147483648) }), invalid: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := (&GoSNMP{}).SnmpDecodePacket(tc.in)
			if tc.invalid {
				assert.ErrorIs(t, err, ErrInvalidMsgs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
