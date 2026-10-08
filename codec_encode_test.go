// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestEncodeCharacterization pins the bytes MarshalMsg and SnmpEncodePacket
// produce for packets that cover every PDU layout, SNMPv3 security level,
// length form and OID edge case, or whether they fail or panic.
func TestEncodeCharacterization(t *testing.T) {
	cases := encodeCases(t)

	results := make([]goldenCase, 0, len(cases))
	for _, c := range cases {
		results = append(results, goldenCase{name: c.name, dump: dumpEncode(c.encode)})
	}
	checkGolden(t, "encode", results)
}

// TestEncodeValueTypesCharacterization pins, for every value tag, the value
// TLV that MarshalMsg writes for each Go value type, or whether it fails or
// panics. It records which Go types the encoder accepts.
// TestMarshalLongOctetStringFields encodes communities, USM engine IDs and
// user names longer than 127 bytes and decodes them back.
func TestMarshalLongOctetStringFields(t *testing.T) {
	type fields struct {
		community, engineID, userName string
	}
	long := func(n int) string { return strings.Repeat("x", n) }
	tests := map[string]fields{
		"community 128 bytes": {community: long(128)},
		"community 256 bytes": {community: long(256)},
		"community 300 bytes": {community: long(300)},
		"engine ID 128 bytes": {engineID: long(128), userName: "user"},
		"engine ID 300 bytes": {engineID: long(300), userName: "user"},
		"user name 128 bytes": {engineID: "\x80\x00\x1f\x88\x04engine", userName: long(128)},
		"user name 256 bytes": {engineID: "\x80\x00\x1f\x88\x04engine", userName: long(256)},
	}

	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			packet := &SnmpPacket{
				Version:   Version2c,
				Community: want.community,
				PDUType:   GetRequest,
				RequestID: 1,
				Variables: []SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: Null}},
			}
			if want.community == "" {
				packet.Version = Version3
				packet.MsgFlags = NoAuthNoPriv
				packet.SecurityModel = UserSecurityModel
				packet.MsgID = 1
				packet.SecurityParameters = &UsmSecurityParameters{AuthoritativeEngineID: want.engineID, UserName: want.userName}
			}
			msg, err := packet.MarshalMsg()
			if err != nil {
				t.Fatalf("MarshalMsg: %v", err)
			}

			decoded, err := (&GoSNMP{}).SnmpDecodePacket(msg)
			if err != nil {
				t.Fatalf("decoding the encoded message: %v\nmessage: %x", err, msg)
			}
			got := fields{community: decoded.Community}
			if usm, ok := decoded.SecurityParameters.(*UsmSecurityParameters); ok {
				got.engineID, got.userName = usm.AuthoritativeEngineID, usm.UserName
			}
			if got != want {
				t.Errorf("decoded %+v, want %+v", got, want)
			}
		})
	}
}

// TestMarshalUnencodableValues checks that MarshalMsg reports caller values
// it cannot encode as errors instead of panicking.
func TestMarshalUnencodableValues(t *testing.T) {
	varbind := func(typ Asn1BER, value any) *SnmpPacket {
		return &SnmpPacket{
			Version:   Version2c,
			Community: "public",
			PDUType:   SetRequest,
			RequestID: 1,
			Variables: []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: typ, Value: value}},
		}
	}
	trap := func(agentAddress string) *SnmpPacket {
		return &SnmpPacket{
			Version:   Version1,
			Community: "public",
			PDUType:   Trap,
			SnmpTrap: SnmpTrap{
				Enterprise:   ".1.3.6.1.4.1.20372",
				AgentAddress: agentAddress,
				GenericTrap:  6,
				Variables:    []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: Null}},
			},
		}
	}
	tests := map[string]*SnmpPacket{
		"Integer with a uint8 value":                varbind(Integer, uint8(200)),
		"ObjectIdentifier with an int value":        varbind(ObjectIdentifier, 5),
		"ObjectIdentifier with a []byte value":      varbind(ObjectIdentifier, []byte(".1.3.6.1")),
		"ObjectIdentifier with a nil value":         varbind(ObjectIdentifier, nil),
		"IPAddress with a string that is not an IP": varbind(IPAddress, "x"),
		"v1 trap with an empty agent address":       trap(""),
		"v1 trap with an agent address not an IP":   trap("x"),
	}

	for name, packet := range tests {
		t.Run(name, func(t *testing.T) {
			var err error
			panicked, _ := observe(func() { _, err = packet.MarshalMsg() })
			if panicked || err == nil {
				t.Errorf("MarshalMsg panicked: %v, error: %v; want an error", panicked, err)
			}
		})
	}
}

func TestEncodeValueTypesCharacterization(t *testing.T) {
	tags := []Asn1BER{
		UnknownType, Boolean, Integer, BitString, OctetString, Null, ObjectIdentifier, ObjectDescription, IPAddress,
		Counter32, Gauge32, TimeTicks, Opaque, NsapAddress, Counter64, Uinteger32, OpaqueFloat, OpaqueDouble,
		NoSuchObject, NoSuchInstance, EndOfMibView,
	}
	values := []struct {
		label string
		value any
	}{
		{"nil", nil},
		{"int(0)", 0},
		{"int(-1)", -1},
		{"int(MaxInt32)", math.MaxInt32},
		{"int(MinInt32)", math.MinInt32},
		{"int8(-1)", int8(-1)},
		{"int32(-5)", int32(-5)},
		{"int64(5)", int64(5)},
		{"int64(MaxInt64)", int64(math.MaxInt64)},
		{"uint(5)", uint(5)},
		{"uint8(200)", uint8(200)},
		{"uint32(MaxUint32)", uint32(math.MaxUint32)},
		{"uint64(2^40)", uint64(1 << 40)},
		{"uint64(MaxUint64)", uint64(math.MaxUint64)},
		{"float32(1.5)", float32(1.5)},
		{"float64(-2.25)", float64(-2.25)},
		{`string("1.3.6.1")`, "1.3.6.1"},
		{`string("192.0.2.1")`, "192.0.2.1"},
		{`string("2001:db8::1")`, "2001:db8::1"},
		{`string("x")`, "x"},
		{`[]byte("x")`, []byte("x")},
		{"[]byte{}", []byte{}},
	}

	results := make([]goldenCase, 0, len(tags))
	for _, tag := range tags {
		var d dumpWriter
		for _, v := range values {
			pkt := &SnmpPacket{
				Version:   Version2c,
				Community: "public",
				PDUType:   SetRequest,
				RequestID: 1,
				Variables: []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: tag, Value: v.value}},
			}
			d.linef("%s: %s", v.label, dumpVarbindValue(pkt))
		}
		results = append(results, goldenCase{name: fmt.Sprintf("0x%02x %s", byte(tag), tag), dump: d.String()})
	}
	checkGolden(t, "encode-value-types", results)
}

type encodeCase struct {
	name   string
	encode func() ([]byte, error)
}

func dumpEncode(encode func() ([]byte, error)) string {
	var out []byte
	var err error
	panicked, wroteStdout := observe(func() { out, err = encode() })

	var d dumpWriter
	switch {
	case panicked:
		d.line("encode: panic")
	case err != nil:
		d.line("encode: " + dumpError(err))
	default:
		d.line("encode: " + dumpBytes(out))
	}
	if wroteStdout {
		d.line("stdout: written")
	}
	return d.String()
}

// dumpVarbindValue marshals a one-varbind v2c packet and returns the value TLV
// of its varbind, the whole message when it cannot be split, or the failure.
func dumpVarbindValue(pkt *SnmpPacket) string {
	var out []byte
	var err error
	panicked, wroteStdout := observe(func() { out, err = pkt.MarshalMsg() })

	var result string
	switch {
	case panicked:
		result = "panic"
	case err != nil:
		result = dumpError(err)
	default:
		if value, ok := lastVarbindValue(out); ok {
			result = fmt.Sprintf("% x", value)
		} else {
			result = "message " + dumpBytes(out)
		}
	}
	if wroteStdout {
		result += " (stdout written)"
	}
	return result
}

// lastVarbindValue returns the value TLV of the last varbind of a v1/v2c
// message, using a minimal BER reader that is independent of the codec.
func lastVarbindValue(msg []byte) ([]byte, bool) {
	path := []int{2, 3, -1, 1} // message -> PDU -> varbind list -> last varbind -> value
	cur := msg
	for _, idx := range path {
		children, ok := berChildren(cur)
		if !ok || len(children) == 0 {
			return nil, false
		}
		if idx < 0 {
			idx = len(children) - 1
		}
		if idx >= len(children) {
			return nil, false
		}
		cur = children[idx]
	}
	return cur, true
}

// berChildren splits the content of one constructed TLV into its child TLVs.
func berChildren(b []byte) ([][]byte, bool) {
	content, rest, ok := berNext(b)
	if !ok || len(rest) != 0 {
		return nil, false
	}
	content = content[berHeaderLen(content):]
	var children [][]byte
	for len(content) > 0 {
		child, next, ok := berNext(content)
		if !ok {
			return nil, false
		}
		children = append(children, child)
		content = next
	}
	return children, true
}

// berNext returns the first TLV of b (header included) and the bytes after it.
func berNext(b []byte) (tlvBytes, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	hdr := berHeaderLen(b)
	if hdr == 0 || hdr > len(b) {
		return nil, nil, false
	}
	n := 0
	if b[1] < 0x80 {
		n = int(b[1])
	} else {
		for _, c := range b[2:hdr] {
			n = n<<8 | int(c)
		}
	}
	if n > len(b)-hdr {
		return nil, nil, false
	}
	return b[:hdr+n], b[hdr+n:], true
}

// berHeaderLen is the length of the tag and length octets of a definite-length TLV, or 0.
func berHeaderLen(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	switch {
	case b[1] < 0x80:
		return 2
	case b[1] == 0x80 || b[1] > 0x84:
		return 0
	default:
		return 2 + int(b[1]&0x7f)
	}
}

// codecUSM returns USM parameters for the synthetic codec-user with localized keys.
func codecUSM(t *testing.T, auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) *UsmSecurityParameters {
	t.Helper()
	sp := &UsmSecurityParameters{
		UserName:                 "codec-user",
		AuthenticationProtocol:   auth,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyProtocol:          priv,
		PrivacyPassphrase:        "codec-priv-pass",
		AuthoritativeEngineID:    "\x80\x00\x1f\x88\x04codec-engine",
		AuthoritativeEngineBoots: 7,
		AuthoritativeEngineTime:  1234,
	}
	if auth != NoAuth {
		if err := sp.InitSecurityKeys(); err != nil {
			t.Fatal(err)
		}
	}
	return sp
}

func encodeCases(t *testing.T) []encodeCase {
	t.Helper()

	nullVar := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: Null}}
	mixedVars := []SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.7.0", Type: Integer, Value: 104},
		{Name: ".1.3.6.1.2.1.1.4.0", Type: OctetString, Value: []byte("Administrator")},
		{Name: ".1.3.6.1.2.1.1.2.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.3.2.10"},
		{Name: ".1.3.6.1.2.1.4.20.1.1.192.0.2.1", Type: IPAddress, Value: "192.0.2.1"},
		{Name: ".1.3.6.1.2.1.2.2.1.10.1", Type: Counter32, Value: uint32(271070065)},
		{Name: ".1.3.6.1.2.1.2.2.1.5.1", Type: Gauge32, Value: uint(100000000)},
		{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(318870100)},
		{Name: ".1.3.6.1.2.1.31.1.1.1.10.1", Type: Counter64, Value: uint64(1527943)},
		{Name: ".1.3.6.1.4.1.2021.1", Type: Opaque, Value: []byte{0x9f, 0x78, 0x04, 0x41, 0x20, 0x00, 0x00}},
		{Name: ".1.3.6.1.4.1.6574.4.2.12.1.0", Type: OpaqueFloat, Value: float32(10.0)},
		{Name: ".1.3.6.1.4.1.6574.4.2.12.2.0", Type: OpaqueDouble, Value: float64(10.0)},
		{Name: ".1.3.6.1.2.1.1.3.1", Type: Uinteger32, Value: uint32(7)},
		{Name: ".1.3.6.1.2.1.1.9.0", Type: NoSuchObject},
		{Name: ".1.3.6.1.2.1.1.9.1", Type: NoSuchInstance},
		{Name: ".1.3.6.1.2.1.1.9.2", Type: EndOfMibView},
	}
	trap := SnmpTrap{
		Enterprise:   ".1.3.6.1.4.1.20372",
		AgentAddress: "192.0.2.1",
		GenericTrap:  6,
		SpecificTrap: 42,
		Timestamp:    256,
	}

	v2c := func(pduType PDUType, vars []SnmpPDU) *SnmpPacket {
		return &SnmpPacket{Version: Version2c, Community: "public", PDUType: pduType, RequestID: 1, Variables: vars}
	}
	v1Trap := func(edit func(*SnmpTrap)) *SnmpPacket {
		tr := trap
		edit(&tr)
		return &SnmpPacket{Version: Version1, Community: "public", PDUType: Trap, SnmpTrap: tr, Variables: nullVar}
	}
	v3 := func(flags SnmpV3MsgFlags, pduType PDUType, sp *UsmSecurityParameters) *SnmpPacket {
		return &SnmpPacket{
			Version:            Version3,
			MsgFlags:           flags,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: sp,
			ContextEngineID:    "\x80\x00\x1f\x88\x04codec-engine",
			ContextName:        "codec-context",
			PDUType:            pduType,
			MsgID:              4242,
			RequestID:          123456,
			Variables:          nullVar,
		}
	}
	withPrivSalt := func(sp *UsmSecurityParameters) *UsmSecurityParameters {
		sp.PrivacyParameters = []byte{0, 0, 0, 7, 0, 0, 0, 1}
		return sp
	}
	// hostVars are n OctetString varbinds; 4 make a v3 scoped PDU need a two-octet
	// length, 20 a three-octet one.
	hostVars := func(n int) []SnmpPDU {
		vars := make([]SnmpPDU, n)
		for i := range vars {
			vars[i] = SnmpPDU{Name: ".1.3.6.1.2.1.1.5." + strconv.Itoa(i), Type: OctetString, Value: []byte("codec-host-" + strconv.Itoa(i))}
		}
		return vars
	}
	withVars := func(p *SnmpPacket, vars []SnmpPDU) *SnmpPacket { p.Variables = vars; return p }
	oidName := func(name string) *SnmpPacket { return v2c(GetRequest, []SnmpPDU{{Name: name, Type: Null}}) }
	marshal := func(p *SnmpPacket) func() ([]byte, error) { return p.MarshalMsg }
	edit := func(p *SnmpPacket, f func(*SnmpPacket)) *SnmpPacket { f(p); return p }

	return []encodeCase{
		// v1 and v2c PDUs.
		{"v1/get-request", marshal(&SnmpPacket{Version: Version1, Community: "public", PDUType: GetRequest, RequestID: 1, Variables: nullVar})},
		{"v2c/get-request", marshal(v2c(GetRequest, nullVar))},
		{"v2c/get-request/no-varbinds", marshal(v2c(GetRequest, nil))},
		{"v2c/get-next-request", marshal(v2c(GetNextRequest, nullVar))},
		{"v2c/getbulk-request", marshal(edit(v2c(GetBulkRequest, slices.Concat(nullVar, nullVar)), func(p *SnmpPacket) { p.NonRepeaters, p.MaxRepetitions = 1, 10 }))},
		{"v2c/getbulk-request/max-repetitions-2^31", marshal(edit(v2c(GetBulkRequest, nullVar), func(p *SnmpPacket) { p.MaxRepetitions = 1 << 31 }))},
		{"v2c/getbulk-request/max-repetitions-max-uint32", marshal(edit(v2c(GetBulkRequest, nullVar), func(p *SnmpPacket) { p.MaxRepetitions = math.MaxUint32 }))},
		{"v2c/set-request/mixed-types", marshal(v2c(SetRequest, mixedVars))},
		{"v2c/get-response/error", marshal(edit(v2c(GetResponse, nullVar), func(p *SnmpPacket) { p.Error, p.ErrorIndex = GenErr, 2 }))},
		{"v2c/get-response/error-index-255", marshal(edit(v2c(GetResponse, nullVar), func(p *SnmpPacket) { p.Error, p.ErrorIndex = TooBig, 255 }))},
		{"v2c/snmpv2-trap", marshal(v2c(SNMPv2Trap, mixedVars[:3]))},
		{"v2c/inform-request", marshal(v2c(InformRequest, nullVar))},
		{"v2c/inform-request/is-inform-flag", marshal(edit(v2c(SNMPv2Trap, nullVar), func(p *SnmpPacket) { p.IsInform = true }))},
		{"v2c/report", marshal(v2c(Report, nullVar))},
		{"v2c/unknown-pdu-type", marshal(v2c(PDUType(0xa9), nullVar))},
		{"v2c/request-id-0", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.RequestID = 0 }))},
		{"v2c/request-id-2^31", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.RequestID = 1 << 31 }))},
		{"v2c/request-id-max-uint32", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.RequestID = math.MaxUint32 }))},
		{"v2c/version-2", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.Version = 2 }))},

		// Lengths.
		{"v2c/community-empty", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.Community = "" }))},
		{"v2c/community-127", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.Community = strings.Repeat("c", 127) }))},
		{"v2c/community-128", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.Community = strings.Repeat("c", 128) }))},
		{"v2c/community-256", marshal(edit(v2c(GetRequest, nullVar), func(p *SnmpPacket) { p.Community = strings.Repeat("c", 256) }))},
		{"v2c/octet-string-127", marshal(v2c(SetRequest, []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 127))}}))},
		{"v2c/octet-string-200", marshal(v2c(SetRequest, []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 200))}}))},
		{"v2c/octet-string-300", marshal(v2c(SetRequest, []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 300))}}))},
		{"v2c/octet-string-70000", marshal(v2c(SetRequest, []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 70000))}}))},
		{"v2c/100-varbinds", marshal(v2c(GetRequest, slices.Repeat(nullVar, 100)))},

		// Varbind names.
		{"oid/no-leading-dot", marshal(oidName("1.3.6.1.2.1.1.5.0"))},
		{"oid/empty", marshal(oidName(""))},
		{"oid/single-arc", marshal(oidName(".1"))},
		{"oid/two-arcs", marshal(oidName(".1.3"))},
		{"oid/first-arc-2", marshal(oidName(".2.999.1"))},
		{"oid/first-arc-3", marshal(oidName(".3.1"))},
		{"oid/second-arc-40", marshal(oidName(".1.40"))},
		{"oid/arc-max-uint32", marshal(oidName(".1.3.6.1.4.1.4294967295"))},
		{"oid/arc-2^32", marshal(oidName(".1.3.6.1.4.1.4294967296"))},
		{"oid/empty-arc", marshal(oidName(".1..3.6"))},
		{"oid/trailing-dot", marshal(oidName(".1.3.6."))},
		{"oid/letters", marshal(oidName(".1.3.abc"))},
		{"oid/negative-arc", marshal(oidName(".1.3.-6"))},
		{"oid/130-arcs", marshal(oidName(".1.3" + strings.Repeat(".129", 128)))},

		// v1 Trap.
		{"v1-trap/basic", marshal(v1Trap(func(*SnmpTrap) {}))},
		{"v1-trap/agent-address-empty", marshal(v1Trap(func(tr *SnmpTrap) { tr.AgentAddress = "" }))},
		{"v1-trap/agent-address-ipv6", marshal(v1Trap(func(tr *SnmpTrap) { tr.AgentAddress = "2001:db8::1" }))},
		{"v1-trap/agent-address-invalid", marshal(v1Trap(func(tr *SnmpTrap) { tr.AgentAddress = "not-an-ip" }))},
		{"v1-trap/enterprise-empty", marshal(v1Trap(func(tr *SnmpTrap) { tr.Enterprise = "" }))},
		{"v1-trap/generic-negative", marshal(v1Trap(func(tr *SnmpTrap) { tr.GenericTrap = -1 }))},
		{"v1-trap/specific-max-int32", marshal(v1Trap(func(tr *SnmpTrap) { tr.SpecificTrap = math.MaxInt32 }))},
		{"v1-trap/timestamp-max-uint32", marshal(v1Trap(func(tr *SnmpTrap) { tr.Timestamp = math.MaxUint32 }))},
		{"v1-trap/in-v2c-message", marshal(edit(v1Trap(func(*SnmpTrap) {}), func(p *SnmpPacket) { p.Version = Version2c }))},

		// SNMPv3.
		{"v3/no-auth-no-priv/discovery", marshal(edit(v3(Reportable|NoAuthNoPriv, GetRequest, &UsmSecurityParameters{}), func(p *SnmpPacket) {
			p.ContextEngineID, p.ContextName, p.Variables = "", "", nil
		}))},
		{"v3/no-auth-no-priv/get-request", marshal(v3(NoAuthNoPriv, GetRequest, codecUSM(t, NoAuth, NoPriv)))},
		{"v3/no-auth-no-priv/msg-id-2^31", marshal(edit(v3(NoAuthNoPriv, GetRequest, codecUSM(t, NoAuth, NoPriv)), func(p *SnmpPacket) { p.MsgID = 1 << 31 }))},
		{"v3/no-auth-no-priv/engine-id-200", marshal(edit(v3(NoAuthNoPriv, GetRequest, codecUSM(t, NoAuth, NoPriv)), func(p *SnmpPacket) {
			p.SecurityParameters.(*UsmSecurityParameters).AuthoritativeEngineID = strings.Repeat("e", 200)
		}))},
		{"v3/no-auth-no-priv/user-name-200", marshal(edit(v3(NoAuthNoPriv, GetRequest, codecUSM(t, NoAuth, NoPriv)), func(p *SnmpPacket) {
			p.SecurityParameters.(*UsmSecurityParameters).UserName = strings.Repeat("u", 200)
		}))},
		{"v3/no-auth-no-priv/max-size-1500", marshal(edit(v3(NoAuthNoPriv, GetRequest, codecUSM(t, NoAuth, NoPriv)), func(p *SnmpPacket) { p.MsgMaxSize = 1500 }))},
		{"v3/no-auth-no-priv/report", marshal(v3(NoAuthNoPriv, Report, codecUSM(t, NoAuth, NoPriv)))},
		{"v3/no-auth-no-priv/nil-security-parameters", marshal(v3(NoAuthNoPriv, GetRequest, nil))},
		{"v3/auth-no-priv/md5", marshal(v3(AuthNoPriv, GetRequest, codecUSM(t, MD5, NoPriv)))},
		{"v3/auth-no-priv/sha", marshal(v3(AuthNoPriv, GetRequest, codecUSM(t, SHA, NoPriv)))},
		{"v3/auth-no-priv/sha224", marshal(v3(AuthNoPriv, GetRequest, codecUSM(t, SHA224, NoPriv)))},
		{"v3/auth-no-priv/sha256", marshal(v3(AuthNoPriv, GetRequest, codecUSM(t, SHA256, NoPriv)))},
		{"v3/auth-no-priv/sha384", marshal(v3(AuthNoPriv, GetRequest, codecUSM(t, SHA384, NoPriv)))},
		{"v3/auth-no-priv/sha512", marshal(v3(AuthNoPriv, GetRequest, codecUSM(t, SHA512, NoPriv)))},
		{"v3/auth-no-priv/flags-without-keys", marshal(v3(AuthNoPriv, GetRequest, &UsmSecurityParameters{UserName: "codec-user"}))},
		{"v3/auth-priv/sha-aes", marshal(v3(AuthPriv, GetRequest, withPrivSalt(codecUSM(t, SHA, AES))))},
		{"v3/auth-priv/sha-aes192", marshal(v3(AuthPriv, GetRequest, withPrivSalt(codecUSM(t, SHA, AES192))))},
		{"v3/auth-priv/sha-aes256c", marshal(v3(AuthPriv, GetRequest, withPrivSalt(codecUSM(t, SHA, AES256C))))},
		{"v3/auth-priv/md5-des", marshal(v3(AuthPriv, GetRequest, withPrivSalt(codecUSM(t, MD5, DES))))},
		{"v3/auth-priv/sha-aes/without-salt", marshal(v3(AuthPriv, GetRequest, codecUSM(t, SHA, AES)))},
		{"v3/no-auth-no-priv/20-varbinds", marshal(withVars(v3(NoAuthNoPriv, GetResponse, codecUSM(t, NoAuth, NoPriv)), hostVars(20)))},
		{"v3/auth-no-priv/sha/20-varbinds", marshal(withVars(v3(AuthNoPriv, GetResponse, codecUSM(t, SHA, NoPriv)), hostVars(20)))},
		{"v3/auth-priv/sha-aes/4-varbinds", marshal(withVars(v3(AuthPriv, GetResponse, withPrivSalt(codecUSM(t, SHA, AES))), hostVars(4)))},
		{"v3/auth-priv/sha-aes/20-varbinds", marshal(withVars(v3(AuthPriv, GetResponse, withPrivSalt(codecUSM(t, SHA, AES))), hostVars(20)))},
		{"v3/auth-priv/md5-des/4-varbinds", marshal(withVars(v3(AuthPriv, GetResponse, withPrivSalt(codecUSM(t, MD5, DES))), hostVars(4)))},
		{"v3/auth-priv/md5-des/20-varbinds", marshal(withVars(v3(AuthPriv, GetResponse, withPrivSalt(codecUSM(t, MD5, DES))), hostVars(20)))},
		{"v3/auth-priv/md5-des/without-salt", marshal(v3(AuthPriv, GetRequest, codecUSM(t, MD5, DES)))},

		// SnmpEncodePacket builds the packet from the GoSNMP configuration.
		{"encode-packet/v1/get-request", func() ([]byte, error) {
			x := &GoSNMP{Version: Version1, Community: "public"}
			return x.SnmpEncodePacket(GetRequest, nullVar, 0, 0)
		}},
		{"encode-packet/v2c/getbulk-request", func() ([]byte, error) {
			x := &GoSNMP{Version: Version2c, Community: "public"}
			return x.SnmpEncodePacket(GetBulkRequest, nullVar, 1, 10)
		}},
		{"encode-packet/v2c/getbulk-request/max-repetitions-max-uint32", func() ([]byte, error) {
			x := &GoSNMP{Version: Version2c, Community: "public"}
			return x.SnmpEncodePacket(GetBulkRequest, nullVar, 0, math.MaxUint32)
		}},
		{"encode-packet/v3/auth-no-priv/sha", func() ([]byte, error) {
			x := &GoSNMP{
				Version:            Version3,
				MsgFlags:           AuthNoPriv,
				SecurityModel:      UserSecurityModel,
				SecurityParameters: codecUSM(t, SHA, NoPriv),
				ContextName:        "codec-context",
			}
			return x.SnmpEncodePacket(GetRequest, nullVar, 0, 0)
		}},
	}
}
