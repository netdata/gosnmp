// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// TestEncodeCharacterization pins the bytes Message.Encode and EncodeMessage
// produce for packets that cover every PDU layout, SNMPv3 security level,
// length form and OID edge case, or whether they fail or panic.
func TestEncodeCharacterization(t *testing.T) {
	cases, wide := encodeCases(t)

	results := make([]goldenCase, 0, len(cases))
	for _, c := range cases {
		gc := goldenCase{name: c.name, wide: wide[c.name]}
		if !gc.skipped() {
			usm.Salts.Set(0x0000000700000001) // the salt of an encrypted case
			gc.dump = dumpEncode(c.encode)
		}
		results = append(results, gc)
	}
	codecGolden.check(t, "encode", results)
}

// TestMarshalLongOctetStringFields encodes communities and USM engine IDs
// longer than 127 bytes, and a user name of 32 bytes (the most RFC 3414
// section 2.4 allows), and decodes them back.
func TestMarshalLongOctetStringFields(t *testing.T) {
	type fields struct {
		community, engineID, userName string
	}
	long := func(n int) string { return strings.Repeat("x", n) }
	tests := map[string]fields{
		"community 128 bytes": {community: long(128)},
		"community 256 bytes": {community: long(256)},
		"community 300 bytes": {community: long(300)},
		"engine ID 64 bytes":  {engineID: long(64), userName: "user"},
		"engine ID 128 bytes": {engineID: long(128), userName: "user"},
		"engine ID 300 bytes": {engineID: long(300), userName: "user"},
		"user name 32 bytes":  {engineID: "\x80\x00\x1f\x88\x04engine", userName: long(32)},
	}

	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			packet := &Message{
				Version:   Version2c,
				Community: want.community,
				PDUType:   GetRequest,
				RequestID: 1,
				VarBinds:  []VarBind{{Name: ".1.3.6.1.2.1.1.1.0", Type: Null}},
			}
			if want.community == "" {
				packet.Version = Version3
				packet.SecurityLevel = NoAuthNoPriv
				packet.MsgID = 1
				packet.SecurityParameters = SecurityParameters{AuthoritativeEngineID: []byte(want.engineID), UserName: want.userName}
			}
			msg, err := packet.Encode(nil)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if len(want.engineID) > maxDecodedEngineIDLen {
				// Longer than the decoder takes: the fields as the encoder
				// laid them out.
				_, err = (&Client{}).DecodeMessage(msg)
				require.ErrorIs(t, err, ErrASNParse)
				m := splitV3Message(t, msg)
				if got := (fields{engineID: string(m.usm[0]), userName: string(m.usm[3])}); got != want {
					t.Errorf("encoded %+v, want %+v", got, want)
				}
				return
			}

			decoded, err := (&Client{}).DecodeMessage(msg)
			if err != nil {
				t.Fatalf("decoding the encoded message: %v\nmessage: %x", err, msg)
			}
			got := fields{
				community: decoded.Community,
				engineID:  string(decoded.SecurityParameters.AuthoritativeEngineID),
				userName:  decoded.SecurityParameters.UserName,
			}
			if got != want {
				t.Errorf("decoded %+v, want %+v", got, want)
			}
		})
	}
}

// TestMarshalUnencodableValues checks that Message.Encode reports caller values
// it cannot encode as errors instead of panicking.
func TestMarshalUnencodableValues(t *testing.T) {
	varbind := func(typ ValueType, value any) *Message {
		return &Message{
			Version:   Version2c,
			Community: "public",
			PDUType:   SetRequest,
			RequestID: 1,
			VarBinds:  []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: typ, Value: value}},
		}
	}
	trap := func(agentAddress string) *Message {
		return &Message{
			Version:      Version1,
			Community:    "public",
			PDUType:      Trap,
			Enterprise:   ".1.3.6.1.4.1.20372",
			AgentAddress: agentAddress,
			GenericTrap:  6,
		}
	}
	tests := map[string]*Message{
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
			panicked, _ := observe(func() { _, err = packet.Encode(nil) })
			if panicked || err == nil {
				t.Errorf("Encode panicked: %v, error: %v; want an error", panicked, err)
			}
		})
	}
}

// TestEncodeValueTypesCharacterization pins, for every value tag, the value
// TLV that Message.Encode writes for each Go value type, or whether it fails or
// panics. It records which Go types the encoder accepts.
func TestEncodeValueTypesCharacterization(t *testing.T) {
	tags := []ValueType{
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
		{`string("::ffff:192.0.2.1")`, "::ffff:192.0.2.1"},
		{`string("x")`, "x"},
		{`[]byte("x")`, []byte("x")},
		{"[]byte{}", []byte{}},
		{"[]byte{192, 0, 2, 1}", []byte{192, 0, 2, 1}},
		{"[]byte{1, 2, 3, 4, 5}", []byte{1, 2, 3, 4, 5}},
		{"[]byte of 2001:db8::1", []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}

	results := make([]goldenCase, 0, len(tags))
	for _, tag := range tags {
		var d dumpWriter
		for _, v := range values {
			pkt := &Message{
				Version:   Version2c,
				Community: "public",
				PDUType:   SetRequest,
				RequestID: 1,
				VarBinds:  []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: tag, Value: v.value}},
			}
			d.linef("%s: %s", v.label, dumpVarbindValue(pkt))
		}
		results = append(results, goldenCase{name: fmt.Sprintf("0x%02x %s", byte(tag), tag), dump: d.String()})
	}
	codecGolden.check(t, "encode-value-types", results)
}

// TestEncodeReportableFlag checks the msgFlags octet of SNMPv3 messages: the
// security level, and the reportable flag set exactly for a PDU of the
// Confirmed Class (RFC 3412 section 6.4), through Message.Encode and
// EncodeMessage.
func TestEncodeReportableFlag(t *testing.T) {
	pduTypes := []PDUType{
		GetRequest, GetNextRequest, GetBulkRequest, SetRequest, InformRequest, Response, SNMPv2Trap, Report, Trap,
	}
	trap := TrapV1Header{Enterprise: ".1.3.6.1.4.1.20372", AgentAddress: "192.0.2.1", GenericTrap: 6}
	vars := []VarBind{{Name: ".1.3.6.1.2.1.1.1.0", Type: Null}}

	for _, pdu := range pduTypes {
		for _, level := range []SecurityLevel{NoAuthNoPriv, AuthNoPriv} {
			t.Run(fmt.Sprintf("Encode/%v/%v", pdu, level), func(t *testing.T) {
				user := codecUser(levelAuth(level), NoPriv)
				msg, err := (&Message{
					Version: Version3, SecurityLevel: level, SecurityParameters: codecHeader(),
					PDUType: pdu, MsgID: 1, RequestID: 1, TrapV1Header: trap, VarBinds: vars,
				}).Encode(&user)
				if err != nil {
					t.Fatalf("Encode: %v", err)
				}
				if got, want := wireFlags(t, msg), classFlags(level, pdu); got != want {
					t.Errorf("msgFlags %v, want %v", got, want)
				}
			})
			if pdu == Trap {
				continue // EncodeMessage has no SNMPv1 trap fields
			}
			t.Run(fmt.Sprintf("EncodeMessage/%v/%v", pdu, level), func(t *testing.T) {
				x := &Client{Version: Version3, SecurityLevel: level, User: codecUser(levelAuth(level), NoPriv)}
				seedEngine(codecEngineID, 7, 1234)(x) // EncodeMessage signs with the engine state's keys
				msg, err := x.EncodeMessage(pdu, vars, 0, 0)
				if err != nil {
					t.Fatalf("EncodeMessage: %v", err)
				}
				if got, want := wireFlags(t, msg), classFlags(level, pdu); got != want {
					t.Errorf("msgFlags %v, want %v", got, want)
				}
			})
		}
	}
}

// classFlags is the msgFlags octet of a message of level and pdu: the
// reportableFlag for a PDU of the Confirmed Class.
func classFlags(level SecurityLevel, pdu PDUType) SecurityLevel {
	if pdu.confirmed() {
		return level | reportableFlag
	}
	return level
}

// TestInvalidSecurityLevel checks that a security level other than the three
// fails: the encoder's check (Message.Encode), the client's (validate, as
// Connect, EncodeMessage and DecodeMessage run it) and UnmarshalTrap's single
// path, which requires the client's level unless told to use the message's;
// privacy without authentication has its own error in the encoder.
func TestInvalidSecurityLevel(t *testing.T) {
	const invalid = "validate: SecurityLevel must be populated with an appropriate security level"
	tests := map[string]struct {
		level            SecurityLevel
		encodeErr, valid string
	}{
		"privacy without authentication": {level: AuthPriv &^ AuthNoPriv, encodeErr: "unable to marshal SNMPv3 msgFlags: privacy without authentication", valid: invalid},
		"the reportableFlag's bit":       {level: reportableFlag, encodeErr: "unable to marshal SNMPv3 security level 4: not NoAuthNoPriv, AuthNoPriv or AuthPriv", valid: invalid},
		"authNoPriv and another bit":     {level: AuthNoPriv | reportableFlag, encodeErr: "unable to marshal SNMPv3 security level 5: not NoAuthNoPriv, AuthNoPriv or AuthPriv", valid: invalid},
		"authPriv and another bit":       {level: AuthPriv | 0x80, encodeErr: "unable to marshal SNMPv3 security level 131: not NoAuthNoPriv, AuthNoPriv or AuthPriv", valid: invalid},
	}
	trap, err := (&Message{
		Version: Version3, SecurityLevel: NoAuthNoPriv, SecurityParameters: codecHeader(),
		PDUType: SNMPv2Trap, MsgID: 1, RequestID: 1,
	}).Encode(nil)
	require.NoError(t, err)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			receiver := &Client{Version: Version3, SecurityLevel: tc.level, User: codecUser(NoAuth, NoPriv)}
			_, err := receiver.UnmarshalTrap(bytes.Clone(trap), false)
			require.EqualError(t, err, tc.valid, "UnmarshalTrap")
			_, err = receiver.UnmarshalTrap(bytes.Clone(trap), true)
			require.NoError(t, err, "UnmarshalTrap with the message's level")
			user := codecUser(SHA, AES)
			_, err = (&Message{
				Version: Version3, SecurityLevel: tc.level, SecurityParameters: codecHeader(),
				PDUType: GetRequest, MsgID: 1, RequestID: 1,
			}).Encode(&user)
			require.EqualError(t, err, tc.encodeErr)
			x := &Client{Version: Version3, SecurityLevel: tc.level, User: user}
			_, err = x.EncodeMessage(GetRequest, nil, 0, 0)
			require.EqualError(t, err, tc.valid)
		})
	}
}

// TestEncodeDerivesLevelKeys pins that Message.Encode derives only the keys
// the message's security level uses, after checking the user's protocols: a
// key the level needs that does not derive fails the signer or the cipher, one
// it does not need is not derived.
func TestEncodeDerivesLevelKeys(t *testing.T) {
	sha := usmUser(SHA, "codec-auth-pass", NoPriv, "")
	shaAES := usmUser(SHA, "codec-auth-pass", AES, "")
	tests := map[string]struct {
		level   SecurityLevel
		user    User
		wantErr string
	}{
		"noAuthNoPriv, an authentication protocol without a passphrase": {level: NoAuthNoPriv, user: User{Name: "codec-user", AuthProtocol: SHA}},
		"noAuthNoPriv, an unsupported protocol": {
			level: NoAuthNoPriv, user: User{Name: "codec-user", AuthProtocol: 99}, wantErr: "User.AuthProtocol AuthProtocol(99) is not supported",
		},
		"authNoPriv": {level: AuthNoPriv, user: sha},
		"authNoPriv, a privacy protocol without a passphrase": {level: AuthNoPriv, user: shaAES},
		"authNoPriv, no authentication passphrase": {
			level: AuthNoPriv, user: User{Name: "codec-user", AuthProtocol: SHA}, wantErr: "usm: no authentication key, want 20 octets",
		},
		"authPriv, no privacy passphrase": {level: AuthPriv, user: shaAES, wantErr: "usm: encrypting: no privacy key, want 16 octets"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := (&Message{
				Version: Version3, SecurityLevel: tc.level, SecurityParameters: codecHeader(),
				PDUType: SNMPv2Trap, MsgID: 1, RequestID: 1,
			}).Encode(&tc.user)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.wantErr)
			}
		})
	}
}

// TestValueKinds checks the value kinds: a type with a kind encodes and one
// without does not, and the decoder reads each kind's boundary values as the
// encoder writes them back to the same type and a value that encodes the same.
func TestValueKinds(t *testing.T) {
	maxOID := ".2.4294967295" + strings.Repeat(".4294967295", 126) // 128 arcs, each the largest
	samples := map[valueKind][]any{
		kindNone:       {nil},
		kindNull:       {nil},
		kindInteger:    {1, 0, math.MinInt32, math.MaxInt32},
		kindUnsigned32: {uint32(1), uint32(0), uint32(math.MaxUint32), uint(math.MaxUint32)},
		kindCounter64:  {uint64(1), uint64(0), uint64(math.MaxUint64)},
		kindOctets:     {[]byte("x"), []byte{}, "text"},
		kindOID:        {".1.3.6.1", ".0.0", maxOID},
		kindIPAddress:  {"192.0.2.1", []byte{192, 0, 2, 1}, "2001:db8::1", make([]byte, 16)},
	}
	for tag := range 256 {
		kind := valueKinds[tag]
		values := samples[kind]
		switch ValueType(tag) {
		case OpaqueFloat:
			values = []any{float32(1), float32(-0.5), float32(math.MaxFloat32)}
		case OpaqueDouble:
			values = []any{float64(1), math.MaxFloat64}
		}
		for _, value := range values {
			out, err := appendValue(nil, ValueType(tag), value)
			switch {
			case kind == kindNone && err == nil:
				t.Errorf("%v: encodes without a kind", ValueType(tag))
			case kind != kindNone && err != nil:
				t.Errorf("%v %#v: %v", ValueType(tag), value, err)
			case err == nil:
				r := ber.NewReader(out)
				wireTag, content, err := r.Next()
				if err != nil {
					t.Fatalf("%v: %x: %v", ValueType(tag), out, err)
				}
				typ, decoded, err := decodeValue(ValueType(wireTag), content)
				if err != nil {
					t.Fatalf("%v: decoding %x: %v", ValueType(tag), out, err)
				}
				again, err := appendValue(nil, typ, decoded)
				if typ != ValueType(tag) || err != nil || !bytes.Equal(again, out) {
					t.Errorf("%v %#v: decodes as %v %#v, which encodes as %x (%v), not %x", ValueType(tag), value, typ, decoded, again, err, out)
				}
			}
		}
	}
}

// levelAuth is the authentication protocol codecUser needs for level.
func levelAuth(level SecurityLevel) AuthProtocol {
	if level.authFlag() {
		return SHA
	}
	return NoAuth
}

// wireFlags returns the msgFlags octet of the SNMPv3 message msg, read from
// msgGlobalData without parsing the rest.
func wireFlags(t *testing.T, msg []byte) SecurityLevel {
	t.Helper()
	next := func(r *ber.Reader) []byte {
		_, content, err := r.Next()
		if err != nil {
			t.Fatalf("reading msgFlags: %v\nmessage: %x", err, msg)
		}
		return content
	}
	r := ber.NewReader(msg)
	m := ber.NewReader(next(&r))
	next(&m) // msgVersion
	g := ber.NewReader(next(&m))
	next(&g) // msgID
	next(&g) // msgMaxSize
	flags := next(&g)
	if len(flags) != 1 {
		t.Fatalf("msgFlags of %d octets\nmessage: %x", len(flags), msg)
	}
	return SecurityLevel(flags[0])
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
func dumpVarbindValue(pkt *Message) string {
	var out []byte
	var err error
	panicked, wroteStdout := observe(func() { out, err = pkt.Encode(nil) })

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

// codecEngineID is the authoritative engine ID of the synthetic codec messages.
const codecEngineID = "\x80\x00\x1f\x88\x04codec-engine"

// codecUser returns the synthetic codec-user with the protocols auth and priv
// and the codec passphrases.
func codecUser(auth AuthProtocol, priv PrivProtocol) User {
	return usmUser(auth, "codec-auth-pass", priv, "codec-priv-pass")
}

// codecHeader returns the USM header of the synthetic codec messages: the
// codec engine ID, boots 7, time 1234 and codec-user.
func codecHeader() SecurityParameters {
	return SecurityParameters{
		AuthoritativeEngineID:    []byte(codecEngineID),
		AuthoritativeEngineBoots: 7,
		AuthoritativeEngineTime:  1234,
		UserName:                 "codec-user",
	}
}

// encodeCases returns the encode characterization cases and the names of those
// whose input needs a 64-bit int or uint (goldenCase.wide).
func encodeCases(t *testing.T) ([]encodeCase, map[string]bool) {
	t.Helper()

	wide := make(map[string]bool)
	wideCase := func(name string, encode func() ([]byte, error)) encodeCase {
		wide[name] = true
		return encodeCase{name, encode}
	}

	nullVar := []VarBind{{Name: ".1.3.6.1.2.1.1.1.0", Type: Null}}
	mixedVars := []VarBind{
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
	trap := TrapV1Header{
		Enterprise:   ".1.3.6.1.4.1.20372",
		AgentAddress: "192.0.2.1",
		GenericTrap:  6,
		SpecificTrap: 42,
		Timestamp:    256,
	}

	v2c := func(pduType PDUType, vars []VarBind) *Message {
		return &Message{Version: Version2c, Community: "public", PDUType: pduType, RequestID: 1, VarBinds: vars}
	}
	beyondInt32 := int64(math.MaxInt32) + 1
	beyondUint32 := uint64(math.MaxUint32) + 1
	// uintValue is a SetRequest of one varbind of typ holding the uint v.
	uintValue := func(typ ValueType, v uint64) *Message {
		return v2c(SetRequest, []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: typ, Value: uint(v)}})
	}
	v1Trap := func(edit func(*TrapV1Header)) *Message {
		tr := trap
		edit(&tr)
		return &Message{Version: Version1, Community: "public", PDUType: Trap, TrapV1Header: tr, VarBinds: nullVar}
	}
	v3 := func(flags SecurityLevel, pduType PDUType) *Message {
		return &Message{
			Version:       Version3,
			SecurityLevel: flags,

			SecurityParameters: codecHeader(),
			ContextEngineID:    []byte(codecEngineID),
			ContextName:        "codec-context",
			PDUType:            pduType,
			MsgID:              4242,
			RequestID:          123456,
			VarBinds:           nullVar,
		}
	}
	// hostVars are n OctetString varbinds; 4 make a v3 scoped PDU need a two-octet
	// length, 20 a three-octet one.
	hostVars := func(n int) []VarBind {
		vars := make([]VarBind, n)
		for i := range vars {
			vars[i] = VarBind{Name: ".1.3.6.1.2.1.1.5." + strconv.Itoa(i), Type: OctetString, Value: []byte("codec-host-" + strconv.Itoa(i))}
		}
		return vars
	}
	withVars := func(p *Message, vars []VarBind) *Message { p.VarBinds = vars; return p }
	oidName := func(name string) *Message { return v2c(GetRequest, []VarBind{{Name: name, Type: Null}}) }
	// withPacketSalt gives the packet a salt of its own, unlike the drawn one:
	// the encoder must neither send nor encrypt with it.
	withPacketSalt := func(p *Message) *Message {
		p.SecurityParameters.PrivacyParameters = []byte{0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee}
		return p
	}
	// fixedIDs starts the client's ID counters at 0, so that its request ID
	// and msgID are 1 (a client draws random ones otherwise).
	fixedIDs := func(x *Client) *Client {
		x.SetRequestID(0)
		x.SetMsgID(0)
		return x
	}
	marshal := func(p *Message) func() ([]byte, error) { return func() ([]byte, error) { return p.Encode(nil) } }
	// marshalAs encodes the SNMPv3 message p with the codec-user of the
	// protocols auth and priv.
	marshalAs := func(auth AuthProtocol, priv PrivProtocol, p *Message) func() ([]byte, error) {
		user := codecUser(auth, priv)
		return func() ([]byte, error) { return p.Encode(&user) }
	}
	// marshalWithKeys encodes the SNMPv3 message p with keys no user derives.
	marshalWithKeys := func(keys usmKeys, p *Message) func() ([]byte, error) {
		return func() ([]byte, error) { return p.marshalMsg(&keys) }
	}
	edit := func(p *Message, f func(*Message)) *Message { f(p); return p }

	return []encodeCase{
		// v1 and v2c PDUs.
		{"v1/get-request", marshal(&Message{Version: Version1, Community: "public", PDUType: GetRequest, RequestID: 1, VarBinds: nullVar})},
		{"v2c/get-request", marshal(v2c(GetRequest, nullVar))},
		{"v2c/get-request/no-varbinds", marshal(v2c(GetRequest, nil))},
		{"v2c/get-next-request", marshal(v2c(GetNextRequest, nullVar))},
		{"v2c/getbulk-request", marshal(edit(v2c(GetBulkRequest, slices.Concat(nullVar, nullVar)), func(p *Message) { p.NonRepeaters, p.MaxRepetitions = 1, 10 }))},
		{"v2c/getbulk-request/max-repetitions-2^31", marshal(edit(v2c(GetBulkRequest, nullVar), func(p *Message) { p.MaxRepetitions = 1 << 31 }))},
		{"v2c/getbulk-request/max-repetitions-max-uint32", marshal(edit(v2c(GetBulkRequest, nullVar), func(p *Message) { p.MaxRepetitions = math.MaxUint32 }))},
		{"v2c/getbulk-request/non-repeaters-200", marshal(edit(v2c(GetBulkRequest, nullVar), func(p *Message) { p.NonRepeaters = 200 }))},
		{"v2c/getbulk-request/request-id-2^31", marshal(edit(v2c(GetBulkRequest, nullVar), func(p *Message) { p.RequestID = 1 << 31 }))},
		{"v2c/set-request/mixed-types", marshal(v2c(SetRequest, mixedVars))},
		{"v2c/get-response/error", marshal(edit(v2c(Response, nullVar), func(p *Message) { p.ErrorStatus, p.ErrorIndex = GenErr, 2 }))},
		{"v2c/get-response/error-index-255", marshal(edit(v2c(Response, nullVar), func(p *Message) { p.ErrorStatus, p.ErrorIndex = TooBig, 255 }))},
		{"v2c/snmpv2-trap", marshal(v2c(SNMPv2Trap, mixedVars[:3]))},
		{"v2c/inform-request", marshal(v2c(InformRequest, nullVar))},
		{"v2c/inform-request/is-inform-flag", marshal(edit(v2c(SNMPv2Trap, nullVar), func(p *Message) { p.IsInform = true }))},
		{"v2c/report", marshal(v2c(Report, nullVar))},
		{"v2c/unknown-pdu-type", marshal(v2c(PDUType(0xa9), nullVar))},
		{"v2c/request-id-0", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.RequestID = 0 }))},
		{"v2c/request-id-2^31", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.RequestID = 1 << 31 }))},
		{"v2c/request-id-max-uint32", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.RequestID = math.MaxUint32 }))},
		{"v2c/version-2", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.Version = 2 }))},
		wideCase("v2c/set-request/counter32-uint-2^32", marshal(uintValue(Counter32, beyondUint32))),
		wideCase("v2c/set-request/gauge32-uint-2^32", marshal(uintValue(Gauge32, beyondUint32))),
		wideCase("v2c/set-request/timeticks-uint-2^32", marshal(uintValue(TimeTicks, beyondUint32))),
		wideCase("v2c/set-request/uinteger32-uint-2^32", marshal(uintValue(Uinteger32, beyondUint32))),

		// Lengths.
		{"v2c/community-empty", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.Community = "" }))},
		{"v2c/community-127", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.Community = strings.Repeat("c", 127) }))},
		{"v2c/community-128", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.Community = strings.Repeat("c", 128) }))},
		{"v2c/community-256", marshal(edit(v2c(GetRequest, nullVar), func(p *Message) { p.Community = strings.Repeat("c", 256) }))},
		{"v2c/octet-string-127", marshal(v2c(SetRequest, []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 127))}}))},
		// 116 value octets make the varbind content exactly 128 bytes, the first long-form length.
		{"v2c/varbind-content-128", marshal(v2c(SetRequest, []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 116))}}))},
		{"v2c/octet-string-200", marshal(v2c(SetRequest, []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 200))}}))},
		{"v2c/octet-string-300", marshal(v2c(SetRequest, []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 300))}}))},
		{"v2c/octet-string-70000", marshal(v2c(SetRequest, []VarBind{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte(strings.Repeat("o", 70000))}}))},
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
		{"oid/128-arcs", marshal(oidName(".1.3" + strings.Repeat(".1", 126)))},
		{"oid/129-arcs", marshal(oidName(".1.3" + strings.Repeat(".1", 127)))},
		{"oid/content-128", marshal(oidName(".1.3" + strings.Repeat(".129", 63) + ".1"))},
		{"oid/first-packed-value-max-uint32", marshal(oidName(".2.4294967215"))},
		{"oid/first-packed-value-over-uint32", marshal(oidName(".2.4294967216"))},
		{"oid/second-arc-max-uint32", marshal(oidName(".2.4294967295"))},
		{"oid/second-arc-over-uint32", marshal(oidName(".2.4294967296"))},

		// v1 Trap.
		{"v1-trap/basic", marshal(v1Trap(func(*TrapV1Header) {}))},
		{"v1-trap/agent-address-empty", marshal(v1Trap(func(tr *TrapV1Header) { tr.AgentAddress = "" }))},
		{"v1-trap/agent-address-ipv4-mapped", marshal(v1Trap(func(tr *TrapV1Header) { tr.AgentAddress = "::ffff:192.0.2.1" }))},
		{"v1-trap/agent-address-ipv6", marshal(v1Trap(func(tr *TrapV1Header) { tr.AgentAddress = "2001:db8::1" }))},
		{"v1-trap/agent-address-invalid", marshal(v1Trap(func(tr *TrapV1Header) { tr.AgentAddress = "not-an-ip" }))},
		{"v1-trap/enterprise-empty", marshal(v1Trap(func(tr *TrapV1Header) { tr.Enterprise = "" }))},
		{"v1-trap/generic-negative", marshal(v1Trap(func(tr *TrapV1Header) { tr.GenericTrap = -1 }))},
		{"v1-trap/specific-max-int32", marshal(v1Trap(func(tr *TrapV1Header) { tr.SpecificTrap = math.MaxInt32 }))},
		wideCase("v1-trap/generic-2^31", marshal(v1Trap(func(tr *TrapV1Header) { tr.GenericTrap = int(beyondInt32) }))),
		wideCase("v1-trap/specific-2^31", marshal(v1Trap(func(tr *TrapV1Header) { tr.SpecificTrap = int(beyondInt32) }))),
		{"v1-trap/timestamp-max-uint32", marshal(v1Trap(func(tr *TrapV1Header) { tr.Timestamp = math.MaxUint32 }))},
		wideCase("v1-trap/timestamp-2^32", marshal(v1Trap(func(tr *TrapV1Header) { tr.Timestamp = uint(beyondUint32) }))),
		{"v1-trap/in-v2c-message", marshal(edit(v1Trap(func(*TrapV1Header) {}), func(p *Message) { p.Version = Version2c }))},

		// SNMPv3.
		{"v3/no-auth-no-priv/discovery", marshal(edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters, p.ContextEngineID, p.ContextName, p.VarBinds = SecurityParameters{}, nil, "", nil
		}))},
		{"v3/no-auth-no-priv/get-request", marshalAs(NoAuth, NoPriv, v3(NoAuthNoPriv, GetRequest))},
		{"v3/no-auth-no-priv/msg-id-2^31", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgID = 1 << 31 }))},
		{"v3/no-auth-no-priv/engine-id-200", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.AuthoritativeEngineID = bytes.Repeat([]byte("e"), 200)
		}))},
		{"v3/no-auth-no-priv/user-name-200", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.UserName = strings.Repeat("u", 200)
		}))},
		{"v3/no-auth-no-priv/user-name-32", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.UserName = strings.Repeat("u", 32)
		}))},
		{"v3/no-auth-no-priv/user-name-33", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.UserName = strings.Repeat("u", 33)
		}))},
		{"v3/no-auth-no-priv/max-size-483", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgMaxSize = 483 }))},
		{"v3/no-auth-no-priv/max-size-484", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgMaxSize = 484 }))},
		{"v3/no-auth-no-priv/msg-id-max-int32", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgID = math.MaxInt32 }))},
		{"v3/no-auth-no-priv/reserved-flags", marshalAs(NoAuth, NoPriv, v3(NoAuthNoPriv|0xf8, GetRequest))},
		{"v3/no-auth-no-priv/v1-trap-pdu", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, Trap), func(p *Message) { p.TrapV1Header = trap }))},
		{"v3/no-auth-no-priv/engine-boots-2^31", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.AuthoritativeEngineBoots = 1 << 31
		}))},
		{"v3/no-auth-no-priv/engine-time-2^31", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.AuthoritativeEngineTime = 1 << 31
		}))},
		{"v3/no-auth-no-priv/engine-boots-and-time-max-int32", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			h := &p.SecurityParameters
			h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime = math.MaxInt32, math.MaxInt32
		}))},
		{"v3/no-auth-no-priv/max-size-1500", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgMaxSize = 1500 }))},
		{"v3/no-auth-no-priv/max-size-max-int32", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgMaxSize = math.MaxInt32 }))},
		{"v3/no-auth-no-priv/max-size-2^31", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) { p.MsgMaxSize = 1 << 31 }))},
		{"v3/no-auth-no-priv/engine-boots-and-time-2^31", marshalAs(NoAuth, NoPriv, edit(v3(NoAuthNoPriv, GetRequest), func(p *Message) {
			h := &p.SecurityParameters
			h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime = 1<<31, 1<<31+1
		}))},
		{"v3/no-auth-no-priv/report", marshalAs(NoAuth, NoPriv, v3(NoAuthNoPriv, Report))},
		{"v3/auth-no-priv/md5", marshalAs(MD5, NoPriv, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha", marshalAs(SHA, NoPriv, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha224", marshalAs(SHA224, NoPriv, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha256", marshalAs(SHA256, NoPriv, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha384", marshalAs(SHA384, NoPriv, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha512", marshalAs(SHA512, NoPriv, v3(AuthNoPriv, GetRequest))},
		// Authentication keys of 80 octets, longer than the hash and the 64-octet
		// HMAC block: refused, as any key of another size than the hash's.
		{"v3/auth-no-priv/md5/key-80", marshalWithKeys(usmKeys{authProtocol: MD5, auth: []byte(strings.Repeat("k", 80))}, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha/key-80", marshalWithKeys(usmKeys{authProtocol: SHA, auth: []byte(strings.Repeat("k", 80))}, v3(AuthNoPriv, GetRequest))},
		{"v3/auth-no-priv/sha256/key-80", marshalWithKeys(usmKeys{authProtocol: SHA256, auth: []byte(strings.Repeat("k", 80))}, v3(AuthNoPriv, GetRequest))},
		// A user name or engine ID that holds the octets of the zero
		// placeholder keeps them: the digest goes into the field.
		{"v3/auth-no-priv/md5/placeholder-in-user-name", marshalAs(MD5, NoPriv, edit(v3(AuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.UserName = "\x04\x0c" + strings.Repeat("\x00", 12)
		}))},
		{"v3/auth-no-priv/md5/placeholder-in-engine-id", marshalAs(MD5, NoPriv, edit(v3(AuthNoPriv, GetRequest), func(p *Message) {
			p.SecurityParameters.AuthoritativeEngineID = []byte("\x80\x00\x1f\x88\x04\x04\x0c" + strings.Repeat("\x00", 12))
		}))},
		{"v3/auth-no-priv/flags-without-keys", marshal(v3(AuthNoPriv, GetRequest))},
		{"v3/auth-priv/sha-aes", marshalAs(SHA, AES, withPacketSalt(v3(AuthPriv, GetRequest)))},
		{"v3/auth-priv/sha-aes192", marshalAs(SHA, AES192, withPacketSalt(v3(AuthPriv, GetRequest)))},
		{"v3/auth-priv/sha-aes256c", marshalAs(SHA, AES256C, withPacketSalt(v3(AuthPriv, GetRequest)))},
		{"v3/auth-priv/md5-des", marshalAs(MD5, DES, withPacketSalt(v3(AuthPriv, GetRequest)))},
		{"v3/priv-without-auth/sha-aes", marshalAs(SHA, AES, withPacketSalt(v3(AuthPriv&^AuthNoPriv, GetRequest)))},
		{"v3/auth-priv/sha-aes/without-salt", marshalAs(SHA, AES, v3(AuthPriv, GetRequest))},
		{"v3/no-auth-no-priv/20-varbinds", marshalAs(NoAuth, NoPriv, withVars(v3(NoAuthNoPriv, Response), hostVars(20)))},
		{"v3/auth-no-priv/sha/20-varbinds", marshalAs(SHA, NoPriv, withVars(v3(AuthNoPriv, Response), hostVars(20)))},
		{"v3/auth-priv/sha-aes/4-varbinds", marshalAs(SHA, AES, withVars(withPacketSalt(v3(AuthPriv, Response)), hostVars(4)))},
		{"v3/auth-priv/sha-aes/20-varbinds", marshalAs(SHA, AES, withVars(withPacketSalt(v3(AuthPriv, Response)), hostVars(20)))},
		{"v3/auth-priv/md5-des/4-varbinds", marshalAs(MD5, DES, withVars(withPacketSalt(v3(AuthPriv, Response)), hostVars(4)))},
		{"v3/auth-priv/md5-des/20-varbinds", marshalAs(MD5, DES, withVars(withPacketSalt(v3(AuthPriv, Response)), hostVars(20)))},
		{"v3/auth-priv/md5-des/without-salt", marshalAs(MD5, DES, v3(AuthPriv, GetRequest))},

		// EncodeMessage builds the message from the client's configuration.
		{"encode-packet/v1/get-request", func() ([]byte, error) {
			x := fixedIDs(&Client{Version: Version1, Community: "public"})
			return x.EncodeMessage(GetRequest, nullVar, 0, 0)
		}},
		{"encode-packet/v2c/getbulk-request", func() ([]byte, error) {
			x := fixedIDs(&Client{Version: Version2c, Community: "public"})
			return x.EncodeMessage(GetBulkRequest, nullVar, 1, 10)
		}},
		{"encode-packet/v2c/getbulk-request/max-repetitions-max-uint32", func() ([]byte, error) {
			x := fixedIDs(&Client{Version: Version2c, Community: "public"})
			return x.EncodeMessage(GetBulkRequest, nullVar, 0, math.MaxUint32)
		}},
		// An SNMPv3 one takes the engine state a request learned: the codec
		// engine with boots 7 and time 1234.
		{"encode-packet/v3/auth-no-priv/sha", func() ([]byte, error) {
			x := fixedIDs(&Client{
				Version:       Version3,
				SecurityLevel: AuthNoPriv,
				User:          codecUser(SHA, NoPriv),
				ContextName:   "codec-context",
			})
			seedEngine(codecEngineID, 7, 1234)(x)
			return x.EncodeMessage(GetRequest, nullVar, 0, 0)
		}},
		{"encode-packet/v3/auth-priv/sha-aes", func() ([]byte, error) {
			x := fixedIDs(&Client{
				Version:       Version3,
				SecurityLevel: AuthPriv,
				User:          codecUser(SHA, AES),
				ContextName:   "codec-context",
			})
			seedEngine(codecEngineID, 7, 1234)(x)
			return x.EncodeMessage(GetRequest, nullVar, 0, 0)
		}},
	}, wide
}
