// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// TestValueAccessors pins each accessor's type set: for a value of every type,
// the accessors that return ok and what they return, in the order Int32,
// Uint32, Int64, Uint64, Bytes, OID, IP, Float32, Float64.
func TestValueAccessors(t *testing.T) {
	tests := map[string]struct {
		value Value
		want  string
	}{
		"Integer -1":         {value: IntegerValue(-1), want: "Integer: Int32 -1, Int64 -1"},
		"Integer MinInt32":   {value: IntegerValue(math.MinInt32), want: "Integer: Int32 -2147483648, Int64 -2147483648"},
		"Counter32":          {value: Counter32Value(math.MaxUint32), want: "Counter32: Uint32 4294967295, Int64 4294967295, Uint64 4294967295"},
		"Gauge32":            {value: Gauge32Value(5), want: "Gauge32: Uint32 5, Int64 5, Uint64 5"},
		"TimeTicks":          {value: TimeTicksValue(6), want: "TimeTicks: Uint32 6, Int64 6, Uint64 6"},
		"Uinteger32":         {value: Uinteger32Value(7), want: "Uinteger32: Uint32 7, Int64 7, Uint64 7"},
		"Counter64":          {value: Counter64Value(math.MaxUint64), want: "Counter64: Uint64 18446744073709551615"},
		"OctetString":        {value: OctetStringValue([]byte("x")), want: `OctetString: Bytes "x"`},
		"Opaque":             {value: OpaqueValue([]byte{1}), want: `Opaque: Bytes "\x01"`},
		"ObjectIdentifier":   {value: ObjectIdentifierValue(".1.3"), want: `ObjectIdentifier: OID ".1.3"`},
		"IPAddress":          {value: IPAddressValue(netip.MustParseAddr("192.0.2.1")), want: "IPAddress: IP 192.0.2.1"},
		"IPAddress IPv6":     {value: IPAddressValue(netip.MustParseAddr("2001:db8::1")), want: "IPAddress: IP 2001:db8::1"},
		"IPAddress zero":     {value: IPAddressValue(netip.Addr{}), want: "IPAddress: IP invalid IP"},
		"OpaqueFloat":        {value: OpaqueFloatValue(1.5), want: "OpaqueFloat: Float32 1.5, Float64 1.5"},
		"OpaqueDouble":       {value: OpaqueDoubleValue(-2.25), want: "OpaqueDouble: Float64 -2.25"},
		"Null":               {value: NullValue(), want: "Null:"},
		"NoSuchObject":       {value: NoSuchObjectValue(), want: "NoSuchObject:"},
		"NoSuchInstance":     {value: NoSuchInstanceValue(), want: "NoSuchInstance:"},
		"EndOfMibView":       {value: EndOfMibViewValue(), want: "EndOfMibView:"},
		"the zero Value":     {value: Value{}, want: "UnknownType:"},
		"decoded IPv4-in-16": {value: decodedIPAddress(t, netip.MustParseAddr("::ffff:192.0.2.1").AsSlice()), want: "IPAddress: IP 192.0.2.1"},
		"decoded empty IP":   {value: decodedIPAddress(t, []byte{}), want: "IPAddress: IP invalid IP"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := describeAccessors(tc.value); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	if !reflect.DeepEqual(decodedIPAddress(t, []byte{}), IPAddressValue(netip.Addr{})) {
		t.Error("a decoded empty IPAddress differs from IPAddressValue(netip.Addr{})")
	}
}

// decodedIPAddress decodes content as an IPAddress value.
func decodedIPAddress(t *testing.T, content []byte) Value {
	t.Helper()
	v, err := decodeValue(IPAddress, content)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// describeAccessors lists the type and the accessors that return ok.
func describeAccessors(v Value) string {
	var parts []string
	if x, ok := v.Int32(); ok {
		parts = append(parts, fmt.Sprintf("Int32 %d", x))
	}
	if x, ok := v.Uint32(); ok {
		parts = append(parts, fmt.Sprintf("Uint32 %d", x))
	}
	if x, ok := v.Int64(); ok {
		parts = append(parts, fmt.Sprintf("Int64 %d", x))
	}
	if x, ok := v.Uint64(); ok {
		parts = append(parts, fmt.Sprintf("Uint64 %d", x))
	}
	if x, ok := v.Bytes(); ok {
		parts = append(parts, fmt.Sprintf("Bytes %q", x))
	}
	if x, ok := v.OID(); ok {
		parts = append(parts, fmt.Sprintf("OID %q", x))
	}
	if x, ok := v.IP(); ok {
		parts = append(parts, "IP "+x.String())
	}
	if x, ok := v.Float32(); ok {
		parts = append(parts, fmt.Sprintf("Float32 %v", x))
	}
	if x, ok := v.Float64(); ok {
		parts = append(parts, fmt.Sprintf("Float64 %v", x))
	}
	return strings.TrimSpace(v.Type().String() + ": " + strings.Join(parts, ", "))
}

// TestIPAddressVarbindValue decodes IpAddress varbind values with various
// BER encodings.
func TestIPAddressVarbindValue(t *testing.T) {
	tests := map[string]struct {
		value   []byte
		want    netip.Addr
		wantErr bool
	}{
		"short-form IPv4": {
			value: []byte{0x40, 0x04, 192, 168, 1, 1},
			want:  netip.MustParseAddr("192.168.1.1"),
		},
		"short-form IPv4 loopback": {
			value: []byte{0x40, 0x04, 127, 0, 0, 1},
			want:  netip.MustParseAddr("127.0.0.1"),
		},
		"short-form IPv6": {
			value: []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		"short-form IPv6 all bytes set": {
			value: []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0xab, 0xcd},
			want:  netip.MustParseAddr("2001:db8:85a3:0:8a2e:370:7334:abcd"),
		},
		"long-form IPv4": {
			value: []byte{0x40, 0x81, 0x04, 192, 168, 1, 1},
			want:  netip.MustParseAddr("192.168.1.1"),
		},
		"long-form IPv6": {
			value: []byte{0x40, 0x81, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		"null IPAddress (length 0)": {
			value: []byte{0x40, 0x00},
			want:  netip.Addr{},
		},
		"truncated IPv4 data": {
			value:   []byte{0x40, 0x04, 192, 168},
			wantErr: true,
		},
		"truncated IPv6 data": {
			value:   []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8},
			wantErr: true,
		},
		"invalid length (not 0, 4, or 16)": {
			value:   []byte{0x40, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantErr: true,
		},
		"indefinite length rejected": {
			value:   []byte{0x40, 0x80, 192, 168, 1, 1, 0x00, 0x00},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			vars, err := testUnmarshalVBL(t, buildVBL(rawVB(0x01, tt.value)))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected an error, got %v", vars)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(vars) != 1 {
				t.Fatalf("got %v, want one varbind", vars)
			}
			got, ok := vars[0].Value.IP()
			if vars[0].Name != ".1.3.6.1" || !ok || got != tt.want {
				t.Errorf("got %s %v %v, want .1.3.6.1 IPAddress %v", vars[0].Name, vars[0].Value.Type(), got, tt.want)
			}
		})
	}
}

// TestVarbindValueAliasesInput pins that OctetString and raw Opaque values
// are slices of the decoded packet, not copies.
func TestVarbindValueAliasesInput(t *testing.T) {
	tests := map[string]struct {
		value []byte
		want  []byte
	}{
		"OctetString": {
			value: []byte{byte(OctetString), 0x03, 'a', 'b', 'c'},
			want:  []byte("abc"),
		},
		"OctetString over-declared by one octet": {
			value: []byte{byte(OctetString), 0x04, 'a', 'b', 'c'},
			want:  []byte("abc"),
		},
		"raw Opaque": {
			value: []byte{byte(Opaque), 0x02, 0x01, 0x02},
			want:  []byte{0x01, 0x02},
		},
		"Opaque with another extension tag": {
			value: []byte{byte(Opaque), 0x04, opaqueExtensionTag, 0x76, 0x01, 0x05},
			want:  []byte{opaqueExtensionTag, 0x76, 0x01, 0x05},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			packet := buildVBL(rawVB(0x01, tt.value))
			vars, err := testUnmarshalVBL(t, packet)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(vars) != 1 {
				t.Fatalf("got %d varbinds, want 1", len(vars))
			}
			got, ok := vars[0].Value.Bytes()
			if !ok || !bytes.Equal(got, tt.want) {
				t.Fatalf("got %s, want %x", dumpValue(vars[0].Value), tt.want)
			}

			for i := range packet {
				packet[i] ^= 0xff
			}
			for i := range got {
				if got[i] != tt.want[i]^0xff {
					t.Fatalf("value %x does not follow the input change at octet %d", got, i)
				}
			}
		})
	}
}

// TestDecodedHeaderCopiesInput pins that the SNMPv3 header fields a decoder
// returns, the security parameters and the context engine ID, are copies of
// the input, unlike OctetString values (TestVarbindValueAliasesInput): a
// caller may reuse the input after DecodeMessage or Receiver.Receive. The
// authPriv message carries privacy parameters, the authNoPriv one a plaintext
// context engine ID.
func TestDecodedHeaderCopiesInput(t *testing.T) {
	user := codecUser(SHA, AES)
	decoders := map[string]func(t *testing.T, in []byte) (*Message, error){
		"DecodeMessage": func(_ *testing.T, in []byte) (*Message, error) {
			return (&Client{Version: Version3, SecurityLevel: AuthPriv, User: user}).DecodeMessage(in)
		},
		"Receive": func(t *testing.T, in []byte) (*Message, error) {
			return receiveMessage(receiverAt(t, []byte(codecEngineID), user), in)
		},
	}
	messages := map[string]func() []byte{"authPriv": v3AuthPrivSHAAESResponse, "authNoPriv": v3AuthNoPrivSHAResponse}
	for name, decode := range decoders {
		for level, message := range messages {
			t.Run(name+"/"+level, func(t *testing.T) {
				in := message()
				p, err := decode(t, in)
				if err != nil {
					t.Fatal(err)
				}
				describe := func() string {
					return fmt.Sprintf("%+v context engine ID %x", p.SecurityParameters, p.ContextEngineID)
				}
				want := describe()
				for i := range in {
					in[i] ^= 0xff
				}
				if got := describe(); got != want {
					t.Fatalf("the header follows the input change:\n got %s\nwant %s", got, want)
				}
			})
		}
	}
}

// TestIPAddressMappedDecodesAsIPv4 checks that 16 octets of an IPv4-mapped
// address, which some devices send for an IpAddress, decode as the IPv4
// address and encode back in 4 octets, as the decoder's address text did:
// every decoded IpAddress is one IPAddressValue builds from its address.
func TestIPAddressMappedDecodesAsIPv4(t *testing.T) {
	tests := map[string]struct {
		content []byte
		want    netip.Addr
	}{
		"IPv4":        {content: []byte{192, 0, 2, 1}, want: netip.MustParseAddr("192.0.2.1")},
		"IPv4-mapped": {content: netip.MustParseAddr("::ffff:192.0.2.1").AsSlice(), want: netip.MustParseAddr("192.0.2.1")},
		"IPv6":        {content: netip.MustParseAddr("2001:db8::1").AsSlice(), want: netip.MustParseAddr("2001:db8::1")},
		"IPv4-compatible": {
			content: netip.MustParseAddr("::c000:201").AsSlice(), want: netip.MustParseAddr("::c000:201"),
		},
		"empty": {content: []byte{}, want: netip.Addr{}},
		"a nonzero octet before 0xffff": {
			content: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 192, 0, 2, 1},
			want:    netip.AddrFrom16([16]byte{9: 1, 10: 0xff, 11: 0xff, 12: 192, 14: 2, 15: 1}),
		},
		"one 0xff": {
			content: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 192, 0, 2, 1},
			want:    netip.AddrFrom16([16]byte{11: 0xff, 12: 192, 14: 2, 15: 1}),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			v := decodedIPAddress(t, tc.content)
			if got, ok := v.IP(); !ok || got != tc.want {
				t.Errorf("IP() = %v, %v; want %v", got, ok, tc.want)
			}
			if !reflect.DeepEqual(v, IPAddressValue(tc.want)) {
				t.Errorf("decoded %#v, IPAddressValue(%v) = %#v", v, tc.want, IPAddressValue(tc.want))
			}
		})
	}
}

// TestIPAddressValueAliasesInput checks that a decoded IpAddress holds the
// octets of the input, which IP reads when called: the last 4 of an
// IPv4-mapped address.
func TestIPAddressValueAliasesInput(t *testing.T) {
	tests := map[string]struct {
		value []byte
		want  netip.Addr
	}{
		"4 octets":         {value: []byte{byte(IPAddress), 0x04, 192, 0, 2, 1}, want: netip.MustParseAddr("63.255.253.254")},
		"16 octets mapped": {value: append([]byte{byte(IPAddress), 0x10}, netip.MustParseAddr("::ffff:192.0.2.1").AsSlice()...), want: netip.MustParseAddr("63.255.253.254")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			packet := buildVBL(rawVB(0x01, tt.value))
			vars, err := testUnmarshalVBL(t, packet)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for i := range packet {
				packet[i] ^= 0xff
			}
			if got, ok := vars[0].Value.IP(); !ok || got != tt.want {
				t.Fatalf("IP() = %v, %v after the input changed; want %v", got, ok, tt.want)
			}
		})
	}
}

// TestValueString pins String for every type: the text %v printed for the
// value decoded as an any before values were typed.
func TestValueString(t *testing.T) {
	tests := map[string]struct {
		value Value
		want  string
	}{
		"Integer -1":               {value: IntegerValue(-1), want: "-1"},
		"Integer MinInt32":         {value: IntegerValue(math.MinInt32), want: "-2147483648"},
		"Counter32":                {value: Counter32Value(math.MaxUint32), want: "4294967295"},
		"Gauge32":                  {value: Gauge32Value(5), want: "5"},
		"TimeTicks":                {value: TimeTicksValue(6), want: "6"},
		"Uinteger32":               {value: Uinteger32Value(7), want: "7"},
		"Counter64":                {value: Counter64Value(math.MaxUint64), want: "18446744073709551615"},
		"OctetString":              {value: OctetStringValue([]byte("ab")), want: "[97 98]"},
		"OctetString empty":        {value: OctetStringValue([]byte{}), want: "[]"},
		"OctetString nil":          {value: OctetStringValue(nil), want: "[]"},
		"Opaque":                   {value: OpaqueValue([]byte{1, 2}), want: "[1 2]"},
		"ObjectIdentifier":         {value: ObjectIdentifierValue(".1.3.6.1"), want: ".1.3.6.1"},
		"IPAddress":                {value: IPAddressValue(netip.MustParseAddr("192.0.2.1")), want: "192.0.2.1"},
		"IPAddress IPv6":           {value: IPAddressValue(netip.MustParseAddr("2001:db8::1")), want: "2001:db8::1"},
		"IPAddress empty":          {value: decodedIPAddress(t, []byte{}), want: "<nil>"},
		"IPAddress IPv4-mapped 16": {value: decodedIPAddress(t, netip.MustParseAddr("::ffff:192.0.2.1").AsSlice()), want: "192.0.2.1"},
		"OpaqueFloat":              {value: OpaqueFloatValue(0.1), want: "0.1"},
		"OpaqueDouble":             {value: OpaqueDoubleValue(-2.25), want: "-2.25"},
		"Null":                     {value: NullValue(), want: "<nil>"},
		"NoSuchObject":             {value: NoSuchObjectValue(), want: "<nil>"},
		"NoSuchInstance":           {value: NoSuchInstanceValue(), want: "<nil>"},
		"EndOfMibView":             {value: EndOfMibViewValue(), want: "<nil>"},
		"the zero Value":           {value: Value{}, want: "<nil>"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := fmt.Sprintf("%v", tc.value); got != tc.want {
				t.Errorf("%%v = %q, want %q", got, tc.want)
			}
		})
	}
}
