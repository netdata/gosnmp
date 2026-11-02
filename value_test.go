// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
)

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
// caller may reuse the input after DecodeMessage or UnmarshalTrap. The
// authPriv message carries privacy parameters, the authNoPriv one a plaintext
// context engine ID.
func TestDecodedHeaderCopiesInput(t *testing.T) {
	user := codecUser(SHA, AES)
	table := NewSnmpV3SecurityParametersTable()
	if err := table.Add(user, []byte(codecEngineID)); err != nil {
		t.Fatal(err)
	}
	decoders := map[string]func(x *Client, in []byte) (*Message, error){
		"DecodeMessage": func(x *Client, in []byte) (*Message, error) { return x.DecodeMessage(in) },
		"UnmarshalTrap": func(x *Client, in []byte) (*Message, error) { return x.UnmarshalTrap(in, true) },
		"UnmarshalTrap with a table": func(x *Client, in []byte) (*Message, error) {
			x.TrapSecurityParametersTable = table
			return x.UnmarshalTrap(in, true)
		},
	}
	messages := map[string]func() []byte{"authPriv": v3AuthPrivSHAAESResponse, "authNoPriv": v3AuthNoPrivSHAResponse}
	for name, decode := range decoders {
		for level, message := range messages {
			t.Run(name+"/"+level, func(t *testing.T) {
				useEngineTimes(t)
				in := message()
				p, err := decode(&Client{Version: Version3, SecurityLevel: AuthPriv, User: user}, in)
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
