// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"testing"
)

// TestOIDPackedFirstSubidentifier checks every OID field against independently
// specified BER bytes. The packed first two arcs may exceed uint32 even though
// each arc fits it (RFC 2578 section 3.5, X.690 section 8.19.4).
func TestOIDPackedFirstSubidentifier(t *testing.T) {
	for _, tc := range []struct {
		oid     string
		content []byte
	}{
		{".2.4294967215", []byte{0x8f, 0xff, 0xff, 0xff, 0x7f}},
		{".2.4294967216", []byte{0x90, 0x80, 0x80, 0x80, 0x00}},
		{".2.4294967295", []byte{0x90, 0x80, 0x80, 0x80, 0x4f}},
		{".2.4294967295.4294967295", []byte{0x90, 0x80, 0x80, 0x80, 0x4f, 0x8f, 0xff, 0xff, 0xff, 0x7f}},
	} {
		t.Run(tc.oid, func(t *testing.T) {
			oid := tlv(byte(ObjectIdentifier), tc.content)
			trap := SnmpTrap{Enterprise: tc.oid, AgentAddress: "192.0.2.1", GenericTrap: 6, SpecificTrap: 42, Timestamp: 256}
			for _, field := range []struct {
				name   string
				packet *SnmpPacket
				wire   []byte
				read   func(*SnmpPacket) string
			}{
				{
					name: "varbind name",
					packet: &SnmpPacket{
						Version: Version2c, Community: "public", PDUType: GetRequest, RequestID: 1,
						Variables: []SnmpPDU{{Name: tc.oid, Type: Null}},
					},
					wire: craftedMsg(1, craftedPDU(GetRequest, craftedVBL(tlv(0x30, oid, tlv(byte(Null)))))),
					read: func(p *SnmpPacket) string { return p.Variables[0].Name },
				},
				{
					name: "varbind value",
					packet: &SnmpPacket{
						Version: Version2c, Community: "public", PDUType: GetResponse, RequestID: 1,
						Variables: []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: ObjectIdentifier, Value: tc.oid}},
					},
					wire: craftedValue(oid),
					read: func(p *SnmpPacket) string { return p.Variables[0].Value.(string) },
				},
				{
					name: "SNMPv1 enterprise",
					packet: &SnmpPacket{
						Version: Version1, Community: "public", PDUType: Trap,
						SnmpTrap: trap,
					},
					wire: craftedV1Trap(oid, craftedAgentAddress, intTLV(6), intTLV(42), craftedTimestamp, craftedVBL()),
					read: func(p *SnmpPacket) string { return p.Enterprise },
				},
			} {
				t.Run(field.name, func(t *testing.T) {
					t.Run("encode", func(t *testing.T) {
						got, err := field.packet.MarshalMsg()
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got, field.wire) {
							t.Errorf("encoded %x, want %x", got, field.wire)
						}
					})
					t.Run("decode", func(t *testing.T) {
						got, err := (&GoSNMP{}).SnmpDecodePacket(field.wire)
						if err != nil {
							t.Fatal(err)
						}
						if value := field.read(got); value != tc.oid {
							t.Errorf("decoded %q, want %q", value, tc.oid)
						}
						back, err := got.MarshalMsg()
						if err != nil || !bytes.Equal(back, field.wire) {
							t.Errorf("reencoded %x, %v; want %x", back, err, field.wire)
						}
					})
				})
			}
		})
	}
}
