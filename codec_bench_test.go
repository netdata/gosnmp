// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"slices"
	"strconv"
	"testing"
)

// BenchmarkDecode measures DecodeMessage on recorded packets.
func BenchmarkDecode(b *testing.B) {
	inputs := []struct {
		name string
		in   func() []byte
	}{
		{"kyoceraResponse", kyoceraResponseBytes},
		{"ciscoGetbulkResponse", ciscoGetbulkResponseBytes},
		{"counter64Response", counter64Response},
		{"opaqueDoubleResponse", opaqueDoubleResponse},
		{"snmpv3HelloResponse", snmpv3HelloResponse},
		{"trap1", trap1},
		{"getBulkResponse50", getBulkResponse50},
		{"snmpv2Trap20", snmpv2Trap20},
	}
	for _, in := range inputs {
		b.Run(in.name, func(b *testing.B) {
			data := in.in()
			x := &Client{}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := x.DecodeMessage(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEncode measures Message.Encode on typical requests, a response, a
// trap and SNMPv3 messages.
func BenchmarkEncode(b *testing.B) {
	oids := make([]VarBind, 10)
	for i := range oids {
		oids[i] = VarBind{Name: ".1.3.6.1.2.1.2.2.1.10." + strconv.Itoa(i+1), Type: Null}
	}
	response, err := (&Client{}).DecodeMessage(kyoceraResponseBytes())
	if err != nil {
		b.Fatal(err)
	}

	v3Request := func(flags SnmpV3MsgFlags, auth AuthProtocol) *Message {
		sp := &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: "codec-auth-pass",
			AuthoritativeEngineID:    "\x80\x00\x1f\x88\x04codec-engine",
			AuthoritativeEngineBoots: 7,
			AuthoritativeEngineTime:  1234,
		}
		if auth != NoAuth {
			if err := sp.InitSecurityKeys(); err != nil {
				b.Fatal(err)
			}
		}
		return &Message{
			Version:            Version3,
			MsgFlags:           flags,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: sp,
			PDUType:            GetRequest,
			MsgID:              4242,
			RequestID:          123456,
			VarBinds:           oids,
		}
	}

	packets := []struct {
		name string
		pkt  *Message
	}{
		{"getRequest10", &Message{Version: Version2c, Community: "public", PDUType: GetRequest, RequestID: 1, VarBinds: oids}},
		{"getBulkRequest", &Message{
			Version: Version2c, Community: "public", PDUType: GetBulkRequest, RequestID: 1,
			MaxRepetitions: 25, VarBinds: oids[:1],
		}},
		{"kyoceraResponse", response},
		{"v1Trap", &Message{
			Version: Version1, Community: "public", PDUType: Trap, VarBinds: slices.Clone(response.VarBinds),
			Enterprise: ".1.3.6.1.4.1.20372", AgentAddress: "192.0.2.1", GenericTrap: 6, SpecificTrap: 1,
		}},
		{"v3NoAuthGetRequest10", v3Request(NoAuthNoPriv, NoAuth)},
		{"v3AuthSHAGetRequest10", v3Request(AuthNoPriv, SHA)},
	}

	for _, p := range packets {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := p.pkt.Encode(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// getBulkResponse50 is an SNMPv2c GetBulk answer of 50 varbinds: ten rows of
// an interface table, each its name, octet and packet counters, speed and
// last change, the types a polling collector reads most.
func getBulkResponse50() []byte {
	vbs := make([]VarBind, 0, 50)
	for i := range 10 {
		row := "." + strconv.Itoa(i+1)
		vbs = append(vbs,
			VarBind{Name: ".1.3.6.1.2.1.31.1.1.1.1" + row, Type: OctetString, Value: []byte("GigabitEthernet0/" + strconv.Itoa(i))},
			VarBind{Name: ".1.3.6.1.2.1.31.1.1.1.6" + row, Type: Counter64, Value: uint64(1)<<40 + uint64(i)},
			VarBind{Name: ".1.3.6.1.2.1.2.2.1.11" + row, Type: Counter32, Value: uint32(3000000000) + uint32(i)},
			VarBind{Name: ".1.3.6.1.2.1.2.2.1.5" + row, Type: Gauge32, Value: uint32(1000000000)},
			VarBind{Name: ".1.3.6.1.2.1.2.2.1.9" + row, Type: TimeTicks, Value: uint32(123456 + i)},
		)
	}
	return mustMarshal(&Message{Version: Version2c, Community: "public", PDUType: Response, RequestID: 1, VarBinds: vbs})
}

// snmpv2Trap20 is an SNMPv2c trap of 20 varbinds: sysUpTime.0, snmpTrapOID.0,
// then integers, strings and counters.
func snmpv2Trap20() []byte {
	vbs := []VarBind{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(987654)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.20372.0.1"},
	}
	for i := range 6 {
		n := ".1.3.6.1.4.1.20372.1." + strconv.Itoa(i+1)
		vbs = append(vbs,
			VarBind{Name: n + ".1", Type: Integer, Value: 100 + i},
			VarBind{Name: n + ".2", Type: OctetString, Value: []byte("trap-field-" + strconv.Itoa(i))},
			VarBind{Name: n + ".3", Type: Counter32, Value: uint32(42 + i)},
		)
	}
	return mustMarshal(&Message{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 7, VarBinds: vbs})
}

func mustMarshal(p *Message) []byte {
	b, err := p.Encode()
	if err != nil {
		panic(err)
	}
	return b
}
