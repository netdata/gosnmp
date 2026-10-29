// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"io"
	"log"
	"slices"
	"strconv"
	"testing"
)

// BenchmarkDecode measures SnmpDecodePacket on recorded packets, without a
// logger (the default) and with a logger that discards its output.
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
	loggers := []struct {
		name   string
		logger Logger
	}{
		{"no-logger", Logger{}},
		{"discard-logger", NewLogger(log.New(io.Discard, "", 0))},
	}

	for _, in := range inputs {
		for _, l := range loggers {
			b.Run(in.name+"/"+l.name, func(b *testing.B) {
				data := in.in()
				x := &GoSNMP{Logger: l.logger}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := x.SnmpDecodePacket(data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkEncode measures MarshalMsg on typical requests, a response, a
// trap and SNMPv3 messages.
func BenchmarkEncode(b *testing.B) {
	oids := make([]SnmpPDU, 10)
	for i := range oids {
		oids[i] = SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.10." + strconv.Itoa(i+1), Type: Null}
	}
	response, err := (&GoSNMP{}).SnmpDecodePacket(kyoceraResponseBytes())
	if err != nil {
		b.Fatal(err)
	}

	v3Request := func(flags SnmpV3MsgFlags, auth SnmpV3AuthProtocol) *SnmpPacket {
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
		return &SnmpPacket{
			Version:            Version3,
			MsgFlags:           flags,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: sp,
			PDUType:            GetRequest,
			MsgID:              4242,
			RequestID:          123456,
			Variables:          oids,
		}
	}

	packets := []struct {
		name string
		pkt  *SnmpPacket
	}{
		{"getRequest10", &SnmpPacket{Version: Version2c, Community: "public", PDUType: GetRequest, RequestID: 1, Variables: oids}},
		{"getBulkRequest", &SnmpPacket{
			Version: Version2c, Community: "public", PDUType: GetBulkRequest, RequestID: 1,
			MaxRepetitions: 25, Variables: oids[:1],
		}},
		{"kyoceraResponse", response},
		{"v1Trap", &SnmpPacket{
			Version: Version1, Community: "public", PDUType: Trap, Variables: slices.Clone(response.Variables),
			Enterprise: ".1.3.6.1.4.1.20372", AgentAddress: "192.0.2.1", GenericTrap: 6, SpecificTrap: 1,
		}},
		{"v3NoAuthGetRequest10", v3Request(NoAuthNoPriv, NoAuth)},
		{"v3AuthSHAGetRequest10", v3Request(AuthNoPriv, SHA)},
	}

	for _, p := range packets {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := p.pkt.MarshalMsg(); err != nil {
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
	vbs := make([]SnmpPDU, 0, 50)
	for i := range 10 {
		row := "." + strconv.Itoa(i+1)
		vbs = append(vbs,
			SnmpPDU{Name: ".1.3.6.1.2.1.31.1.1.1.1" + row, Type: OctetString, Value: []byte("GigabitEthernet0/" + strconv.Itoa(i))},
			SnmpPDU{Name: ".1.3.6.1.2.1.31.1.1.1.6" + row, Type: Counter64, Value: uint64(1)<<40 + uint64(i)},
			SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.11" + row, Type: Counter32, Value: uint32(3000000000) + uint32(i)},
			SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.5" + row, Type: Gauge32, Value: uint32(1000000000)},
			SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.9" + row, Type: TimeTicks, Value: uint32(123456 + i)},
		)
	}
	return mustMarshal(&SnmpPacket{Version: Version2c, Community: "public", PDUType: GetResponse, RequestID: 1, Variables: vbs})
}

// snmpv2Trap20 is an SNMPv2c trap of 20 varbinds: sysUpTime.0, snmpTrapOID.0,
// then integers, strings and counters.
func snmpv2Trap20() []byte {
	vbs := []SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(987654)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.20372.0.1"},
	}
	for i := range 6 {
		n := ".1.3.6.1.4.1.20372.1." + strconv.Itoa(i+1)
		vbs = append(vbs,
			SnmpPDU{Name: n + ".1", Type: Integer, Value: 100 + i},
			SnmpPDU{Name: n + ".2", Type: OctetString, Value: []byte("trap-field-" + strconv.Itoa(i))},
			SnmpPDU{Name: n + ".3", Type: Counter32, Value: uint32(42 + i)},
		)
	}
	return mustMarshal(&SnmpPacket{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 7, Variables: vbs})
}

func mustMarshal(p *SnmpPacket) []byte {
	b, err := p.MarshalMsg()
	if err != nil {
		panic(err)
	}
	return b
}
