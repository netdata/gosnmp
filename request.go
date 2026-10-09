// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import "fmt"

func (x *GoSNMP) MkSnmpPacket(pdutype PDUType, pdus []SnmpPDU, nonRepeaters uint8, maxRepetitions uint32) *SnmpPacket {
	return x.mkSnmpPacket(pdutype, pdus, nonRepeaters, maxRepetitions)
}

func (x *GoSNMP) mkSnmpPacket(pdutype PDUType, pdus []SnmpPDU, nonRepeaters uint8, maxRepetitions uint32) *SnmpPacket {
	var newSecParams SnmpV3SecurityParameters
	if x.SecurityParameters != nil {
		newSecParams = x.SecurityParameters.Copy()
	}
	return &SnmpPacket{
		Version:            x.Version,
		Community:          x.Community,
		MsgFlags:           x.MsgFlags,
		SecurityModel:      x.SecurityModel,
		SecurityParameters: newSecParams,
		ContextEngineID:    x.ContextEngineID,
		ContextName:        x.ContextName,
		Error:              0,
		ErrorIndex:         0,
		PDUType:            pdutype,
		NonRepeaters:       nonRepeaters,
		MaxRepetitions:     (maxRepetitions & 0x7FFFFFFF),
		Variables:          pdus,
	}
}

// Get sends an SNMP GET request
func (x *GoSNMP) Get(oids []string) (result *SnmpPacket, err error) {
	packetOut, err := x.oidRequest(GetRequest, oids, 0, 0)
	if err != nil {
		return nil, err
	}
	return x.send(packetOut)
}

// Set sends an SNMP SET request
func (x *GoSNMP) Set(pdus []SnmpPDU) (result *SnmpPacket, err error) {
	var packetOut *SnmpPacket
	switch pdus[0].Type {
	// TODO test Gauge32
	case Integer, OctetString, Gauge32, IPAddress, ObjectIdentifier, Counter32, Counter64, Null, TimeTicks, Uinteger32, OpaqueFloat, OpaqueDouble:
		packetOut = x.mkSnmpPacket(SetRequest, pdus, 0, 0)
	default:
		return nil, fmt.Errorf("ERR:gosnmp currently only supports SNMP SETs for Integer, OctetString, Gauge32, IPAddress, ObjectIdentifier, Counter32, Counter64, Null, TimeTicks, Uinteger32, OpaqueFloat, and OpaqueDouble. Not %s", pdus[0].Type)
	}
	return x.send(packetOut)
}

// GetNext sends an SNMP GETNEXT request
func (x *GoSNMP) GetNext(oids []string) (result *SnmpPacket, err error) {
	packetOut, err := x.oidRequest(GetNextRequest, oids, 0, 0)
	if err != nil {
		return nil, err
	}
	return x.send(packetOut)
}

// GetBulk sends an SNMP GETBULK request
//
// For maxRepetitions greater than 255, use BulkWalk() or BulkWalkAll()
func (x *GoSNMP) GetBulk(oids []string, nonRepeaters uint8, maxRepetitions uint32) (result *SnmpPacket, err error) {
	if x.Version == Version1 {
		return nil, fmt.Errorf("GETBULK not supported in SNMPv1")
	}
	packetOut, err := x.oidRequest(GetBulkRequest, oids, nonRepeaters, maxRepetitions)
	if err != nil {
		return nil, err
	}
	return x.send(packetOut)
}

// oidRequest builds the request packet of pdutype for oids, each as a Null
// varbind, after checking their count against MaxOids.
func (x *GoSNMP) oidRequest(pdutype PDUType, oids []string, nonRepeaters uint8, maxRepetitions uint32) (*SnmpPacket, error) {
	if len(oids) > x.MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MaxOids (%d)", len(oids), x.MaxOids)
	}
	pdus := make([]SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		pdus = append(pdus, SnmpPDU{Name: oid, Type: Null, Value: nil})
	}
	return x.mkSnmpPacket(pdutype, pdus, nonRepeaters, maxRepetitions), nil
}
