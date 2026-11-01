// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"math"
)

// MkSnmpPacket builds a request or trap packet of pdutype with the variable
// bindings pdus from the client's version, community, SNMPv3 flags, security
// model, a copy of its security parameters (none for a nil
// *UsmSecurityParameters) and its context; maxRepetitions is kept with its top
// bit cleared.
func (x *GoSNMP) MkSnmpPacket(pdutype PDUType, pdus []SnmpPDU, nonRepeaters uint8, maxRepetitions uint32) *SnmpPacket {
	var newSecParams SnmpV3SecurityParameters
	if sp := usmOf(x.SecurityParameters); sp != nil {
		newSecParams = sp.Copy()
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
		MaxRepetitions:     maxRepetitions & math.MaxInt32,
		Variables:          pdus,
	}
}

// Get sends a GET request for oids, at most MaxOids of them, and returns the
// answer.
func (x *GoSNMP) Get(oids []string) (result *SnmpPacket, err error) {
	packetOut, err := x.oidRequest(GetRequest, oids, 0)
	if err != nil {
		return nil, err
	}
	return x.send(packetOut)
}

// oidRequest builds the request packet of pdutype for oids, each as a Null
// varbind, with maxRepetitions for a GetBulk, after checking their count
// against MaxOids: Get's, and each of a walk's GetNext and GetBulk requests.
func (x *GoSNMP) oidRequest(pdutype PDUType, oids []string, maxRepetitions uint32) (*SnmpPacket, error) {
	if len(oids) > x.MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MaxOids (%d)", len(oids), x.MaxOids)
	}
	pdus := make([]SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		pdus = append(pdus, SnmpPDU{Name: oid, Type: Null, Value: nil})
	}
	return x.MkSnmpPacket(pdutype, pdus, 0, maxRepetitions), nil
}
