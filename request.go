// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"math"
)

// NewMessage builds a request or trap message of pduType with the varbinds
// varBinds from the client's version, community, SNMPv3 security level, user
// name and context name; maxRepetitions is kept with its top bit cleared. An
// SNMPv3 message's engine fields and context engine ID are left empty: a
// request takes them from the client's engine state, and the caller sets them
// for a message it encodes itself.
func (x *Client) NewMessage(pduType PDUType, varBinds []VarBind, nonRepeaters uint8, maxRepetitions uint32) *Message {
	return &Message{
		Version:            x.Version,
		Community:          x.Community,
		SecurityLevel:      x.SecurityLevel,
		SecurityParameters: SecurityParameters{UserName: x.User.Name},
		ContextName:        x.ContextName,
		ErrorStatus:        0,
		ErrorIndex:         0,
		PDUType:            pduType,
		NonRepeaters:       nonRepeaters,
		MaxRepetitions:     maxRepetitions & math.MaxInt32,
		VarBinds:           varBinds,
	}
}

// Get sends a GET request for oids, at most MaxOids of them, and returns the
// answer, a Response whatever its error-status; on an error it returns no
// message, also when an SNMPv3 Report answered the request.
func (x *Client) Get(oids []string) (result *Message, err error) {
	packetOut, err := x.oidRequest(GetRequest, oids, 0)
	if err != nil {
		return nil, err
	}
	return x.send(packetOut)
}

// oidRequest builds the request packet of pdutype for oids, each as a Null
// varbind, with maxRepetitions for a GetBulk, after checking their count
// against MaxOids: Get's, and each of a walk's GetNext and GetBulk requests.
func (x *Client) oidRequest(pdutype PDUType, oids []string, maxRepetitions uint32) (*Message, error) {
	if len(oids) > x.MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MaxOids (%d)", len(oids), x.MaxOids)
	}
	pdus := make([]VarBind, 0, len(oids))
	for _, oid := range oids {
		pdus = append(pdus, VarBind{Name: oid, Value: NullValue()})
	}
	return x.NewMessage(pdutype, pdus, 0, maxRepetitions), nil
}
