// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
)

// SnmpVersion 1, 2c and 3 implemented
type SnmpVersion uint8

// SnmpVersion 1, 2c and 3 implemented
const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
	Version3  SnmpVersion = 0x3
)

// SnmpPacket struct represents the entire SNMP Message or Sequence at the
// application layer.
type SnmpPacket struct {
	Version            SnmpVersion
	MsgFlags           SnmpV3MsgFlags
	SecurityModel      SnmpV3SecurityModel
	SecurityParameters SnmpV3SecurityParameters // interface
	ContextEngineID    string
	ContextName        string
	Community          string
	PDUType            PDUType
	MsgID              uint32
	RequestID          uint32
	MsgMaxSize         uint32
	Error              SNMPError
	ErrorIndex         uint8
	NonRepeaters       uint8
	MaxRepetitions     uint32
	Variables          []SnmpPDU
	Logger             Logger

	// v1 traps have a very different format from v2c and v3 traps. SnmpTrap
	// holds the v1 trap header and the inform flag.
	SnmpTrap
}

// SnmpTrap holds what only traps and informs carry: the v1 trap header and
// whether the packet is an InformRequest.
type SnmpTrap struct {
	Variables []SnmpPDU

	// If true, the trap is an InformRequest, not a trap. This has no effect on
	// v1 traps, as Inform is not part of the v1 protocol.
	IsInform bool

	// These fields are required for SNMPV1 Trap Headers
	Enterprise   string
	AgentAddress string
	GenericTrap  int
	SpecificTrap int
	Timestamp    uint
}

// VarBind struct represents an SNMP Varbind.
type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// PDUType describes which SNMP Protocol Data Unit is being sent.
type PDUType byte

// The currently supported PDUType's
const (
	Sequence       PDUType = 0x30
	GetRequest     PDUType = 0xa0
	GetNextRequest PDUType = 0xa1
	GetResponse    PDUType = 0xa2
	SetRequest     PDUType = 0xa3
	Trap           PDUType = 0xa4 // v1
	GetBulkRequest PDUType = 0xa5
	InformRequest  PDUType = 0xa6
	SNMPv2Trap     PDUType = 0xa7 // v2c, v3
	Report         PDUType = 0xa8 // v3
)

//go:generate go tool -modfile=tools/go.mod stringer -type=PDUType

func (packet *SnmpPacket) SafeString() string {
	sp := ""
	if packet.SecurityParameters != nil {
		sp = packet.SecurityParameters.SafeString()
	}
	return fmt.Sprintf("Version:%s, MsgFlags:%s, SecurityModel:%s, SecurityParameters:%s, ContextEngineID:%s, ContextName:%s, Community:%s, PDUType:%s, MsgID:%d, RequestID:%d, MsgMaxSize:%d, Error:%s, ErrorIndex:%d, NonRepeaters:%d, MaxRepetitions:%d, Variables:%v",
		packet.Version,
		packet.MsgFlags,
		packet.SecurityModel,
		sp,
		packet.ContextEngineID,
		packet.ContextName,
		packet.Community,
		packet.PDUType,
		packet.MsgID,
		packet.RequestID,
		packet.MsgMaxSize,
		packet.Error,
		packet.ErrorIndex,
		packet.NonRepeaters,
		packet.MaxRepetitions,
		packet.Variables,
	)
}

// MarshalMsg marshalls a snmp packet, ready for sending across the wire
func (packet *SnmpPacket) MarshalMsg() ([]byte, error) {
	return packet.marshalMsg()
}
