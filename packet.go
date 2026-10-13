// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
)

// SnmpVersion is the SNMP version of a message, as it is encoded.
type SnmpVersion uint8

// The SNMP versions.
const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
	Version3  SnmpVersion = 0x3
)

// String returns "1", "2c" or "3". Known bug: it returns "3" for an unknown
// version too.
func (s SnmpVersion) String() string {
	switch s {
	case Version1:
		return "1"
	case Version2c:
		return "2c"
	case Version3:
		return "3"
	default:
		return "3"
	}
}

// SnmpPacket is an SNMP message: a request, an answer or a trap. A decoded
// packet holds the fields the message carried; its SecurityParameters are a
// copy of the client's, protocols, passphrases and keys included, with the
// message's fields decoded into them, and its Logger is the client's.
type SnmpPacket struct {
	// Version is the SNMP version.
	Version SnmpVersion

	// The SNMPv3 header: the flags, the security model and its parameters.
	MsgFlags           SnmpV3MsgFlags
	SecurityModel      SnmpV3SecurityModel
	SecurityParameters SnmpV3SecurityParameters

	// The SNMPv3 context of the scoped PDU.
	ContextEngineID string
	ContextName     string

	// Community is the community of an SNMPv1 or SNMPv2c message.
	Community string

	// PDUType is the type of the PDU.
	PDUType PDUType

	// MsgID is the SNMPv3 msgID, RequestID the PDU's request ID.
	MsgID     uint32
	RequestID uint32

	// MsgMaxSize is the SNMPv3 msgMaxSize; the encoder sends 65535 for zero.
	MsgMaxSize uint32

	// Error and ErrorIndex are the PDU's error status and index, each decoded
	// to its low byte; a GetBulkRequest has NonRepeaters and MaxRepetitions
	// in their place.
	Error          SNMPError
	ErrorIndex     uint8
	NonRepeaters   uint8
	MaxRepetitions uint32

	// Variables are the varbinds.
	Variables []SnmpPDU

	// Logger is the Logger of Check.
	Logger Logger

	// SnmpTrap holds what only traps and informs carry.
	SnmpTrap
}

// SnmpTrap holds what only traps and informs carry: the SNMPv1 trap header,
// and whether the packet is an InformRequest.
type SnmpTrap struct {
	// Variables is not used: SnmpPacket.Variables, which hides it, holds the
	// varbinds of traps too.
	Variables []SnmpPDU

	// IsInform reports that the packet is an InformRequest, which its sender
	// expects an answer to, not a trap; SNMPv1 has no informs.
	IsInform bool

	// The SNMPv1 trap header (RFC 1157): the enterprise OID, the agent's IPv4
	// address, the generic and specific trap numbers and the timestamp in
	// TimeTicks.
	Enterprise   string
	AgentAddress string
	GenericTrap  int
	SpecificTrap int
	Timestamp    uint
}

// VarBind is a varbind in encoding/asn1 types. The library does not use it:
// SnmpPDU is its varbind.
type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// PDUType is the BER tag of a PDU, which names its type.
type PDUType byte

// The PDU types (RFC 3416; Trap is SNMPv1's), and Sequence, the tag of a BER
// SEQUENCE, which is not one.
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

// SafeString formats the packet for logs, with the SafeString of its
// security parameters, which leaves the passphrases and keys out; the
// community is in it.
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

// MarshalMsg encodes the packet as it is, ready for the wire. An SNMPv3
// message is encrypted with its PrivacyParameters as the salt and signed when
// its flags ask for it, with the keys in its SecurityParameters; MarshalMsg
// draws no new msgID or salt (GoSNMP.SnmpEncodePacket does).
func (packet *SnmpPacket) MarshalMsg() ([]byte, error) {
	return packet.marshalMsg()
}
