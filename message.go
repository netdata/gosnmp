// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import "net/netip"

// Version is the SNMP version of a message, as it is encoded. Its String
// is "1", "2c" or "3", and "Version(N)" for another value.
type Version uint8

// The SNMP versions.
const (
	Version1  Version = 0x0 // 1
	Version2c Version = 0x1 // 2c
	Version3  Version = 0x3 // 3
)

//go:generate go tool -modfile=tools/go.mod stringer -type=Version -linecomment

// Message is an SNMP message: a request, an answer or a trap. A decoded
// message holds the fields it carried, its SNMPv3 security parameters
// included; it holds no secret.
type Message struct {
	// Version is the SNMP version.
	Version Version

	// The SNMPv3 header: the security level and the User-based Security
	// Model's parameters.
	SecurityLevel      SecurityLevel
	SecurityParameters SecurityParameters

	// The SNMPv3 context of the scoped PDU.
	ContextEngineID []byte
	ContextName     string

	// Community is the community of an SNMPv1 or SNMPv2c message.
	Community string

	// PDUType is the type of the PDU.
	PDUType PDUType

	// MsgID is the SNMPv3 msgID, at most 2147483647 to encode; RequestID the
	// PDU's request ID, an Integer32 whose two's complement it holds.
	MsgID     uint32
	RequestID uint32

	// MsgMaxSize is the SNMPv3 msgMaxSize, 484..2147483647 to encode; the
	// encoder sends 65535 for zero.
	MsgMaxSize uint32

	// ErrorStatus and ErrorIndex are the PDU's error status and index, each
	// decoded to its low byte; a GetBulkRequest has NonRepeaters and
	// MaxRepetitions in their place.
	ErrorStatus    ErrorStatus
	ErrorIndex     uint8
	NonRepeaters   uint8
	MaxRepetitions uint32

	// VarBinds are the varbinds.
	VarBinds []VarBind

	// IsInform reports that the message is an InformRequest, which its sender
	// expects an answer to, not a trap; SNMPv1 has no informs.
	IsInform bool

	// TrapV1Header is the SNMPv1 trap header.
	TrapV1Header
}

// TrapV1Header is the SNMPv1 trap header (RFC 1157): the enterprise OID in
// dotted form, the agent's IPv4 address (the zero Addr for the empty one some
// devices send), the generic and specific trap numbers and the timestamp in
// TimeTicks, each of the Go type of its SMI type (see Value).
type TrapV1Header struct {
	Enterprise   string
	AgentAddress netip.Addr
	GenericTrap  int32
	SpecificTrap int32
	Timestamp    uint32
}

// PDUType is the BER tag of a PDU, which names its type.
type PDUType byte

// The PDU types (RFC 3416; Trap is SNMPv1's).
const (
	GetRequest     PDUType = 0xa0
	GetNextRequest PDUType = 0xa1
	Response       PDUType = 0xa2
	SetRequest     PDUType = 0xa3
	Trap           PDUType = 0xa4 // v1
	GetBulkRequest PDUType = 0xa5
	InformRequest  PDUType = 0xa6
	SNMPv2Trap     PDUType = 0xa7 // v2c, v3
	Report         PDUType = 0xa8 // v3
)

//go:generate go tool -modfile=tools/go.mod stringer -type=PDUType

// known reports whether t is a PDU type the codec reads and writes: the
// SNMPv1 Trap-PDU, the PDUs of RFC 3416 and the Report.
func (t PDUType) known() bool {
	switch t {
	case GetRequest, GetNextRequest, Response, SetRequest, Trap, GetBulkRequest, InformRequest, SNMPv2Trap, Report:
		return true
	}
	return false
}

// confirmed reports whether t is a PDU of the Confirmed Class (RFC 3411
// section 2.8.2): a request or an inform, which its receiver answers.
func (t PDUType) confirmed() bool {
	switch t {
	case GetRequest, GetNextRequest, GetBulkRequest, SetRequest, InformRequest:
		return true
	}
	return false
}

// Encode encodes the message as it is, ready for the wire. An SNMPv3
// message is encrypted and signed when its security level asks for it, with
// user's keys localized to its engine ID (SecurityParameters'
// AuthoritativeEngineID), which the level requires; Encode derives only the
// keys the level uses. Each encrypted message gets a new salt, whatever
// PrivacyParameters holds. The message names its user itself
// (SecurityParameters' UserName). SNMPv1 and SNMPv2c messages take no user
// (nil), and an SNMPv3 message at NoAuthNoPriv takes nil or any user with valid
// protocols. Encode draws no new msgID (Client.EncodeMessage does).
func (packet *Message) Encode(user *User) ([]byte, error) {
	var keys usmKeys
	if packet.Version == Version3 && user != nil {
		var err error
		if keys, err = user.keysAt(packet.SecurityLevel, packet.SecurityParameters.AuthoritativeEngineID); err != nil {
			return nil, err
		}
	}
	return packet.marshalMsg(&keys)
}
