// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"math"
	"net/netip"
)

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

	// ErrorStatus and ErrorIndex are the PDU's error status and index; a
	// GetBulkRequest has NonRepeaters and MaxRepetitions in their place.
	// Decoded, an error status outside 0..255 fails the message, and an error
	// index or non-repeaters of 256..2147483647 reads as 255, and a larger one
	// fails the message.
	ErrorStatus    ErrorStatus
	ErrorIndex     uint8
	NonRepeaters   uint8
	MaxRepetitions uint32

	// VarBinds are the varbinds.
	VarBinds []VarBind

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

//go:generate go tool -modfile=tools/go.mod stringer -type ErrorStatus

// ErrorStatus is the error-status of a PDU (RFC 3416 section 3): NoError, or
// why the agent did not process a request as asked.
type ErrorStatus uint8

// The error statuses (RFC 3416; SNMPv1 has the first six).
const (
	NoError             ErrorStatus = iota // No error occurred. This code is also used in all request PDUs, since they have no error status to report.
	TooBig                                 // The size of the Response-PDU would be too large to transport.
	NoSuchName                             // The name of a requested object was not found.
	BadValue                               // A value in the request didn't match the structure that the recipient of the request had for the object. For example, an object in the request was specified with an incorrect length or type.
	ReadOnly                               // An attempt was made to set a variable that has an Access value indicating that it is read-only.
	GenErr                                 // An error occurred other than one indicated by a more specific error code in this table.
	NoAccess                               // Access was denied to the object for security reasons.
	WrongType                              // The object type in a variable binding is incorrect for the object.
	WrongLength                            // A variable binding specifies a length incorrect for the object.
	WrongEncoding                          // A variable binding specifies an encoding incorrect for the object.
	WrongValue                             // The value given in a variable binding is not possible for the object.
	NoCreation                             // A specified variable does not exist and cannot be created.
	InconsistentValue                      // A variable binding specifies a value that could be held by the variable but cannot be assigned to it at this time.
	ResourceUnavailable                    // An attempt to set a variable required a resource that is not available.
	CommitFailed                           // An attempt to set a particular variable failed.
	UndoFailed                             // An attempt to set a particular variable as part of a group of variables failed, and the attempt to then undo the setting of other variables was not successful.
	AuthorizationError                     // A problem occurred in authorization.
	NotWritable                            // The variable cannot be written or created.
	InconsistentName                       // The name in a variable binding specifies a variable that does not exist.
)

// NewMessage builds a request or trap message of pduType with the varbinds
// varBinds from the client's version, community, SNMPv3 security level, user
// name and context name; maxRepetitions is kept with its top bit cleared. An
// SNMPv3 message's engine fields and context engine ID are left empty: a
// request takes them from the client's engine state, and the caller sets them
// for a message it encodes itself.
func (c *Client) NewMessage(pduType PDUType, varBinds []VarBind, nonRepeaters uint8, maxRepetitions uint32) *Message {
	return &Message{
		Version:            c.config.Version,
		Community:          c.config.Community,
		SecurityLevel:      c.config.SecurityLevel,
		SecurityParameters: SecurityParameters{UserName: c.config.User.Name},
		ContextName:        c.config.ContextName,
		ErrorStatus:        0,
		ErrorIndex:         0,
		PDUType:            pduType,
		NonRepeaters:       nonRepeaters,
		MaxRepetitions:     maxRepetitions & math.MaxInt32,
		VarBinds:           varBinds,
	}
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
func (m *Message) Encode(user *User) ([]byte, error) {
	var keys usmKeys
	if m.Version == Version3 && user != nil {
		var err error
		if keys, err = user.keysAt(m.SecurityLevel, m.SecurityParameters.AuthoritativeEngineID); err != nil {
			return nil, err
		}
	}
	return m.marshalMsg(&keys)
}

// EncodeMessage encodes a request or trap, for another transport or for tests:
// it builds the message with NewMessage and numbers it with the next request ID
// and, for SNMPv3, the next msgID, as a request's attempt does. An SNMPv3
// message takes the client's engine state as a request starts it: its engine ID
// and context engine ID, the keys localized to it, and the latest engine boots
// and time received, not advanced as a request's attempt advances them. It runs
// no discovery: before the client knows the agent's engine the message has no
// engine ID and no keys, so an authenticated or private one fails. On an error
// it returns no message.
func (c *Client) EncodeMessage(pduType PDUType, varBinds []VarBind, nonRepeaters uint8, maxRepetitions uint32) ([]byte, error) {
	m := c.NewMessage(pduType, varBinds, nonRepeaters, maxRepetitions)
	m.RequestID = c.nextRequestID()
	var keys usmKeys
	if c.config.Version == Version3 {
		c.startEngine()
		c.engine.stamp(m)
		m.SecurityParameters.AuthoritativeEngineBoots = c.engine.clock.boots
		m.SecurityParameters.AuthoritativeEngineTime = c.engine.clock.latest
		keys = c.engine.keys
		m.MsgID = c.nextMsgID()
	}
	return m.marshalMsg(&keys)
}

// DecodeMessage decodes a message, from another transport or for tests; an
// SNMPv3 message with the configuration's User, whose keys it derives for the
// message's engine ID: the authentication key when the message asks for
// authentication, the privacy key to decrypt. Of the security processing (RFC
// 3414 section 3.2) it makes only the checks that need no digest: the user must
// have the protocols the message asks for, and the message is decrypted exactly
// when it asks for privacy; it checks neither the user name, the digest nor the
// time window, nor any minimum level. It does not write data (see the package
// documentation for the values that alias it). On an error it returns no
// message.
func (c *Client) DecodeMessage(data []byte) (*Message, error) {
	result := new(Message)
	cursor, w, err := unmarshalHeader(data, result)
	if err != nil {
		return nil, fmt.Errorf("unable to decode packet header: %w", err)
	}
	if result.Version == Version3 {
		var in inbound
		if in, err = receiveV3(data, w, result, &c.config.User, nil); err != nil {
			return nil, fmt.Errorf("unable to decode packet header: %w", err)
		}
		if data, cursor, err = in.scopedPDU(result); err != nil {
			return nil, err
		}
	}
	if err = unmarshalPayload(data, cursor, result); err != nil {
		return nil, fmt.Errorf("unable to decode packet body: %w", err)
	}
	return result, nil
}
