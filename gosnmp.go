// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxOids is the default of Client.MaxOids, the maximum number of OIDs in
	// a Get request and in each request of a walk. MaxOids too high can cause
	// remote devices to fail strangely. 60 seems to be a common value that
	// works; set Client.MaxOids to change it.
	MaxOids = 60

	// defaultMaxRepetitions is the walks' GetBulk max-repetitions unless
	// Client.MaxRepetitions is set; Java SNMP uses 50, net-snmp 10.
	defaultMaxRepetitions = 50
)

// Client is an SNMP client: its exported fields configure it, Connect opens
// its connection, and its methods send requests. A Client is not safe for
// concurrent use, Close excepted: requests share its connection, receive
// buffer and deadline, so run one request at a time, or give each goroutine
// its own Client.
type Client struct {
	// Conn is the connection to the agent, the UDP socket Connect opened, or
	// set by the caller in its place: the client then lacks Connect's defaults
	// and checks, so the caller sets the fields it needs (MaxOids, for one); a
	// request supplies its receive buffer and IDs. A request writes each
	// message with Write and reads each reply, one per read, with ReadFrom when
	// Conn is a net.PacketConn and with Read otherwise. The client owns the
	// connection Conn holds: Close and a later Connect close it; a connection
	// the caller replaces in Conn is the caller's again. Each attempt of a
	// request uses the connection Conn holds when it starts: Close interrupts
	// it once the attempt has set its deadline, whatever Conn holds then, and
	// before that closes it only if Conn still holds it. Set Conn only while
	// no Close runs.
	Conn net.Conn

	// Target is the agent's host name or IP address, which Connect dials.
	Target string

	// Port is the agent's port, usually 161; it has no default.
	Port uint16

	// Community is the community of SNMPv1 and SNMPv2c messages.
	Community string

	// Version is the SNMP version: Version1, Version2c or Version3.
	Version Version

	// Timeout is how long each attempt of a request waits for its answer, and
	// how long Connect may take to look up Target and dial. It has no default:
	// a zero Timeout times out every attempt at once, and leaves Connect
	// without a time limit.
	Timeout time.Duration

	// Retries is the number of attempts after the first; a negative value
	// counts as 0.
	Retries int

	// MaxOids is the maximum number of OIDs in a Get request, and in each
	// request of a walk, which carries one. Connect replaces zero with the
	// MaxOids constant.
	MaxOids int

	// MaxRepetitions is the GETBULK max-repetitions of BulkWalkAll, sent with
	// its top bit cleared; zero means 50. Some devices fail with large values;
	// see https://github.com/gosnmp/gosnmp/issues/100.
	MaxRepetitions uint32

	// SecurityLevel is the SNMPv3 security level: NoAuthNoPriv, AuthNoPriv or
	// AuthPriv; another value fails Connect. The encoder sets the reportable
	// flag of each message by its PDU type (RFC 3412 section 6.4: set for
	// requests and informs, clear for the others).
	SecurityLevel SecurityLevel

	// User is the SNMPv3 user. What the client learns of the agent's engine
	// it keeps to itself (see the package documentation, SNMPv3, and
	// ForgetEngine).
	User User

	// ContextName is the SNMPv3 context name of requests; their context
	// engine ID is the agent's engine ID.
	ContextName string

	// requestID and msgID count the request IDs and the SNMPv3 msgIDs;
	// requestIDSet and msgIDSet report that they were started, at a random
	// value on first use or by SetRequestID and SetMsgID.
	requestID    atomic.Uint32
	msgID        atomic.Uint32
	requestIDSet atomic.Bool
	msgIDSet     atomic.Bool

	// rx is the receive buffer, allocated by the first request.
	rx *receiveBuffer // has to be pointer due to https://github.com/golang/go/issues/11728

	// engine is the SNMPv3 engine state requests read and commit, and
	// forgetEngine reports that ForgetEngine ran since the last request
	// started (startEngine).
	engine       engineState
	forgetEngine bool

	// mu guards Conn, closed and attempt against Close, which may run on any
	// goroutine: Connect and Close change them under it, each attempt reads
	// them and registers itself under it.
	mu sync.Mutex
	// closed reports that Close ran since the last successful Connect.
	closed bool
	// attempt is the running attempt, which Close and the request's context
	// interrupt.
	attempt runningAttempt
}

// VarBind is a variable binding (varbind): the name of an object and its
// value. Requests, answers and traps carry them in Message.VarBinds.
type VarBind struct {
	// Name is the object's OID in dotted form, such as ".1.3.6.1.2.1.1.1.0":
	// with the leading dot when decoded from an OBJECT IDENTIFIER, with or
	// without it when sent. A name a device sent as an OCTET STRING or an
	// IpAddress is kept as text.
	Name string

	// Value is the value; the requests of Get and the walks send Null.
	Value Value
}

//go:generate go tool -modfile=tools/go.mod stringer -type ValueType

// ValueType is the BER tag of a varbind value, which names its type.
type ValueType byte

// The value types: the SMI's (RFC 2578), ASN.1's Null, net-snmp's OpaqueFloat
// and OpaqueDouble, which it wraps in an Opaque, and the exceptions of RFC 3416
// (NoSuchObject, NoSuchInstance, EndOfMibView). UnknownType is a value of a
// type the decoder does not decode, such as ASN.1's BOOLEAN or BIT STRING.
const (
	UnknownType      ValueType = 0x00
	Integer          ValueType = 0x02
	OctetString      ValueType = 0x04
	Null             ValueType = 0x05
	ObjectIdentifier ValueType = 0x06
	IPAddress        ValueType = 0x40
	Counter32        ValueType = 0x41
	Gauge32          ValueType = 0x42
	TimeTicks        ValueType = 0x43
	Opaque           ValueType = 0x44
	Counter64        ValueType = 0x46
	Uinteger32       ValueType = 0x47
	OpaqueFloat      ValueType = 0x78
	OpaqueDouble     ValueType = 0x79
	NoSuchObject     ValueType = 0x80
	NoSuchInstance   ValueType = 0x81
	EndOfMibView     ValueType = 0x82
)

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

// prepare readies the client for Connect, EncodeMessage and
// DecodeMessage, which call it each time: it fills in the default MaxOids,
// rejects a negative MaxOids and, for SNMPv3, checks the security level and
// parameters.
func (x *Client) prepare() error {
	if x.MaxOids == 0 {
		x.MaxOids = MaxOids
	} else if x.MaxOids < 0 {
		return fmt.Errorf("field MaxOids cannot be less than 0")
	}

	if x.Version == Version3 {
		if err := x.validateParametersV3(); err != nil {
			return err
		}
	}
	return nil
}

// EncodeMessage encodes a request or trap, for another transport or for
// tests: it prepares the client as Connect does, builds the message with
// NewMessage and numbers it with the next request ID and, for SNMPv3, the
// next msgID, as a request's attempt does. An SNMPv3 message takes the
// client's engine state as a request starts it (startEngine): its engine ID
// and context engine ID, the keys localized to it, and the latest engine boots
// and time received, not advanced as a request's attempt advances them. It runs
// no discovery: before the client knows the agent's engine the message has no
// engine ID and no keys, so an authenticated or private one fails. On an error
// it returns no message.
func (x *Client) EncodeMessage(pduType PDUType, varBinds []VarBind, nonRepeaters uint8, maxRepetitions uint32) ([]byte, error) {
	if err := x.prepare(); err != nil {
		return nil, err
	}
	pkt := x.NewMessage(pduType, varBinds, nonRepeaters, maxRepetitions)
	pkt.RequestID = x.nextRequestID()
	var keys usmKeys
	if x.Version == Version3 {
		if err := x.startEngine(); err != nil {
			return nil, err
		}
		x.engine.stamp(pkt)
		pkt.SecurityParameters.AuthoritativeEngineBoots = x.engine.clock.boots
		pkt.SecurityParameters.AuthoritativeEngineTime = x.engine.clock.latest
		keys = x.engine.keys
		pkt.MsgID = x.nextMsgID()
	}
	return pkt.marshalMsg(&keys)
}

// DecodeMessage decodes a message, from another transport or for tests,
// after preparing the client as Connect does; an SNMPv3 message with the
// client's User, whose keys it derives for the message's engine ID: the
// authentication key when the message asks for authentication, the privacy key
// to decrypt. Of the security processing (RFC 3414 section 3.2) it makes only
// the checks that need no digest: the user must have the protocols the message
// asks for, and the message is decrypted exactly when it asks for privacy; it
// checks neither the user name, the digest nor the time window, nor any
// minimum level. It does not write data (see the package documentation for the
// values that alias it). On an error it returns no message.
func (x *Client) DecodeMessage(data []byte) (*Message, error) {
	if err := x.prepare(); err != nil {
		return nil, err
	}

	result := new(Message)
	cursor, w, err := unmarshalHeader(data, result)
	if err != nil {
		return nil, fmt.Errorf("unable to decode packet header: %w", err)
	}
	if result.Version == Version3 {
		var in inbound
		if in, err = receiveV3(data, w, result, &x.User, nil); err != nil {
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
