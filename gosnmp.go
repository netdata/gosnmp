// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"context"
	"fmt"
	"math/big"
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
	// request supplies its Context default, receive buffer and IDs. A request
	// writes each message with Write and reads each reply, one per read, with
	// ReadFrom when Conn is a net.PacketConn and with Read otherwise. The
	// client owns the connection Conn holds: Close and a later Connect close
	// it; a connection the caller or a hook replaces in Conn is the caller's
	// again. Each attempt of a request uses the connection Conn holds when it
	// starts, which Close interrupts even after a hook replaced it. Set Conn
	// only while no Close runs.
	Conn net.Conn

	// Target is the agent's host name or IP address, which Connect dials.
	Target string

	// Port is the agent's port, usually 161; it has no default.
	Port uint16

	// Community is the community of SNMPv1 and SNMPv2c messages.
	Community string

	// Version is the SNMP version: Version1, Version2c or Version3.
	Version Version

	// Context, when set, bounds Connect (its lookup of Target and its dial)
	// and every request: no attempt starts once it is done, and its
	// cancellation or deadline ends a running attempt at once. Connect sets
	// context.Background() when it is nil, and a request without one uses
	// context.Background().
	Context context.Context

	// Timeout is how long each attempt of a request waits for its answer, and
	// how long Connect may take to look up Target and dial. It has no default:
	// a zero Timeout times out every attempt at once, and leaves Connect
	// without a time limit.
	Timeout time.Duration

	// Retries is the number of attempts after the first; a negative value
	// counts as 0.
	Retries int

	// The message hooks are called at points of a request, each with the
	// client, for example to time requests, count them or trace them. The
	// package documentation gives their order. A request calls the hooks set
	// when it starts; a hook that panics ends the request (see the package
	// documentation, Hooks).
	//
	// PreSend is called in each attempt after the request is encoded, before
	// it is written.
	PreSend func(*Client)

	// OnSent is called in each attempt after the request is written.
	OnSent func(*Client)

	// OnRecv is called after each reply is read, before it is decoded.
	OnRecv func(*Client)

	// OnRetry is called before each retry: after an attempt that failed in a
	// way another attempt may cure (a timeout, or another write or read error
	// than a closed connection), when another attempt follows. It is not
	// called after the last attempt, nor when the Context is done.
	OnRetry func(*Client)

	// OnFinish is called each time an exchange (a request and the answer to
	// it, after any retries) ends without an error, including one answered by
	// a Report the client resynchronizes from (unknownEngineID, the usual answer
	// to SNMPv3 engine discovery, or notInTimeWindow). It is not called when an
	// exchange fails.
	OnFinish func(*Client)

	// MaxOids is the maximum number of OIDs in a Get request, and in each
	// request of a walk, which carries one. Connect replaces zero with the
	// MaxOids constant.
	MaxOids int

	// MaxRepetitions is the GETBULK max-repetitions of BulkWalkAll, sent with
	// its top bit cleared; zero means 50. Some devices fail with large values;
	// see https://github.com/gosnmp/gosnmp/issues/100.
	MaxRepetitions uint32

	// MsgFlags is the SNMPv3 security level: NoAuthNoPriv, AuthNoPriv or
	// AuthPriv. The encoder sets the reportable flag of each message by its PDU
	// type (RFC 3412 section 6.4: set for requests and informs, clear for the
	// others), whatever MsgFlags holds besides the level.
	MsgFlags SnmpV3MsgFlags

	// SecurityModel is the SNMPv3 security model; UserSecurityModel is the
	// only one.
	SecurityModel SnmpV3SecurityModel

	// SecurityParameters are the SNMPv3 security parameters, a
	// *UsmSecurityParameters, one value per client. The client keeps what it
	// learns of the agent's engine to itself and shows it in their engine ID,
	// boots, time and keys (see the package documentation, SNMPv3).
	SecurityParameters SnmpV3SecurityParameters

	// TrapSecurityParametersTable, when set, holds the security parameters
	// UnmarshalTrap decodes SNMPv3 messages with, by user name, instead of
	// SecurityParameters.
	TrapSecurityParametersTable *SnmpV3SecurityParametersTable

	// ContextEngineID is the SNMPv3 context engine ID of requests; when it is
	// empty, requests take the agent's engine ID, which the client then shows
	// here.
	ContextEngineID string

	// ContextName is the SNMPv3 context name of requests.
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

	// engine is the SNMPv3 engine state requests read and commit.
	engine engineState

	// mu guards Conn, closed and attempt against Close, which may run on any
	// goroutine: Connect and Close change them under it, each attempt reads
	// them and registers itself under it.
	mu sync.Mutex
	// closed reports that Close ran since the last successful Connect.
	closed bool
	// attempt is the running attempt, which Close and the Context interrupt.
	attempt runningAttempt
}

// VarBind is a variable binding (varbind): the name of an object, and the
// type and value of its value. Requests, answers and traps carry them in
// Message.VarBinds.
type VarBind struct {
	// Value is the value, whose Go type depends on Type (see the package
	// documentation). The requests of Get and the walks send nil.
	Value any

	// Name is the object's OID in dotted form, such as ".1.3.6.1.2.1.1.1.0":
	// with the leading dot when decoded from an OBJECT IDENTIFIER, with or
	// without it when sent. A name a device sent as an OCTET STRING or an
	// IpAddress is kept as text.
	Name string

	// Type is the type of the value.
	Type ValueType
}

//go:generate go tool -modfile=tools/go.mod stringer -type ValueType

// ValueType is the BER tag of a varbind value, which names its type.
type ValueType byte

// The value types: ASN.1's, those of the SMI (RFC 2578), net-snmp's
// OpaqueFloat and OpaqueDouble, the tags of the floats it wraps in an Opaque,
// and the exceptions of RFC 3416 (NoSuchObject, NoSuchInstance, EndOfMibView).
// The decoder gives UnknownType, which shares 0x00 with EndOfContents, for a
// value of a type it does not decode.
const (
	EndOfContents     ValueType = 0x00
	UnknownType       ValueType = 0x00
	Boolean           ValueType = 0x01
	Integer           ValueType = 0x02
	BitString         ValueType = 0x03
	OctetString       ValueType = 0x04
	Null              ValueType = 0x05
	ObjectIdentifier  ValueType = 0x06
	ObjectDescription ValueType = 0x07
	IPAddress         ValueType = 0x40
	Counter32         ValueType = 0x41
	Gauge32           ValueType = 0x42
	TimeTicks         ValueType = 0x43
	Opaque            ValueType = 0x44
	NsapAddress       ValueType = 0x45
	Counter64         ValueType = 0x46
	Uinteger32        ValueType = 0x47
	OpaqueFloat       ValueType = 0x78
	OpaqueDouble      ValueType = 0x79
	NoSuchObject      ValueType = 0x80
	NoSuchInstance    ValueType = 0x81
	EndOfMibView      ValueType = 0x82
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
// DecodeMessage, which call it each time: it fills in the defaults (MaxOids,
// a background Context), rejects a negative MaxOids and, for SNMPv3, checks
// the security model and parameters.
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

	if x.Context == nil {
		x.Context = context.Background()
	}
	return nil
}

// EncodeMessage encodes a request or trap, for another transport or for
// tests: it prepares the client as Connect does, builds the message with
// NewMessage and numbers it with the next request ID and, for SNMPv3, the
// next msgID, as a request's attempt does. It runs no engine discovery and
// derives no keys: an authenticated or private SNMPv3 message needs the keys
// in SecurityParameters (InitSecurityKeys derives them), and fails without
// them. It carries the engine boots and time of SecurityParameters as they
// are: after a request, the latest values the client accepted, not advanced
// as a request advances them. On an error it returns an empty message.
func (x *Client) EncodeMessage(pduType PDUType, varBinds []VarBind, nonRepeaters uint8, maxRepetitions uint32) ([]byte, error) {
	if err := x.prepare(); err != nil {
		return []byte{}, err
	}
	pkt := x.NewMessage(pduType, varBinds, nonRepeaters, maxRepetitions)
	pkt.RequestID = x.nextRequestID()
	if x.Version == Version3 {
		pkt.MsgID = x.nextMsgID()
	}
	out, err := pkt.marshalMsg()
	if err != nil {
		return []byte{}, err
	}
	return out, nil
}

// DecodeMessage decodes a message, from another transport or for tests,
// with a copy of the client's security parameters, after preparing the client
// as Connect does; for an SNMPv3 message from another engine ID it derives the
// authentication key, and the privacy key to decrypt, so parameters with a key
// given without its passphrase decode no such message. Of the security
// processing (RFC 3414 section 3.2) it makes only the checks that need no
// digest: the parameters must have the protocols the message asks for, and the
// message is decrypted exactly when it asks for privacy; it checks neither the
// user name, the digest nor the time window, nor any minimum level. It does not
// write data (see the package documentation for the values that alias it). On
// an error it returns what it decoded so far.
func (x *Client) DecodeMessage(data []byte) (*Message, error) {
	result := &Message{}
	if err := x.prepare(); err != nil {
		return result, err
	}
	if sp := usmOf(x.SecurityParameters); sp != nil {
		result.SecurityParameters = sp.Copy()
	}

	cursor, w, err := unmarshalHeader(data, result)
	if result.Version == Version3 && result.SecurityParameters == nil {
		result.SecurityParameters = &UsmSecurityParameters{}
	}
	if err != nil {
		if result.Version == Version3 {
			// The result returned with the error carries the USM fields
			// that decoded.
			_, _ = result.SecurityParameters.usm().receive(result.MsgFlags, &w, false)
		}
		return result, fmt.Errorf("unable to decode packet header: %w", err)
	}
	if result.Version == Version3 {
		var in inbound
		if in, err = receiveV3(data, w, result, result.SecurityParameters.usm()); err != nil {
			return result, fmt.Errorf("unable to decode packet header: %w", err)
		}
		if data, cursor, err = in.scopedPDU(result); err != nil {
			return result, err
		}
	}
	if err = unmarshalPayload(data, cursor, result); err != nil {
		return result, fmt.Errorf("unable to decode packet body: %w", err)
	}
	return result, nil
}

// ToBigInt converts an integer varbind value (an int, int8, int16, int32,
// int64, uint, uint8, uint16, uint32 or uint64, not a uintptr or a named
// type), or a string holding a decimal integer of any size, to a new big.Int,
// and anything else to zero. It saves a type switch over the integer types
// values decode to.
func ToBigInt(value any) *big.Int {
	switch value := value.(type) { // shadow
	case int:
		return big.NewInt(int64(value))
	case int8:
		return big.NewInt(int64(value))
	case int16:
		return big.NewInt(int64(value))
	case int32:
		return big.NewInt(int64(value))
	case int64:
		return big.NewInt(value)
	case uint8:
		return big.NewInt(int64(value))
	case uint16:
		return big.NewInt(int64(value))
	case uint32:
		return big.NewInt(int64(value))
	case uint: // may not fit an int64
		return new(big.Int).SetUint64(uint64(value))
	case uint64:
		return new(big.Int).SetUint64(value)
	case string:
		// The syntax strconv.ParseInt accepts in base 10: an optional sign
		// and digits.
		if v, ok := new(big.Int).SetString(value, 10); ok {
			return v
		}
	}
	return new(big.Int)
}
