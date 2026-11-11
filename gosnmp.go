// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"cmp"
	"fmt"
	"sync"
	"time"
)

const (
	// MaxOids is the default of Config.MaxOids, the maximum number of OIDs in
	// a Get request and in each request of a walk. MaxOids too high can cause
	// remote devices to fail strangely. 60 seems to be a common value that
	// works; set Config.MaxOids to change it.
	MaxOids = 60

	// defaultPort and defaultTimeout are the defaults of Config.Port and
	// Config.Timeout (net-snmp's timeout).
	defaultPort    = 161
	defaultTimeout = time.Second

	// defaultMaxRepetitions is the max-repetitions BulkWalkAll sends for a
	// zero argument; Java SNMP uses 50, net-snmp 10.
	defaultMaxRepetitions = 50
)

// Config configures a Client. NewClient checks it and fills in its
// defaults; the client keeps it as it is.
type Config struct {
	// Target is the agent's host name or IP address, which Connect dials; an
	// empty Target fails Connect. A client that only encodes and decodes
	// messages needs none.
	Target string

	// Port is the agent's port; zero means 161.
	Port uint16

	// Version is the SNMP version: Version1, Version2c or Version3; another
	// value fails NewClient. The zero value is Version1, as the version is
	// encoded.
	Version Version

	// Community is the community of SNMPv1 and SNMPv2c messages.
	Community string

	// Timeout is how long each attempt of a request waits for its answer, and
	// how long Connect may take to look up Target and dial; zero means 1 s.
	Timeout time.Duration

	// Retries is the number of attempts after the first; zero makes one
	// attempt.
	Retries int

	// MaxOids is the maximum number of OIDs in a Get request, and in each
	// request of a walk, which carries one; zero means the MaxOids constant.
	MaxOids int

	// SecurityLevel is the SNMPv3 security level: NoAuthNoPriv, AuthNoPriv or
	// AuthPriv. The encoder sets the reportable flag of each message by its
	// PDU type (RFC 3412 section 6.4: set for requests and informs, clear for
	// the others).
	SecurityLevel SecurityLevel

	// User is the SNMPv3 user. What the client learns of the agent's engine
	// it keeps to itself (see the package documentation, SNMPv3, and
	// ForgetEngine).
	User User

	// ContextName is the SNMPv3 context name of requests; their context
	// engine ID is the agent's engine ID.
	ContextName string
}

// Client is an SNMP client: NewClient makes it from a Config, Connect opens
// its connection, and its methods send requests. A Client is not safe for
// concurrent use, Close excepted: requests share its connection, receive
// buffer and deadline, so run one request at a time, or give each goroutine
// its own Client.
type Client struct {
	// config is the configuration NewClient checked, with its defaults.
	config Config

	// requestID and msgID count the request IDs and the SNMPv3 msgIDs from
	// the random values NewClient drew.
	requestID, msgID uint32

	// rx is the receive buffer, allocated by the first successful Connect.
	rx *receiveBuffer // has to be pointer due to https://github.com/golang/go/issues/11728

	// engine is the SNMPv3 engine state requests read and commit, and
	// forgetEngine reports that ForgetEngine ran since the last request
	// started (startEngine).
	engine       engineState
	forgetEngine bool

	// mu guards conn and closed against Close, which may run on any
	// goroutine, and attempt against the request's context, whose interrupt
	// runs on a goroutine of its own: Connect and Close change conn and closed
	// under it, each attempt reads them and registers itself under it.
	mu sync.Mutex
	// conn is the client's connection, the UDP socket Connect opened, nil
	// before the first Connect and after Close. The client owns it: Close and
	// a later Connect close it.
	conn transport
	// closed reports that Close ran since the last successful Connect.
	closed bool
	// attempt is the running attempt, which the request's context
	// interrupts.
	attempt runningAttempt
}

// NewClient returns a client of config with its defaults filled in: Port
// 161, Timeout 1 s and MaxOids the MaxOids constant for zero values. A
// Version other than the three, and a negative Timeout, Retries or MaxOids
// fail it; so do, for SNMPv3, a security level other than the three, a user
// the level does not fit (a name outside 1..32 octets, a protocol out of its
// set, a protocol the level needs missing, a protocol without a passphrase)
// and keys that do not derive (FIPS 140-only mode refuses MD5 and SHA-1). The
// SNMPv3 fields of an SNMPv1 or SNMPv2c client are not checked. Its errors
// name the field. The client keeps the configuration: nothing changes it.
func NewClient(config Config) (*Client, error) {
	if err := config.check(); err != nil {
		return nil, err
	}
	config.Port = cmp.Or(config.Port, defaultPort)
	config.Timeout = cmp.Or(config.Timeout, defaultTimeout)
	config.MaxOids = cmp.Or(config.MaxOids, MaxOids)
	return &Client{
		config:    config,
		requestID: randomID(),
		msgID:     randomID(),
		engine:    newEngineState(&config.User),
	}, nil
}

// check checks the configuration as NewClient does.
func (c *Config) check() error {
	switch {
	case c.Version != Version1 && c.Version != Version2c && c.Version != Version3:
		return fmt.Errorf("Config.Version is %v, not Version1, Version2c or Version3", c.Version)
	case c.Timeout < 0:
		return fmt.Errorf("Config.Timeout %v is negative", c.Timeout)
	case c.Retries < 0:
		return fmt.Errorf("Config.Retries %d is negative", c.Retries)
	case c.MaxOids < 0:
		return fmt.Errorf("Config.MaxOids %d is negative", c.MaxOids)
	case c.Version != Version3:
		return nil
	}
	// validate names the user's fields and the level as fields of Config.
	if err := c.User.validate(c.SecurityLevel); err != nil {
		return fmt.Errorf("Config.%w", err)
	}
	// The keys derive for the engine ID discovery finds; before it, they must
	// derive all the same: FIPS 140-only mode, for one, refuses MD5 and SHA-1.
	if _, err := c.User.localize(nil); err != nil {
		return fmt.Errorf("Config.User: %w", err)
	}
	return nil
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

// EncodeMessage encodes a request or trap, for another transport or for tests:
// it builds the message with NewMessage and numbers it with the next request ID
// and, for SNMPv3, the next msgID, as a request's attempt does. An SNMPv3
// message takes the client's engine state as a request starts it (startEngine):
// its engine ID and context engine ID, the keys localized to it, and the latest
// engine boots and time received, not advanced as a request's attempt advances
// them. It runs no discovery: before the client knows the agent's engine the
// message has no engine ID and no keys, so an authenticated or private one
// fails. On an error it returns no message.
func (x *Client) EncodeMessage(pduType PDUType, varBinds []VarBind, nonRepeaters uint8, maxRepetitions uint32) ([]byte, error) {
	pkt := x.NewMessage(pduType, varBinds, nonRepeaters, maxRepetitions)
	pkt.RequestID = x.nextRequestID()
	var keys usmKeys
	if x.config.Version == Version3 {
		x.startEngine()
		x.engine.stamp(pkt)
		pkt.SecurityParameters.AuthoritativeEngineBoots = x.engine.clock.boots
		pkt.SecurityParameters.AuthoritativeEngineTime = x.engine.clock.latest
		keys = x.engine.keys
		pkt.MsgID = x.nextMsgID()
	}
	return pkt.marshalMsg(&keys)
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
func (x *Client) DecodeMessage(data []byte) (*Message, error) {
	result := new(Message)
	cursor, w, err := unmarshalHeader(data, result)
	if err != nil {
		return nil, fmt.Errorf("unable to decode packet header: %w", err)
	}
	if result.Version == Version3 {
		var in inbound
		if in, err = receiveV3(data, w, result, &x.config.User, nil); err != nil {
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
