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
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// MaxOids is the default of GoSNMP.MaxOids, the maximum number of OIDs in
	// a Get, GetNext or GetBulk request. MaxOids too high can cause remote
	// devices to fail strangely. 60 seems to be a common value that works;
	// set GoSNMP.MaxOids to change it.
	MaxOids = 60

	// MaxObjectSubIdentifierValue is the largest OID sub-identifier (RFC
	// 2578 section 7.1.3). The library does not use it.
	MaxObjectSubIdentifierValue = 4294967295

	// defaultMaxRepetitions is the walks' GetBulk max-repetitions unless
	// GoSNMP.MaxRepetitions is set; Java SNMP uses 50, net-snmp 10.
	defaultMaxRepetitions = 50

	// "udp" and "tcp" are used regularly, prevent 'goconst' complaints
	udp = "udp"
	tcp = "tcp"
)

// GoSNMP is an SNMP client: its exported fields configure it, Connect opens
// its connection, and its methods send requests. A GoSNMP is not safe for
// concurrent use, Close excepted: requests share its connection, receive
// buffer and deadline, so run one request at a time, or give each goroutine
// its own GoSNMP.
type GoSNMP struct {
	// Conn is the connection to the agent, opened by Connect, or set by the
	// caller in its place: the client then lacks Connect's defaults and checks,
	// so the caller sets the fields it needs (MaxOids, for one); a request
	// supplies its Context default, receive buffer and IDs, a TCP reopen
	// opens it again with the request's Transport, Target, Port, LocalAddr and
	// Control, and with UseUnconnectedUDPSocket a request writes to the
	// agent's address the last successful Connect in that mode resolved (see
	// UseUnconnectedUDPSocket). The client owns the connection Conn holds:
	// Close and a later Connect close it; a connection the caller or a hook
	// replaces in Conn is the caller's again. Each attempt of a request uses
	// the connection Conn holds when it starts, which Close interrupts even
	// after a hook replaced it. Set Conn only while no Close runs.
	Conn net.Conn

	// Target is the agent's host name or IP address.
	Target string

	// Port is the agent's port, usually 161; it has no default.
	Port uint16

	// Transport is the network: "udp" (when empty) or "tcp", or either with
	// "4" or "6" for IPv4 or IPv6 only. Connect fills in "udp" when it is empty
	// and connects over it narrowed to IPv4 for an IPv4 LocalAddr, ConnectIPv4
	// and ConnectIPv6 over it with the suffix; it does not change Transport
	// otherwise.
	Transport string

	// Community is the community of SNMPv1 and SNMPv2c messages.
	Community string

	// Version is the SNMP version: Version1, Version2c or Version3.
	Version SnmpVersion

	// Context, when set, bounds Connect (its name lookups and dial) and every
	// request: no attempt starts once it is done, and its cancellation or
	// deadline ends a running attempt at once. Connect sets
	// context.Background() when it is nil, and a request without one uses
	// context.Background().
	Context context.Context

	// Timeout is how long each attempt of a request waits for its answer, and
	// how long Connect, and a TCP reopen, may take to look up names and dial.
	// It has no default: a zero Timeout times out every attempt at once, and
	// leaves Connect without a time limit.
	Timeout time.Duration

	// Retries is the number of attempts after the first; a negative value
	// counts as 0.
	Retries int

	// ExponentialTimeout doubles the timeout for each retry.
	ExponentialTimeout bool

	// Logger receives the client's debug output; the zero Logger disables it.
	// For verbose logging to stdout:
	//
	//	x.Logger = NewLogger(log.New(os.Stdout, "", 0))
	Logger Logger

	// The message hooks are called at points of a request, each with the
	// client, for example to time requests, count them or trace them. The
	// package documentation gives their order. A request calls the hooks set
	// when it starts.
	//
	// PreSend is called in each attempt after the request is encoded, before
	// it is written.
	PreSend func(*GoSNMP)

	// OnSent is called in each attempt after the request is written.
	OnSent func(*GoSNMP)

	// OnRecv is called after each reply is read, before it is decoded.
	OnRecv func(*GoSNMP)

	// OnRetry is called before each retry: after an attempt that failed in a
	// way another attempt may cure (a timeout, another write or read error
	// than a closed connection, a reply that does not decode or authenticate,
	// a TCP connection the agent closed, which the next attempt opens again),
	// when another attempt follows. It is not called after the last attempt,
	// nor when the Context is done.
	OnRetry func(*GoSNMP)

	// OnFinish is called each time an exchange (a request and the answer to
	// it, after any retries) ends without an error, including one answered by
	// a Report the client resynchronizes from (unknownEngineID, the usual answer
	// to SNMPv3 engine discovery, or notInTimeWindow). It is not called when an
	// exchange fails.
	OnFinish func(*GoSNMP)

	// MaxOids is the maximum number of OIDs in a Get, GetNext or GetBulk
	// request; Set does not check it. Connect replaces zero with the MaxOids
	// constant.
	MaxOids int

	// MaxRepetitions is the GETBULK max-repetitions of BulkWalk and
	// BulkWalkAll, sent with its top bit cleared; zero means 50. Some devices
	// fail with large values; see https://github.com/gosnmp/gosnmp/issues/100.
	MaxRepetitions uint32

	// NonRepeaters is not used.
	//
	// Deprecated: GetBulk takes the non-repeaters as an argument.
	NonRepeaters int

	// UseUnconnectedUDPSocket makes a UDP client send from an unconnected
	// socket, with sendto and recvfrom, for agents that answer from another
	// address than the one the request went to, as some multi-homed devices
	// do. Replies are then read from any address. A Conn the caller sets is
	// then written to the agent's address the last successful Connect in
	// this mode resolved, which Close keeps and a Connect in connected mode
	// clears: a request resolves no name; without such a Connect there is
	// none.
	UseUnconnectedUDPSocket bool

	// Control, when set, is the Control function of Connect's net.Dialer: it
	// is called after the socket is created and before it connects, for
	// example to set socket options. An unconnected UDP socket is not dialed,
	// so it does not get it.
	Control func(network, address string, c syscall.RawConn) error

	// LocalAddr is the local address of a UDP or TCP connection, "host:port";
	// an empty host or port, or port 0, lets the system choose.
	LocalAddr string

	// AppOpts holds net-snmp application options (snmpwalk -C). Only "c" is
	// used: when the key is present, whatever its value, Walk and BulkWalk do
	// not check that the names they receive increase, so the caller must end a
	// walk that loops.
	//
	//	x.AppOpts = map[string]any{"c": true}
	AppOpts map[string]any

	// MsgFlags is the SNMPv3 security level: NoAuthNoPriv, AuthNoPriv or
	// AuthPriv. Connect adds Reportable.
	MsgFlags SnmpV3MsgFlags

	// SecurityModel is the SNMPv3 security model; UserSecurityModel is the
	// only one.
	SecurityModel SnmpV3SecurityModel

	// SecurityParameters are the SNMPv3 security parameters, a
	// *UsmSecurityParameters. The client stores the agent's engine ID, boots
	// and time, and the keys, in them.
	SecurityParameters SnmpV3SecurityParameters

	// TrapSecurityParametersTable, when set, holds the security parameters
	// UnmarshalTrap decodes SNMPv3 messages with, by user name, instead of
	// SecurityParameters.
	TrapSecurityParametersTable *SnmpV3SecurityParametersTable

	// ContextEngineID is the SNMPv3 context engine ID of requests; when it is
	// empty, the client takes the agent's engine ID.
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

	// rxBuf is the receive buffer, allocated by the first request.
	rxBuf *[rxBufSize]byte // has to be pointer due to https://github.com/golang/go/issues/11728

	// mu guards Conn, opened, closed, lost, attempt and unconnectedAddr against
	// Close, which may run on any goroutine: Connect, Close and a TCP reopen
	// change them under it, each attempt reads them and registers itself under
	// it.
	mu sync.Mutex
	// opened is the connection the client opened (Connect or a TCP reopen),
	// while Conn holds it.
	opened connection
	// closed reports that Close ran since the last successful Connect.
	closed bool
	// lost is the TCP connection an attempt found failed: while Conn holds
	// it, the next attempt opens it again.
	lost net.Conn
	// attempt is the running attempt, which Close and the Context interrupt.
	attempt runningAttempt
	// unconnectedAddr is the agent's address the last successful Connect
	// resolved for an unconnected UDP socket, nil after one in connected mode;
	// Close keeps it. A Conn the caller sets in unconnected mode writes to it.
	unconnectedAddr *net.UDPAddr
}

// Default is a client with default settings, used by the examples. Like any
// GoSNMP, it is not safe for concurrent use.
//
//nolint:gochecknoglobals
var Default = &GoSNMP{
	Port:               161,
	Transport:          udp,
	Community:          "public",
	Version:            Version2c,
	Timeout:            time.Duration(2) * time.Second,
	Retries:            3,
	ExponentialTimeout: true,
	MaxOids:            MaxOids,
}

// SnmpPDU is a variable binding (varbind): the name of an object, and the
// type and value of its value. Requests, answers and traps carry them in
// SnmpPacket.Variables.
type SnmpPDU struct {
	// Value is the value, whose Go type depends on Type (see the package
	// documentation). Get, GetNext and GetBulk send nil.
	Value any

	// Name is the object's OID in dotted form, such as ".1.3.6.1.2.1.1.1.0":
	// with the leading dot when decoded from an OBJECT IDENTIFIER, with or
	// without it when sent. A name a device sent as an OCTET STRING or an
	// IpAddress is kept as text.
	Name string

	// Type is the type of the value.
	Type Asn1BER
}

//go:generate go tool -modfile=tools/go.mod stringer -type Asn1BER

// Asn1BER is the BER tag of a varbind value, which names its type.
type Asn1BER byte

// The value types: ASN.1's, those of the SMI (RFC 2578), net-snmp's
// OpaqueFloat and OpaqueDouble, the tags of the floats it wraps in an Opaque,
// and the exceptions of RFC 3416 (NoSuchObject, NoSuchInstance, EndOfMibView).
// The decoder gives UnknownType, which shares 0x00 with EndOfContents, for a
// value of a type it does not decode.
const (
	EndOfContents     Asn1BER = 0x00
	UnknownType       Asn1BER = 0x00
	Boolean           Asn1BER = 0x01
	Integer           Asn1BER = 0x02
	BitString         Asn1BER = 0x03
	OctetString       Asn1BER = 0x04
	Null              Asn1BER = 0x05
	ObjectIdentifier  Asn1BER = 0x06
	ObjectDescription Asn1BER = 0x07
	IPAddress         Asn1BER = 0x40
	Counter32         Asn1BER = 0x41
	Gauge32           Asn1BER = 0x42
	TimeTicks         Asn1BER = 0x43
	Opaque            Asn1BER = 0x44
	NsapAddress       Asn1BER = 0x45
	Counter64         Asn1BER = 0x46
	Uinteger32        Asn1BER = 0x47
	OpaqueFloat       Asn1BER = 0x78
	OpaqueDouble      Asn1BER = 0x79
	NoSuchObject      Asn1BER = 0x80
	NoSuchInstance    Asn1BER = 0x81
	EndOfMibView      Asn1BER = 0x82
)

//go:generate go tool -modfile=tools/go.mod stringer -type SNMPError

// SNMPError is the type for standard SNMP errors.
type SNMPError uint8

// SNMP Errors
const (
	NoError             SNMPError = iota // No error occurred. This code is also used in all request PDUs, since they have no error status to report.
	TooBig                               // The size of the Response-PDU would be too large to transport.
	NoSuchName                           // The name of a requested object was not found.
	BadValue                             // A value in the request didn't match the structure that the recipient of the request had for the object. For example, an object in the request was specified with an incorrect length or type.
	ReadOnly                             // An attempt was made to set a variable that has an Access value indicating that it is read-only.
	GenErr                               // An error occurred other than one indicated by a more specific error code in this table.
	NoAccess                             // Access was denied to the object for security reasons.
	WrongType                            // The object type in a variable binding is incorrect for the object.
	WrongLength                          // A variable binding specifies a length incorrect for the object.
	WrongEncoding                        // A variable binding specifies an encoding incorrect for the object.
	WrongValue                           // The value given in a variable binding is not possible for the object.
	NoCreation                           // A specified variable does not exist and cannot be created.
	InconsistentValue                    // A variable binding specifies a value that could be held by the variable but cannot be assigned to it at this time.
	ResourceUnavailable                  // An attempt to set a variable required a resource that is not available.
	CommitFailed                         // An attempt to set a particular variable failed.
	UndoFailed                           // An attempt to set a particular variable as part of a group of variables failed, and the attempt to then undo the setting of other variables was not successful.
	AuthorizationError                   // A problem occurred in authorization.
	NotWritable                          // The variable cannot be written or created.
	InconsistentName                     // The name in a variable binding specifies a variable that does not exist.
)

// prepare readies the client for Connect, SnmpEncodePacket and
// SnmpDecodePacket, which call it each time: it fills in the defaults (the UDP
// transport, MaxOids, a background Context), rejects a negative MaxOids and,
// for SNMPv3, sets Reportable, checks the security model and parameters and
// hands the client's Logger to the security parameters.
func (x *GoSNMP) prepare() error {
	if x.Transport == "" {
		x.Transport = udp
	}

	if x.MaxOids == 0 {
		x.MaxOids = MaxOids
	} else if x.MaxOids < 0 {
		return fmt.Errorf("field MaxOids cannot be less than 0")
	}

	if x.Version == Version3 {
		x.MsgFlags |= Reportable // tell the snmp server that a report PDU MUST be sent

		if err := x.validateParametersV3(); err != nil {
			return err
		}
		x.SecurityParameters.usm().setLogger(x.Logger)
	}

	if x.Context == nil {
		x.Context = context.Background()
	}
	return nil
}

// SnmpEncodePacket encodes a request or trap, for another transport or for
// tests: it prepares the client as Connect does, builds the packet with
// MkSnmpPacket and numbers it with the next request ID and, for SNMPv3, the
// next msgID, as a request's attempt does. It runs no engine discovery and
// derives no keys: an authenticated or private SNMPv3 message needs the keys
// in SecurityParameters. Known bug: without an authentication key the message
// is signed with an empty one. On an error it returns an empty message.
func (x *GoSNMP) SnmpEncodePacket(pdutype PDUType, pdus []SnmpPDU, nonRepeaters uint8, maxRepetitions uint32) ([]byte, error) {
	if err := x.prepare(); err != nil {
		return []byte{}, err
	}
	pkt := x.MkSnmpPacket(pdutype, pdus, nonRepeaters, maxRepetitions)
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

// SnmpDecodePacket decodes a message, from another transport or for tests,
// with a copy of the client's security parameters, after preparing the client
// as Connect does; keys are derived for an SNMPv3 message from another engine
// ID. It does not check the digest, and it decodes in place (see the package
// documentation). On an error it returns what it decoded so far. Known bug:
// some malformed SNMPv3 messages make it panic (see the package
// documentation).
func (x *GoSNMP) SnmpDecodePacket(resp []byte) (*SnmpPacket, error) {
	result := &SnmpPacket{}
	if err := x.prepare(); err != nil {
		return result, err
	}
	result.Logger = x.Logger
	if x.SecurityParameters != nil {
		result.SecurityParameters = x.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(resp, result)
	if err != nil {
		return result, fmt.Errorf("unable to decode packet header: %w", err)
	}
	if result.Version == Version3 {
		if resp, cursor, err = unmarshalScopedPDU(resp, cursor, result); err != nil {
			return result, err
		}
	}
	if err = unmarshalPayload(resp, cursor, result); err != nil {
		return result, fmt.Errorf("unable to decode packet body: %w", err)
	}
	return result, nil
}

// Partition reports whether currentPosition ends a partition when a slice of
// sliceLength items is cut into partitions of partitionSize, the last one
// possibly shorter: a loop over many OIDs can send a Get each time it reports
// true. A position outside the slice reports false. Known bug: a
// partitionSize of 0 panics for a position inside the slice.
//
// For a slice of 8 items in partitions of 3, it reports true at 2, 5 and 7:
//
//	0  1  2  3  4  5  6  7
//	      T        T     T
func Partition(currentPosition, partitionSize, sliceLength int) bool {
	if currentPosition < 0 || currentPosition >= sliceLength {
		return false
	}
	if partitionSize == 1 { // redundant, but an obvious optimisation
		return true
	}
	if currentPosition%partitionSize == partitionSize-1 {
		return true
	}
	if currentPosition == sliceLength-1 {
		return true
	}
	return false
}

// ToBigInt converts an integer varbind value, of any Go integer type, or a
// string holding a decimal integer, to a big.Int, and anything else to zero.
// It saves a type switch over the integer types values decode to. Known bug:
// a uint above math.MaxInt64 converts through int64 and comes out negative.
func ToBigInt(value any) *big.Int {
	var val int64

	switch value := value.(type) { // shadow
	case int:
		val = int64(value)
	case int8:
		val = int64(value)
	case int16:
		val = int64(value)
	case int32:
		val = int64(value)
	case int64:
		val = value
	case uint:
		val = int64(value) //nolint:gosec
	case uint8:
		val = int64(value)
	case uint16:
		val = int64(value)
	case uint32:
		val = int64(value)
	case uint64: // beware: int64(MaxUint64) overflow, handle different
		return new(big.Int).SetUint64(value)
	case string:
		// for testing and other apps - numbers may appear as strings
		var err error
		if val, err = strconv.ParseInt(value, 10, 64); err != nil {
			val = 0
		}
	default:
		val = 0
	}

	return big.NewInt(val)
}
