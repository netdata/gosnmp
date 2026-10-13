// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"math"
	"time"
)

//go:generate go tool -modfile=tools/go.mod mockgen -source=interface.go -destination=mocks/gosnmp_mock.go -package=mocks

// Handler is the interface of a GoSNMP, provided for mocks in tests; the
// methods that act are documented on GoSNMP, the others get or set its
// fields. Like a GoSNMP, a Handler is not safe for concurrent use.
type Handler interface {
	// Connect: see GoSNMP.Connect.
	Connect() error

	// ConnectIPv4: see GoSNMP.ConnectIPv4.
	ConnectIPv4() error

	// ConnectIPv6: see GoSNMP.ConnectIPv6.
	ConnectIPv6() error

	// Get: see GoSNMP.Get.
	Get(oids []string) (result *SnmpPacket, err error)

	// GetBulk: see GoSNMP.GetBulk.
	GetBulk(oids []string, nonRepeaters uint8, maxRepetitions uint32) (result *SnmpPacket, err error)

	// GetNext: see GoSNMP.GetNext.
	GetNext(oids []string) (result *SnmpPacket, err error)

	// Walk: see GoSNMP.Walk.
	Walk(rootOid string, walkFn WalkFunc) error

	// WalkAll: see GoSNMP.WalkAll.
	WalkAll(rootOid string) (results []SnmpPDU, err error)

	// BulkWalk: see GoSNMP.BulkWalk.
	BulkWalk(rootOid string, walkFn WalkFunc) error

	// BulkWalkAll: see GoSNMP.BulkWalkAll.
	BulkWalkAll(rootOid string) (results []SnmpPDU, err error)

	// UnmarshalTrap: see GoSNMP.UnmarshalTrap.
	UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (result *SnmpPacket, err error)

	// Set: see GoSNMP.Set.
	Set(pdus []SnmpPDU) (result *SnmpPacket, err error)

	// Check: see GoSNMP.Check.
	Check(err error)

	// Close closes the connection; see NewHandler for how its Close differs
	// from GoSNMP.Close.
	Close() error

	// Target gets the Target
	Target() string

	// SetTarget sets the Target
	SetTarget(target string)

	// Port gets the Port
	Port() uint16

	// SetPort sets the Port
	SetPort(port uint16)

	// Community gets the Community
	Community() string

	// SetCommunity sets the Community
	SetCommunity(community string)

	// Version gets the Version
	Version() SnmpVersion

	// SetVersion sets the Version
	SetVersion(version SnmpVersion)

	// Timeout gets the Timeout
	Timeout() time.Duration

	// SetTimeout sets the Timeout
	SetTimeout(timeout time.Duration)

	// Retries gets the Retries
	Retries() int

	// SetRetries sets the Retries
	SetRetries(retries int)

	// GetExponentialTimeout gets the ExponentialTimeout
	GetExponentialTimeout() bool

	// SetExponentialTimeout sets the ExponentialTimeout
	SetExponentialTimeout(value bool)

	// Logger gets the Logger
	Logger() Logger

	// SetLogger sets the Logger
	SetLogger(logger Logger)

	// MaxOids gets the MaxOids
	MaxOids() int

	// SetMaxOids sets the MaxOids
	SetMaxOids(maxOids int)

	// MaxRepetitions gets the MaxRepetitions
	MaxRepetitions() uint32

	// SetMaxRepetitions sets the MaxRepetitions, with its top bit cleared
	SetMaxRepetitions(maxRepetitions uint32)

	// MsgFlags gets the MsgFlags
	MsgFlags() SnmpV3MsgFlags

	// SetMsgFlags sets the MsgFlags
	SetMsgFlags(msgFlags SnmpV3MsgFlags)

	// SecurityModel gets the SecurityModel
	SecurityModel() SnmpV3SecurityModel

	// SetSecurityModel sets the SecurityModel
	SetSecurityModel(securityModel SnmpV3SecurityModel)

	// SecurityParameters gets the SecurityParameters
	SecurityParameters() SnmpV3SecurityParameters

	// SetSecurityParameters sets the SecurityParameters
	SetSecurityParameters(securityParameters SnmpV3SecurityParameters)

	// ContextEngineID gets the ContextEngineID
	ContextEngineID() string

	// SetContextEngineID sets the ContextEngineID
	SetContextEngineID(contextEngineID string)

	// ContextName gets the ContextName
	ContextName() string

	// SetContextName sets the ContextName
	SetContextName(contextName string)
}

// snmpHandler is a wrapper around gosnmp
type snmpHandler struct {
	GoSNMP
}

// NewHandler returns a Handler backed by a new GoSNMP with the Port,
// Community, Version, Timeout, Retries and MaxOids of Default; Transport and
// ExponentialTimeout stay unset. Known bug: its Close closes Conn directly,
// so it panics without a connection and leaves Conn set.
func NewHandler() Handler {
	return &snmpHandler{
		GoSNMP{
			Port:      Default.Port,
			Community: Default.Community,
			Version:   Default.Version,
			Timeout:   Default.Timeout,
			Retries:   Default.Retries,
			MaxOids:   Default.MaxOids,
		},
	}
}

func (x *snmpHandler) Target() string {
	// not x.Target because it would reference function Target
	return x.GoSNMP.Target
}

func (x *snmpHandler) SetTarget(target string) {
	x.GoSNMP.Target = target
}

func (x *snmpHandler) Port() uint16 {
	return x.GoSNMP.Port
}

func (x *snmpHandler) SetPort(port uint16) {
	x.GoSNMP.Port = port
}

func (x *snmpHandler) Community() string {
	return x.GoSNMP.Community
}

func (x *snmpHandler) SetCommunity(community string) {
	x.GoSNMP.Community = community
}

func (x *snmpHandler) Version() SnmpVersion {
	return x.GoSNMP.Version
}

func (x *snmpHandler) SetVersion(version SnmpVersion) {
	x.GoSNMP.Version = version
}

func (x *snmpHandler) Timeout() time.Duration {
	return x.GoSNMP.Timeout
}

func (x *snmpHandler) SetTimeout(timeout time.Duration) {
	x.GoSNMP.Timeout = timeout
}

func (x *snmpHandler) Retries() int {
	return x.GoSNMP.Retries
}

func (x *snmpHandler) SetRetries(retries int) {
	x.GoSNMP.Retries = retries
}

func (x *snmpHandler) GetExponentialTimeout() bool {
	return x.ExponentialTimeout
}

func (x *snmpHandler) SetExponentialTimeout(value bool) {
	x.ExponentialTimeout = value
}

func (x *snmpHandler) Logger() Logger {
	return x.GoSNMP.Logger
}

func (x *snmpHandler) SetLogger(logger Logger) {
	x.GoSNMP.Logger = logger
}

func (x *snmpHandler) MaxOids() int {
	return x.GoSNMP.MaxOids
}

func (x *snmpHandler) SetMaxOids(maxOids int) {
	x.GoSNMP.MaxOids = maxOids
}

func (x *snmpHandler) MaxRepetitions() uint32 {
	return x.GoSNMP.MaxRepetitions
}

// SetMaxRepetitions sets MaxRepetitions with its top bit cleared.
func (x *snmpHandler) SetMaxRepetitions(maxRepetitions uint32) {
	x.GoSNMP.MaxRepetitions = maxRepetitions & math.MaxInt32
}

func (x *snmpHandler) MsgFlags() SnmpV3MsgFlags {
	return x.GoSNMP.MsgFlags
}

func (x *snmpHandler) SetMsgFlags(msgFlags SnmpV3MsgFlags) {
	x.GoSNMP.MsgFlags = msgFlags
}

func (x *snmpHandler) SecurityModel() SnmpV3SecurityModel {
	return x.GoSNMP.SecurityModel
}

func (x *snmpHandler) SetSecurityModel(securityModel SnmpV3SecurityModel) {
	x.GoSNMP.SecurityModel = securityModel
}

func (x *snmpHandler) SecurityParameters() SnmpV3SecurityParameters {
	return x.GoSNMP.SecurityParameters
}

func (x *snmpHandler) SetSecurityParameters(securityParameters SnmpV3SecurityParameters) {
	x.GoSNMP.SecurityParameters = securityParameters
}

func (x *snmpHandler) ContextEngineID() string {
	return x.GoSNMP.ContextEngineID
}

func (x *snmpHandler) SetContextEngineID(contextEngineID string) {
	x.GoSNMP.ContextEngineID = contextEngineID
}

func (x *snmpHandler) ContextName() string {
	return x.GoSNMP.ContextName
}

func (x *snmpHandler) SetContextName(contextName string) {
	x.GoSNMP.ContextName = contextName
}

func (x *snmpHandler) Close() error {
	// Known bug: it closes Conn itself instead of calling GoSNMP.Close, so a
	// nil Conn panics, Conn is not cleared (a second call returns the
	// connection's error), and the lock GoSNMP.Close takes is skipped.
	return x.Conn.Close()
}
