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

// Handler is the interface of a Client, provided for mocks in tests; the
// methods that act are documented on Client, the others get or set its
// fields. Like a Client, a Handler is not safe for concurrent use, Close
// excepted.
type Handler interface {
	// Connect: see Client.Connect.
	Connect() error

	// Get: see Client.Get.
	Get(oids []string) (result *Message, err error)

	// WalkAll: see Client.WalkAll.
	WalkAll(rootOid string) (results []VarBind, err error)

	// BulkWalkAll: see Client.BulkWalkAll.
	BulkWalkAll(rootOid string) (results []VarBind, err error)

	// UnmarshalTrap: see Client.UnmarshalTrap.
	UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (result *Message, err error)

	// Close: see Client.Close.
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
	Version() Version

	// SetVersion sets the Version
	SetVersion(version Version)

	// Timeout gets the Timeout
	Timeout() time.Duration

	// SetTimeout sets the Timeout
	SetTimeout(timeout time.Duration)

	// Retries gets the Retries
	Retries() int

	// SetRetries sets the Retries
	SetRetries(retries int)

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
	Client
}

// NewHandler returns a Handler backed by a new Client with Port 161,
// Community "public", Version2c, a Timeout of 2 seconds, 3 Retries and
// MaxOids at the MaxOids constant.
func NewHandler() Handler {
	return &snmpHandler{
		Client{
			Port:      161,
			Community: "public",
			Version:   Version2c,
			Timeout:   2 * time.Second,
			Retries:   3,
			MaxOids:   MaxOids,
		},
	}
}

func (x *snmpHandler) Target() string {
	// not x.Target because it would reference function Target
	return x.Client.Target
}

func (x *snmpHandler) SetTarget(target string) {
	x.Client.Target = target
}

func (x *snmpHandler) Port() uint16 {
	return x.Client.Port
}

func (x *snmpHandler) SetPort(port uint16) {
	x.Client.Port = port
}

func (x *snmpHandler) Community() string {
	return x.Client.Community
}

func (x *snmpHandler) SetCommunity(community string) {
	x.Client.Community = community
}

func (x *snmpHandler) Version() Version {
	return x.Client.Version
}

func (x *snmpHandler) SetVersion(version Version) {
	x.Client.Version = version
}

func (x *snmpHandler) Timeout() time.Duration {
	return x.Client.Timeout
}

func (x *snmpHandler) SetTimeout(timeout time.Duration) {
	x.Client.Timeout = timeout
}

func (x *snmpHandler) Retries() int {
	return x.Client.Retries
}

func (x *snmpHandler) SetRetries(retries int) {
	x.Client.Retries = retries
}

func (x *snmpHandler) MaxOids() int {
	return x.Client.MaxOids
}

func (x *snmpHandler) SetMaxOids(maxOids int) {
	x.Client.MaxOids = maxOids
}

func (x *snmpHandler) MaxRepetitions() uint32 {
	return x.Client.MaxRepetitions
}

// SetMaxRepetitions sets MaxRepetitions with its top bit cleared.
func (x *snmpHandler) SetMaxRepetitions(maxRepetitions uint32) {
	x.Client.MaxRepetitions = maxRepetitions & math.MaxInt32
}

func (x *snmpHandler) MsgFlags() SnmpV3MsgFlags {
	return x.Client.MsgFlags
}

func (x *snmpHandler) SetMsgFlags(msgFlags SnmpV3MsgFlags) {
	x.Client.MsgFlags = msgFlags
}

func (x *snmpHandler) SecurityModel() SnmpV3SecurityModel {
	return x.Client.SecurityModel
}

func (x *snmpHandler) SetSecurityModel(securityModel SnmpV3SecurityModel) {
	x.Client.SecurityModel = securityModel
}

func (x *snmpHandler) SecurityParameters() SnmpV3SecurityParameters {
	return x.Client.SecurityParameters
}

func (x *snmpHandler) SetSecurityParameters(securityParameters SnmpV3SecurityParameters) {
	x.Client.SecurityParameters = securityParameters
}

func (x *snmpHandler) ContextEngineID() string {
	return x.Client.ContextEngineID
}

func (x *snmpHandler) SetContextEngineID(contextEngineID string) {
	x.Client.ContextEngineID = contextEngineID
}

func (x *snmpHandler) ContextName() string {
	return x.Client.ContextName
}

func (x *snmpHandler) SetContextName(contextName string) {
	x.Client.ContextName = contextName
}
