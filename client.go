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
// its connection, and its methods send requests. A zero Client, which
// NewClient did not make, has a zero configuration without its defaults: it
// can only encode SNMPv1 messages and decode messages. A Client is not safe for
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
