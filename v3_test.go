// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMsgFlagsPredicates pins the flag each predicate reads: the authFlag and
// the privFlag bits (RFC 3412 section 6.4), whatever the others hold.
func TestMsgFlagsPredicates(t *testing.T) {
	type flags struct{ auth, priv bool }
	tests := map[string]struct {
		in   SnmpV3MsgFlags
		want flags
	}{
		"noAuthNoPriv":                    {in: NoAuthNoPriv, want: flags{}},
		"authNoPriv":                      {in: AuthNoPriv, want: flags{auth: true}},
		"privacy without authentication":  {in: AuthPriv &^ AuthNoPriv, want: flags{priv: true}},
		"authPriv":                        {in: AuthPriv, want: flags{auth: true, priv: true}},
		"reportable noAuthNoPriv":         {in: Reportable, want: flags{}},
		"reportable authPriv":             {in: AuthPriv | Reportable, want: flags{auth: true, priv: true}},
		"reportable privacy without auth": {in: AuthPriv&^AuthNoPriv | Reportable, want: flags{priv: true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, flags{auth: tc.in.authFlag(), priv: tc.in.privFlag()})
		})
	}
}

// TestNilSecurityParameters checks that a nil *UsmSecurityParameters in
// SecurityParameters, an interface that holds it and so is not nil, counts as
// no parameters wherever the field is read, as a nil interface does.
func TestNilSecurityParameters(t *testing.T) {
	encode := func(version Version, pduType PDUType) []byte {
		msg, err := (&Client{Version: version, Community: "public"}).EncodeMessage(pduType,
			[]VarBind{{Name: engineOID, Type: Null}}, 0, 0)
		require.NoError(t, err)
		return msg
	}
	request, trap := encode(Version2c, GetRequest), encode(Version2c, SNMPv2Trap)
	get := func(x *Client) error {
		_, err := x.Get([]string{engineOID})
		return err
	}
	const (
		errMustBeSet = "error: SNMPV3 SecurityParameters must be set"
		errNoneToAdd = "error: no security parameters to add for the key user"
	)
	tests := map[string]struct {
		version Version
		run     func(x *Client) error
		want    string
	}{
		"SNMPv2c Get":    {version: Version2c, run: get, want: "error: request timeout (after 0 retries)"},
		"SNMPv3 Get":     {version: Version3, run: get, want: errMustBeSet},
		"SNMPv3 Connect": {version: Version3, run: func(x *Client) error { return x.Connect() }, want: errMustBeSet},
		"SNMPv3 EncodeMessage": {version: Version3, run: func(x *Client) error {
			_, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Type: Null}}, 0, 0)
			return err
		}, want: errMustBeSet},
		"SNMPv2c DecodeMessage": {version: Version2c, run: func(x *Client) error {
			_, err := x.DecodeMessage(request)
			return err
		}, want: "ok"},
		"SNMPv3 DecodeMessage": {version: Version3, run: func(x *Client) error {
			_, err := x.DecodeMessage(request)
			return err
		}, want: errMustBeSet},
		"SNMPv2c UnmarshalTrap": {version: Version2c, run: func(x *Client) error {
			_, err := x.UnmarshalTrap(trap, false)
			return err
		}, want: "ok"},
		"table Add": {run: func(*Client) error {
			return NewSnmpV3SecurityParametersTable().Add("user", (*UsmSecurityParameters)(nil))
		}, want: errNoneToAdd},
		"table Add of a nil interface": {run: func(*Client) error {
			return NewSnmpV3SecurityParametersTable().Add("user", nil)
		}, want: errNoneToAdd},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{
				Target: "127.0.0.1", Port: 161, Version: tc.version, Community: "public", Timeout: 10 * time.Millisecond,
				MaxOids: MaxOids, SecurityModel: UserSecurityModel, MsgFlags: NoAuthNoPriv,
				SecurityParameters: (*UsmSecurityParameters)(nil), Conn: fakePacketTransport{newFakeTransport(nil, nil)},
			}
			assert.Equal(t, tc.want, outcomeOf(func() error { return tc.run(x) }))
		})
	}
}

// outcomeOf describes how fn ended: "panic: " and the value it panicked with,
// "error: " and the error it returned, or "ok".
func outcomeOf(fn func() error) string {
	var err error
	if v, _ := recoverPanic(func() { err = fn() }); v != nil {
		return fmt.Sprintf("panic: %v", v)
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return "ok"
}
