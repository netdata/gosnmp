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

// TestNilSecurityParameters pins what a nil *UsmSecurityParameters in
// SecurityParameters, an interface that holds it and so is not nil, does where
// the field is read.
func TestNilSecurityParameters(t *testing.T) {
	encode := func(version SnmpVersion, pduType PDUType) []byte {
		msg, err := (&GoSNMP{Version: version, Community: "public"}).SnmpEncodePacket(pduType,
			[]SnmpPDU{{Name: engineOID, Type: Null}}, 0, 0)
		require.NoError(t, err)
		return msg
	}
	request, trap := encode(Version2c, GetRequest), encode(Version2c, SNMPv2Trap)
	get := func(x *GoSNMP) error {
		_, err := x.Get([]string{engineOID})
		return err
	}
	tests := map[string]struct {
		version SnmpVersion
		run     func(x *GoSNMP) error
		want    string
	}{
		"SNMPv2c Get": {
			version: Version2c, run: get,
			want: "panic: runtime error: invalid memory address or nil pointer dereference",
		},
		"SNMPv3 Get": {
			version: Version3, run: get,
			want: "panic: runtime error: invalid memory address or nil pointer dereference",
		},
		"SNMPv3 Connect": {
			version: Version3, run: func(x *GoSNMP) error { return x.Connect() },
			want: "panic: runtime error: invalid memory address or nil pointer dereference",
		},
		"SNMPv3 SnmpEncodePacket": {version: Version3, run: func(x *GoSNMP) error {
			_, err := x.SnmpEncodePacket(GetRequest, []SnmpPDU{{Name: engineOID, Type: Null}}, 0, 0)
			return err
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
		"SNMPv2c SnmpDecodePacket": {version: Version2c, run: func(x *GoSNMP) error {
			_, err := x.SnmpDecodePacket(request)
			return err
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
		"SNMPv3 SnmpDecodePacket": {version: Version3, run: func(x *GoSNMP) error {
			_, err := x.SnmpDecodePacket(request)
			return err
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
		"SNMPv2c UnmarshalTrap": {version: Version2c, run: func(x *GoSNMP) error {
			_, err := x.UnmarshalTrap(trap, false)
			return err
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
		"table Add": {run: func(*GoSNMP) error {
			return NewSnmpV3SecurityParametersTable(Logger{}).Add("user", (*UsmSecurityParameters)(nil))
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
		"table Add of a nil interface": {run: func(*GoSNMP) error {
			return NewSnmpV3SecurityParametersTable(Logger{}).Add("user", nil)
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
		"packet SafeString": {run: func(*GoSNMP) error {
			_ = (&SnmpPacket{SecurityParameters: (*UsmSecurityParameters)(nil)}).SafeString()
			return nil
		}, want: "panic: runtime error: invalid memory address or nil pointer dereference"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &GoSNMP{
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
