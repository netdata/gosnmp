// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWalkRequestChecks pins the checks a walk makes before its first
// request, in their order, on a client without Connect (MaxOids zero unless
// set): the root, then GetBulk on SNMPv1, then MaxOids against the one OID a
// request carries, then a nil context.
func TestWalkRequestChecks(t *testing.T) {
	tests := map[string]struct {
		version    Version
		bulk       bool
		root       string
		maxOids    int
		nilContext bool
		wantErr    string
	}{
		"root before SNMPv1": {
			version: Version1, bulk: true, root: "1.3.6.x", wantErr: `unable to marshal OID "1.3.6.x": invalid object identifier`,
		},
		"SNMPv1 before MaxOids": {version: Version1, bulk: true, root: walkSystem, wantErr: "GETBULK not supported in SNMPv1"},
		"MaxOids, GetNext":      {version: Version2c, root: walkSystem, wantErr: "oid count (1) is greater than MaxOids (0)"},
		"MaxOids, GetBulk":      {version: Version2c, bulk: true, root: walkSystem, wantErr: "oid count (1) is greater than MaxOids (0)"},
		"MaxOids before the context": {
			version: Version2c, root: walkSystem, nilContext: true, wantErr: "oid count (1) is greater than MaxOids (0)",
		},
		"nil context, GetNext": {version: Version2c, root: walkSystem, maxOids: 1, nilContext: true, wantErr: "nil context"},
		"nil context, GetBulk": {
			version: Version2c, bulk: true, root: walkSystem, maxOids: 1, nilContext: true, wantErr: "nil context",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Version: tc.version, MaxOids: tc.maxOids}
			walk := x.WalkAll
			if tc.bulk {
				walk = x.BulkWalkAll
			}
			ctx := context.Background()
			if tc.nilContext {
				ctx = nil
			}
			values, err := walk(ctx, tc.root)
			assert.EqualError(t, err, tc.wantErr)
			assert.Empty(t, values)
		})
	}
}

// TestEncodeMessageErrors pins that EncodeMessage returns no message with each
// of its errors: the client's configuration, the message's version, a varbind,
// and the SNMPv3 keys an authenticated or private message needs before the
// client knows the agent's engine (TestEncodeMessageEmptyKey).
func TestEncodeMessageErrors(t *testing.T) {
	authPriv := User{
		Name:           "codec-user",
		AuthProtocol:   SHA,
		AuthPassphrase: "codec-auth-pass",
		PrivProtocol:   AES,
		PrivPassphrase: "codec-priv-pass",
	}
	tests := map[string]struct {
		x       *Client
		pdus    []VarBind
		wantErr string
	}{
		"invalid parameters": {
			x: &Client{Version: Version2c, MaxOids: -1}, wantErr: "field MaxOids cannot be less than 0",
		},
		"unknown version": {
			x:       &Client{Version: Version(7)},
			wantErr: "unable to marshal SNMP version 7: not 1, 2c or 3",
		},
		"unencodable varbind": {
			x:       &Client{Version: Version2c, Community: "public"},
			pdus:    []VarBind{{Name: "not an oid", Value: NullValue()}},
			wantErr: "invalid object identifier",
		},
		"private before the engine is known": {
			x:       &Client{Version: Version3, SecurityLevel: AuthPriv, User: authPriv},
			pdus:    []VarBind{{Name: engineOID, Value: NullValue()}},
			wantErr: "usm: encrypting: no privacy key, want 16 octets",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := tc.x.EncodeMessage(GetRequest, tc.pdus, 0, 0)
			assert.ErrorContains(t, err, tc.wantErr)
			assert.Nil(t, out)
		})
	}
}

// TestEncodeMessageEmptyKey checks that EncodeMessage does not sign an
// authenticated SNMPv3 message before the client knows the agent's engine: the
// engine state has no engine ID to derive a key for, and the signer refuses
// the empty key with the rule's error and no message.
func TestEncodeMessageEmptyKey(t *testing.T) {
	x := &Client{
		Version:       Version3,
		SecurityLevel: AuthNoPriv,
		User:          User{Name: "codec-user", AuthProtocol: SHA, AuthPassphrase: "codec-auth-pass"},
	}
	out, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Value: NullValue()}}, 0, 0)
	require.EqualError(t, err, "usm: no authentication key, want 20 octets")
	assert.Nil(t, out)
	assert.Empty(t, x.engine.keys.auth, "key derived")
}

// TestRequestAndMsgIDs pins, through the encoded messages, the request ID and
// msgID counters: each starts at a random value on first use unless
// SetRequestID or SetMsgID set it, counts up and wraps to 0 after 2147483647,
// and Connect leaves both as they are.
func TestRequestAndMsgIDs(t *testing.T) {
	newClient := func() *Client {
		return &Client{
			Target:        "127.0.0.1",
			Port:          unusedUDPPort(t),
			Version:       Version3,
			SecurityLevel: NoAuthNoPriv,
			User:          User{Name: "codec-user"},
		}
	}
	ids := func(x *Client) [2]uint32 {
		t.Helper()
		data, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Value: NullValue()}}, 0, 0)
		require.NoError(t, err)
		p, err := x.DecodeMessage(data)
		require.NoError(t, err)
		return [2]uint32{p.RequestID, p.MsgID}
	}
	connect := func(x *Client) {
		t.Helper()
		require.NoError(t, x.Connect(context.Background()))
		conn := x.Conn
		t.Cleanup(func() { _ = conn.Close() })
	}
	next := func(id [2]uint32) [2]uint32 { return [2]uint32{(id[0] + 1) & 0x7FFFFFFF, (id[1] + 1) & 0x7FFFFFFF} }

	t.Run("random start, counting on across Connect", func(t *testing.T) {
		x := newClient()
		connect(x)
		first := ids(x)
		assert.Equal(t, next(first), ids(x))
		connect(x)
		assert.Equal(t, next(next(first)), ids(x), "a second Connect resets nothing")
	})
	t.Run("set counters survive Connect", func(t *testing.T) {
		x := newClient()
		x.SetRequestID(5)
		x.SetMsgID(70)
		connect(x)
		assert.Equal(t, [2]uint32{6, 71}, ids(x))
		x.SetRequestID(0x7FFFFFFF)
		x.SetMsgID(0x7FFFFFFF)
		assert.Equal(t, [2]uint32{0, 0}, ids(x), "wrap")
	})
	t.Run("random start without Connect", func(t *testing.T) {
		// An unseeded counter would start at 1 (a 2^-31 chance of a false
		// failure for each).
		id := ids(newClient())
		assert.NotEqual(t, uint32(1), id[0], "request ID")
		assert.NotEqual(t, uint32(1), id[1], "msgID")
	})
}

// unusedUDPPort returns a local UDP port nothing listens on.
func unusedUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	p, err := strconv.ParseUint(port, 10, 16)
	require.NoError(t, err)
	return uint16(p)
}
