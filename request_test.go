// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"math"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandlerMaxRepetitions pins that a Handler keeps max-repetitions with
// its top bit cleared.
func TestHandlerMaxRepetitions(t *testing.T) {
	h := NewHandler()
	assert.Equal(t, uint32(0), h.MaxRepetitions(), "new")
	h.SetMaxRepetitions(math.MaxUint32)
	assert.Equal(t, uint32(math.MaxInt32), h.MaxRepetitions())
}

// TestNewHandler pins the client a new Handler is backed by: SNMPv2c to port
// 161 with the community "public", a Timeout of 2 seconds, 3 Retries and
// MaxOids at the MaxOids constant, nothing else set.
func TestNewHandler(t *testing.T) {
	h, ok := NewHandler().(*snmpHandler)
	require.True(t, ok)
	want := &Client{Port: 161, Community: "public", Version: Version2c, Timeout: 2 * time.Second, Retries: 3, MaxOids: MaxOids}
	assert.Equal(t, want, &h.Client)
}

// TestWalkRequestChecks pins the checks a walk makes before its first
// request, in their order, on a client without Connect (MaxOids zero): the
// root, then GetBulk on SNMPv1, then MaxOids against the one OID a request
// carries.
func TestWalkRequestChecks(t *testing.T) {
	tests := map[string]struct {
		version Version
		bulk    bool
		root    string
		wantErr string
	}{
		"root before SNMPv1": {
			version: Version1, bulk: true, root: "1.3.6.x", wantErr: `unable to marshal OID "1.3.6.x": invalid object identifier`,
		},
		"SNMPv1 before MaxOids": {version: Version1, bulk: true, root: walkSystem, wantErr: "GETBULK not supported in SNMPv1"},
		"MaxOids, GetNext":      {version: Version2c, root: walkSystem, wantErr: "oid count (1) is greater than MaxOids (0)"},
		"MaxOids, GetBulk":      {version: Version2c, bulk: true, root: walkSystem, wantErr: "oid count (1) is greater than MaxOids (0)"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Version: tc.version}
			walk := x.WalkAll
			if tc.bulk {
				walk = x.BulkWalkAll
			}
			values, err := walk(tc.root)
			assert.EqualError(t, err, tc.wantErr)
			assert.Empty(t, values)
		})
	}
}

// TestEncodeMessageErrors pins that EncodeMessage returns an empty,
// non-nil message with each of its errors.
func TestEncodeMessageErrors(t *testing.T) {
	tests := map[string]struct {
		x       *Client
		pdus    []VarBind
		wantErr string
	}{
		"invalid parameters": {
			x: &Client{Version: Version2c, MaxOids: -1}, wantErr: "field MaxOids cannot be less than 0",
		},
		"unencodable varbind": {
			x:       &Client{Version: Version2c, Community: "public"},
			pdus:    []VarBind{{Name: "not an oid", Type: Null}},
			wantErr: "invalid object identifier",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := tc.x.EncodeMessage(GetRequest, tc.pdus, 0, 0)
			assert.ErrorContains(t, err, tc.wantErr)
			assert.Equal(t, []byte{}, out)
		})
	}
}

// TestEncodeMessageEmptyKey checks that EncodeMessage does not sign an
// authenticated SNMPv3 message without a key: it derives none, and the signer
// refuses the empty key with the rule's error and an empty message.
func TestEncodeMessageEmptyKey(t *testing.T) {
	x := &Client{
		Version:       Version3,
		SecurityLevel: AuthNoPriv,
		SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthoritativeEngineID:    usmCharEngineID,
			AuthenticationProtocol:   SHA,
			AuthenticationPassphrase: "codec-auth-pass",
		},
	}
	out, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Type: Null}}, 0, 0)
	require.EqualError(t, err, "usm: no authentication key, want 20 octets")
	assert.Equal(t, []byte{}, out)
	assert.Empty(t, x.SecurityParameters.usm().SecretKey, "key derived")
}

// TestRequestAndMsgIDs pins, through the encoded messages, the request ID and
// msgID counters: each starts at a random value on first use unless
// SetRequestID or SetMsgID set it, counts up and wraps to 0 after 2147483647,
// and Connect leaves both as they are.
func TestRequestAndMsgIDs(t *testing.T) {
	newClient := func() *Client {
		return &Client{
			Target:             "127.0.0.1",
			Port:               unusedUDPPort(t),
			Version:            Version3,
			SecurityLevel:      NoAuthNoPriv,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: &UsmSecurityParameters{UserName: "codec-user"},
		}
	}
	ids := func(x *Client) [2]uint32 {
		t.Helper()
		data, err := x.EncodeMessage(GetRequest, []VarBind{{Name: engineOID, Type: Null}}, 0, 0)
		require.NoError(t, err)
		p, err := x.DecodeMessage(data)
		require.NoError(t, err)
		return [2]uint32{p.RequestID, p.MsgID}
	}
	connect := func(x *Client) {
		t.Helper()
		require.NoError(t, x.Connect())
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
