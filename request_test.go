// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"math"
	"net"
	"strconv"
	"testing"

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

// TestGetBulkChecks pins the order of GetBulk's input checks: the SNMPv1
// check comes before the MaxOids check.
func TestGetBulkChecks(t *testing.T) {
	x := &GoSNMP{Version: Version1, MaxOids: 1}
	_, err := x.GetBulk([]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0"}, 0, 10)
	assert.EqualError(t, err, "GETBULK not supported in SNMPv1")
}

// TestSnmpEncodePacketErrors pins that SnmpEncodePacket returns an empty,
// non-nil message with each of its errors.
func TestSnmpEncodePacketErrors(t *testing.T) {
	tests := map[string]struct {
		x       *GoSNMP
		pdus    []SnmpPDU
		wantErr string
	}{
		"invalid parameters": {
			x: &GoSNMP{Version: Version2c, MaxOids: -1}, wantErr: "field MaxOids cannot be less than 0",
		},
		"unencodable varbind": {
			x:       &GoSNMP{Version: Version2c, Community: "public"},
			pdus:    []SnmpPDU{{Name: "not an oid", Type: Null}},
			wantErr: "invalid object identifier",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := tc.x.SnmpEncodePacket(GetRequest, tc.pdus, 0, 0)
			assert.ErrorContains(t, err, tc.wantErr)
			assert.Equal(t, []byte{}, out)
		})
	}
}

// TestSnmpEncodePacketEmptyKey pins that SnmpEncodePacket signs an
// authenticated SNMPv3 message with an empty key when the client has no key:
// it derives none, and the signer does not refuse an empty one. Known bug.
func TestSnmpEncodePacketEmptyKey(t *testing.T) {
	x := &GoSNMP{
		Version:       Version3,
		MsgFlags:      AuthNoPriv,
		SecurityModel: UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthoritativeEngineID:    usmCharEngineID,
			AuthenticationProtocol:   SHA,
			AuthenticationPassphrase: "codec-auth-pass",
		},
	}
	out, err := x.SnmpEncodePacket(GetRequest, []SnmpPDU{{Name: engineOID, Type: Null}}, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, x.SecurityParameters.usm().SecretKey, "key derived")

	// Decoding zeroes the digest in out, which leaves the message as signed.
	p, err := x.SnmpDecodePacket(out)
	require.NoError(t, err)
	digest := []byte(p.SecurityParameters.usm().AuthenticationParameters)
	ok, err := SHA.spec().Verify(nil, out, digest)
	require.NoError(t, err)
	assert.True(t, ok, "not signed with an empty key")
}

// TestRequestAndMsgIDs pins, through the encoded messages, the request ID and
// msgID counters: each starts at a random value on first use unless
// SetRequestID or SetMsgID set it, counts up and wraps to 0 after 2147483647,
// and Connect leaves both as they are.
func TestRequestAndMsgIDs(t *testing.T) {
	newClient := func() *GoSNMP {
		return &GoSNMP{
			Target:             "127.0.0.1",
			Port:               unusedUDPPort(t),
			Version:            Version3,
			MsgFlags:           NoAuthNoPriv,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: &UsmSecurityParameters{UserName: "codec-user"},
		}
	}
	ids := func(x *GoSNMP) [2]uint32 {
		t.Helper()
		data, err := x.SnmpEncodePacket(GetRequest, []SnmpPDU{{Name: engineOID, Type: Null}}, 0, 0)
		require.NoError(t, err)
		p, err := x.SnmpDecodePacket(data)
		require.NoError(t, err)
		return [2]uint32{p.RequestID, p.MsgID}
	}
	connect := func(x *GoSNMP) {
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
		// An unseeded counter would start at 1 (a 2^-62 chance of a false
		// failure).
		assert.NotEqual(t, [2]uint32{1, 1}, ids(newClient()))
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
