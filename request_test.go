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

// TestRequestAndMsgIDs pins, through the encoded messages, how Connect seeds
// the request and msg IDs from the client's one random value, how
// SetRequestID and SetMsgID move them and how both wrap to 0 after
// 2147483647. Known bug: Connect reseeds both, discarding SetRequestID and
// SetMsgID.
func TestRequestAndMsgIDs(t *testing.T) {
	x := &GoSNMP{
		Target:             "127.0.0.1",
		Port:               unusedUDPPort(t),
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: "codec-user"},
	}
	ids := func() (requestID, msgID uint32) {
		t.Helper()
		data, err := x.SnmpEncodePacket(GetRequest, []SnmpPDU{{Name: engineOID, Type: Null}}, 0, 0)
		require.NoError(t, err)
		p, err := x.SnmpDecodePacket(data)
		require.NoError(t, err)
		return p.RequestID, p.MsgID
	}
	connect := func() {
		t.Helper()
		require.NoError(t, x.Connect())
		conn := x.Conn
		t.Cleanup(func() { _ = conn.Close() })
	}

	connect()
	seedReq, seedMsg := ids()
	assert.Equal(t, seedReq, seedMsg, "one seed for both")
	req, msg := ids()
	assert.Equal(t, [2]uint32{(seedReq + 1) & 0x7FFFFFFF, (seedMsg + 1) & 0x7FFFFFFF}, [2]uint32{req, msg})

	x.SetRequestID(5)
	x.SetMsgID(70)
	req, msg = ids()
	assert.Equal(t, [2]uint32{6, 71}, [2]uint32{req, msg})

	x.SetRequestID(0x7FFFFFFF)
	x.SetMsgID(0x7FFFFFFF)
	req, msg = ids()
	assert.Equal(t, [2]uint32{0, 0}, [2]uint32{req, msg}, "wrap")

	connect()
	req, msg = ids()
	assert.Equal(t, [2]uint32{seedReq, seedMsg}, [2]uint32{req, msg}, "Connect reseeds from the same random value")
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
