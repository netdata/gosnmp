// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

// Tests for SNMPv3 engine-ID discovery when the device responds with
// usmStatsUnknownUserNames instead of the standard usmStatsUnknownEngineIDs.
//
// Some devices (e.g. Dell EMC switches) behave this way: they respond to the
// discovery probe with a Report containing usmStatsUnknownUserNames
// (.1.3.6.1.6.3.15.1.1.3.0) but still include valid engine parameters
// (AuthoritativeEngineID, boots, time) in the USM security header of that
// same response. net-snmp extracts those parameters and proceeds; the library
// previously treated the response as a fatal error and aborted.
//
// These tests use a minimal mock UDP agent that replicates the exact packet
// exchange observed in packet captures from an affected device.

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// testDiscoveryEngineID is the AuthoritativeEngineID the mock agent advertises
// in all discovery tests in this file.
var testDiscoveryEngineID = string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04})

const (
	testDiscoveryEngineBoots uint32 = 174
	testDiscoveryEngineTime  uint32 = 572518
)

// mockAgentUnknownUserNames is a minimal UDP SNMP agent that responds to
// SNMPv3 discovery probes with usmStatsUnknownUserNames rather than the
// standard usmStatsUnknownEngineIDs. Subsequent authenticated requests
// receive a minimal Response so the full Get() call can succeed.
//
// Set failAuthRequests to true before calling serve() to make the mock also
// return usmStatsUnknownUserNames for post-discovery authenticated requests,
// simulating an agent that does not recognise the user credentials.
type mockAgentUnknownUserNames struct {
	conn                 *net.UDPConn
	engineID             string
	boots                uint32
	engineTime           uint32
	done                 chan struct{}
	errs                 chan error
	failAuthRequests     bool
	omitEngineIDInReport bool   // send usmStatsUnknownUserNames with empty AuthoritativeEngineID
	reportUserName       string // the user name of the usmStatsUnknownUserNames Report
}

// newMockAgentUnknownUserNames returns an agent with the engine
// testDiscoveryEngineID, testDiscoveryEngineBoots and testDiscoveryEngineTime.
func newMockAgentUnknownUserNames(t *testing.T) *mockAgentUnknownUserNames {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	return &mockAgentUnknownUserNames{
		conn:       conn,
		engineID:   testDiscoveryEngineID,
		boots:      testDiscoveryEngineBoots,
		engineTime: testDiscoveryEngineTime,
		done:       make(chan struct{}),
		errs:       make(chan error, 16),
	}
}

func (m *mockAgentUnknownUserNames) port() uint16 {
	return uint16(m.conn.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec
}

// closeAndCheck stops the mock server and fails the test if any internal
// error occurred during packet processing (e.g. parse or marshal failure).
// It must be called after the goroutine started by serve() has been launched.
func (m *mockAgentUnknownUserNames) closeAndCheck(t *testing.T) {
	t.Helper()
	m.conn.Close()
	<-m.done
	for {
		select {
		case err := <-m.errs:
			t.Errorf("mock agent internal error: %v", err)
		default:
			return
		}
	}
}

func (m *mockAgentUnknownUserNames) sendErr(err error) {
	select {
	case m.errs <- err:
	default:
	}
}

// serve processes packets until the connection is closed. It detects discovery
// probes by the empty AuthoritativeEngineID in the USM security parameters and
// responds with usmStatsUnknownUserNames. All other packets are treated as
// authenticated requests and receive a Response, unless failAuthRequests is
// set in which case they also receive usmStatsUnknownUserNames.
func (m *mockAgentUnknownUserNames) serve() {
	defer close(m.done)

	buf := make([]byte, rxBufSize)
	for {
		n, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		req := &Message{}
		cursor, _, err := unmarshalHeader(buf[:n], req)
		if err != nil {
			m.sendErr(fmt.Errorf("unmarshalHeader: %w", err))
			continue
		}

		// unmarshalScopedPDU advances the cursor past the ScopedPDU wrapper
		// and context fields, leaving it at the PDU type byte; the client
		// sends noAuthNoPriv requests, which take no keys.
		pkt, cursor, err := unmarshalScopedPDU(buf[:n], cursor, req, req.SecurityLevel.privFlag(), &usmKeys{})
		if err != nil {
			m.sendErr(fmt.Errorf("decryptPacket: %w", err))
			continue
		}

		if err = unmarshalPayload(pkt, cursor, req); err != nil {
			m.sendErr(fmt.Errorf("unmarshalPayload: %w", err))
			continue
		}

		var responseBytes []byte
		if len(req.SecurityParameters.AuthoritativeEngineID) == 0 || m.failAuthRequests {
			// Discovery probe (empty engine ID) or an agent configured to
			// reject all users: respond with usmStatsUnknownUserNames and
			// include valid engine parameters in the USM security header.
			responseBytes, err = m.marshalUnknownUserNamesReport(req)
		} else {
			responseBytes, err = m.marshalResponse(req)
		}
		if err != nil {
			m.sendErr(fmt.Errorf("marshal response: %w", err))
			continue
		}
		if _, err = m.conn.WriteToUDP(responseBytes, addr); err != nil {
			m.sendErr(fmt.Errorf("WriteToUDP: %w", err))
		}
	}
}

func (m *mockAgentUnknownUserNames) secParams() SecurityParameters {
	return SecurityParameters{
		AuthoritativeEngineID:    []byte(m.engineID),
		AuthoritativeEngineBoots: m.boots,
		AuthoritativeEngineTime:  m.engineTime,
	}
}

// marshalUnknownUserNamesReport builds a Report PDU that carries
// usmStatsUnknownUserNames but contains valid engine parameters — the
// non-standard response that triggers the bug. If omitEngineIDInReport is set,
// the AuthoritativeEngineID in the security parameters is left empty to simulate
// a malformed device response.
func (m *mockAgentUnknownUserNames) marshalUnknownUserNamesReport(req *Message) ([]byte, error) {
	secParams := m.secParams()
	if m.omitEngineIDInReport {
		secParams.AuthoritativeEngineID = nil
	}
	secParams.UserName = m.reportUserName
	pkt := &Message{
		Version:       Version3,
		SecurityLevel: NoAuthNoPriv,

		SecurityParameters: secParams,
		PDUType:            Report,
		MsgID:              req.MsgID,
		RequestID:          req.RequestID,
		VarBinds: []VarBind{{
			Name:  usmStatsUnknownUserNames,
			Value: IntegerValue(1),
		}},
	}
	return pkt.Encode(nil)
}

// marshalResponse builds a Response that echoes the client's MsgID,
// RequestID and user name, as an agent does, and returns a single OID value.
func (m *mockAgentUnknownUserNames) marshalResponse(req *Message) ([]byte, error) {
	secParams := m.secParams()
	secParams.UserName = req.SecurityParameters.UserName
	pkt := &Message{
		Version:       Version3,
		SecurityLevel: NoAuthNoPriv,

		SecurityParameters: secParams,
		PDUType:            Response,
		MsgID:              req.MsgID,
		RequestID:          req.RequestID,
		ContextEngineID:    []byte(m.engineID),
		VarBinds: []VarBind{{
			Name:  ".1.3.6.1.2.1.1.1.0",
			Value: OctetStringValue([]byte("mock sysDescr")),
		}},
	}
	return pkt.Encode(nil)
}

// newV3NoAuthClientForDiscoveryTest returns a client configured for
// NoAuthNoPriv SNMPv3, which knows no engine yet, so that the first request
// starts with engine-ID discovery (discoveryPacket).
func newV3NoAuthClientForDiscoveryTest(port uint16) *Client {
	config := testConfigV3(NoAuthNoPriv, User{Name: "testUser"})
	config.Target, config.Port, config.Retries = "127.0.0.1", port, 0
	return mustClient(config)
}

// setupDiscoveryTest creates a mock agent and a connected SNMPv3 client for
// the usmStatsUnknownUserNames discovery tests. Cleanup is registered
// automatically via t.Cleanup; callers must not close the agent or connection
// themselves.
func setupDiscoveryTest(t *testing.T) *Client {
	t.Helper()
	agent := newMockAgentUnknownUserNames(t)
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect(context.Background()))
	t.Cleanup(func() { _ = ts.Close() })

	return ts
}

// TestV3DiscoveryUnknownUserNames verifies that negotiateInitialSecurityParameters
// succeeds — and correctly stores the engine ID, boots, and time — when the
// device responds to the discovery probe with usmStatsUnknownUserNames instead
// of the standard usmStatsUnknownEngineIDs.
//
// Before the fix this test fails: negotiateInitialSecurityParameters propagates
// ErrUnknownUsername and never stores the engine parameters.
func TestV3DiscoveryUnknownUserNames(t *testing.T) {
	ts := setupDiscoveryTest(t)

	// NewMessage produces the same packet shape that Get() passes to
	// negotiateInitialSecurityParameters internally.
	pkt := ts.NewMessage(GetRequest, nil, 0, 0)
	ts.startEngine()
	answer, err := ts.negotiateInitialSecurityParameters(context.Background(), pkt)
	require.NoError(t, err, "negotiateInitialSecurityParameters must succeed even when the device "+
		"responds with usmStatsUnknownUserNames during engine-ID discovery")
	require.Nil(t, answer, "a discovery that succeeds returns no answer")

	stored := &ts.engine
	require.Equal(t, []byte(testDiscoveryEngineID), stored.engineID,
		"engine ID must be extracted from the usmStatsUnknownUserNames Report")
	require.Equal(t, testDiscoveryEngineBoots, stored.clock.boots,
		"engine boots must be extracted from the usmStatsUnknownUserNames Report")
	require.Equal(t, testDiscoveryEngineTime, stored.clock.latest,
		"engine time must be extracted from the usmStatsUnknownUserNames Report")
}

// TestV3GetWithDiscoveryUnknownUserNames is an end-to-end test that exercises
// the complete Get() flow against a mock agent that returns
// usmStatsUnknownUserNames during discovery. It mirrors the packet exchange
// observed in the real-world packet captures:
//
//  1. Client sends discovery probe (engineID="", userName="").
//  2. Agent responds: Report with usmStatsUnknownUserNames + valid engine params.
//  3. Client sends authenticated GetRequest.
//  4. Agent responds: Response with OID data.
//
// Before the fix, step 2 causes Get() to return ErrUnknownUsername. After the
// fix, all four steps complete successfully.
func TestV3GetWithDiscoveryUnknownUserNames(t *testing.T) {
	ts := setupDiscoveryTest(t)

	result, err := ts.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"})
	require.NoError(t, err, "Get() must succeed when the device responds with "+
		"usmStatsUnknownUserNames during engine-ID discovery")
	require.NotNil(t, result)
	require.Len(t, result.VarBinds, 1)
	require.Equal(t, ".1.3.6.1.2.1.1.1.0", result.VarBinds[0].Name)
	require.Equal(t, OctetStringValue([]byte("mock sysDescr")), result.VarBinds[0].Value)
}

// TestV3DiscoveryUnknownUserNamesNoEngineID verifies that ErrUnknownUsername is
// propagated when the device responds to the discovery probe with
// usmStatsUnknownUserNames but provides an empty AuthoritativeEngineID in the
// USM security parameters. Without a valid engine ID there is nothing useful to
// extract, so the error must not be suppressed.
func TestV3DiscoveryUnknownUserNamesNoEngineID(t *testing.T) {
	agent := newMockAgentUnknownUserNames(t)
	agent.omitEngineIDInReport = true
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect(context.Background()))
	t.Cleanup(func() { _ = ts.Close() })

	pkt := ts.NewMessage(GetRequest, nil, 0, 0)
	ts.startEngine()
	answer, err := ts.negotiateInitialSecurityParameters(context.Background(), pkt)
	require.ErrorIs(t, err, ErrUnknownUsername,
		"ErrUnknownUsername must not be suppressed when the Report carries an empty engine ID")
	require.NotNil(t, answer, "the discovery returns the Report that ended it")
}

// TestV3GetRealUnknownUserNameStillFails verifies that ErrUnknownUsername is
// still returned for actual (post-discovery) requests, confirming the fix does
// not suppress genuine authentication failures.
//
// The mock is configured to return usmStatsUnknownUserNames for all requests.
// Discovery succeeds (the fix applies), but the subsequent Get fails because
// the agent continues to reject the user on the actual request.
func TestV3GetRealUnknownUserNameStillFails(t *testing.T) {
	agent := newMockAgentUnknownUserNames(t)
	// failAuthRequests must be set before serve() is started.
	agent.failAuthRequests = true
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect(context.Background()))
	t.Cleanup(func() { _ = ts.Close() })

	_, err := ts.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"})
	require.ErrorIs(t, err, ErrUnknownUsername,
		"ErrUnknownUsername from a post-discovery request must not be suppressed")
	require.ErrorIs(t, err, ErrAnswered, "the agent's Report ended the request")
}

// TestV3DiscoveryUnknownUserNamesOtherUser pins a discovery answered with a
// usmStatsUnknownUserNames Report that names another user than the
// discovery's empty one: the client discards it (RFC 3414 section 3.2 step 4),
// so the discovery times out with an error that also unwraps to the discard's,
// ErrUnknownUsername, and the client takes no engine parameters.
func TestV3DiscoveryUnknownUserNamesOtherUser(t *testing.T) {
	agent := newMockAgentUnknownUserNames(t)
	agent.reportUserName = "other-user"
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect(context.Background()))
	t.Cleanup(func() { _ = ts.Close() })

	pkt := ts.NewMessage(GetRequest, nil, 0, 0)
	ts.startEngine()
	answer, err := ts.negotiateInitialSecurityParameters(context.Background(), pkt)
	require.ErrorIs(t, err, errUnknownUser)
	require.Nil(t, answer, "no answer ended the discovery: it timed out")
	require.Empty(t, ts.engine.engineID)
}
