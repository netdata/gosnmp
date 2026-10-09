// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This set of end-to-end integration tests execute gosnmp against a real
// SNMP MIB-2 host. Potential test systems could include a router, NAS box, printer,
// or a linux box running snmpd, snmpsimd.py, etc.
//
// Ensure "gosnmp-test-host" is defined in your hosts file, and points to your
// generic test system.

//go:build end2end

package gosnmp

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func getTarget(t *testing.T) (string, uint16) {
	envTarget := os.Getenv("GOSNMP_TARGET")
	envPort := os.Getenv("GOSNMP_PORT")

	if envTarget == "" {
		t.Skip("environment variable not set: GOSNMP_TARGET")
	}

	if envPort == "" {
		t.Skip("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)

	if port > 65535 {
		t.Skipf("invalid port number %d", port)
	}

	return envTarget, uint16(port)
}

func connectToTarget(t *testing.T, gs *GoSNMP) {
	target, port := getTarget(t)

	gs.Target = target
	gs.Port = port

	err := gs.Connect()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

func connectToTargetIPv4(t *testing.T, gs *GoSNMP) {
	target, port := getTarget(t)

	gs.Target = target
	gs.Port = port

	err := gs.ConnectIPv4()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

func TestClose(t *testing.T) {
	gs := newTestGoSNMP()
	gs.Retries = 1

	connectToTarget(t, gs)

	// Ensure connection is open
	if gs.Conn == nil {
		t.Fatal("expected connection to be established, got nil")
	}

	// Close the connection
	err := gs.Close()
	if err != nil {
		t.Fatalf("Close() returned an error: %v", err)
	}

	// Try closing again to make sure it handles idempotency
	err = gs.Close()
	if err != nil {
		t.Errorf("Close() on already-closed connection should not error, got: %v", err)
	}
}

func TestClose_NilConnection(t *testing.T) {
	gs := &GoSNMP{
		Conn: nil,
	}

	err := gs.Close()
	if err != nil {
		t.Errorf("expected nil error when closing nil connection, got: %v", err)
	}
}

func TestClose_Concurrent(t *testing.T) {
	gs := newTestGoSNMP()
	gs.Timeout = time.Second
	gs.Retries = 1

	connectToTarget(t, gs)

	var wg sync.WaitGroup
	for range 100 { // simulate 100 concurrent calls
		wg.Go(func() {
			_ = gs.Close()
		})
	}

	wg.Wait()

	if gs.Conn != nil {
		t.Errorf("expected connection to be nil after Close")
	}
}

/*
TODO work out ipv6 networking, etc

func setupConnectionIPv6(t *testing.T) *GoSNMP {
	envTarget := os.Getenv("GOSNMP_TARGET_IPV6")
	envPort := os.Getenv("GOSNMP_PORT_IPV6")
	gs := newTestGoSNMP()

	if envTarget == "" {
		t.Error("environment variable not set: GOSNMP_TARGET_IPV6")
	}
	gs.Target = envTarget

	if envPort == "" {
		t.Error("environment variable not set: GOSNMP_PORT_IPV6")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)
	gs.Port = uint16(port)

	err := gs.ConnectIPv6()
	if err != nil {
		if len(envTarget) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%s?\n(err: %v)",
				envTarget, envPort, err)
		}
	}
	return gs
}
*/

func TestGenericBasicGet(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestGenericBasicGetIPv4Only(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTargetIPv4(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

/*
func TestGenericBasicGetIPv6Only(t *testing.T) {
	gs := setupConnectionIPv6(t)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}
*/

func TestGenericMultiGet(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // SNMP MIB-2 sysDescr
		".1.3.6.1.2.1.1.5.0", // SNMP MIB-2 sysName
	}
	result, err := gs.Get(oids)
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Expected result of size 2")
	}
	for _, v := range result.Variables {
		if v.Type != OctetString {
			t.Fatalf("Expected OctetString")
		}
	}
}

func TestGenericGetNext(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	sysDescrOid := ".1.3.6.1.2.1.1.1.0" // SNMP MIB-2 sysDescr
	result, err := gs.GetNext([]string{sysDescrOid})
	if err != nil {
		t.Fatalf("GetNext() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Name == sysDescrOid {
		t.Fatalf("Expected next OID")
	}
}

func TestGenericWalk(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.WalkAll("")
	if err != nil {
		t.Fatalf("WalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestGenericBulkWalk(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.BulkWalkAll("")
	if err != nil {
		t.Fatalf("BulkWalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestV1BulkWalkError(t *testing.T) {
	g := newTestGoSNMP()
	g.Version = Version1
	connectToTarget(t, g)

	g.Conn.Close()

	_, err := g.BulkWalkAll("")
	if err == nil {
		t.Fatalf("BulkWalkAll() should fail in SNMPv1 but returned nil")
	}
}

// Standard exception/error tests

func TestMaxOids(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	gs.MaxOids = 1

	var err error
	oids := []string{
		".1.3.6.1.2.1.1.7.0",
		".1.3.6.1.2.1.2.2.1.10.1",
	} // 2 arbitrary Oids
	errString := "oid count (2) is greater than MaxOids (1)"

	_, err = gs.Get(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = gs.GetNext(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = gs.GetBulk(oids, 0, 0)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}
}

func TestGenericFailureUnknownHost(t *testing.T) {
	unknownHost := "nonexistent.invalid" // .invalid is guaranteed by RFC 2606 to never resolve.
	gs := newTestGoSNMP()
	gs.Target = unknownHost
	err := gs.Connect()
	if err == nil {
		t.Fatalf("Expected connection failure due to unknown host")
	}

	lerr := strings.ToLower(err.Error())
	if !strings.Contains(lerr, "no such host") && !strings.Contains(lerr, "i/o timeout") {
		t.Fatalf("Expected connection error of type 'no such host' or 'i/o timeout'! Got => %v", err)
	}

	_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected get to fail due to missing connection")
	}
}

func TestGenericFailureConnectionTimeout(t *testing.T) {
	t.Skip("local testing - skipping this slow one") // TODO test tag, or something
	envTarget := os.Getenv("GOSNMP_TARGET")
	if envTarget == "" {
		t.Skip("local testing - skipping this slow one")
	}

	gs := newTestGoSNMP()
	gs.Target = "198.51.100.1" // Black hole
	err := gs.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid IP")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Expected timeout error. Got => %v", err)
	}
}

func TestGenericFailureConnectionRefused(t *testing.T) {
	gs := newTestGoSNMP()
	gs.Target = "127.0.0.1"
	gs.Port = 1 // Don't expect SNMP to be running here!
	err := gs.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid port")
	}
	if !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "forcibly closed") {
		t.Fatalf("Expected connection refused error. Got => %v", err)
	}
}

// TestSnmpV3Users gets sysDescr and walks the system group as each user of
// testdata/snmp_users.txt, one per authentication and privacy protocol pair,
// after the engine discovery of a new connection.
func TestSnmpV3Users(t *testing.T) {
	for _, u := range loadSnmpUsers(t) {
		t.Run(u.name, func(t *testing.T) {
			gs := newTestGoSNMPv3(u.msgFlags(), u.securityParameters())
			connectToTarget(t, gs)
			defer gs.Conn.Close()

			result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
			if err != nil {
				t.Fatalf("Get() failed with error => %v", err)
			}
			if len(result.Variables) != 1 || result.Variables[0].Type != OctetString {
				t.Fatalf("Expected one OctetString sysDescr, got %v", result.Variables)
			}
			if sysDescr := result.Variables[0].Value.([]byte); len(sysDescr) == 0 {
				t.Fatalf("Got a zero length sysDescr")
			}

			values, err := gs.BulkWalkAll(".1.3.6.1.2.1.1") // SNMP MIB-2 system
			if err != nil {
				t.Fatalf("BulkWalkAll() failed with error => %v", err)
			}
			if len(values) <= 1 {
				t.Fatalf("Expected multiple values, got %d", len(values))
			}
		})
	}
}
