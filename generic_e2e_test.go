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
	"context"
	"math"
	"os"
	"slices"
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

// connectToTarget returns the client of config, with the test agent's Target
// and Port, connected.
func connectToTarget(t *testing.T, config Config) *Client {
	target, port := getTarget(t)

	config.Target = target
	config.Port = port
	gs, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	err = gs.Connect(context.Background())
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
	return gs
}

func TestClose(t *testing.T) {
	config := testConfig()
	config.Retries = 1
	gs := connectToTarget(t, config)

	// Ensure connection is open
	if gs.conn == nil {
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
	gs := mustClient(Config{})

	err := gs.Close()
	if err != nil {
		t.Errorf("expected nil error when closing nil connection, got: %v", err)
	}
}

func TestClose_Concurrent(t *testing.T) {
	config := testConfig()
	config.Timeout = time.Second
	config.Retries = 1
	gs := connectToTarget(t, config)

	var wg sync.WaitGroup
	for range 100 { // simulate 100 concurrent calls
		wg.Go(func() {
			_ = gs.Close()
		})
	}

	wg.Wait()

	if gs.conn != nil {
		t.Errorf("expected connection to be nil after Close")
	}
}

func TestGenericBasicGet(t *testing.T) {
	gs := connectToTarget(t, testConfig())
	defer gs.Close()

	result, err := gs.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.VarBinds) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.VarBinds[0].Value.Type() != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr, _ := result.VarBinds[0].Value.Bytes()
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestGenericMultiGet(t *testing.T) {
	gs := connectToTarget(t, testConfig())
	defer gs.Close()

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // SNMP MIB-2 sysDescr
		".1.3.6.1.2.1.1.5.0", // SNMP MIB-2 sysName
	}
	result, err := gs.Get(context.Background(), oids)
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.VarBinds) != 2 {
		t.Fatalf("Expected result of size 2")
	}
	for _, v := range result.VarBinds {
		if v.Value.Type() != OctetString {
			t.Fatalf("Expected OctetString")
		}
	}
}

func TestGenericWalk(t *testing.T) {
	gs := connectToTarget(t, testConfig())
	defer gs.Close()

	result, end, err := gs.WalkAll(context.Background(), "")
	if err != nil {
		t.Fatalf("WalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
	if end.Reason != WalkException || end.VarBind.Value.Type() != EndOfMibView {
		t.Fatalf("Expected the walk to end at EndOfMibView, got %v %v", end.Reason, end.VarBind)
	}
}

func TestGenericBulkWalk(t *testing.T) {
	gs := connectToTarget(t, testConfig())
	defer gs.Close()

	result, end, err := gs.BulkWalkAll(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("BulkWalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
	if end.Reason != WalkException || end.VarBind.Value.Type() != EndOfMibView {
		t.Fatalf("Expected the walk to end at EndOfMibView, got %v %v", end.Reason, end.VarBind)
	}
}

// TestGenericBulkWalkMaxRepetitions walks the system group with the default,
// the smallest and the largest max-repetitions: the agent returns the same
// objects for each.
func TestGenericBulkWalkMaxRepetitions(t *testing.T) {
	gs := connectToTarget(t, testConfig())
	defer gs.Close()

	walkNames := func(t *testing.T, maxRepetitions uint32) []string {
		t.Helper()
		values, _, err := gs.BulkWalkAll(context.Background(), ".1.3.6.1.2.1.1", maxRepetitions) // SNMP MIB-2 system
		if err != nil {
			t.Fatalf("BulkWalkAll() failed with error => %v", err)
		}
		names := make([]string, 0, len(values))
		for _, vb := range values {
			names = append(names, vb.Name)
		}
		return names
	}
	want := walkNames(t, 0)
	if len(want) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(want))
	}
	for name, maxRepetitions := range map[string]uint32{"one": 1, "max-int32": math.MaxInt32} {
		t.Run(name, func(t *testing.T) {
			if got := walkNames(t, maxRepetitions); !slices.Equal(got, want) {
				t.Errorf("names = %v, want %v", got, want)
			}
		})
	}
}

func TestV1BulkWalkError(t *testing.T) {
	config := testConfig()
	config.Version = Version1
	g := connectToTarget(t, config)

	g.Close()

	_, _, err := g.BulkWalkAll(context.Background(), "", 0)
	if err == nil {
		t.Fatalf("BulkWalkAll() should fail in SNMPv1 but returned nil")
	}
}

// TestGenericWalkEnd walks roots that end a walk in each way an agent ends
// one, with GETNEXT and GETBULK, and checks how each walk ended: the system
// group past its last object, a leaf scalar got with one Get, an instance the
// agent does not have (NoSuchInstance) and an object it does not have
// (NoSuchObject); and over SNMPv1, the noSuchName of a root past the MIB.
func TestGenericWalkEnd(t *testing.T) {
	const (
		system  = ".1.3.6.1.2.1.1"
		sysName = ".1.3.6.1.2.1.1.5.0"
	)
	type want struct {
		reason  WalkReason
		name    string    // the end's varbind name, "" for any
		typ     ValueType // the end's varbind type
		values  int       // -1 for more than one
		outside bool      // the end's varbind is outside the root
	}
	cases := map[string]struct {
		version Version
		root    string
		want    want
	}{
		"subtree":          {version: Version2c, root: system, want: want{reason: WalkOutside, values: -1, outside: true}},
		"leaf":             {version: Version2c, root: sysName, want: want{reason: WalkLeaf, name: sysName, typ: OctetString, values: 1}},
		"no-such-instance": {version: Version2c, root: ".1.3.6.1.2.1.1.5.1", want: want{reason: WalkLeaf, name: ".1.3.6.1.2.1.1.5.1", typ: NoSuchInstance}},
		"no-such-object":   {version: Version2c, root: ".1.3.6.1.2.1.1.10", want: want{reason: WalkLeaf, name: ".1.3.6.1.2.1.1.10", typ: NoSuchObject}},
		"v1/subtree":       {version: Version1, root: system, want: want{reason: WalkOutside, values: -1, outside: true}},
		"v1/past-the-mib":  {version: Version1, root: ".1.3.6.1.6.3.99", want: want{reason: WalkLeaf}},
	}
	for name, tc := range cases {
		config := testConfig()
		config.Version = tc.version
		gs := connectToTarget(t, config)
		walks := map[string]func() ([]VarBind, WalkEnd, error){
			"WalkAll": func() ([]VarBind, WalkEnd, error) { return gs.WalkAll(context.Background(), tc.root) },
		}
		if tc.version != Version1 {
			walks["BulkWalkAll"] = func() ([]VarBind, WalkEnd, error) { return gs.BulkWalkAll(context.Background(), tc.root, 0) }
		}
		for api, walk := range walks {
			t.Run(name+"/"+api, func(t *testing.T) {
				values, end, err := walk()
				if err != nil {
					t.Fatalf("walk: %v", err)
				}
				switch {
				case tc.want.values < 0 && len(values) <= 1:
					t.Errorf("values = %d, want more than one", len(values))
				case tc.want.values >= 0 && len(values) != tc.want.values:
					t.Errorf("values = %v, want %d", values, tc.want.values)
				}
				if end.Reason != tc.want.reason {
					t.Errorf("end = %v, want %v", end.Reason, tc.want.reason)
				}
				if tc.want.name != "" && end.VarBind.Name != tc.want.name {
					t.Errorf("end varbind = %q, want %q", end.VarBind.Name, tc.want.name)
				}
				if tc.want.typ != UnknownType && end.VarBind.Value.Type() != tc.want.typ {
					t.Errorf("end varbind type = %v, want %v", end.VarBind.Value.Type(), tc.want.typ)
				}
				if tc.want.outside && (end.VarBind.Name == "" || strings.HasPrefix(end.VarBind.Name, tc.root+".")) {
					t.Errorf("end varbind %q is not outside %s", end.VarBind.Name, tc.root)
				}
			})
		}
		gs.Close()
	}
}

// Standard exception/error tests

func TestMaxOids(t *testing.T) {
	config := testConfig()
	config.MaxOids = 1
	gs := connectToTarget(t, config)
	defer gs.Close()

	var err error
	oids := []string{
		".1.3.6.1.2.1.1.7.0",
		".1.3.6.1.2.1.2.2.1.10.1",
	} // 2 arbitrary Oids
	errString := "oid count (2) is greater than MaxOids (1)"

	_, err = gs.Get(context.Background(), oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}
}

func TestGenericFailureUnknownHost(t *testing.T) {
	unknownHost := "nonexistent.invalid" // .invalid is guaranteed by RFC 2606 to never resolve.
	config := testConfig()
	config.Target = unknownHost
	gs := mustClient(config)
	err := gs.Connect(context.Background())
	if err == nil {
		t.Fatalf("Expected connection failure due to unknown host")
	}

	lerr := strings.ToLower(err.Error())
	if !strings.Contains(lerr, "no such host") && !strings.Contains(lerr, "i/o timeout") {
		t.Fatalf("Expected connection error of type 'no such host' or 'i/o timeout'! Got => %v", err)
	}

	_, err = gs.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

	config := testConfig()
	config.Target = "198.51.100.1" // Black hole
	gs := mustClient(config)
	err := gs.Connect(context.Background())
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = gs.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid IP")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Expected timeout error. Got => %v", err)
	}
}

func TestGenericFailureConnectionRefused(t *testing.T) {
	config := testConfig()
	config.Target = "127.0.0.1"
	config.Port = 1 // Don't expect SNMP to be running here!
	gs := mustClient(config)
	err := gs.Connect(context.Background())
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = gs.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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
			gs := connectToTarget(t, testConfigV3(u.msgFlags(), u.securityParameters()))
			defer gs.Close()

			result, err := gs.Get(context.Background(), []string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
			if err != nil {
				t.Fatalf("Get() failed with error => %v", err)
			}
			if len(result.VarBinds) != 1 || result.VarBinds[0].Value.Type() != OctetString {
				t.Fatalf("Expected one OctetString sysDescr, got %v", result.VarBinds)
			}
			if sysDescr, _ := result.VarBinds[0].Value.Bytes(); len(sysDescr) == 0 {
				t.Fatalf("Got a zero length sysDescr")
			}

			values, _, err := gs.BulkWalkAll(context.Background(), ".1.3.6.1.2.1.1", 0) // SNMP MIB-2 system
			if err != nil {
				t.Fatalf("BulkWalkAll() failed with error => %v", err)
			}
			if len(values) <= 1 {
				t.Fatalf("Expected multiple values, got %d", len(values))
			}
		})
	}
}
