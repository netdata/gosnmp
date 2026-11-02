// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"fmt"
	"log"
	"time"

	g "github.com/netdata/gosnmp"
)

func main() {
	// A Client literal configures the client: SNMPv2c to port 161 with the
	// community "public"; Connect fills in MaxOids (60).
	client := &g.Client{
		Target:    "192.168.1.10",
		Port:      161,
		Community: "public",
		Version:   g.Version2c,
		Timeout:   2 * time.Second,
		Retries:   3,
	}
	err := client.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer client.Close()

	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	result, err2 := client.Get(oids) // Get accepts up to MaxOids OIDs (60 by default)
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	for i, variable := range result.VarBinds {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		// Each value type has its accessor (see Value): text for an
		// OctetString, a number for the integer types (Uint64 for Counter64), ...
		if b, ok := variable.Value.Bytes(); ok {
			fmt.Printf("string: %s\n", string(b))
		} else if n, ok := variable.Value.Int64(); ok {
			fmt.Printf("number: %d\n", n)
		} else if n, ok := variable.Value.Uint64(); ok {
			fmt.Printf("number: %d\n", n)
		} else {
			fmt.Printf("type: %v\n", variable.Value.Type())
		}
	}
}
