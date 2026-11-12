// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

/*
Example usage and output:

$ GOSNMP_TARGET=10.12.0.1 GOSNMP_PORT=161 go run main.go
2021/01/03 13:31:15 Query latency in seconds: 0.000625777
0: oid: .1.3.6.1.2.1.1.4.0 string: contact
1: oid: .1.3.6.1.2.1.1.7.0 number: 78

*/

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	g "github.com/netdata/gosnmp"
)

func main() {
	// get Target and Port from environment
	envTarget := os.Getenv("GOSNMP_TARGET")
	envPort := os.Getenv("GOSNMP_PORT")
	if len(envTarget) == 0 {
		log.Fatalf("environment variable not set: GOSNMP_TARGET")
	}
	if len(envPort) == 0 {
		log.Fatalf("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)

	params := &g.Client{
		Target:    envTarget,
		Port:      uint16(port),
		Community: "public",
		Version:   g.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}
	ctx := context.Background()
	err := params.Connect(ctx)
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Close()

	// The time a request takes, its retries included.
	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	start := time.Now()
	result, err2 := params.Get(ctx, oids) // Get accepts up to MaxOids OIDs (60 by default)
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}
	log.Println("Query latency in seconds:", time.Since(start).Seconds())

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
