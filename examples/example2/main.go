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
	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Close()

	// Function handles for collecting metrics on query latencies.
	var sent time.Time
	params.OnSent = func(_ *g.Client) {
		sent = time.Now()
	}
	params.OnRecv = func(_ *g.Client) {
		log.Println("Query latency in seconds:", time.Since(sent).Seconds())
	}

	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	result, err2 := params.Get(oids) // Get accepts up to MaxOids OIDs (60 by default)
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	for i, variable := range result.VarBinds {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		// The Go type of a Value depends on its Type (see the package
		// documentation). You could do a type switch...
		switch variable.Type {
		case g.OctetString:
			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
		}
	}
}
