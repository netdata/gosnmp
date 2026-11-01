// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	g "github.com/netdata/gosnmp"
)

func main() {
	// A GoSNMP literal configures the client: SNMPv2c to port 161 with the
	// community "public"; Connect fills in MaxOids (60).
	client := &g.GoSNMP{
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

	for i, variable := range result.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)
		switch variable.Type {
		case g.OctetString:
			value := variable.Value.([]byte)
			if strings.Contains(strconv.Quote(string(value)), "\\x") {
				var tmp strings.Builder
				for i := range value {
					fmt.Fprintf(&tmp, "%v", value[i])
					if i != (len(value) - 1) {
						tmp.WriteString(" ")
					}
				}
				fmt.Printf("Hex-String: %s\n", tmp.String())
			} else {
				fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
			}
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
		}
	}
}
