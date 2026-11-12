// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This program demonstrates BulkWalkAll.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/netdata/gosnmp"
)

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s [-community=<community>] host [oid]\n", filepath.Base(os.Args[0]))
		fmt.Printf("     host      - the host to walk/scan\n")
		fmt.Printf("     oid       - the MIB/Oid defining a subtree of values\n\n")
		flag.PrintDefaults()
	}

	var community string
	flag.StringVar(&community, "community", "public", "the community string for device")

	flag.Parse()

	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	target := flag.Args()[0]
	var oid string
	if len(flag.Args()) > 1 {
		oid = flag.Args()[1]
	}

	client := &gosnmp.Client{
		Target:    target,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   10 * time.Second, // Timeout better suited to walking
		Retries:   3,
	}
	err := client.Connect()
	if err != nil {
		fmt.Printf("Connect err: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	values, err := client.BulkWalkAll(oid)
	for _, vb := range values {
		printValue(vb)
	}
	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
}

func printValue(vb gosnmp.VarBind) {
	fmt.Printf("%s = ", vb.Name)

	if b, ok := vb.Value.Bytes(); ok {
		fmt.Printf("STRING: %s\n", string(b))
	} else if n, ok := vb.Value.Int64(); ok {
		fmt.Printf("%v: %d\n", vb.Value.Type(), n)
	} else {
		fmt.Printf("%v\n", vb.Value.Type())
	}
}
