// Copyright 2021 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This example enables and disables logging at runtime.
package main

import (
	"log"
	"os"

	g "github.com/netdata/gosnmp"
)

func main() {
	stdoutLogger := g.NewLogger(log.New(os.Stdout, "", 0)) // enable logging with stdout
	disabledLogger := g.NewLogger(nil)                     // disable logging

	params := &g.GoSNMP{
		Target:    "127.0.0.1",
		Port:      uint16(1161),
		Community: "public",
	}
	_ = params.Connect() // no logger specified, logging is disabled
	params.Conn.Close()

	params.Logger = stdoutLogger
	_ = params.Connect() // logging enabled using stdout
	params.Conn.Close()

	params.Logger = disabledLogger
	_ = params.Connect() // logging is disabled
	params.Conn.Close()
}
