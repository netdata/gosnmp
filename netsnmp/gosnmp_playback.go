// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build !netsnmp

package netsnmp

import (
	"github.com/netdata/gosnmp"
)

func isPlayback() bool {
	return true
}

func netSnmpPduPkt(fname string, _ gosnmp.VarBind, _ *gosnmp.Client, _ uint32, _ bool) ([]byte, error) {
	return readRecording(fname)
}
