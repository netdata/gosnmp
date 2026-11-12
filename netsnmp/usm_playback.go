// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build !netsnmp

package netsnmp

import (
	"errors"

	"github.com/netdata/gosnmp"
)

// errPlayback is returned by the net-snmp USM primitives without
// `-tags netsnmp`; TestUSM reads the recordings instead of calling them.
var errPlayback = errors.New("net-snmp USM primitives require `-tags netsnmp` and libsnmp")

func netSnmpAuthKey(gosnmp.AuthProtocol, string, string) ([]byte, error) {
	return nil, errPlayback
}

func netSnmpPrivKey(gosnmp.AuthProtocol, gosnmp.PrivProtocol, string, string) ([]byte, error) {
	return nil, errPlayback
}

func netSnmpHMAC(gosnmp.AuthProtocol, []byte, []byte) ([]byte, error) {
	return nil, errPlayback
}

func netSnmpEncrypt(gosnmp.PrivProtocol, []byte, []byte, []byte) ([]byte, error) {
	return nil, errPlayback
}
