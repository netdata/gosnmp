// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"time"
)

// newTestClient returns an unconnected SNMPv2c client.
func newTestClient() *Client {
	return &Client{
		Port:      161,
		Community: "public",
		Version:   Version2c,
		Timeout:   2 * time.Second,
		Retries:   3,
		MaxOids:   MaxOids,
	}
}

// newTestClientV3 returns an unconnected SNMPv3 client of the User-based
// Security Model with msgFlags and user.
func newTestClientV3(msgFlags SecurityLevel, user User) *Client {
	gs := newTestClient()
	gs.Version = Version3
	gs.SecurityLevel = msgFlags
	gs.User = user
	return gs
}
