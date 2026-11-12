// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"time"
)

// testConfig returns the configuration of an SNMPv2c client.
func testConfig() Config {
	return Config{
		Community: "public",
		Version:   Version2c,
		Timeout:   2 * time.Second,
		Retries:   3,
	}
}

// testConfigV3 returns the configuration of an SNMPv3 client with level and
// user.
func testConfigV3(level SecurityLevel, user User) Config {
	c := testConfig()
	c.Version, c.SecurityLevel, c.User = Version3, level, user
	return c
}

// mustClient returns the client NewClient makes of config; it panics on an
// error, a bug of the test.
func mustClient(config Config) *Client {
	x, err := NewClient(config)
	if err != nil {
		panic(err)
	}
	return x
}
