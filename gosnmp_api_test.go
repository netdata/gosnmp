// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// The purpose of these tests is to validate gosnmp's public APIs.
//
// IMPORTANT: If you're modifying _any_ existing code in this file, you
// should be asking yourself about API compatibility!

package gosnmp_test // force external view

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netdata/gosnmp"
)

func TestAPIConfigTypes(_ *testing.T) {
	g := &gosnmp.Client{}
	g.Target = ""
	g.Port = 0
	g.Community = ""
	g.Version = gosnmp.Version1
	g.Version = gosnmp.Version2c
	g.Timeout = time.Duration(0)
	g.Retries = 0
	g.MaxOids = 0
	g.MaxRepetitions = 0
	var c net.Conn = g.Conn
	_ = c
}

func TestAPIConnectMethodSignature(_ *testing.T) {
	var f func(context.Context) error = (&gosnmp.Client{}).Connect
	_ = f
}

func TestAPIGetMethodSignature(_ *testing.T) {
	var f func(context.Context, []string) (*gosnmp.Message, error) = (&gosnmp.Client{}).Get
	_ = f
}

func TestAPIBulkWalkAllMethodSignature(_ *testing.T) {
	var f func(context.Context, string) ([]gosnmp.VarBind, error) = (&gosnmp.Client{}).BulkWalkAll
	_ = f
}

func TestAPIWalkAllMethodSignature(_ *testing.T) {
	var f func(context.Context, string) ([]gosnmp.VarBind, error) = (&gosnmp.Client{}).WalkAll
	_ = f
}
