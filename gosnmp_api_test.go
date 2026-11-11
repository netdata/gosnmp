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
	"testing"
	"time"

	"github.com/netdata/gosnmp"
)

func TestAPIConfigTypes(_ *testing.T) {
	var f func(gosnmp.Config) (*gosnmp.Client, error) = gosnmp.NewClient
	_ = f
	_ = gosnmp.Config{
		Target:        "",
		Port:          0,
		Version:       gosnmp.Version2c,
		Community:     "",
		Timeout:       time.Duration(0),
		Retries:       0,
		MaxOids:       0,
		SecurityLevel: gosnmp.NoAuthNoPriv,
		User:          gosnmp.User{},
		ContextName:   "",
	}
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
	var f func(context.Context, string, uint32) ([]gosnmp.VarBind, gosnmp.WalkEnd, error) = (&gosnmp.Client{}).BulkWalkAll
	_ = f
}

func TestAPIWalkAllMethodSignature(_ *testing.T) {
	var f func(context.Context, string) ([]gosnmp.VarBind, gosnmp.WalkEnd, error) = (&gosnmp.Client{}).WalkAll
	_ = f
}
