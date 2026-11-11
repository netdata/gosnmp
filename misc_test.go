// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import "testing"

// ---------------------------------------------------------------------

var testsVersionString = []struct {
	in  Version
	out string
}{
	{Version1, "1"},
	{Version2c, "2c"},
	{Version3, "3"},
	{Version(2), "Version(2)"},
	{Version(255), "Version(255)"},
}

func TestVersionString(t *testing.T) {
	for i, test := range testsVersionString {
		result := test.in.String()
		if result != test.out {
			t.Errorf("#%d, got %v expected %v", i, result, test.out)
		}
	}
}
