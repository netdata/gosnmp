// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"strings"
	"testing"

	"github.com/netdata/gosnmp/internal/ber"
)

func TestOidCompare(t *testing.T) {
	tests := []struct {
		name     string
		oid1     string
		oid2     string
		expected int
	}{
		// oid1 == oid2 (returns 0)
		{"equal", ".1.3.6.1", ".1.3.6.1", 0},
		{"equal ignores leading dot", ".1.3.6.1", "1.3.6.1", 0},

		// oid1 < oid2 (returns -1)
		{"less by component value", ".1.3.6.1", ".1.3.6.2", -1},
		{"less by length", ".1.3.6.1", ".1.3.6.1.4", -1},
		{"less by numeric not string order", ".1.3.6.1.2", ".1.3.6.1.10", -1},
		{"less at uint32 max", ".1.3.4294967294", ".1.3.4294967295", -1},
		{"empty less than any oid", "", ".1.3.6.1", -1},

		// oid1 > oid2 (returns 1)
		{"greater by component value", ".1.3.6.2", ".1.3.6.1", 1},
		{"greater when response decreases", ".1.3.6.1.4.1.2636.3.60.1.2.1.1.6.578.227", ".1.3.6.1.4.1.2636.3.60.1.2.1.1.6.578.0", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oidCompare(tc.oid1, tc.oid2)
			if got != tc.expected {
				t.Errorf("oidCompare(%q, %q) = %d, want %d", tc.oid1, tc.oid2, got, tc.expected)
			}
		})
	}
}

// TestWalkRoot keeps normalization within the codec's accepted OID grammar,
// including the packed first two arcs and the arc count and value limits.
func TestWalkRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		root string
		want string
		err  error
	}{
		{name: "default", want: ".1.3.6.1"},
		{name: "dot-default", root: ".", want: ".1.3.6.1"},
		{name: "zero-arcs", root: "..00..00..", want: ".0.0"},
		{name: "packed-arcs", root: ".02.04294967295.04294967295.", want: ".2.4294967295.4294967295"},
		{name: "128-arcs", root: ".01..03" + strings.Repeat(".01", 126), want: ".1.3" + strings.Repeat(".1", 126)},
		{name: "dots-only", root: "..", err: ber.ErrInvalidOID},
		{name: "one-arc", root: ".1", err: ber.ErrInvalidOID},
		{name: "129-arcs", root: ".1.3" + strings.Repeat(".1", 127), err: ber.ErrInvalidOID},
		{name: "first-arc", root: ".3.1", err: ber.ErrInvalidOID},
		{name: "second-arc", root: ".1.40", err: ber.ErrInvalidOID},
		{name: "overflow", root: ".1.3.4294967296", err: ber.ErrOIDOutOfRange},
		{name: "negative", root: ".1.-3", err: ber.ErrInvalidOID},
		{name: "letters", root: "x", err: ber.ErrInvalidOID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := walkRoot(tc.root)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Errorf("walkRoot(%q) = %q, %v; want %q, %v", tc.root, got, err, tc.want, tc.err)
			}
		})
	}
}
