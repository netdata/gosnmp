// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"math"
	"math/big"
	"testing"
)

// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------

var testsPartition = []struct {
	currentPosition int
	partitionSize   int
	sliceLength     int
	ok              bool
}{
	{-1, 3, 8, false}, // test out of range
	{8, 3, 8, false},  // test out of range
	{0, 3, 8, false},  // test 0-7/3 per doco
	{1, 3, 8, false},
	{2, 3, 8, true},
	{3, 3, 8, false},
	{4, 3, 8, false},
	{5, 3, 8, true},
	{6, 3, 8, false},
	{7, 3, 8, true},
	{-1, 1, 3, false}, // partition size of one
	{0, 1, 3, true},
	{1, 1, 3, true},
	{2, 1, 3, true},
	{3, 1, 3, false},
}

func TestPartition(t *testing.T) {
	for i, test := range testsPartition {
		ok := Partition(test.currentPosition, test.partitionSize, test.sliceLength)
		if ok != test.ok {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ok, test.ok)
		}
	}
}

// ---------------------------------------------------------------------

var testsToBigInt = []struct {
	in       any
	expected *big.Int
}{
	{int8(-42), big.NewInt(-42)},
	{int16(42), big.NewInt(42)},
	{int32(-42), big.NewInt(-42)},
	{int64(42), big.NewInt(42)},

	{uint8(42), big.NewInt(42)},
	{uint16(42), big.NewInt(42)},
	{uint32(42), big.NewInt(42)},
	{uint64(42), big.NewInt(42)},

	// edge case, max uint64
	{uint64(math.MaxUint64), new(big.Int).SetUint64(math.MaxUint64)},

	// string: valid number
	{"-123456789", big.NewInt(-123456789)},

	// string: invalid number
	{"foo", new(big.Int)},

	// unhandled type
	{struct{}{}, new(big.Int)},
}

func TestToBigInt(t *testing.T) {
	for i, test := range testsToBigInt {
		result := ToBigInt(test.in)
		if result.Cmp(test.expected) != 0 {
			t.Errorf("#%d, %T: got %v expected %v", i, test.in, result, test.expected)
		}
	}
}

// ---------------------------------------------------------------------

var testsSnmpVersionString = []struct {
	in  SnmpVersion
	out string
}{
	{Version1, "1"},
	{Version2c, "2c"},
	{Version3, "3"},
}

func TestSnmpVersionString(t *testing.T) {
	for i, test := range testsSnmpVersionString {
		result := test.in.String()
		if result != test.out {
			t.Errorf("#%d, got %v expected %v", i, result, test.out)
		}
	}
}

// ---------------------------------------------------------------------

/*
var testMarshalTimeticks = []struct {
	timeticks uint32
	out       []byte
}{
	{1034156, []byte{0x0f, 0xc7, 0xac}},
}

func TestMarshalTimeticks(t *testing.T) {
	for i, test := range testMarshalTimeticks {
		result, err := marshalTimeticks(test.timeticks)
		if err != nil {
			t.Errorf("%d: expected %v got err %v", i, result, err)
		}
		if !bytes.Equal(result, test.out) {
			t.Errorf("#%d, got %v expected %v", i, result, test.out)
		}
	}
}
*/

// ---------------------------------------------------------------------
