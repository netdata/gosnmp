// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
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
	{0, 5, 3, false}, // partition size above the slice length: one partition
	{1, 5, 3, false},
	{2, 5, 3, true},
	{0, 0, 3, false}, // partition size of 0: one partition
	{1, 0, 3, false},
	{2, 0, 3, true},
	{-1, 0, 3, false}, // out of range
	{3, 0, 3, false},
	{0, -1, 3, false}, // negative partition size: one partition
	{1, -1, 3, false},
	{2, -1, 3, true},
	{0, -3, 4, false},
	{2, -3, 4, false},
	{3, -3, 4, true},
	{3, -1, 3, false}, // out of range
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
	{int(-42), big.NewInt(-42)},
	{int8(-42), big.NewInt(-42)},
	{int16(42), big.NewInt(42)},
	{int32(-42), big.NewInt(-42)},
	{int64(42), big.NewInt(42)},

	{uint(42), big.NewInt(42)},
	{uint8(42), big.NewInt(42)},
	{uint16(42), big.NewInt(42)},
	{uint32(42), big.NewInt(42)},
	{uint64(42), big.NewInt(42)},

	// edge cases: each type's minimum and maximum
	{int(math.MinInt), big.NewInt(math.MinInt)},
	{int(math.MaxInt), big.NewInt(math.MaxInt)},
	{int8(math.MinInt8), big.NewInt(math.MinInt8)},
	{int8(math.MaxInt8), big.NewInt(math.MaxInt8)},
	{int16(math.MinInt16), big.NewInt(math.MinInt16)},
	{int16(math.MaxInt16), big.NewInt(math.MaxInt16)},
	{int32(math.MinInt32), big.NewInt(math.MinInt32)},
	{int32(math.MaxInt32), big.NewInt(math.MaxInt32)},
	{int64(math.MinInt64), big.NewInt(math.MinInt64)},
	{int64(math.MaxInt64), big.NewInt(math.MaxInt64)},
	{uint(0), new(big.Int)},
	{uint8(math.MaxUint8), big.NewInt(math.MaxUint8)},
	{uint16(math.MaxUint16), big.NewInt(math.MaxUint16)},
	{uint32(math.MaxUint32), big.NewInt(math.MaxUint32)},
	{uint64(0), new(big.Int)},
	{^uint(0), new(big.Int).SetUint64(uint64(^uint(0)))}, // above math.MaxInt64 on 64-bit platforms
	{uint64(math.MaxUint64), new(big.Int).SetUint64(math.MaxUint64)},

	// string: valid number
	{"-123456789", big.NewInt(-123456789)},
	{"+42", big.NewInt(42)},
	{"-0", new(big.Int)},
	{"9223372036854775807", big.NewInt(math.MaxInt64)},
	{"-9223372036854775808", big.NewInt(math.MinInt64)},

	// string: a number outside int64
	{"9223372036854775808", new(big.Int).Lsh(big.NewInt(1), 63)},
	{"18446744073709551615", new(big.Int).SetUint64(math.MaxUint64)},
	{"-9223372036854775809", new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1))},
	{"-340282366920938463463374607431768211456", new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 128))},

	// string: invalid number
	{"foo", new(big.Int)},
	{"", new(big.Int)},
	{" 42", new(big.Int)},
	{"4_2", new(big.Int)},
	{"0x2a", new(big.Int)},
	{"42.0", new(big.Int)},

	// unhandled type
	{struct{}{}, new(big.Int)},
	{nil, new(big.Int)},
	{float64(42), new(big.Int)},
	{[]byte("42"), new(big.Int)},
}

func TestToBigInt(t *testing.T) {
	for i, test := range testsToBigInt {
		result := ToBigInt(test.in)
		if result.Cmp(test.expected) != 0 {
			t.Errorf("#%d, %T: got %v expected %v", i, test.in, result, test.expected)
		}
	}
}

// TestToBigIntFreshValue checks that each call returns a new big.Int, which the
// caller may change.
func TestToBigIntFreshValue(t *testing.T) {
	for _, in := range []any{nil, "foo", "42", 42, uint(42), uint32(42), uint64(42)} {
		want := new(big.Int).Set(ToBigInt(in))
		ToBigInt(in).SetInt64(-7)
		assert.Zero(t, want.Cmp(ToBigInt(in)), "%T %v", in, in)
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
	{SnmpVersion(2), "SnmpVersion(2)"},
	{SnmpVersion(255), "SnmpVersion(255)"},
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

// TestBitStringValueAt checks At over the bits of Bytes, an index outside
// BitLength, and a BitLength beyond Bytes.
func TestBitStringValueAt(t *testing.T) {
	bits := BitStringValue{Bytes: []byte{0xa5, 0xff}, BitLength: 9}
	tests := map[string]struct {
		value BitStringValue
		i     int
		want  string
	}{
		"first bit":                  {value: bits, i: 0, want: "1"},
		"second bit":                 {value: bits, i: 1, want: "0"},
		"last bit of the first byte": {value: bits, i: 7, want: "1"},
		"last bit":                   {value: bits, i: 8, want: "1"},
		"below 0":                    {value: bits, i: -1, want: "0"},
		"a byte below 0":             {value: bits, i: -8, want: "0"},
		"at BitLength":               {value: bits, i: 9, want: "0"},
		"last bit of Bytes, BitLength beyond": {
			value: BitStringValue{Bytes: []byte{0x01}, BitLength: 16}, i: 7, want: "1",
		},
		"past Bytes": {value: BitStringValue{Bytes: []byte{0xff}, BitLength: 16}, i: 8, want: "0"},
		"no Bytes":   {value: BitStringValue{BitLength: 8}, i: 0, want: "0"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got string
			if v, _ := recoverPanic(func() { got = strconv.Itoa(tc.value.At(tc.i)) }); v != nil {
				got = fmt.Sprintf("panic: %v", v)
			}
			assert.Equal(t, tc.want, got)
		})
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

// TestNewLoggerNilPointer checks that NewLogger given a nil pointer, a nil
// *log.Logger, disables logging as a nil logger does: a table's Add, which
// logs to an enabled Logger, succeeds.
func TestNewLoggerNilPointer(t *testing.T) {
	tests := map[string]struct {
		logger LoggerInterface
		want   string
	}{
		"nil":             {logger: nil, want: "ok"},
		"nil *log.Logger": {logger: (*log.Logger)(nil), want: "ok"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			table := NewSnmpV3SecurityParametersTable(NewLogger(tc.logger))
			got := outcomeOf(func() error { return table.Add("user", &UsmSecurityParameters{UserName: "user"}) })
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------

var benchBigInt *big.Int

// BenchmarkToBigInt converts the Go types integer values decode to (Integer:
// int; Counter32, Gauge32: uint; Uinteger32, TimeTicks: uint32; Counter64:
// uint64) and a decimal string.
func BenchmarkToBigInt(b *testing.B) {
	values := []struct {
		name  string
		value any
	}{
		{"int", 1234567},
		{"uint", uint(1234567)},
		{"uint32", uint32(1234567)},
		{"uint64", uint64(12345678901)},
		{"string", "1234567"},
	}
	for _, v := range values {
		b.Run(v.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchBigInt = ToBigInt(v.value)
			}
		})
	}
}
