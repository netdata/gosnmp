// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netdata/gosnmp/internal/ber"
)

// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/ is useful

func TestMarshalObjectIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		oid     string
		want    []byte
		wantErr bool
	}{
		// Standard OIDs
		{
			name: "sysDescr (1.3.6.1.2.1.1.1)",
			oid:  ".1.3.6.1.2.1.1.1",
			want: []byte{43, 6, 1, 2, 1, 1, 1},
		},
		{
			name: "minimal 0.0",
			oid:  ".0.0",
			want: []byte{0x00},
		},
		// Multi-byte first sub-identifier (X.690 8.19.5)
		{
			name: "joint-iso-itu-t 2.999.3 (X.690 example)",
			oid:  ".2.999.3",
			want: []byte{0x88, 0x37, 0x03},
		},
		{
			name: "joint-iso-itu-t 2.100.3 (stdlib test vector)",
			oid:  ".2.100.3",
			want: []byte{0x81, 0x34, 0x03},
		},
		{
			name: "joint-iso-itu-t 2.48",
			oid:  ".2.48",
			want: []byte{0x81, 0x00},
		},
		{
			name: "second arc 40 allowed under arc 2",
			oid:  ".2.40",
			want: []byte{0x78},
		},
		{
			name: "largest second arc under arc 2",
			oid:  ".2.4294967215", // MaxObjectSubIdentifierValue - 80
			want: []byte{0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
		},
		// Invalid OIDs
		{
			name:    "first arc greater than 2",
			oid:     ".3.1",
			wantErr: true,
		},
		{
			name:    "second arc 40 under arc 1",
			oid:     ".1.40",
			wantErr: true,
		},
		{
			name:    "second arc too large under arc 2",
			oid:     ".2.4294967216", // MaxObjectSubIdentifierValue - 79
			wantErr: true,
		},
		{
			name:    "sub-identifier exceeds uint32",
			oid:     ".1.3.4294967296",
			wantErr: true,
		},
		{
			name:    "sub-identifier overflows int64 accumulator",
			oid:     ".1.3.18446744073709551617", // 2^64 + 1
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalObjectIdentifier(tt.oid)
			if (err != nil) != tt.wantErr {
				t.Fatalf("marshalObjectIdentifier() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("marshalObjectIdentifier() = % X, want % X", got, tt.want)
			}
			// Round-trip through the decoder
			back, err := ber.OID(got)
			if err != nil {
				t.Fatalf("ber.OID() roundtrip error = %v", err)
			}
			if back != tt.oid {
				t.Errorf("roundtrip = %q, want %q", back, tt.oid)
			}
		})
	}
}

func BenchmarkMarshalObjectIdentifier(b *testing.B) {
	oid := ".1.3.6.3.30.11.1.10"
	for i := 0; i < b.N; i++ {
		if _, err := marshalObjectIdentifier(oid); err != nil {
			b.Fatal(err)
		}
	}
}

type testsMarshalUint32T struct {
	value     uint32
	goodBytes []byte
}

var testsMarshalUint32 = []testsMarshalUint32T{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{18542501, []byte{0x01, 0x1a, 0xef, 0xa5}},
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{2147483648, []byte{0x00, 0x80, 0x00, 0x0, 0x0}},
}

func TestMarshalUint32(t *testing.T) {
	for i, test := range testsMarshalUint32 {
		result, err := marshalUint32(test.value)
		if err != nil {
			t.Errorf("%d: expected %0x got err %v", i, test.goodBytes, err)
		}
		if !bytes.Equal(test.goodBytes, result) {
			t.Errorf("%d: expected %0x got %0x", i, test.goodBytes, result)
		}
	}
}

func TestMarshalUint64(t *testing.T) {
	tests := []struct {
		value    any
		expected []byte
	}{
		// RFC 2578 Section 7.1.15: Counter64 is an unsigned 64-bit integer.
		// X.690 Section 8.3.1: Integers shall be encoded in two's complement binary.
		// X.690 Section 8.3.2: Use the minimum number of octets.

		// Case 1: Zero should be encoded as a single byte: 0x00
		{uint64(0), []byte{0x00}},

		// Case 2: 127 (0x7F) has MSB clear, encoded as single byte
		{uint64(127), []byte{0x7F}},

		// Case 3: 128 (0x80) has MSB set, must prepend 0x00
		{uint64(128), []byte{0x00, 0x80}},

		// Case 4: 255 (0xFF) has MSB set, must prepend 0x00
		{uint64(255), []byte{0x00, 0xFF}},

		// Case 5: 256 (0x0100) MSB of first byte is 0, no need to prepend
		{uint64(256), []byte{0x01, 0x00}},

		// Case 6: 2^32 - 1 = 0xFFFFFFFF MSB set in first byte, must prepend 0x00
		{uint64(0xFFFFFFFF), []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF}},

		// Case 7: 2^63 = 0x8000000000000000 MSB set in trimmed output, must prepend 0x00
		{uint64(0x8000000000000000), []byte{
			0x00, // prepend
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},

		// Case 8: Max uint64 = 0xFFFFFFFFFFFFFFFF, must prepend 0x00 to keep positive
		{uint64(0xFFFFFFFFFFFFFFFF), []byte{
			0x00, // prepend
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}},
	}

	for _, test := range tests {
		actual, err := marshalUint64(test.value)
		if err != nil {
			t.Errorf("marshalUint64(%v) returned unexpected error: %v", test.value, err)
			continue
		}
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("marshalUint64(%v) = %x, expected %x", test.value, actual, test.expected)
		}
	}
}

var testsMarshalInt32 = []struct {
	value     int
	goodBytes []byte
}{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{-2147483648, []byte{0x80, 0x00, 0x00, 0x00}},
	{-16777217, []byte{0xfe, 0xff, 0xff, 0xff}},
	{-16777216, []byte{0xff, 0x00, 0x00, 0x00}},
	{-65537, []byte{0xfe, 0xff, 0xff}},
	{-65536, []byte{0xff, 0x00, 0x00}},
	{-257, []byte{0xfe, 0xff}},
	{-256, []byte{0xff, 0x00}},
	{-2, []byte{0xfe}},
	{-1, []byte{0xff}},
}

func TestMarshalInt32(t *testing.T) {
	for _, aTest := range testsMarshalInt32 {
		result, err := marshalInt32(aTest.value)
		assert.NoErrorf(t, err, "value %d", aTest.value)
		assert.EqualValues(t, aTest.goodBytes, result, "bad marshalInt32()")
	}
}

var testsInvalidSNMPResponses = []string{
	"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",
	"MBoCAQEEB3ByaXZhdGWiDAIESESkywIBBQIBAA==",
	"MEo=",
}

func TestInvalidSNMPResponses(t *testing.T) {
	g := newTestGoSNMP()
	g.Target = "127.0.0.1"

	for i, test := range testsInvalidSNMPResponses {
		testBytes, _ := base64.StdEncoding.DecodeString(test)
		result, err := g.SnmpDecodePacket(testBytes)
		if err == nil {
			t.Errorf("#%d, failed to error %v", i, result)
		}
	}
}

// TestIPAddressDecodeValue tests IPAddress parsing via decodeValue with various BER encodings
func TestIPAddressDecodeValue(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantIP   string
		wantNull bool
		wantErr  bool
	}{
		// Standard short-form BER encoding (most common)
		{
			name:   "short-form IPv4",
			data:   []byte{0x40, 0x04, 192, 168, 1, 1},
			wantIP: "192.168.1.1",
		},
		{
			name:   "short-form IPv4 loopback",
			data:   []byte{0x40, 0x04, 127, 0, 0, 1},
			wantIP: "127.0.0.1",
		},
		{
			name:   "short-form IPv6",
			data:   []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantIP: "2001:db8::1",
		},
		{
			name:   "short-form IPv6 all bytes set",
			data:   []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0xab, 0xcd},
			wantIP: "2001:db8:85a3:0:8a2e:370:7334:abcd",
		},
		// Long-form BER encoding
		{
			name:   "long-form IPv4",
			data:   []byte{0x40, 0x81, 0x04, 192, 168, 1, 1},
			wantIP: "192.168.1.1",
		},
		{
			name:   "long-form IPv6",
			data:   []byte{0x40, 0x81, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantIP: "2001:db8::1",
		},
		// Edge cases
		{
			name:     "null IPAddress (length 0)",
			data:     []byte{0x40, 0x00},
			wantNull: true,
		},
		// Error cases
		{
			name:    "truncated IPv4 data",
			data:    []byte{0x40, 0x04, 192, 168},
			wantErr: true,
		},
		{
			name:    "truncated IPv6 data",
			data:    []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8},
			wantErr: true,
		},
		{
			name:    "invalid length (not 0, 4, or 16)",
			data:    []byte{0x40, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantErr: true,
		},
		{
			name:    "indefinite length rejected",
			data:    []byte{0x40, 0x80, 192, 168, 1, 1, 0x00, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &GoSNMP{}
			retVal := &variable{}
			err := x.decodeValue(tt.data, retVal)

			if tt.wantErr {
				if err == nil {
					t.Errorf("decodeValue() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("decodeValue() unexpected error: %v", err)
				return
			}
			if tt.wantNull {
				if retVal.Value != nil {
					t.Errorf("decodeValue() = %v, want nil", retVal.Value)
				}
				return
			}
			if retVal.Value != tt.wantIP {
				t.Errorf("decodeValue() = %v, want %v", retVal.Value, tt.wantIP)
			}
			if retVal.Type != IPAddress {
				t.Errorf("decodeValue() type = %v, want IPAddress", retVal.Type)
			}
		})
	}
}

// TestIPAddressParseRawField tests IPAddress parsing via parseRawField.
// Note: parseRawField only supports IPv4, not IPv6 (returns error for length != 4).
func TestIPAddressParseRawField(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantIP     string
		wantLength int
		wantNull   bool
		wantErr    bool
	}{
		// Standard short-form
		{
			name:       "short-form IPv4",
			data:       []byte{0x40, 0x04, 192, 168, 1, 1},
			wantIP:     "192.168.1.1",
			wantLength: 6,
		},
		{
			name:       "short-form IPv4 loopback",
			data:       []byte{0x40, 0x04, 127, 0, 0, 1},
			wantIP:     "127.0.0.1",
			wantLength: 6,
		},
		// Long-form BER
		{
			name:       "long-form IPv4",
			data:       []byte{0x40, 0x81, 0x04, 10, 0, 0, 1},
			wantIP:     "10.0.0.1",
			wantLength: 7,
		},
		// Edge cases
		{
			name:       "null IPAddress (length 0)",
			data:       []byte{0x40, 0x00},
			wantNull:   true,
			wantLength: 2,
		},
		// Error cases - parseRawField only supports IPv4
		{
			name:    "IPv6 rejected by parseRawField",
			data:    []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name:    "truncated IPv4",
			data:    []byte{0x40, 0x04, 192, 168},
			wantErr: true,
		},
		{
			name:    "indefinite length rejected",
			data:    []byte{0x40, 0x80, 192, 168, 1, 1, 0x00, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, length, err := parseRawField(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseRawField() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("parseRawField() unexpected error: %v", err)
				return
			}
			if length != tt.wantLength {
				t.Errorf("parseRawField() length = %v, want %v", length, tt.wantLength)
			}
			if tt.wantNull {
				if val != nil {
					t.Errorf("parseRawField() = %v, want nil", val)
				}
				return
			}
			if val != tt.wantIP {
				t.Errorf("parseRawField() = %v, want %v", val, tt.wantIP)
			}
		})
	}
}

func TestMarshalFloat32(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			input:   float32(0.0),
			want:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "positive 1.0",
			input:   float32(1.0),
			want:    []byte{0x3f, 0x80, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "negative 1.0",
			input:   float32(-1.0),
			want:    []byte{0xbf, 0x80, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "pi approx",
			input:   float32(3.14159),
			want:    []byte{0x40, 0x49, 0x0f, 0xd0},
			wantErr: false,
		},
		{
			name:    "wrong type int",
			input:   42,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type float64",
			input:   float64(1.0),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type string",
			input:   "1.0",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalFloat32(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("marshalFloat32() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("marshalFloat32() unexpected error: %v", err)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("marshalFloat32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalFloat64(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			input:   float64(0.0),
			want:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "positive 1.0",
			input:   float64(1.0),
			want:    []byte{0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "negative 1.0",
			input:   float64(-1.0),
			want:    []byte{0xbf, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "pi approx",
			input:   float64(3.141592653589793),
			want:    []byte{0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18},
			wantErr: false,
		},
		{
			name:    "wrong type int",
			input:   42,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type float32",
			input:   float32(1.0),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong type string",
			input:   "1.0",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalFloat64(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("marshalFloat64() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("marshalFloat64() unexpected error: %v", err)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("marshalFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}
