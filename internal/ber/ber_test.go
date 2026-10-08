// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package ber

import (
	"strings"
	"testing"
)

// TestLength tests the Length function with various BER length encodings
func TestLength(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantLength int
		wantCursor int
		wantErr    bool
		errContain string
	}{
		// Short form length encoding (length byte <= 127)
		{
			name:       "short form length 4",
			data:       []byte{0x04, 0x04, 0x01, 0x02, 0x03, 0x04},
			wantLength: 6,
			wantCursor: 2,
			wantErr:    false,
		},
		{
			name:       "short form length 0 (null)",
			data:       []byte{0x04, 0x00},
			wantLength: 2,
			wantCursor: 2,
			wantErr:    false,
		},
		{
			name:       "short form max length 127",
			data:       append([]byte{0x04, 0x7F}, make([]byte, 127)...),
			wantLength: 129,
			wantCursor: 2,
			wantErr:    false,
		},
		// Long form length encoding (first byte > 127, subsequent bytes contain length)
		{
			name:       "long form 1 byte length (0x81 0x80 = 128)",
			data:       append([]byte{0x04, 0x81, 0x80}, make([]byte, 128)...),
			wantLength: 131,
			wantCursor: 3,
			wantErr:    false,
		},
		{
			name:       "long form 2 byte length (0x82 0x01 0x00 = 256)",
			data:       append([]byte{0x04, 0x82, 0x01, 0x00}, make([]byte, 256)...),
			wantLength: 260,
			wantCursor: 4,
			wantErr:    false,
		},
		// Edge cases
		{
			name:       "exactly 2 bytes should use short form parsing",
			data:       []byte{0x04, 0x00},
			wantLength: 2,
			wantCursor: 2,
			wantErr:    false,
		},
		{
			name:       "1 byte input uses fallback",
			data:       []byte{0x04},
			wantLength: 1,
			wantCursor: 1,
			wantErr:    false,
		},
		{
			name:       "empty input uses fallback",
			data:       []byte{},
			wantLength: 0,
			wantCursor: 0,
			wantErr:    false,
		},
		// Indefinite length encoding - prohibited per RFC 3417 Section 8
		{
			name:       "indefinite length 0x80 should be rejected",
			data:       []byte{0x04, 0x80, 0x01, 0x02, 0x00, 0x00},
			wantErr:    true,
			errContain: "indefinite length",
		},
		// Invalid long form data
		{
			name:    "truncated long form length",
			data:    []byte{0x04, 0x82, 0x01}, // missing second length byte
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, cursor, err := Length(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Length() expected error, got nil")
				} else if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Length() error = %v, want error containing %q", err, tt.errContain)
				}
				return
			}
			if err != nil {
				t.Errorf("Length() unexpected error: %v", err)
				return
			}
			if length != tt.wantLength {
				t.Errorf("Length() length = %v, want %v", length, tt.wantLength)
			}
			if cursor != tt.wantCursor {
				t.Errorf("Length() cursor = %v, want %v", cursor, tt.wantCursor)
			}
		})
	}
}

func TestUint64(t *testing.T) {
	tests := []struct {
		data []byte
		n    uint64
	}{
		{[]byte{}, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x01, 0x01}, 257},
		{[]byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e, 0xb3, 0xbf}, 18446744073694786495},
	}
	for _, test := range tests {
		if ret, err := Uint64(test.data); err != nil || ret != test.n {
			t.Errorf("Uint64(%v) = %d, %v want %d, <nil>", test.data, ret, err, test.n)
		}
	}
}

func TestOID(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr error
	}{
		// First byte encoding: first two sub-identifiers encoded as (x*40 + y)
		// where x is first sub-id (0, 1, or 2) and y is second sub-id
		{
			name: "iso.org (1.3)",
			data: []byte{43}, // 1*40 + 3 = 43
			want: ".1.3",
		},
		{
			name: "iso.member-body (1.2)",
			data: []byte{42}, // 1*40 + 2 = 42
			want: ".1.2",
		},
		{
			name: "joint-iso-itu-t (2.0)",
			data: []byte{80}, // 2*40 + 0 = 80
			want: ".2.0",
		},
		{
			name: "itu-t (0.0)",
			data: []byte{0}, // 0*40 + 0 = 0
			want: ".0.0",
		},
		{
			name: "first byte max second sub-id (0.39)",
			data: []byte{39}, // 0*40 + 39 = 39
			want: ".0.39",
		},
		{
			name: "first byte boundary (1.0)",
			data: []byte{40}, // 1*40 + 0 = 40
			want: ".1.0",
		},
		// Multi-byte first sub-identifier (X.690 8.19.5)
		{
			name: "joint-iso-itu-t 2.999 (X.690 example)",
			data: []byte{0x88, 0x37, 0x03}, // first sub-id 1079 = 2*40+999, then arc 3
			want: ".2.999.3",
		},
		{
			name: "joint-iso-itu-t 2.48",
			data: []byte{0x81, 0x00}, // first sub-id 128 = 2*40+48
			want: ".2.48",
		},
		{
			name: "joint-iso-itu-t 2.100 (stdlib test vector)",
			data: []byte{0x81, 0x34, 0x03}, // first sub-id 180 = 2*40+100, then arc 3
			want: ".2.100.3",
		},
		// Standard OIDs
		{
			name: "sysDescr (1.3.6.1.2.1.1.1)",
			data: []byte{43, 6, 1, 2, 1, 1, 1},
			want: ".1.3.6.1.2.1.1.1",
		},
		{
			name: "ifTable (1.3.6.1.2.1.2.2)",
			data: []byte{43, 6, 1, 2, 1, 2, 2},
			want: ".1.3.6.1.2.1.2.2",
		},
		{
			name: "enterprises (1.3.6.1.4.1)",
			data: []byte{43, 6, 1, 4, 1},
			want: ".1.3.6.1.4.1",
		},
		// Multi-byte sub-identifiers
		{
			name: "two-byte sub-id (128)",
			data: []byte{43, 0x81, 0x00}, // .1.3.128
			want: ".1.3.128",
		},
		{
			name: "two-byte sub-id (255)",
			data: []byte{43, 0x81, 0x7F}, // .1.3.255
			want: ".1.3.255",
		},
		{
			name: "three-byte sub-id (16384)",
			data: []byte{43, 0x81, 0x80, 0x00}, // .1.3.16384
			want: ".1.3.16384",
		},
		{
			name: "max uint32 sub-id (4294967295)",
			data: []byte{43, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
			want: ".1.3.4294967295",
		},
		{
			name: "mixed sub-id sizes",
			data: []byte{43, 6, 1, 2, 1, 31, 1, 1, 1, 10, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
			want: ".1.3.6.1.2.1.31.1.1.1.10.4294967295",
		},
		{
			name: "zero-length encoded OID",
			data: []byte{},
			want: ".0.0",
		},
		// Error cases
		{
			name:    "overflow sub-id (4294967296)",
			data:    []byte{43, 0x90, 0x80, 0x80, 0x80, 0x00},
			want:    "",
			wantErr: ErrBase128IntegerTooLarge,
		},
		{
			name:    "truncated first sub-id",
			data:    []byte{0x80}, // continuation byte as only byte
			want:    "",
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated multi-byte sub-id",
			data:    []byte{43, 0x81}, // continuation byte without termination
			want:    "",
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated mid-sequence",
			data:    []byte{43, 6, 0x81, 0x82}, // two continuation bytes
			want:    "",
			wantErr: ErrBase128IntegerTruncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := OID(tt.data)
			if err != tt.wantErr {
				t.Errorf("OID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("OID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBase128Uint32(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		initOffset int
		want       uint32
		wantOffset int
		wantErr    error
	}{
		// Single byte values (0-127)
		{
			name:       "zero",
			data:       []byte{0x00},
			want:       0,
			wantOffset: 1,
		},
		{
			name:       "one",
			data:       []byte{0x01},
			want:       1,
			wantOffset: 1,
		},
		{
			name:       "max single byte (127)",
			data:       []byte{0x7F},
			want:       127,
			wantOffset: 1,
		},
		// Two byte values (128-16383)
		{
			name:       "min two byte (128)",
			data:       []byte{0x81, 0x00},
			want:       128,
			wantOffset: 2,
		},
		{
			name:       "two byte value 300",
			data:       []byte{0x82, 0x2C}, // 2*128 + 44 = 300
			want:       300,
			wantOffset: 2,
		},
		{
			name:       "max two byte (16383)",
			data:       []byte{0xFF, 0x7F}, // 127*128 + 127 = 16383
			want:       16383,
			wantOffset: 2,
		},
		// Three byte values
		{
			name:       "min three byte (16384)",
			data:       []byte{0x81, 0x80, 0x00},
			want:       16384,
			wantOffset: 3,
		},
		// Four byte values
		{
			name:       "four byte value",
			data:       []byte{0x81, 0x80, 0x80, 0x00}, // 2097152
			want:       2097152,
			wantOffset: 4,
		},
		// Five byte values - boundary cases
		{
			name:       "max uint32 (4294967295)",
			data:       []byte{0x8F, 0xFF, 0xFF, 0xFF, 0x7F},
			want:       4294967295,
			wantOffset: 5,
		},
		// Overflow cases
		{
			name:    "overflow - uint32 max + 1 (4294967296)",
			data:    []byte{0x90, 0x80, 0x80, 0x80, 0x00},
			want:    0,
			wantErr: ErrBase128IntegerTooLarge,
		},
		{
			name:    "overflow - 6 bytes (exceeds max base128 length for uint32)",
			data:    []byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x00},
			want:    0,
			wantErr: ErrBase128IntegerTooLarge,
		},
		// Truncation cases
		{
			name:    "truncated - single continuation byte",
			data:    []byte{0x80},
			want:    0,
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated - multiple continuation bytes",
			data:    []byte{0x81, 0x82, 0x83},
			want:    0,
			wantErr: ErrBase128IntegerTruncated,
		},
		{
			name:    "truncated - empty input",
			data:    []byte{},
			want:    0,
			wantErr: ErrBase128IntegerTruncated,
		},
		// Non-minimal encoding (accepted per permissive parsing)
		{
			name:       "non-minimal encoding of 1",
			data:       []byte{0x80, 0x01}, // could be just 0x01
			want:       1,
			wantOffset: 2,
		},
		// Offset handling
		{
			name:       "value with trailing data",
			data:       []byte{0x7F, 0x99, 0x99}, // 127 followed by garbage
			want:       127,
			wantOffset: 1, // should stop after first byte
		},
		{
			name:       "parse from middle of slice",
			data:       []byte{0x99, 0x99, 0x82, 0x2C, 0x99}, // garbage, 300, garbage
			initOffset: 2,
			want:       300,
			wantOffset: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, offset, err := base128Uint32(tt.data, tt.initOffset)
			if err != tt.wantErr {
				t.Errorf("base128Uint32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got != tt.want {
					t.Errorf("base128Uint32() value = %v, want %v", got, tt.want)
				}
				if offset != tt.wantOffset {
					t.Errorf("base128Uint32() offset = %v, want %v", offset, tt.wantOffset)
				}
			}
		})
	}
}

func BenchmarkOID(b *testing.B) {
	oid := []byte{43, 6, 3, 30, 11, 1, 10}
	for i := 0; i < b.N; i++ {
		if _, err := OID(oid); err != nil {
			b.Fatal(err)
		}
	}
}
