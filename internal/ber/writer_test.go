// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package ber

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestAppendLength(t *testing.T) {
	tests := map[string]struct {
		n    int
		want []byte
	}{
		"zero":             {n: 0, want: []byte{0x00}},
		"one":              {n: 1, want: []byte{0x01}},
		"short form limit": {n: 127, want: []byte{0x7f}},
		"one long octet":   {n: 128, want: []byte{0x81, 0x80}},
		"129":              {n: 129, want: []byte{0x81, 0x81}},
		"255":              {n: 255, want: []byte{0x81, 0xff}},
		"272":              {n: 272, want: []byte{0x82, 0x01, 0x10}},
		"435":              {n: 435, want: []byte{0x82, 0x01, 0xb3}},
		"256":              {n: 256, want: []byte{0x82, 0x01, 0x00}},
		"65535":            {n: 65535, want: []byte{0x82, 0xff, 0xff}},
		"65536":            {n: 65536, want: []byte{0x83, 0x01, 0x00, 0x00}},
		"2^24":             {n: 1 << 24, want: []byte{0x84, 0x01, 0x00, 0x00, 0x00}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := AppendLength([]byte{0xaa}, tt.n)
			if want := append([]byte{0xaa}, tt.want...); !bytes.Equal(got, want) {
				t.Errorf("AppendLength(%d) = % x, want % x", tt.n, got, want)
			}

			header := AppendHeader(nil, 0x04, tt.n)
			length, cursor, err := Length(header)
			if err != nil || length-cursor != tt.n || cursor != len(header) {
				t.Errorf("Length(AppendHeader(%d)) = %d, %d, %v", tt.n, length, cursor, err)
			}
		})
	}
}

func TestBeginEnd(t *testing.T) {
	tests := map[string]struct {
		contentLen int
		header     []byte
	}{
		"empty":            {contentLen: 0, header: []byte{0x30, 0x00}},
		"one octet":        {contentLen: 1, header: []byte{0x30, 0x01}},
		"short form limit": {contentLen: 127, header: []byte{0x30, 0x7f}},
		"long form 128":    {contentLen: 128, header: []byte{0x30, 0x81, 0x80}},
		"long form 255":    {contentLen: 255, header: []byte{0x30, 0x81, 0xff}},
		"long form 256":    {contentLen: 256, header: []byte{0x30, 0x82, 0x01, 0x00}},
		"long form 65535":  {contentLen: 65535, header: []byte{0x30, 0x82, 0xff, 0xff}},
		"long form 65536":  {contentLen: 65536, header: []byte{0x30, 0x83, 0x01, 0x00, 0x00}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			content := make([]byte, tt.contentLen)
			for i := range content {
				content[i] = byte(i)
			}
			dst, start := Begin([]byte{0xaa, 0xbb}, 0x30)
			dst = End(append(dst, content...), start)

			want := append(append([]byte{0xaa, 0xbb}, tt.header...), content...)
			if !bytes.Equal(dst, want) {
				t.Errorf("Begin/End with %d content octets: header % x, want % x",
					tt.contentLen, dst[2:min(len(dst), 2+len(tt.header))], tt.header)
			}
		})
	}
}

func TestBeginEndNested(t *testing.T) {
	inner := bytes.Repeat([]byte{0x05}, 200)

	dst, outer := Begin(nil, 0x30)
	dst = append(dst, 0x02, 0x01, 0x07)
	dst, mid := Begin(dst, 0x30)
	dst = End(append(dst, inner...), mid)
	dst = End(dst, outer)

	want := append([]byte{0x30, 0x81, 0xce, 0x02, 0x01, 0x07, 0x30, 0x81, 0xc8}, inner...)
	if !bytes.Equal(dst, want) {
		t.Errorf("nested TLVs = % x, want % x", dst[:9], want[:9])
	}
}

func TestAppendInt64(t *testing.T) {
	tests := map[string]struct {
		v    int64
		want []byte
	}{
		"zero":         {v: 0, want: []byte{0x00}},
		"2":            {v: 2, want: []byte{0x02}},
		"127":          {v: 127, want: []byte{0x7f}},
		"128":          {v: 128, want: []byte{0x00, 0x80}},
		"257":          {v: 257, want: []byte{0x01, 0x01}},
		"65537":        {v: 65537, want: []byte{0x01, 0x00, 0x01}},
		"16777217":     {v: 16777217, want: []byte{0x01, 0x00, 0x00, 0x01}},
		"max int32":    {v: math.MaxInt32, want: []byte{0x7f, 0xff, 0xff, 0xff}},
		"2^31":         {v: 1 << 31, want: []byte{0x00, 0x80, 0x00, 0x00, 0x00}},
		"max int64":    {v: math.MaxInt64, want: []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		"-1":           {v: -1, want: []byte{0xff}},
		"-2":           {v: -2, want: []byte{0xfe}},
		"-128":         {v: -128, want: []byte{0x80}},
		"-129":         {v: -129, want: []byte{0xff, 0x7f}},
		"-256":         {v: -256, want: []byte{0xff, 0x00}},
		"-257":         {v: -257, want: []byte{0xfe, 0xff}},
		"-65536":       {v: -65536, want: []byte{0xff, 0x00, 0x00}},
		"-65537":       {v: -65537, want: []byte{0xfe, 0xff, 0xff}},
		"-16777216":    {v: -16777216, want: []byte{0xff, 0x00, 0x00, 0x00}},
		"-16777217":    {v: -16777217, want: []byte{0xfe, 0xff, 0xff, 0xff}},
		"min int32":    {v: math.MinInt32, want: []byte{0x80, 0x00, 0x00, 0x00}},
		"min int32 -1": {v: math.MinInt32 - 1, want: []byte{0xff, 0x7f, 0xff, 0xff, 0xff}},
		"min int64":    {v: math.MinInt64, want: []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := AppendInt64([]byte{0xaa}, tt.v)
			if want := append([]byte{0xaa}, tt.want...); !bytes.Equal(got, want) {
				t.Errorf("AppendInt64(%d) = % x, want % x", tt.v, got, want)
			}
			if back, err := Int64(got[1:]); err != nil || back != tt.v {
				t.Errorf("Int64(AppendInt64(%d)) = %d, %v", tt.v, back, err)
			}
		})
	}
}

func TestAppendUint64(t *testing.T) {
	tests := map[string]struct {
		v    uint64
		want []byte
	}{
		"zero":         {v: 0, want: []byte{0x00}},
		"2":            {v: 2, want: []byte{0x02}},
		"127":          {v: 127, want: []byte{0x7f}},
		"128":          {v: 128, want: []byte{0x00, 0x80}},
		"255":          {v: 255, want: []byte{0x00, 0xff}},
		"256":          {v: 256, want: []byte{0x01, 0x00}},
		"257":          {v: 257, want: []byte{0x01, 0x01}},
		"65537":        {v: 65537, want: []byte{0x01, 0x00, 0x01}},
		"16777217":     {v: 16777217, want: []byte{0x01, 0x00, 0x00, 0x01}},
		"18542501":     {v: 18542501, want: []byte{0x01, 0x1a, 0xef, 0xa5}},
		"max int32":    {v: math.MaxInt32, want: []byte{0x7f, 0xff, 0xff, 0xff}},
		"2^31":         {v: 1 << 31, want: []byte{0x00, 0x80, 0x00, 0x00, 0x00}},
		"max uint32":   {v: math.MaxUint32, want: []byte{0x00, 0xff, 0xff, 0xff, 0xff}},
		"2^63":         {v: 1 << 63, want: []byte{0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		"max uint64":   {v: math.MaxUint64, want: []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		"2^56":         {v: 1 << 56, want: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		"2^63 - 1":     {v: math.MaxInt64, want: []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		"0x80000001ff": {v: 0x80000001ff, want: []byte{0x00, 0x80, 0x00, 0x00, 0x01, 0xff}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := AppendUint64([]byte{0xaa}, tt.v)
			if want := append([]byte{0xaa}, tt.want...); !bytes.Equal(got, want) {
				t.Errorf("AppendUint64(%d) = % x, want % x", tt.v, got, want)
			}
			if back, err := Uint64(got[1:]); err != nil || back != tt.v {
				t.Errorf("Uint64(AppendUint64(%d)) = %d, %v", tt.v, back, err)
			}
		})
	}
}

func TestAppendFloat(t *testing.T) {
	tests32 := map[string]struct {
		v    float32
		want []byte
	}{
		"zero":         {v: 0, want: []byte{0x00, 0x00, 0x00, 0x00}},
		"positive 1.0": {v: 1, want: []byte{0x3f, 0x80, 0x00, 0x00}},
		"negative 1.0": {v: -1, want: []byte{0xbf, 0x80, 0x00, 0x00}},
		"pi approx":    {v: 3.14159, want: []byte{0x40, 0x49, 0x0f, 0xd0}},
		"NaN payload":  {v: math.Float32frombits(0x7fc00001), want: []byte{0x7f, 0xc0, 0x00, 0x01}},
	}
	for name, tt := range tests32 {
		t.Run("float32 "+name, func(t *testing.T) {
			got := AppendFloat32(nil, tt.v)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("AppendFloat32(%v) = % x, want % x", tt.v, got, tt.want)
			}
			if back, err := Float32(got); err != nil || math.Float32bits(back) != math.Float32bits(tt.v) {
				t.Errorf("Float32(AppendFloat32(%v)) = %v, %v", tt.v, back, err)
			}
		})
	}

	tests64 := map[string]struct {
		v    float64
		want []byte
	}{
		"zero":         {v: 0, want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		"positive 1.0": {v: 1, want: []byte{0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		"negative 1.0": {v: -1, want: []byte{0xbf, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		"pi":           {v: math.Pi, want: []byte{0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18}},
	}
	for name, tt := range tests64 {
		t.Run("float64 "+name, func(t *testing.T) {
			got := AppendFloat64(nil, tt.v)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("AppendFloat64(%v) = % x, want % x", tt.v, got, tt.want)
			}
			if back, err := Float64(got); err != nil || back != tt.v {
				t.Errorf("Float64(AppendFloat64(%v)) = %v, %v", tt.v, back, err)
			}
		})
	}
}

func TestAppendOID(t *testing.T) {
	tests := map[string]struct {
		oid     string
		want    []byte
		dotted  string // what OID decodes the result to
		wantErr error
	}{
		"sysDescr":                 {oid: ".1.3.6.1.2.1.1.1", want: []byte{43, 6, 1, 2, 1, 1, 1}, dotted: ".1.3.6.1.2.1.1.1"},
		"no leading dot":           {oid: "1.3.6.1", want: []byte{43, 6, 1}, dotted: ".1.3.6.1"},
		"minimal 0.0":              {oid: ".0.0", want: []byte{0x00}, dotted: ".0.0"},
		"empty arcs are skipped":   {oid: "1..3.6", want: []byte{43, 6}, dotted: ".1.3.6"},
		"trailing dot is skipped":  {oid: ".1.3.6.", want: []byte{43, 6}, dotted: ".1.3.6"},
		"multi-octet sub-id":       {oid: ".1.3.6.1.4.1.20372", want: []byte{43, 6, 1, 4, 1, 0x81, 0x9f, 0x14}, dotted: ".1.3.6.1.4.1.20372"},
		"2.999.3 (X.690 example)":  {oid: ".2.999.3", want: []byte{0x88, 0x37, 0x03}, dotted: ".2.999.3"},
		"2.100.3":                  {oid: ".2.100.3", want: []byte{0x81, 0x34, 0x03}, dotted: ".2.100.3"},
		"2.48":                     {oid: ".2.48", want: []byte{0x81, 0x00}, dotted: ".2.48"},
		"arc 40 under arc 2":       {oid: ".2.40", want: []byte{0x78}, dotted: ".2.40"},
		"largest arc under arc 2":  {oid: ".2.4294967215", want: []byte{0x8f, 0xff, 0xff, 0xff, 0x7f}, dotted: ".2.4294967215"},
		"max uint32 sub-id":        {oid: ".1.3.4294967295", want: []byte{43, 0x8f, 0xff, 0xff, 0xff, 0x7f}, dotted: ".1.3.4294967295"},
		"128 sub-identifiers":      {oid: "1.3" + strings.Repeat(".1", 126), want: append([]byte{43}, bytes.Repeat([]byte{1}, 126)...), dotted: ".1.3" + strings.Repeat(".1", 126)},
		"empty":                    {oid: "", wantErr: ErrInvalidOID},
		"single arc":               {oid: ".1", wantErr: ErrInvalidOID},
		"129 sub-identifiers":      {oid: "1.3" + strings.Repeat(".1", 127), wantErr: ErrInvalidOID},
		"letters":                  {oid: ".1.3.a", wantErr: ErrInvalidOID},
		"negative arc":             {oid: ".1.3.-6", wantErr: ErrInvalidOID},
		"first arc 3":              {oid: ".3.1", wantErr: ErrInvalidOID},
		"arc 40 under arc 1":       {oid: ".1.40", wantErr: ErrInvalidOID},
		"arc under arc 2 too big":  {oid: ".2.4294967216", wantErr: ErrOIDOutOfRange},
		"sub-id above uint32":      {oid: ".1.3.4294967296", wantErr: ErrOIDOutOfRange},
		"sub-id overflowing int64": {oid: ".1.3.18446744073709551617", wantErr: ErrOIDOutOfRange},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			prefix := []byte{0xaa}
			got, err := AppendOID(prefix, tt.oid)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("AppendOID(%q) error = %v, want %v", tt.oid, err, tt.wantErr)
			}
			if err != nil {
				if !bytes.Equal(got, prefix) {
					t.Errorf("AppendOID(%q) on error returned % x, want the unchanged % x", tt.oid, got, prefix)
				}
				return
			}
			if want := append([]byte{0xaa}, tt.want...); !bytes.Equal(got, want) {
				t.Errorf("AppendOID(%q) = % x, want % x", tt.oid, got, want)
			}
			if back, err := OID(got[1:]); err != nil || back != tt.dotted {
				t.Errorf("OID(AppendOID(%q)) = %q, %v, want %q", tt.oid, back, err, tt.dotted)
			}
		})
	}
}

func BenchmarkAppendOID(b *testing.B) {
	oid := ".1.3.6.3.30.11.1.10"
	buf := make([]byte, 0, 64)
	for b.Loop() {
		if _, err := AppendOID(buf[:0], oid); err != nil {
			b.Fatal(err)
		}
	}
}
