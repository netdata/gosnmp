// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package ber

import (
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
)

// Errors returned by AppendOID.
var (
	ErrInvalidOID    = errors.New("invalid object identifier")
	ErrOIDOutOfRange = errors.New("object identifier sub-identifier out of range")
)

// Limits AppendOID enforces.
const (
	maxSubIDs        = 128 // sub-identifiers in an SNMP OID (RFC 2578 3.5)
	maxSubIdentifier = math.MaxUint32
)

// AppendLength appends the minimal definite-form encoding of the length n,
// which must not be negative: one octet up to 127, otherwise 0x80 plus the
// number of big-endian length octets that follow.
func AppendLength(dst []byte, n int) []byte {
	if n <= 127 {
		return append(dst, byte(n)) //nolint:gosec
	}
	k := (bits.Len(uint(n)) + 7) / 8
	dst = append(dst, 0x80|byte(k)) //nolint:gosec
	for i := k - 1; i >= 0; i-- {
		dst = append(dst, byte(n>>(8*i))) //nolint:gosec
	}
	return dst
}

// AppendHeader appends the tag and length octets of a TLV whose content is n
// bytes long.
func AppendHeader(dst []byte, tag byte, n int) []byte {
	return AppendLength(append(dst, tag), n)
}

// Begin appends the tag of a TLV whose length is not known yet and a
// placeholder length octet. It returns the offset of the TLV's content, which
// the caller appends next and passes to End.
func Begin(dst []byte, tag byte) ([]byte, int) {
	dst = append(dst, tag, 0)
	return dst, len(dst)
}

// End sets the length of the TLV whose content started at offset start (from
// Begin) and runs to the end of dst. A content longer than 127 bytes is moved
// to make room for the long-form length octets.
func End(dst []byte, start int) []byte {
	n := len(dst) - start
	if n <= 127 {
		dst[start-1] = byte(n) //nolint:gosec
		return dst
	}
	k := (bits.Len(uint(n)) + 7) / 8
	dst = append(dst, make([]byte, k)...)
	copy(dst[start+k:], dst[start:start+n])
	dst[start-1] = 0x80 | byte(k) //nolint:gosec
	for i := k - 1; i >= 0; i-- {
		dst[start+i] = byte(n)
		n >>= 8
	}
	return dst
}

// AppendInt64 appends the content octets of an INTEGER: v in big-endian two's
// complement, in the fewest octets (X.690 8.3.2).
func AppendInt64(dst []byte, v int64) []byte {
	u := uint64(v) //nolint:gosec
	if v < 0 {
		u = ^u
	}
	for i := bits.Len64(u) / 8; i >= 0; i-- {
		dst = append(dst, byte(v>>(8*i))) //nolint:gosec
	}
	return dst
}

// AppendUint64 appends the content octets of an unsigned value: v big-endian
// in the fewest octets, with a leading zero octet when the high bit of the
// first octet is set, so it reads as a non-negative INTEGER.
func AppendUint64(dst []byte, v uint64) []byte {
	for i := bits.Len64(v) / 8; i >= 0; i-- {
		dst = append(dst, byte(v>>(8*i))) //nolint:gosec
	}
	return dst
}

// AppendFloat32 appends the four content octets of an Opaque float: v as an
// IEEE 754 binary32 value.
func AppendFloat32(dst []byte, v float32) []byte {
	return binary.BigEndian.AppendUint32(dst, math.Float32bits(v))
}

// AppendFloat64 appends the eight content octets of an Opaque double: v as an
// IEEE 754 binary64 value.
func AppendFloat64(dst []byte, v float64) []byte {
	return binary.BigEndian.AppendUint64(dst, math.Float64bits(v))
}

// AppendOID appends the content octets of the OBJECT IDENTIFIER written in
// dotted form, with or without a leading dot, such as ".1.3.6.1". It needs two
// to 128 sub-identifiers of at most 2^32-1; the first is 0, 1 or 2, and the
// second is below 40 unless the first is 2. Empty sub-identifiers (repeated or
// trailing dots) are skipped. On error dst is returned unchanged.
func AppendOID(dst []byte, oid string) ([]byte, error) {
	start := len(dst)
	var firstArc int64
	i := 0
	for j := 0; j < len(oid); {
		if oid[j] == '.' {
			j++
			continue
		}
		var val int64
		for j < len(oid) && oid[j] != '.' {
			ch := int64(oid[j] - '0')
			if ch > 9 {
				return dst[:start], ErrInvalidOID
			}
			val = val*10 + ch
			// Bounding each sub-identifier here also keeps the int64
			// accumulator from wrapping on absurdly long digit runs.
			if val > maxSubIdentifier {
				return dst[:start], ErrOIDOutOfRange
			}
			j++
		}
		switch i {
		case 0:
			if val > 2 {
				return dst[:start], ErrInvalidOID
			}
			firstArc = val
		case 1:
			// The first two arcs are encoded as one sub-identifier,
			// arc1*40 + arc2, with arc2 <= 39 when arc1 < 2 (X.690 8.19).
			if firstArc < 2 && val >= 40 {
				return dst[:start], ErrInvalidOID
			}
			if val > maxSubIdentifier-80 {
				return dst[:start], ErrOIDOutOfRange
			}
			dst = appendBase128(dst, firstArc*40+val)
		default:
			dst = appendBase128(dst, val)
		}
		i++
	}
	if i < 2 || i > maxSubIDs {
		return dst[:start], ErrInvalidOID
	}
	return dst, nil
}

// appendBase128 appends n in base 128, most significant group first, with the
// high bit set on every octet but the last.
func appendBase128(dst []byte, n int64) []byte {
	if n == 0 {
		return append(dst, 0)
	}
	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}
	for i := l - 1; i >= 0; i-- {
		o := byte(n>>uint(i*7)) & 0x7f //nolint:gosec
		if i != 0 {
			o |= 0x80
		}
		dst = append(dst, o)
	}
	return dst
}
