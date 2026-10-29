// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Package ber reads and writes the ASN.1 BER encodings SNMP messages are
// built from: TLV headers and lengths, integers, object identifiers and Opaque
// floats. Its decoder keeps the leniencies it has always had (see Length),
// because they decide which device responses the library accepts.
package ber

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// Errors returned by the decoders. The root package exports them under the
// same names.
var (
	ErrBase128IntegerTooLarge  = errors.New("base 128 integer too large")
	ErrBase128IntegerTruncated = errors.New("base 128 integer truncated")
	ErrFloatBufferTooShort     = errors.New("float buffer too short")
	ErrFloatTooLarge           = errors.New("float too large")
	ErrIntegerTooLarge         = errors.New("integer too large")
	ErrInvalidPacketLength     = errors.New("invalid packet length")
	ErrZeroLenInteger          = errors.New("zero length integer")
)

// Length returns the length of the TLV at the start of bytes, counting its tag
// and length octets, and the number of those header octets. It reads a
// single-octet tag without examining it and does not check that the content
// is present; callers compare the length with their input.
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
//   - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
//   - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//     7-1 give the number of additional length octets. Second and following
//     octets give the length, base 256, most significant digit first.
//
// Kept leniencies: input shorter than two octets is a TLV of that length with
// no content; the long form accumulates in an int, so more length octets than
// an int holds wrap silently, while a length that overflows when the header is
// added fails with ErrInvalidPacketLength. The indefinite form is rejected.
func Length(bytes []byte) (int, int, error) {
	switch {
	case len(bytes) < 2:
		// handle null octet strings ie "0x04 0x00"
		return len(bytes), len(bytes), nil
	case bytes[1] <= 127:
		return int(bytes[1]) + 2, 2, nil
	case bytes[1] == 0x80:
		// Indefinite length encoding (0x80) is prohibited in SNMP per RFC 3417 Section 8:
		// "When encoding the length field, only the definite form is used;
		// use of the indefinite form encoding is prohibited."
		return 0, 0, fmt.Errorf("indefinite length encoding (0x80) is not permitted in SNMP")
	}

	numOctets := int(bytes[1]) & 127
	if len(bytes) < 2+numOctets {
		return 0, 0, ErrInvalidPacketLength
	}
	var length int
	for _, b := range bytes[2 : 2+numOctets] {
		length = length<<8 + int(b)
		if length < 0 {
			// Invalid length due to overflow, return an error
			return 0, 0, ErrInvalidPacketLength
		}
	}
	header := 2 + numOctets
	if length += header; length < 0 {
		// The header overflows the length.
		return 0, 0, ErrInvalidPacketLength
	}
	return length, header, nil
}

// Int64 decodes the content octets of an INTEGER: a big-endian, two's
// complement number of one to eight octets.
func Int64(bytes []byte) (int64, error) {
	switch {
	case len(bytes) == 0:
		// X.690 8.3.1: Encoding of an integer value:
		// The encoding of an integer value shall be primitive.
		// The contents octets shall consist of one or more octets.
		return 0, ErrZeroLenInteger
	case len(bytes) > 8:
		// We'll overflow an int64 in this case.
		return 0, ErrIntegerTooLarge
	}
	var ret int64
	for bytesRead := range bytes {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}
	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8 //nolint:gosec
	ret >>= 64 - uint8(len(bytes))*8 //nolint:gosec
	return ret, nil
}

// Uint64 decodes unsigned content octets: a big-endian number of up to eight
// octets, or nine with a leading zero. Empty content decodes as 0.
func Uint64(bytes []byte) (uint64, error) {
	var ret uint64
	if len(bytes) > 9 || (len(bytes) > 8 && bytes[0] != 0x0) {
		// We'll overflow a uint64 in this case.
		return 0, ErrIntegerTooLarge
	}
	for bytesRead := range bytes {
		ret <<= 8
		ret |= uint64(bytes[bytesRead])
	}
	return ret, nil
}

// oidSubIdentifier reads one base-128 OID subidentifier and returns its value
// and the next offset. limit is maxSubIdentifier for an individual arc or that
// limit plus 80 for the packed first two arcs; either bounds the accumulator
// below 2^33 before each shift.
func oidSubIdentifier(bytes []byte, initOffset int, limit uint64) (uint64, int, error) {
	var ret uint64
	offset := initOffset
	for offset < len(bytes) {
		b := bytes[offset]
		offset++
		ret = (ret << 7) | uint64(b&0x7f)
		if ret > limit {
			return 0, 0, ErrBase128IntegerTooLarge
		}
		if b&0x80 == 0 {
			return ret, offset, nil
		}
	}
	return 0, 0, ErrBase128IntegerTruncated
}

// OID decodes the content octets of an OBJECT IDENTIFIER into dotted form
// with a leading dot, such as ".1.3.6.1". Empty content decodes as ".0.0"
// for compatibility with earlier versions of this library. Each arc may be up
// to 2^32-1 (RFC 2578 section 3.5), so the first subidentifier, which packs the
// first two arcs, may reach 2^32+79 (X.690 section 8.19.4). net-snmp v5.9.4
// rejects any subidentifier above 2^32-1, the packed first one included, so it
// cannot exchange an OID whose second arc under arc 2 exceeds 4294967215.
func OID(src []byte) (string, error) {
	if len(src) == 0 {
		return ".0.0", nil
	}

	// Worst-case: first byte expands to 5 chars (".2.39"), rest to 4 chars (".127")
	out := make([]byte, 0, len(src)*4+1)

	// First sub-identifier encodes arc1 and arc2 as (arc1*40 + arc2);
	// arc1 is 0, 1, or 2, with arc2 <= 39 when arc1 < 2.
	// The packed pair can reach MaxUint32+80; later arcs remain uint32.
	v, offset, err := oidSubIdentifier(src, 0, maxSubIdentifier+80)
	if err != nil {
		return "", err
	}
	out = append(out, '.')
	if v < 80 {
		out = strconv.AppendUint(out, v/40, 10)
		out = append(out, '.')
		out = strconv.AppendUint(out, v%40, 10)
	} else {
		out = append(out, '2', '.')
		out = strconv.AppendUint(out, v-80, 10)
	}

	for offset < len(src) {
		out = append(out, '.')
		v, offset, err = oidSubIdentifier(src, offset, maxSubIdentifier)
		if err != nil {
			return "", err
		}
		out = strconv.AppendUint(out, v, 10)
	}
	return string(out), nil
}

// Float32 decodes the four content octets of an Opaque float as an IEEE 754
// binary32 value.
func Float32(bytes []byte) (float32, error) {
	if len(bytes) > 4 {
		// More than a binary32 holds.
		return 0, ErrFloatTooLarge
	}
	if len(bytes) < 4 {
		// We'll cause a panic in binary.BigEndian.Uint32() in this case
		return 0, ErrFloatBufferTooShort
	}
	return math.Float32frombits(binary.BigEndian.Uint32(bytes)), nil
}

// Float64 decodes the eight content octets of an Opaque double as an IEEE 754
// binary64 value.
func Float64(bytes []byte) (float64, error) {
	if len(bytes) > 8 {
		// More than a binary64 holds.
		return 0, ErrFloatTooLarge
	}
	if len(bytes) < 8 {
		// We'll cause a panic in binary.BigEndian.Uint64() in this case
		return 0, ErrFloatBufferTooShort
	}
	return math.Float64frombits(binary.BigEndian.Uint64(bytes)), nil
}
