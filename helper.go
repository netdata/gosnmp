// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"

	"github.com/netdata/gosnmp/internal/ber"
)

// variable struct is used by decodeValue()
type variable struct {
	Value any
	Type  Asn1BER
}

// helper error modes
var (
	ErrBase128IntegerTooLarge  = ber.ErrBase128IntegerTooLarge
	ErrBase128IntegerTruncated = ber.ErrBase128IntegerTruncated
	ErrFloatBufferTooShort     = ber.ErrFloatBufferTooShort
	ErrFloatTooLarge           = ber.ErrFloatTooLarge
	ErrIntegerTooLarge         = ber.ErrIntegerTooLarge
	ErrInvalidOidLength        = errors.New("invalid OID length")
	ErrInvalidPacketLength     = ber.ErrInvalidPacketLength
	ErrZeroByteBuffer          = errors.New("zero byte buffer")
	ErrZeroLenInteger          = ber.ErrZeroLenInteger
)

// -- helper functions (mostly) in alphabetical order --------------------------

// Check makes checking errors easy, so they actually get a minimal check
func (x *GoSNMP) Check(err error) {
	if err != nil {
		x.Logger.Printf("Check: %v\n", err)
		os.Exit(1)
	}
}

// Check makes checking errors easy, so they actually get a minimal check
func (packet *SnmpPacket) Check(err error) {
	if err != nil {
		packet.Logger.Printf("Check: %v\n", err)
		os.Exit(1)
	}
}

// Check makes checking errors easy, so they actually get a minimal check
func Check(err error) {
	if err != nil {
		log.Fatalf("Check: %v\n", err)
	}
}

func decodeValue(data []byte, retVal *variable) error {
	if len(data) == 0 {
		return ErrZeroByteBuffer
	}

	switch Asn1BER(data[0]) {
	case Integer, Uinteger32:
		// 0x02. signed
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		// check for truncated packets
		if length > len(data) {
			return fmt.Errorf("bytes: % x err: truncated (data %d length %d)", data, len(data), length)
		}

		var ret int
		if ret, err = parseInt(data[cursor:length]); err != nil {
			return fmt.Errorf("bytes: % x err: %w", data, err)
		}
		retVal.Type = Asn1BER(data[0])
		switch Asn1BER(data[0]) {
		case Uinteger32:
			retVal.Value = uint32(ret) //nolint:gosec
		default:
			retVal.Value = ret
		}

	case OctetString:
		// 0x04
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		// check for truncated packet and throw an error
		if length > len(data) {
			return fmt.Errorf("bytes: % x err: truncated (data %d length %d)", data, len(data), length)
		}

		retVal.Type = OctetString
		retVal.Value = data[cursor:length]
	case Null:
		// 0x05
		retVal.Type = Null
		retVal.Value = nil
	case ObjectIdentifier:
		// 0x06
		rawOid, _, err := parseRawField(data)
		if err != nil {
			return fmt.Errorf("error parsing OID Value: %w", err)
		}
		oid, ok := rawOid.(string)
		if !ok {
			return fmt.Errorf("unable to type assert rawOid |%v| to string", rawOid)
		}
		retVal.Type = ObjectIdentifier
		retVal.Value = oid
	case IPAddress:
		// 0x40
		retVal.Type = IPAddress
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		// length includes header bytes, ipLen is just the address bytes
		ipLen := length - cursor
		switch ipLen {
		case 0: // real life, buggy devices returning bad data
			retVal.Value = nil
			return nil
		case 4: // IPv4
			if len(data) < cursor+4 {
				return fmt.Errorf("not enough data for ipv4 address: %x", data)
			}
			retVal.Value = net.IP(data[cursor : cursor+4]).String()
		case 16: // IPv6
			if len(data) < cursor+16 {
				return fmt.Errorf("not enough data for ipv6 address: %x", data)
			}
			d := make(net.IP, 16)
			copy(d, data[cursor:cursor+16])
			retVal.Value = d.String()
		default:
			return fmt.Errorf("got ipaddress len %d, expected 4 or 16", ipLen)
		}
	case Counter32:
		// 0x41. unsigned
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Counter32 %x (data %d length %d)", data, len(data), length)
		}

		ret, err := parseUint(data[cursor:length])
		if err != nil {
			break
		}
		retVal.Type = Counter32
		retVal.Value = ret
	case Gauge32:
		// 0x42. unsigned
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Gauge32 %x (data %d length %d)", data, len(data), length)
		}

		ret, err := parseUint(data[cursor:length])
		if err != nil {
			break
		}
		retVal.Type = Gauge32
		retVal.Value = ret
	case TimeTicks:
		// 0x43
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for TimeTicks %x (data %d length %d)", data, len(data), length)
		}

		ret, err := parseUint32(data[cursor:length])
		if err != nil {
			break
		}
		retVal.Type = TimeTicks
		retVal.Value = ret
	case Opaque:
		// 0x44
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Opaque %x (data %d length %d)", data, len(data), length)
		}
		return parseOpaque(data[cursor:length], retVal)
	case Counter64:
		// 0x46
		length, cursor, err := ber.Length(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Counter64 %x (data %d length %d)", data, len(data), length)
		}
		ret, err := ber.Uint64(data[cursor:length])
		if err != nil {
			break
		}
		retVal.Type = Counter64
		retVal.Value = ret
	case NoSuchObject:
		// 0x80
		retVal.Type = NoSuchObject
		retVal.Value = nil
	case NoSuchInstance:
		// 0x81
		retVal.Type = NoSuchInstance
		retVal.Value = nil
	case EndOfMibView:
		// 0x82
		retVal.Type = EndOfMibView
		retVal.Value = nil
	default:
		retVal.Type = UnknownType
		retVal.Value = nil
	}
	return nil
}

// appendBase128Int appends a base-128 encoded integer to the given slice.
// Returns the extended slice.
func appendBase128Int(dst []byte, n int64) []byte {
	if n == 0 {
		return append(dst, 0)
	}

	// Count number of 7-bit groups needed
	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}

	// Encode from most significant to least significant 7-bit group
	for i := l - 1; i >= 0; i-- {
		o := byte(n>>uint(i*7)) & 0x7f //nolint:gosec
		if i != 0 {
			o |= 0x80
		}
		dst = append(dst, o)
	}

	return dst
}

/*
	snmp Integer32 and INTEGER:
	-2^31 and 2^31-1 inclusive (-2147483648 to 2147483647 decimal)
	(FYI https://groups.google.com/forum/#!topic/comp.protocols.snmp/1xaAMzCe_hE)

	versus:

	snmp Counter32, Gauge32, TimeTicks, Unsigned32: (below)
	non-negative integer, maximum value of 2^32-1 (4294967295 decimal)
*/

// marshalInt32 builds a byte representation of a signed 32 bit int in BigEndian form
// ie -2^31 and 2^31-1 inclusive (-2147483648 to 2147483647 decimal)
func marshalInt32(value int) ([]byte, error) {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return nil, fmt.Errorf("unable to marshal: %d overflows int32", value)
	}
	const mask1 uint32 = 0xFFFFFF80
	const mask2 uint32 = 0xFFFF8000
	const mask3 uint32 = 0xFF800000
	// const mask4 uint32 = 0x80000000
	// ITU-T Rec. X.690 (2002) 8.3.2
	// If the contents octets of an integer value encoding consist of more than
	// one octet, then the bits of the first octet and bit 8 of the second octet:
	//  a) shall not all be ones; and
	//  b) shall not all be zero
	// These rules ensure that an integer value is always encoded in the smallest
	// possible number of octets.
	val := uint32(value) //nolint:gosec
	switch {
	case val&mask1 == 0 || val&mask1 == mask1:
		return []byte{byte(val)}, nil
	case val&mask2 == 0 || val&mask2 == mask2:
		return []byte{byte(val >> 8), byte(val)}, nil
	case val&mask3 == 0 || val&mask3 == mask3:
		return []byte{byte(val >> 16), byte(val >> 8), byte(val)}, nil
	default:
		return []byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}, nil
	}
}

// marshalUint64 encodes a uint64 into BER-compliant bytes for SNMP Counter64.
// It trims leading zero bytes and prepends one if MSB is set (per X.690 §8.3.2)
func marshalUint64(v any) ([]byte, error) {
	// gracefully handle type assertion to uint64
	source, ok := v.(uint64)
	if !ok {
		return nil, fmt.Errorf("marshalUint64: input is not a uint64")
	}
	// Step 1: Encode uint64 in big-endian (8 bytes)
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, source)

	// Step 2: Trim leading 0x00 bytes (X.690 §8.3.2: use minimal number of octets)
	trimmed := bytes.TrimLeft(bs, "\x00")

	// Step 3: Ensure at least one byte remains
	if len(trimmed) == 0 {
		return []byte{0}, nil
	}

	// Step 4: If the MSB of the first byte is set, prepend 0x00 to indicate positive value
	if trimmed[0]&0x80 > 0 {
		trimmed = append([]byte{0}, trimmed...)
	}
	return trimmed, nil
}

// Counter32, Gauge32, TimeTicks, Unsigned32, SNMPError
func marshalUint32(v any) ([]byte, error) {
	var source uint32
	switch val := v.(type) {
	case uint32:
		source = val
	case uint:
		source = uint32(val) //nolint:gosec
	case uint8:
		source = uint32(val)
	case SNMPError:
		source = uint32(val)
	// We could do others here, but coercing from anything else is dangerous.
	// Even uint could be 64 bits, though in practice nothing we work with is.
	default:
		return nil, fmt.Errorf("unable to marshal %T to uint32", v)
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, source)
	var i int
	for i = 0; i < 3; i++ {
		if buf[i] != 0 {
			break
		}
	}
	buf = buf[i:]
	// if the highest bit in buf is set and x is not negative - prepend a byte to make it positive
	if len(buf) > 0 && buf[0]&0x80 > 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf, nil
}

func marshalFloat32(v any) ([]byte, error) {
	source, ok := v.(float32)
	if !ok {
		return nil, fmt.Errorf("marshalFloat32: expected float32, got %T", v)
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, math.Float32bits(source))
	return buf, nil
}

func marshalFloat64(v any) ([]byte, error) {
	source, ok := v.(float64)
	if !ok {
		return nil, fmt.Errorf("marshalFloat64: expected float64, got %T", v)
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, math.Float64bits(source))
	return buf, nil
}

// marshalLength builds a byte representation of length
//
// http://luca.ntop.org/Teaching/Appunti/asn1.html
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
//   - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
//   - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//     7-1 give the number of additional length octets. Second and following
//     octets give the length, base 256, most significant digit first.
func marshalLength(length int) ([]byte, error) {
	// more convenient to pass length as int than uint64. Therefore check < 0
	if length < 0 {
		return nil, fmt.Errorf("length must be >= 0")
	}
	if length <= 127 {
		return []byte{byte(length)}, nil
	}

	// Encode length as big-endian uint64 and find first non-zero byte
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(length))

	// Find first non-zero byte to trim leading zeros
	start := 0
	for start < 8 && buf[start] == 0 {
		start++
	}

	// Build result: header byte + length bytes
	numBytes := 8 - start
	result := make([]byte, 1+numBytes)
	result[0] = byte(128 | numBytes) //nolint:gosec
	copy(result[1:], buf[start:])
	return result, nil
}

// marshalTLV writes a BER TLV (type-length-value) to buf using proper length
// encoding. Handles values of any size, including those exceeding 127 bytes.
func marshalTLV(buf *bytes.Buffer, tag byte, value []byte) error {
	length, err := marshalLength(len(value))
	if err != nil {
		return err
	}
	buf.WriteByte(tag)
	buf.Write(length)
	buf.Write(value)
	return nil
}

func marshalObjectIdentifier(oid string) ([]byte, error) {
	oidLength := len(oid)

	// Worst-case: 2 chars per output byte (e.g., ".128" = 4 chars → 2 bytes)
	// This ratio holds at base-128 boundaries; smaller values use more chars per byte
	out := make([]byte, 0, oidLength/2)

	var firstArc int64
	i := 0
	for j := 0; j < oidLength; {
		if oid[j] == '.' {
			j++
			continue
		}
		var val int64
		for j < oidLength && oid[j] != '.' {
			ch := int64(oid[j] - '0')
			if ch > 9 {
				return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
			}
			val *= 10
			val += ch
			// Bounding each sub-identifier here also keeps the int64
			// accumulator from wrapping on absurdly long digit runs
			if val > MaxObjectSubIdentifierValue {
				return nil, fmt.Errorf("unable to marshal OID: Value out of range")
			}
			j++
		}
		switch i {
		case 0:
			if val > 2 {
				return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
			}
			firstArc = val
		case 1:
			// First sub-identifier encodes arc1 and arc2 as (arc1*40 + arc2)
			// in base 128; arc2 <= 39 when arc1 < 2 (X.690 8.19)
			if firstArc < 2 && val >= 40 {
				return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
			}
			if val > MaxObjectSubIdentifierValue-80 {
				return nil, fmt.Errorf("unable to marshal OID: Value out of range")
			}
			out = appendBase128Int(out, firstArc*40+val)
		default:
			out = appendBase128Int(out, val)
		}
		i++
	}
	if i < 2 || i > 128 {
		return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
	}

	return out, nil
}

// TODO no tests
func ipv4toBytes(ip net.IP) []byte {
	return []byte(ip)[12:]
}

// parseOpaque  parses a Opaque encoded data
// Known data-types is OpaqueDouble and OpaqueFloat
// Other data decoded as binary Opaque data
// TODO: add OpaqueCounter64 (0x76), OpaqueInteger64 (0x80), OpaqueUinteger64 (0x81)
func parseOpaque(data []byte, retVal *variable) error {
	if len(data) == 0 {
		return ErrZeroByteBuffer
	}
	if len(data) > 2 && data[0] == AsnExtensionTag {
		switch Asn1BER(data[1]) {
		case OpaqueDouble:
			// 0x79
			data = data[1:]
			length, cursor, err := ber.Length(data)
			if err != nil {
				return err
			}
			if length > len(data) {
				return fmt.Errorf("not enough data for OpaqueDouble %x (data %d length %d)", data, len(data), length)
			}
			retVal.Type = OpaqueDouble
			retVal.Value, err = ber.Float64(data[cursor:length])
			if err != nil {
				return err
			}
		case OpaqueFloat:
			// 0x78
			data = data[1:]
			length, cursor, err := ber.Length(data)
			if err != nil {
				return err
			}
			if length > len(data) {
				return fmt.Errorf("not enough data for OpaqueFloat %x (data %d length %d)", data, len(data), length)
			}
			if cursor > length {
				return fmt.Errorf("invalid cursor position for OpaqueFloat %x (data %d length %d cursor %d)", data, len(data), length, cursor)
			}
			retVal.Type = OpaqueFloat
			retVal.Value, err = ber.Float32(data[cursor:length])
			if err != nil {
				return err
			}
		default:
			retVal.Type = Opaque
			retVal.Value = data[0:]
		}
	} else {
		retVal.Type = Opaque
		retVal.Value = data[0:]
	}
	return nil
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt(bytes []byte) (int, error) {
	ret64, err := ber.Int64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != int64(int(ret64)) {
		return 0, ErrIntegerTooLarge
	}
	return int(ret64), nil
}

// parseUint32 treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseUint32(bytes []byte) (uint32, error) {
	ret, err := parseUint(bytes)
	if err != nil {
		return 0, err
	}
	return uint32(ret), nil //nolint:gosec
}

// parseUint treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseUint(bytes []byte) (uint, error) {
	ret64, err := ber.Uint64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != uint64(uint(ret64)) {
		return 0, ErrIntegerTooLarge
	}
	return uint(ret64), nil
}

// -- Bit String ---------------------------------------------------------------

// BitStringValue is the structure to use when you want an ASN.1 BIT STRING type. A
// bit string is padded up to the nearest byte in memory and the number of
// valid bits is recorded. Padding bits will be zero.
type BitStringValue struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

// At returns the bit at the given index. If the index is out of range it
// returns false.
func (b BitStringValue) At(i int) int {
	if i < 0 || i >= b.BitLength {
		return 0
	}
	x := i / 8
	y := 7 - uint(i%8)
	return int(b.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (b BitStringValue) RightAlign() []byte {
	shift := uint(8 - (b.BitLength % 8))
	if shift == 8 || len(b.Bytes) == 0 {
		return b.Bytes
	}

	a := make([]byte, len(b.Bytes))
	a[0] = b.Bytes[0] >> shift
	for i := 1; i < len(b.Bytes); i++ {
		a[i] = b.Bytes[i-1] << (8 - shift)
		a[i] |= b.Bytes[i] >> shift
	}

	return a
}

// -- SnmpVersion --------------------------------------------------------------

func (s SnmpVersion) String() string {
	switch s {
	case Version1:
		return "1"
	case Version2c:
		return "2c"
	case Version3:
		return "3"
	default:
		return "3"
	}
}
