// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"

	"github.com/netdata/gosnmp/internal/ber"
)

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

// marshalInt32 encodes the content octets of an INTEGER within the int32
// range, which SNMP Integer32 fields use.
func marshalInt32(value int) ([]byte, error) {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return nil, fmt.Errorf("unable to marshal: %d overflows int32", value)
	}
	return ber.AppendInt64(nil, int64(value)), nil
}

// marshalUint32 encodes the content octets of an unsigned 32-bit field
// (Counter32, Gauge32, TimeTicks, Unsigned32, SNMPError) from the Go types
// those fields hold; a uint is truncated to 32 bits.
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
	default:
		return nil, fmt.Errorf("unable to marshal %T to uint32", v)
	}
	return ber.AppendUint64(nil, uint64(source)), nil
}

// marshalLength encodes a TLV length (see ber.AppendLength).
func marshalLength(length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("length must be >= 0")
	}
	return ber.AppendLength(nil, length), nil
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

// marshalOctetString writes s to buf as an OCTET STRING TLV.
func marshalOctetString(buf *bytes.Buffer, s string) error {
	length, err := marshalLength(len(s))
	if err != nil {
		return err
	}
	buf.WriteByte(byte(OctetString))
	buf.Write(length)
	buf.WriteString(s)
	return nil
}

// marshalObjectIdentifier encodes the content octets of an OBJECT IDENTIFIER
// (see ber.AppendOID).
func marshalObjectIdentifier(oid string) ([]byte, error) {
	return ber.AppendOID(nil, oid)
}

// marshalIPAddress returns the four octets of an IpAddress given as a string:
// the last four bytes of the parsed address, so an IPv6 address loses its
// first twelve. It returns an array so the parsed address stays on the stack.
func marshalIPAddress(s string) ([4]byte, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return [4]byte{}, fmt.Errorf("%q is not an IP address", s)
	}
	return [4]byte(ip[12:]), nil
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
