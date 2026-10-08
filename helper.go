// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"errors"
	"log"
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
