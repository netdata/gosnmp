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

// Errors that some decode errors wrap (match them with errors.Is): those of
// the BER decoder, and ErrZeroByteBuffer for a varbind without a value or an
// empty Opaque. Other decode, configuration and authentication errors are not
// exported. ErrInvalidOidLength is not returned.
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

// Check logs a non-nil err to the client's Logger and exits the process with
// status 1. It is meant for examples; a program should handle the error.
func (x *GoSNMP) Check(err error) {
	if err != nil {
		x.Logger.Printf("Check: %v\n", err)
		os.Exit(1)
	}
}

// Check logs a non-nil err to the packet's Logger and exits the process with
// status 1. It is meant for examples; a program should handle the error.
func (packet *SnmpPacket) Check(err error) {
	if err != nil {
		packet.Logger.Printf("Check: %v\n", err)
		os.Exit(1)
	}
}

// Check logs a non-nil err with the standard logger and exits the process
// with status 1 (log.Fatalf). It is meant for examples; a program should
// handle the error.
func Check(err error) {
	if err != nil {
		log.Fatalf("Check: %v\n", err)
	}
}

// BitStringValue is an ASN.1 BIT STRING: the bits packed into bytes, the
// first bit in the high bit of the first byte, and the number of valid bits;
// the padding bits are zero. The encoder and decoder do not use it: BitString
// is not an SNMP value type, which the encoder refuses and the decoder reads
// as UnknownType (SMIv2 sends BITS as an OctetString).
type BitStringValue struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

// At returns the bit at index i, or 0 when i is out of range.
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
