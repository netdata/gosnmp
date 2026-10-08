// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"net"

	"github.com/netdata/gosnmp/internal/ber"
)

// decodeValue decodes the content octets of a varbind value with the given
// tag into the type and Go value of the varbind:
//
//   - Integer: int; Uinteger32: uint32; Counter32, Gauge32: uint; TimeTicks:
//     uint32; Counter64: uint64
//   - OctetString, Opaque: []byte, aliasing content
//   - OpaqueFloat: float32; OpaqueDouble: float64 (see decodeOpaque)
//   - ObjectIdentifier: dotted string; IPAddress: IPv4 or IPv6 string, or nil
//     when empty
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: nil, content ignored
//   - any other tag: UnknownType and nil, content ignored
//
// Integer, Uinteger32, Counter32, Gauge32 and TimeTicks decode through the
// platform's int or uint, so 32-bit platforms reject or drop values that
// 64-bit platforms keep. Uinteger32 is decoded as a signed INTEGER and
// truncated, TimeTicks is truncated to 32 bits, and a Counter32, Gauge32,
// TimeTicks or Counter64 that fails to decode is not an error: it decodes as
// UnknownType with a nil value.
func decodeValue(tag Asn1BER, content []byte) (Asn1BER, any, error) {
	switch tag {
	case Integer:
		v, err := parseInt(content)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid Integer: %w", err)
		}
		return Integer, v, nil
	case Uinteger32:
		v, err := parseInt(content)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid Uinteger32: %w", err)
		}
		return Uinteger32, uint32(v), nil //nolint:gosec
	case OctetString:
		return OctetString, content, nil
	case ObjectIdentifier:
		oid, err := ber.OID(content)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid ObjectIdentifier: %w", err)
		}
		return ObjectIdentifier, oid, nil
	case IPAddress:
		switch len(content) {
		case 0: // real life, buggy devices returning bad data
			return IPAddress, nil, nil
		case 4, 16:
			return IPAddress, net.IP(content).String(), nil
		default:
			return 0, nil, fmt.Errorf("got ipaddress len %d, expected 4 or 16", len(content))
		}
	case Counter32, Gauge32:
		v, err := parseUint(content)
		if err != nil {
			return UnknownType, nil, nil
		}
		return tag, v, nil
	case TimeTicks:
		v, err := parseUint(content)
		if err != nil {
			return UnknownType, nil, nil
		}
		return TimeTicks, uint32(v), nil //nolint:gosec
	case Counter64:
		v, err := ber.Uint64(content)
		if err != nil {
			return UnknownType, nil, nil
		}
		return Counter64, v, nil
	case Opaque:
		return decodeOpaque(content)
	case Null, NoSuchObject, NoSuchInstance, EndOfMibView:
		return tag, nil, nil
	default:
		return UnknownType, nil, nil
	}
}

// decodeOpaque decodes the content of an Opaque value. net-snmp wraps floats
// and doubles in an Opaque as a TLV whose identifier is the extension octet
// 0x9f followed by the OpaqueFloat or OpaqueDouble tag: that TLV is read from
// its second identifier octet on, and octets after it are ignored. Content of
// up to two octets is never such a TLV; anything else is a raw Opaque. Empty
// content fails with ErrZeroByteBuffer.
func decodeOpaque(content []byte) (Asn1BER, any, error) {
	if len(content) == 0 {
		return 0, nil, ErrZeroByteBuffer
	}
	if len(content) <= 2 || content[0] != AsnExtensionTag {
		return Opaque, content, nil
	}
	tag := Asn1BER(content[1])
	if tag != OpaqueFloat && tag != OpaqueDouble {
		return Opaque, content, nil
	}

	r := ber.NewReader(content[1:])
	_, inner, err := r.Next()
	if err != nil {
		return 0, nil, fmt.Errorf("invalid %v: %w", tag, err)
	}
	var v any
	if tag == OpaqueFloat {
		v, err = ber.Float32(inner)
	} else {
		v, err = ber.Float64(inner)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("invalid %v: %w", tag, err)
	}
	return tag, v, nil
}

// parseInt decodes INTEGER content into the platform's int; a value that does
// not fit fails with ErrIntegerTooLarge.
func parseInt(content []byte) (int, error) {
	ret64, err := ber.Int64(content)
	if err != nil {
		return 0, err
	}
	if ret64 != int64(int(ret64)) {
		return 0, ErrIntegerTooLarge
	}
	return int(ret64), nil
}

// parseUint decodes unsigned content, where empty content is 0, into the
// platform's uint; a value that does not fit fails with ErrIntegerTooLarge.
func parseUint(content []byte) (uint, error) {
	ret64, err := ber.Uint64(content)
	if err != nil {
		return 0, err
	}
	if ret64 != uint64(uint(ret64)) {
		return 0, ErrIntegerTooLarge
	}
	return uint(ret64), nil
}
