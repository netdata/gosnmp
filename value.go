// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"math"
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

// appendValue appends the TLV of a varbind value with the given tag. The Go
// types it accepts per tag:
//
//   - Integer: int within the int32 range
//   - Counter32, Gauge32, TimeTicks, Uinteger32: uint32, or uint truncated to
//     32 bits
//   - Counter64: uint64
//   - OctetString, BitString, Opaque: []byte or string, written as is (a
//     BitString without its unused-bits octet)
//   - ObjectIdentifier: dotted string
//   - IPAddress: []byte written as is, or a string whose parsed address
//     contributes its last four bytes (so IPv6 loses its first twelve)
//   - OpaqueFloat: float32; OpaqueDouble: float64 (see appendOpaqueFloat)
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: any, ignored
//
// Other tags and types are errors.
func appendValue(dst []byte, tag Asn1BER, value any) ([]byte, error) {
	switch tag {
	case Null, NoSuchObject, NoSuchInstance, EndOfMibView:
		return append(dst, byte(tag), 0), nil
	case Integer:
		v, ok := value.(int)
		if !ok {
			return nil, errors.New("unable to marshal PDU Integer; not int")
		}
		out, err := appendInt32(dst, Integer, v)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal PDU Integer: %w", err)
		}
		return out, nil
	case Counter32, Gauge32, TimeTicks, Uinteger32:
		var v uint32
		switch value := value.(type) {
		case uint32:
			v = value
		case uint:
			v = uint32(value) //nolint:gosec
		default:
			return nil, fmt.Errorf("unable to marshal pdu.Type %v; unknown pdu.Value %v[type=%T]", tag, value, value)
		}
		return appendUint(dst, tag, uint64(v)), nil
	case Counter64:
		v, ok := value.(uint64)
		if !ok {
			return nil, fmt.Errorf("unable to marshal PDU Counter64; not uint64")
		}
		return appendUint(dst, Counter64, v), nil
	case OctetString, BitString, Opaque:
		switch value := value.(type) {
		case []byte:
			return appendOctets(dst, tag, value), nil
		case string:
			return appendOctets(dst, tag, value), nil
		default:
			return nil, fmt.Errorf("unable to marshal PDU OctetString; not []byte or string")
		}
	case ObjectIdentifier:
		v, ok := value.(string)
		if !ok {
			return nil, errors.New("unable to marshal PDU ObjectIdentifier; not string")
		}
		return appendObjectIdentifier(dst, v)
	case IPAddress:
		switch value := value.(type) {
		case []byte:
			return appendOctets(dst, IPAddress, value), nil
		case string:
			ip, err := marshalIPAddress(value)
			if err != nil {
				return nil, fmt.Errorf("unable to marshal PDU IPAddress: %w", err)
			}
			return appendOctets(dst, IPAddress, ip[:]), nil
		default:
			return nil, fmt.Errorf("unable to marshal PDU IPAddress; not []byte or string")
		}
	case OpaqueFloat, OpaqueDouble:
		return appendOpaqueFloat(dst, tag, value)
	default:
		return nil, fmt.Errorf("unable to marshal PDU: unknown BER type %q", tag)
	}
}

// appendOctets appends a TLV whose content is v as is.
func appendOctets[T string | []byte](dst []byte, tag Asn1BER, v T) []byte {
	return append(ber.AppendHeader(dst, byte(tag), len(v)), v...)
}

// appendInt32 appends a TLV holding v as an INTEGER; v must be within the
// int32 range, as SNMP Integer32 values are.
func appendInt32(dst []byte, tag Asn1BER, v int) ([]byte, error) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return nil, fmt.Errorf("%d overflows int32", v)
	}
	return appendInt(dst, tag, int64(v)), nil
}

// appendInt appends a TLV holding v as an INTEGER.
func appendInt(dst []byte, tag Asn1BER, v int64) []byte {
	dst, start := ber.Begin(dst, byte(tag))
	return ber.End(ber.AppendInt64(dst, v), start)
}

// appendUint appends a TLV holding the unsigned v as a non-negative INTEGER.
func appendUint(dst []byte, tag Asn1BER, v uint64) []byte {
	dst, start := ber.Begin(dst, byte(tag))
	return ber.End(ber.AppendUint64(dst, v), start)
}

// appendOpaqueFloat appends a float or double the way net-snmp wraps it in an
// Opaque: an Opaque TLV holding a TLV whose identifier is the extension octet
// 0x9f followed by the OpaqueFloat or OpaqueDouble tag (see decodeOpaque).
func appendOpaqueFloat(dst []byte, tag Asn1BER, value any) ([]byte, error) {
	dst, start := ber.Begin(dst, byte(Opaque))
	dst = append(dst, AsnExtensionTag)
	switch v := value.(type) {
	case float32:
		if tag != OpaqueFloat {
			break
		}
		return ber.End(ber.AppendFloat32(ber.AppendHeader(dst, byte(OpaqueFloat), 4), v), start), nil
	case float64:
		if tag != OpaqueDouble {
			break
		}
		return ber.End(ber.AppendFloat64(ber.AppendHeader(dst, byte(OpaqueDouble), 8), v), start), nil
	}
	return nil, fmt.Errorf("unable to marshal PDU %v; got %T", tag, value)
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

// appendObjectIdentifier appends an OBJECT IDENTIFIER TLV for the dotted OID
// string (see ber.AppendOID).
func appendObjectIdentifier(dst []byte, oid string) ([]byte, error) {
	dst, start := ber.Begin(dst, byte(ObjectIdentifier))
	dst, err := ber.AppendOID(dst, oid)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal OID %q: %w", oid, err)
	}
	return ber.End(dst, start), nil
}
