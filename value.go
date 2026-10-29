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

// decodeValue decodes the content octets of a varbind value with the given tag
// into the type and Go value of the varbind, by the tag's rule (valueRules):
//
//   - Integer: int, an INTEGER of one to eight octets cut to 32 bits
//     (int32Value)
//   - Counter32, Gauge32: uint; TimeTicks, Uinteger32: uint32; each unsigned
//     and cut to 32 bits (unsigned32)
//   - Counter64: uint64, unsigned, of one to eight octets or nine with a
//     leading zero
//   - OctetString, Opaque: []byte, aliasing content, empty included
//   - OpaqueFloat: float32; OpaqueDouble: float64 (see decodeOpaque)
//   - ObjectIdentifier: dotted string (ber.OID)
//   - IPAddress: an IPv4 address as text; quirks of devices: an empty one is
//     nil, one of 16 octets IPv6 text
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: nil, content ignored
//   - any other tag, BitString and a bare OpaqueFloat or OpaqueDouble tag
//     included (net-snmp wraps those in an Opaque): UnknownType and nil,
//     content ignored
//
// An unsigned value that is empty or too long is not an error: it decodes as
// UnknownType with a nil value, so that one bad counter does not fail the
// message, and allocates nothing. The other types' failures are errors.
func decodeValue(tag Asn1BER, content []byte) (Asn1BER, any, error) {
	switch valueRules[tag].kind {
	case kindInteger:
		v, err := int32Value(content)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid Integer: %w", err)
		}
		return Integer, int(v), nil
	case kindUnsigned32:
		v, ok := unsigned32(content)
		switch {
		case !ok:
			return UnknownType, nil, nil
		case tag == Counter32, tag == Gauge32:
			return tag, uint(v), nil
		}
		return tag, v, nil
	case kindCounter64:
		if len(content) == 0 {
			return UnknownType, nil, nil
		}
		v, err := ber.Uint64(content)
		if err != nil {
			return UnknownType, nil, nil
		}
		return Counter64, v, nil
	case kindOctets:
		if tag == Opaque {
			return decodeOpaque(content)
		}
		return OctetString, content, nil
	case kindOID:
		oid, err := ber.OID(content)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid ObjectIdentifier: %w", err)
		}
		return ObjectIdentifier, oid, nil
	case kindIPAddress:
		switch len(content) {
		case 0: // real life, buggy devices returning bad data
			return IPAddress, nil, nil
		case 4, 16:
			return IPAddress, net.IP(content).String(), nil
		default:
			return 0, nil, fmt.Errorf("got ipaddress len %d, expected 4 or 16", len(content))
		}
	case kindNull:
		return tag, nil, nil
	default:
		return UnknownType, nil, nil
	}
}

// int32Value decodes INTEGER content of one to eight octets and cuts it to 32
// bits by two's complement, the width of SNMP's Integer32 (RFC 2578 section
// 7.1.1), on every platform. net-snmp v5.9.4 cuts too, but keeps a value above
// 2^31-1 as its low 32 bits, unsigned, which a 32-bit int cannot hold.
func int32Value(content []byte) (int32, error) {
	v, err := ber.Int64(content)
	return int32(v), err //nolint:gosec // the cut
}

// unsigned32 decodes the content of an unsigned value of 32 bits (Counter32,
// Gauge32, TimeTicks, Uinteger32) as net-snmp v5.9.4 does: one to eight
// octets, or nine with a leading zero, not sign-extended, cut to the low 32
// bits. ok is false for empty or longer content.
func unsigned32(content []byte) (v uint32, ok bool) {
	if len(content) == 0 {
		return 0, false
	}
	u, err := ber.Uint64(content)
	return uint32(u), err == nil //nolint:gosec // the cut
}

// The identifier octet of the floats net-snmp wraps in an Opaque (an
// OpaqueFloat or OpaqueDouble value): AsnExtensionTag, a context-specific
// (AsnContext) tag in the high-tag-number form (AsnExtensionID), whose number,
// OpaqueFloat or OpaqueDouble, follows in the next octet.
const (
	AsnContext      = 0x80
	AsnExtensionID  = 0x1F
	AsnExtensionTag = (AsnContext | AsnExtensionID) // 0x9F
)

// decodeOpaque decodes the content of an Opaque value. net-snmp wraps floats
// and doubles in an Opaque as a TLV whose identifier is the extension octet
// 0x9f followed by the OpaqueFloat or OpaqueDouble tag: that TLV is read from
// its second identifier octet on, and octets after it are ignored. Content of
// up to two octets, empty included, is never such a TLV; anything else is a
// raw Opaque.
func decodeOpaque(content []byte) (Asn1BER, any, error) {
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

// valueKind is the rule a value type follows on the wire; the types of one
// kind share it.
type valueKind uint8

const (
	kindNone        valueKind = iota // no rule: not encoded
	kindNull                         // Null and the exceptions: no content
	kindInteger                      // Integer32 (RFC 2578 section 7.1.1)
	kindUnsigned32                   // Counter32, Gauge32, TimeTicks, Uinteger32
	kindCounter64                    // Counter64
	kindOctets                       // OctetString, Opaque
	kindOID                          // ObjectIdentifier
	kindIPAddress                    // IpAddress
	kindOpaqueFloat                  // OpaqueFloat and OpaqueDouble, wrapped in an Opaque
)

// valueRule is the rule of a value type: its kind, and whether Set takes it.
type valueRule struct {
	kind     valueKind
	settable bool
}

// valueRules holds the rule of each value tag; a tag without one has
// kindNone. BitString has none: it is not an SMIv2 type (RFC 2578 section
// 7.1.4 encodes BITS as an OCTET STRING).
var valueRules = [256]valueRule{ //nolint:gochecknoglobals // a read-only table
	Null:             {kindNull, true},
	NoSuchObject:     {kindNull, false},
	NoSuchInstance:   {kindNull, false},
	EndOfMibView:     {kindNull, false},
	Integer:          {kindInteger, true},
	Counter32:        {kindUnsigned32, true},
	Gauge32:          {kindUnsigned32, true},
	TimeTicks:        {kindUnsigned32, true},
	Uinteger32:       {kindUnsigned32, true},
	Counter64:        {kindCounter64, true},
	OctetString:      {kindOctets, true},
	Opaque:           {kindOctets, true},
	ObjectIdentifier: {kindOID, true},
	IPAddress:        {kindIPAddress, true},
	OpaqueFloat:      {kindOpaqueFloat, true},
	OpaqueDouble:     {kindOpaqueFloat, true},
}

// appendValue appends the TLV of a varbind value with the given tag, by the
// tag's rule (valueRules). The Go types it accepts per tag:
//
//   - Integer: int within the int32 range
//   - Counter32, Gauge32, TimeTicks, Uinteger32: uint32, or uint up to
//     4294967295
//   - Counter64: uint64
//   - OctetString, Opaque: []byte or string, written as is
//   - ObjectIdentifier: dotted string
//   - IPAddress: []byte of 4 or 16 octets, or an address as text: an IPv4
//     address (an IPv4-mapped one included) in 4 octets, another IPv6 address
//     in 16
//   - OpaqueFloat: float32; OpaqueDouble: float64 (see appendOpaqueFloat)
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: any, ignored
//
// Other tags, BitString included, and types are errors.
func appendValue(dst []byte, tag Asn1BER, value any) ([]byte, error) {
	switch valueRules[tag].kind {
	case kindNull:
		return append(dst, byte(tag), 0), nil
	case kindInteger:
		v, ok := value.(int)
		if !ok {
			return nil, errors.New("unable to marshal PDU Integer; not int")
		}
		out, err := appendInt32(dst, Integer, v)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal PDU Integer: %w", err)
		}
		return out, nil
	case kindUnsigned32:
		var v uint32
		switch value := value.(type) {
		case uint32:
			v = value
		case uint:
			if uint64(value) > math.MaxUint32 {
				return nil, fmt.Errorf("unable to marshal PDU %v: %d overflows uint32", tag, value)
			}
			v = uint32(value)
		default:
			return nil, fmt.Errorf("unable to marshal pdu.Type %v; unknown pdu.Value %v[type=%T]", tag, value, value)
		}
		return appendUint(dst, tag, uint64(v)), nil
	case kindCounter64:
		v, ok := value.(uint64)
		if !ok {
			return nil, fmt.Errorf("unable to marshal PDU Counter64; not uint64")
		}
		return appendUint(dst, Counter64, v), nil
	case kindOctets:
		switch value := value.(type) {
		case []byte:
			return appendOctets(dst, tag, value), nil
		case string:
			return appendOctets(dst, tag, value), nil
		default:
			return nil, fmt.Errorf("unable to marshal PDU OctetString; not []byte or string")
		}
	case kindOID:
		v, ok := value.(string)
		if !ok {
			return nil, errors.New("unable to marshal PDU ObjectIdentifier; not string")
		}
		return appendObjectIdentifier(dst, v)
	case kindIPAddress:
		return appendIPAddress(dst, value)
	case kindOpaqueFloat:
		return appendOpaqueFloat(dst, tag, value)
	default:
		return nil, fmt.Errorf("unable to marshal PDU: %v is not an SNMP value type", tag)
	}
}

// appendIPAddress appends an IpAddress value (see appendValue).
func appendIPAddress(dst []byte, value any) ([]byte, error) {
	switch value := value.(type) {
	case []byte:
		if len(value) != 4 && len(value) != 16 {
			return nil, fmt.Errorf("unable to marshal PDU IPAddress: %d octets, not 4 or 16", len(value))
		}
		return appendOctets(dst, IPAddress, value), nil
	case string:
		ip, n, err := parseIPAddress(value)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal PDU IPAddress: %w", err)
		}
		return appendOctets(dst, IPAddress, ip[:n]), nil
	default:
		return nil, fmt.Errorf("unable to marshal PDU IPAddress; not []byte or string")
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

// parseIPAddress returns the octets of an IpAddress written as text, in an
// array and a length so that the parsed address stays on the stack: four for
// an IPv4 address, an IPv4-mapped IPv6 address included, sixteen for another
// IPv6 address.
func parseIPAddress(s string) (ip [16]byte, n int, err error) {
	parsed := net.ParseIP(s)
	if parsed == nil {
		return ip, 0, fmt.Errorf("%q is not an IP address", s)
	}
	if v4 := parsed.To4(); v4 != nil {
		return ip, copy(ip[:], v4), nil
	}
	return ip, copy(ip[:], parsed), nil
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
