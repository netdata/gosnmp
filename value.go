// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"math"
	"net/netip"

	"github.com/netdata/gosnmp/internal/ber"
)

// Value is a varbind's value: its type and the number, octets or OID it
// holds. Each type holds one Go type, read through its accessor:
//
//   - Integer: int32 (Int32)
//   - Counter32, Gauge32, TimeTicks, Uinteger32: uint32 (Uint32)
//   - Counter64: uint64 (Uint64)
//   - OctetString, Opaque: []byte (Bytes)
//   - ObjectIdentifier: a dotted string (OID)
//   - IPAddress: a netip.Addr (IP), the zero Addr for the empty one some
//     devices send
//   - OpaqueFloat: float32 (Float32); OpaqueDouble: float64 (Float64)
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView, UnknownType: none
//
// Int64, Uint64 and Float64 also read the narrower types they hold exactly.
// The zero Value is UnknownType, a value of a type the decoder does not decode,
// which the encoder refuses. Values are built by the constructor of their type,
// such as Counter32Value; octets, and the octets of an address, are held as
// given, not copied.
type Value struct {
	num  uint64 // Integer's two's complement, an unsigned value or a float's bits
	data []byte // OctetString and Opaque octets; IPAddress's 0, 4 or 16 octets
	oid  string // ObjectIdentifier
	typ  ValueType
}

// IntegerValue returns an Integer.
func IntegerValue(v int32) Value {
	return Value{typ: Integer, num: uint64(int64(v))} //nolint:gosec // the two's complement
}

// Counter32Value returns a Counter32.
func Counter32Value(v uint32) Value { return Value{typ: Counter32, num: uint64(v)} }

// Gauge32Value returns a Gauge32.
func Gauge32Value(v uint32) Value { return Value{typ: Gauge32, num: uint64(v)} }

// TimeTicksValue returns a TimeTicks, in hundredths of a second.
func TimeTicksValue(v uint32) Value { return Value{typ: TimeTicks, num: uint64(v)} }

// Uinteger32Value returns a Uinteger32.
func Uinteger32Value(v uint32) Value { return Value{typ: Uinteger32, num: uint64(v)} }

// Counter64Value returns a Counter64.
func Counter64Value(v uint64) Value { return Value{typ: Counter64, num: v} }

// OctetStringValue returns an OctetString holding v.
func OctetStringValue(v []byte) Value { return Value{typ: OctetString, data: v} }

// OpaqueValue returns an Opaque holding v.
func OpaqueValue(v []byte) Value { return Value{typ: Opaque, data: v} }

// OpaqueFloatValue returns net-snmp's OpaqueFloat, sent wrapped in an Opaque.
func OpaqueFloatValue(v float32) Value {
	return Value{typ: OpaqueFloat, num: uint64(math.Float32bits(v))}
}

// OpaqueDoubleValue returns net-snmp's OpaqueDouble, sent wrapped in an Opaque.
func OpaqueDoubleValue(v float64) Value {
	return Value{typ: OpaqueDouble, num: math.Float64bits(v)}
}

// ObjectIdentifierValue returns an ObjectIdentifier: oid in dotted form, with
// or without the leading dot; the encoder checks it.
func ObjectIdentifierValue(oid string) Value { return Value{typ: ObjectIdentifier, oid: oid} }

// IPAddressValue returns an IPAddress: an IPv4 address, an IPv4-mapped one
// included, in 4 octets, another IPv6 address in 16, without its zone; the
// zero Addr is the empty IPAddress, which the encoder refuses.
func IPAddressValue(a netip.Addr) Value {
	return Value{typ: IPAddress, data: a.Unmap().AsSlice()}
}

// NullValue returns a Null, the value a request sends.
func NullValue() Value { return Value{typ: Null} }

// NoSuchObjectValue returns the noSuchObject exception (RFC 3416 section 4.2.1).
func NoSuchObjectValue() Value { return Value{typ: NoSuchObject} }

// NoSuchInstanceValue returns the noSuchInstance exception (RFC 3416 section
// 4.2.1).
func NoSuchInstanceValue() Value { return Value{typ: NoSuchInstance} }

// EndOfMibViewValue returns the endOfMibView exception (RFC 3416 section
// 4.2.2).
func EndOfMibViewValue() Value { return Value{typ: EndOfMibView} }

// Type returns the value's type.
func (v Value) Type() ValueType { return v.typ }

// Int32 returns an Integer.
func (v Value) Int32() (int32, bool) {
	if v.typ != Integer {
		return 0, false
	}
	return int32(v.num), true //nolint:gosec // the two's complement IntegerValue stored
}

// Uint32 returns a Counter32, Gauge32, TimeTicks or Uinteger32.
func (v Value) Uint32() (uint32, bool) {
	if valueKinds[v.typ] != kindUnsigned32 {
		return 0, false
	}
	return uint32(v.num), true //nolint:gosec // stored from a uint32
}

// Int64 returns an Integer, Counter32, Gauge32, TimeTicks or Uinteger32: every
// integer type but Counter64, whose values int64 cannot all hold.
func (v Value) Int64() (int64, bool) {
	switch valueKinds[v.typ] {
	case kindInteger:
		return int64(v.num), true //nolint:gosec // the two's complement IntegerValue stored
	case kindUnsigned32:
		return int64(v.num), true //nolint:gosec // below 2^32
	}
	return 0, false
}

// Uint64 returns a Counter64, Counter32, Gauge32, TimeTicks or Uinteger32:
// every unsigned type.
func (v Value) Uint64() (uint64, bool) {
	switch valueKinds[v.typ] {
	case kindUnsigned32, kindCounter64:
		return v.num, true
	}
	return 0, false
}

// Bytes returns an OctetString's or Opaque's octets, as built or decoded (see
// the package documentation for those that alias a decoded message).
func (v Value) Bytes() ([]byte, bool) {
	if valueKinds[v.typ] != kindOctets {
		return nil, false
	}
	return v.data, true
}

// OID returns an ObjectIdentifier in dotted form: a decoded one with a leading
// dot.
func (v Value) OID() (string, bool) {
	if v.typ != ObjectIdentifier {
		return "", false
	}
	return v.oid, true
}

// IP returns an IPAddress: the zero Addr for an empty one, an IPv6 address for
// 16 octets, as a device sent them.
func (v Value) IP() (netip.Addr, bool) {
	if v.typ != IPAddress {
		return netip.Addr{}, false
	}
	a, _ := netip.AddrFromSlice(v.data)
	return a, true
}

// Float32 returns an OpaqueFloat.
func (v Value) Float32() (float32, bool) {
	if v.typ != OpaqueFloat {
		return 0, false
	}
	return math.Float32frombits(uint32(v.num)), true //nolint:gosec // stored from 32 bits
}

// Float64 returns an OpaqueDouble or OpaqueFloat.
func (v Value) Float64() (float64, bool) {
	switch v.typ {
	case OpaqueDouble:
		return math.Float64frombits(v.num), true
	case OpaqueFloat:
		return float64(math.Float32frombits(uint32(v.num))), true //nolint:gosec // stored from 32 bits
	}
	return 0, false
}

// decodeValue decodes the content octets of a varbind value with the given tag
// by the tag's kind (valueKinds):
//
//   - Integer: an INTEGER of one to eight octets cut to 32 bits (int32Value)
//   - Counter32, Gauge32, TimeTicks, Uinteger32: unsigned, cut to 32 bits
//     (unsigned32)
//   - Counter64: unsigned, of one to eight octets or nine with a leading zero
//   - OctetString, Opaque: the content, aliased, empty included
//   - OpaqueFloat, OpaqueDouble: wrapped in an Opaque (see decodeOpaque)
//   - ObjectIdentifier: dotted with a leading dot (ber.OID)
//   - IPAddress: 4 octets, or the quirks of devices: none, or 16 (IPv6),
//     aliased
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: content ignored
//   - any other tag, and a bare OpaqueFloat or OpaqueDouble tag (net-snmp
//     wraps those in an Opaque): UnknownType, content ignored
//
// An unsigned value that is empty or too long is not an error: it decodes as
// UnknownType, so that one bad counter does not fail the message. The other
// types' failures are errors.
func decodeValue(tag ValueType, content []byte) (Value, error) {
	switch valueKinds[tag] {
	case kindInteger:
		v, err := int32Value(content)
		if err != nil {
			return Value{}, fmt.Errorf("invalid Integer: %w", err)
		}
		return IntegerValue(v), nil
	case kindUnsigned32:
		v, ok := unsigned32(content)
		if !ok {
			return Value{}, nil
		}
		return Value{typ: tag, num: uint64(v)}, nil
	case kindCounter64:
		if len(content) == 0 {
			return Value{}, nil
		}
		if v, err := ber.Uint64(content); err == nil {
			return Counter64Value(v), nil
		}
		return Value{}, nil
	case kindOctets:
		if tag == Opaque {
			return decodeOpaque(content)
		}
		return OctetStringValue(content), nil
	case kindOID:
		oid, err := ber.OID(content)
		if err != nil {
			return Value{}, fmt.Errorf("invalid ObjectIdentifier: %w", err)
		}
		return ObjectIdentifierValue(oid), nil
	case kindIPAddress:
		switch len(content) {
		case 0: // real life, devices returning bad data: the zero Addr
			return Value{typ: IPAddress}, nil
		case 4, 16: // 16 octets: devices returning IPv6
			return Value{typ: IPAddress, data: content}, nil
		default:
			return Value{}, fmt.Errorf("got ipaddress len %d, expected 4 or 16", len(content))
		}
	case kindNull:
		return Value{typ: tag}, nil
	default:
		return Value{}, nil
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

// opaqueExtensionTag is the identifier octet of the floats net-snmp wraps in
// an Opaque (an OpaqueFloat or OpaqueDouble value; net-snmp's ASN_OPAQUE_TAG1):
// a context-specific tag (0x80) in the high-tag-number form (0x1f), whose
// number, OpaqueFloat or OpaqueDouble, follows in the next octet.
const opaqueExtensionTag = 0x80 | 0x1f

// decodeOpaque decodes the content of an Opaque value. net-snmp wraps floats
// and doubles in an Opaque as a TLV whose identifier is the extension octet
// 0x9f followed by the OpaqueFloat or OpaqueDouble tag: that TLV is read from
// its second identifier octet on, and octets after it are ignored. Content of
// up to two octets, empty included, is never such a TLV; anything else is a
// raw Opaque.
func decodeOpaque(content []byte) (Value, error) {
	if len(content) <= 2 || content[0] != opaqueExtensionTag {
		return OpaqueValue(content), nil
	}
	tag := ValueType(content[1])
	if tag != OpaqueFloat && tag != OpaqueDouble {
		return OpaqueValue(content), nil
	}

	r := ber.NewReader(content[1:])
	_, inner, err := r.Next()
	if err != nil {
		return Value{}, fmt.Errorf("invalid %v: %w", tag, err)
	}
	var v Value
	if tag == OpaqueFloat {
		var f float32
		if f, err = ber.Float32(inner); err == nil {
			v = OpaqueFloatValue(f)
		}
	} else {
		var f float64
		if f, err = ber.Float64(inner); err == nil {
			v = OpaqueDoubleValue(f)
		}
	}
	if err != nil {
		return Value{}, fmt.Errorf("invalid %v: %w", tag, err)
	}
	return v, nil
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

// valueKinds holds the kind of each value tag; a tag without one, UnknownType
// and the ASN.1 types SMIv2 does not use included, has kindNone: BIT STRING,
// for one, is not an SMIv2 type (RFC 2578 section 7.1.4 encodes BITS as an
// OCTET STRING).
var valueKinds = [256]valueKind{ //nolint:gochecknoglobals // a read-only table
	Null:             kindNull,
	NoSuchObject:     kindNull,
	NoSuchInstance:   kindNull,
	EndOfMibView:     kindNull,
	Integer:          kindInteger,
	Counter32:        kindUnsigned32,
	Gauge32:          kindUnsigned32,
	TimeTicks:        kindUnsigned32,
	Uinteger32:       kindUnsigned32,
	Counter64:        kindCounter64,
	OctetString:      kindOctets,
	Opaque:           kindOctets,
	ObjectIdentifier: kindOID,
	IPAddress:        kindIPAddress,
	OpaqueFloat:      kindOpaqueFloat,
	OpaqueDouble:     kindOpaqueFloat,
}

// appendValue appends the TLV of a varbind value by its type's kind
// (valueKinds); its constructors make a value of each type hold its Go type.
// An IPAddress must have 4 or 16 octets, an ObjectIdentifier must encode
// (ber.AppendOID); UnknownType is an error.
func appendValue(dst []byte, v Value) ([]byte, error) {
	switch valueKinds[v.typ] {
	case kindNull:
		return append(dst, byte(v.typ), 0), nil
	case kindInteger:
		return appendInt(dst, int64(v.num)), nil //nolint:gosec // the two's complement IntegerValue stored
	case kindUnsigned32, kindCounter64:
		return appendUint(dst, v.typ, v.num), nil
	case kindOctets:
		return appendOctets(dst, v.typ, v.data), nil
	case kindOID:
		return appendObjectIdentifier(dst, v.oid)
	case kindIPAddress:
		if len(v.data) != 4 && len(v.data) != 16 {
			return nil, fmt.Errorf("unable to marshal PDU IPAddress: %d octets, not 4 or 16", len(v.data))
		}
		return appendOctets(dst, IPAddress, v.data), nil
	case kindOpaqueFloat:
		return appendOpaqueFloat(dst, v), nil
	default:
		return nil, fmt.Errorf("unable to marshal PDU: %v is not an SNMP value type", v.typ)
	}
}

// appendOctets appends a TLV whose content is v as is.
func appendOctets[T string | []byte](dst []byte, tag ValueType, v T) []byte {
	return append(ber.AppendHeader(dst, byte(tag), len(v)), v...)
}

// appendInt appends a TLV holding v as an INTEGER.
func appendInt(dst []byte, v int64) []byte {
	dst, start := ber.Begin(dst, byte(Integer))
	return ber.End(ber.AppendInt64(dst, v), start)
}

// appendUint appends a TLV holding the unsigned v as a non-negative INTEGER.
func appendUint(dst []byte, tag ValueType, v uint64) []byte {
	dst, start := ber.Begin(dst, byte(tag))
	return ber.End(ber.AppendUint64(dst, v), start)
}

// appendOpaqueFloat appends a float or double the way net-snmp wraps it in an
// Opaque: an Opaque TLV holding a TLV whose identifier is the extension octet
// 0x9f followed by the OpaqueFloat or OpaqueDouble tag (see decodeOpaque).
func appendOpaqueFloat(dst []byte, v Value) []byte {
	dst, start := ber.Begin(dst, byte(Opaque))
	dst = append(dst, opaqueExtensionTag)
	if v.typ == OpaqueFloat {
		return ber.End(ber.AppendFloat32(ber.AppendHeader(dst, byte(OpaqueFloat), 4), math.Float32frombits(uint32(v.num))), start) //nolint:gosec // stored from 32 bits
	}
	return ber.End(ber.AppendFloat64(ber.AppendHeader(dst, byte(OpaqueDouble), 8), math.Float64frombits(v.num)), start)
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
