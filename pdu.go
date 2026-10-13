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

// -- Header fields ------------------------------------------------------------

// fieldKind is the Go type a field decoded to.
type fieldKind uint8

const (
	fieldNone   fieldKind = iota // an IpAddress with no octets
	fieldInt                     // INTEGER
	fieldString                  // OCTET STRING, OBJECT IDENTIFIER or a 4-octet IpAddress
	fieldUint                    // TimeTicks
)

// field is a message, PDU or v1 trap header field, or a varbind name,
// decoded by its own tag. The decoders keep a field only when it decoded to
// the kind they expect, but a field that fails to decode fails the packet.
type field struct {
	kind fieldKind
	i    int
	u    uint
	s    string
}

// readField reads the next field. Only INTEGER, OCTET STRING, OBJECT
// IDENTIFIER, IpAddress and TimeTicks are fields; the tag is checked before
// the length is parsed.
func readField(r *ber.Reader) (field, error) {
	tag, ok := r.Peek()
	if !ok {
		return field{}, errors.New("no field left to read")
	}
	switch Asn1BER(tag) {
	case Integer, OctetString, ObjectIdentifier, IPAddress, TimeTicks:
	default:
		return field{}, fmt.Errorf("unknown field type: %x", tag)
	}
	_, content, err := r.Next()
	if err != nil {
		return field{}, err
	}

	switch Asn1BER(tag) {
	case Integer:
		i, err := parseInt(content)
		if err != nil {
			return field{}, fmt.Errorf("unable to parse raw INTEGER: %w", err)
		}
		return field{kind: fieldInt, i: i}, nil
	case OctetString:
		return field{kind: fieldString, s: string(content)}, nil
	case ObjectIdentifier:
		oid, err := ber.OID(content)
		if err != nil {
			return field{}, err
		}
		return field{kind: fieldString, s: oid}, nil
	case IPAddress:
		switch len(content) {
		case 0: // real life, buggy devices returning bad data
			return field{kind: fieldNone}, nil
		case 4:
			return field{kind: fieldString, s: net.IP(content).String()}, nil
		default:
			return field{}, fmt.Errorf("got ipaddress len %d, expected 4", len(content))
		}
	default: // TimeTicks
		u, err := parseUint(content)
		if err != nil {
			return field{}, fmt.Errorf("error in parseUint: %w", err)
		}
		return field{kind: fieldUint, u: u}, nil
	}
}

// fieldReader reads header fields in order: each read returns the value and
// whether the field decoded to the expected kind. The first failure is kept
// in err as "error parsing <name>: <cause>", and every read after it returns
// false without reading, so a decoder checks err once after its reads, and
// before anything that must not run after a failure. The reader is passed to
// each read rather than kept here: escape analysis tracks a struct as one
// value, so returning err would move a reader kept beside it to the heap.
type fieldReader struct {
	err error
}

// int reads the next field; ok reports whether it is an INTEGER.
func (fr *fieldReader) int(r *ber.Reader, name string) (v int, ok bool) {
	f := fr.next(r, name)
	return f.i, f.kind == fieldInt
}

// string reads the next field; ok reports whether it decoded to text.
func (fr *fieldReader) string(r *ber.Reader, name string) (v string, ok bool) {
	f := fr.next(r, name)
	return f.s, f.kind == fieldString
}

// uint reads the next field; ok reports whether it is TimeTicks.
func (fr *fieldReader) uint(r *ber.Reader, name string) (v uint, ok bool) {
	f := fr.next(r, name)
	return f.u, f.kind == fieldUint
}

// next reads the next field unless an earlier read failed; a failed or
// skipped read returns the zero field, whose kind matches no read.
func (fr *fieldReader) next(r *ber.Reader, name string) field {
	if fr.err != nil {
		return field{}
	}
	f, err := readField(r)
	if err != nil {
		fr.err = fmt.Errorf("error parsing %s: %w", name, err)
		return field{}
	}
	return f
}

// readWhole reads the TLV that b must consist of and returns its content.
func readWhole(b []byte) ([]byte, error) {
	r := ber.NewReader(b)
	_, content, err := r.Next()
	if err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("%d bytes after the TLV", r.Len())
	}
	return content, nil
}

// -- Messages and PDUs --------------------------------------------------------

// errEmptyPacket is the error of a message shorter than a TLV header.
var errEmptyPacket = errors.New("cannot unmarshal empty packet")

// readVersion reads the message SEQUENCE, which must span the whole packet,
// and its version field. It returns the version and the offset of the field
// after it. A version that is not an INTEGER reads as Version1.
func readVersion(packet []byte) (SnmpVersion, int, error) {
	if len(packet) < 2 {
		return 0, 0, errEmptyPacket
	}
	if PDUType(packet[0]) != Sequence {
		return 0, 0, errors.New("invalid packet header")
	}
	msg, err := readWhole(packet)
	if err != nil {
		return 0, 0, fmt.Errorf("error verifying packet sanity: %w", err)
	}

	r := ber.NewReader(msg)
	version, err := readField(&r)
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing SNMP packet version: %w", err)
	}
	if r.Len() == 0 {
		return 0, 0, errors.New("error parsing SNMP packet: nothing after the version")
	}
	cursor := len(packet) - r.Len()
	if version.kind != fieldInt {
		return 0, cursor, nil
	}
	return SnmpVersion(version.i), cursor, nil //nolint:gosec
}

// unmarshalHeader reads the message header: the version and, for SNMPv1 and
// SNMPv2c, the community, or for SNMPv3 the header and security parameters.
// It returns the offset of the PDU.
func (x *GoSNMP) unmarshalHeader(packet []byte, response *SnmpPacket) (int, error) {
	version, cursor, err := readVersion(packet)
	// Known bug: a packet that is not too short to read presets the variables
	// to an empty list, also when it then fails to decode.
	if !errors.Is(err, errEmptyPacket) {
		response.Variables = make([]SnmpPDU, 0, 5)
	}
	if err != nil {
		return 0, err
	}
	response.Version = version

	if response.Version == Version3 {
		cursor, err = x.unmarshalV3Header(packet, cursor, response)
		if err != nil {
			return 0, err
		}
		return cursor, nil
	}

	r := ber.NewReader(packet[cursor:])
	var fr fieldReader
	if v, ok := fr.string(&r, "community string"); ok {
		response.Community = v
	}
	if fr.err != nil {
		return 0, fr.err
	}
	return len(packet) - r.Len(), nil
}

// unmarshalPayload reads the PDU at packet[cursor:], which must span the rest
// of the packet.
func unmarshalPayload(packet []byte, cursor int, response *SnmpPacket) error {
	if len(packet) == 0 {
		return errors.New("cannot unmarshal nil or empty payload packet")
	}
	if cursor >= len(packet) {
		return fmt.Errorf("cannot unmarshal payload, packet length %d cursor %d", len(packet), cursor)
	}

	// Parse SNMP packet type
	requestType := PDUType(packet[cursor])
	switch requestType {
	// known, supported types
	case GetResponse, GetNextRequest, GetBulkRequest, Report, SNMPv2Trap, GetRequest, SetRequest, InformRequest:
		response.PDUType = requestType
		if err := unmarshalResponse(packet[cursor:], requestType, response); err != nil {
			return fmt.Errorf("error in unmarshalResponse: %w", err)
		}
		// If it's an InformRequest, mark the trap.
		response.IsInform = (requestType == InformRequest)
	case Trap:
		response.PDUType = requestType
		if err := unmarshalTrapV1(packet[cursor:], response); err != nil {
			return fmt.Errorf("error in unmarshalTrapV1: %w", err)
		}
	default:
		// Known bug: %#x formats the hexadecimal of the type's name.
		return fmt.Errorf("unknown PDUType %#x", requestType)
	}
	return nil
}

// unmarshalResponse reads a PDU of pduType other than the SNMPv1 trap: the
// request ID, the non-repeaters and max-repetitions of a GetBulkRequest or the
// error status and index of any other PDU, and the varbinds. Fields of another
// type than INTEGER are skipped; error status and index keep their low byte.
func unmarshalResponse(packet []byte, pduType PDUType, response *SnmpPacket) error {
	pdu, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying Response sanity: %w", err)
	}
	r := ber.NewReader(pdu)
	var fr fieldReader

	if v, ok := fr.int(&r, "SNMP packet request ID"); ok {
		response.RequestID = uint32(v) //nolint:gosec
	}
	if pduType == GetBulkRequest {
		if v, ok := fr.int(&r, "SNMP packet non repeaters"); ok {
			response.NonRepeaters = uint8(v) //nolint:gosec
		}
		if v, ok := fr.int(&r, "SNMP packet max repetitions"); ok {
			response.MaxRepetitions = uint32(v & math.MaxInt32)
		}
	} else {
		if v, ok := fr.int(&r, "SNMP packet error"); ok {
			response.Error = SNMPError(v) //nolint:gosec
		}
		if v, ok := fr.int(&r, "SNMP packet error index"); ok {
			response.ErrorIndex = uint8(v) //nolint:gosec
		}
	}
	if fr.err != nil {
		return fr.err
	}
	return unmarshalVBL(r.Rest(), response)
}

// unmarshalTrapV1 reads an SNMPv1 trap PDU: enterprise, agent address,
// generic and specific trap, timestamp and the varbinds. Fields of another
// type than expected are skipped; any text field fills enterprise and agent
// address.
func unmarshalTrapV1(packet []byte, response *SnmpPacket) error {
	pdu, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying Response sanity: %w", err)
	}
	r := ber.NewReader(pdu)
	var fr fieldReader

	if v, ok := fr.string(&r, "SNMPv1 trap enterprise"); ok {
		response.Enterprise = v
	}
	if v, ok := fr.string(&r, "SNMPv1 trap agent address"); ok {
		response.AgentAddress = v
	}
	if v, ok := fr.int(&r, "SNMPv1 trap generic trap"); ok {
		response.GenericTrap = v
	}
	if v, ok := fr.int(&r, "SNMPv1 trap specific trap"); ok {
		response.SpecificTrap = v
	}
	if v, ok := fr.uint(&r, "SNMPv1 trap timestamp"); ok {
		response.Timestamp = v
	}
	if fr.err != nil {
		return fr.err
	}
	return unmarshalVBL(r.Rest(), response)
}

// unmarshalVBL reads a varbind list, which must span all of packet, and
// appends its varbinds to response.Variables; on an error the ones before it
// stay appended.
func unmarshalVBL(packet []byte, response *SnmpPacket) error {
	if len(packet) == 0 {
		return errors.New("truncated packet when unmarshalling a VBL")
	}
	if PDUType(packet[0]) != Sequence {
		return fmt.Errorf("expected a sequence when unmarshalling a VBL, got %x", packet[0])
	}
	vbl, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying VBL length: %w", err)
	}

	r := ber.NewReader(vbl)
	for r.Len() > 0 {
		vb, err := readVarbind(&r)
		if err != nil {
			return err
		}
		response.Variables = append(response.Variables, vb)
	}
	return nil
}

// readVarbind reads the next varbind: a SEQUENCE of the name, any text field,
// and the value TLV, which must span the rest of it.
func readVarbind(r *ber.Reader) (SnmpPDU, error) {
	if tag, _ := r.Peek(); PDUType(tag) != Sequence {
		return SnmpPDU{}, fmt.Errorf("expected a sequence when unmarshalling a VB, got %x", tag)
	}
	_, vb, err := r.Next()
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error reading varbind: %w", err)
	}

	fields := ber.NewReader(vb)
	name, err := readField(&fields)
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error parsing OID Value: %w", err)
	}
	if name.kind != fieldString {
		return SnmpPDU{}, errors.New("varbind name is not an OBJECT IDENTIFIER or text")
	}

	value := fields.Rest()
	if len(value) == 0 {
		return SnmpPDU{}, fmt.Errorf("error decoding value: %w", ErrZeroByteBuffer)
	}
	length, header, err := ber.Length(value)
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error parsing value TLV in varbind: %w", err)
	}
	tag := Asn1BER(value[0])
	// Some MikroTik responses overdeclare OctetString lengths by one byte.
	// The enclosing varbind provides the content boundary for this case.
	overdeclared := tag == OctetString && length == len(value)+1
	if length != len(value) && !overdeclared {
		return SnmpPDU{}, fmt.Errorf("value TLV length mismatch in varbind (TLV %d, remaining %d)", length, len(value))
	}
	typ, val, err := decodeValue(tag, value[header:])
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error decoding value: %w", err)
	}
	return SnmpPDU{Name: name.s, Type: typ, Value: val}, nil
}

// marshalMsg encodes the message: a SEQUENCE of the version, then the
// community and the PDU, or for SNMPv3 the header, the security parameters and
// the scoped PDU; an SNMPv3 message is then authenticated when its flags ask
// for it. The version always takes one octet.
func (packet *SnmpPacket) marshalMsg() ([]byte, error) {
	dst, start := ber.Begin(make([]byte, 0, packet.sizeHint()), byte(Sequence))
	dst = append(dst, byte(Integer), 1, byte(packet.Version))
	var err error
	if packet.Version == Version3 {
		dst, err = packet.appendV3(dst)
	} else {
		dst, err = packet.appendPDU(appendOctets(dst, OctetString, packet.Community))
	}
	if err != nil {
		return nil, err
	}
	return packet.sign(ber.End(dst, start))
}

// sizeHint estimates the encoded size of the message so that marshalMsg
// usually allocates once: room for the headers and the security parameters,
// the text fields, and per varbind its name in dotted form (no shorter than
// its encoding), its headers and an OCTET STRING or Opaque value.
func (packet *SnmpPacket) sizeHint() int {
	n := 64 + len(packet.Community) + len(packet.ContextEngineID) + len(packet.ContextName)
	if packet.Version == Version3 {
		n += 128
	}
	for i := range packet.Variables {
		n += 16 + len(packet.Variables[i].Name)
		switch v := packet.Variables[i].Value.(type) {
		case []byte:
			n += len(v)
		case string:
			n += len(v)
		}
	}
	return n
}

// appendPDU appends the PDU: the request ID with the non-repeaters and
// max-repetitions of a GetBulkRequest or the error status and index of other
// PDUs, or the header of an SNMPv1 trap, then the varbind list. The request ID
// goes through the platform's int, so on 32-bit platforms IDs of 2^31 and up
// encode as negative INTEGERs.
func (packet *SnmpPacket) appendPDU(dst []byte) ([]byte, error) {
	dst, start := ber.Begin(dst, byte(packet.PDUType))
	switch packet.PDUType {
	case GetBulkRequest:
		dst = appendInt(dst, Integer, int64(int(packet.RequestID)))
		dst = appendUint(dst, Integer, uint64(packet.NonRepeaters))
		dst = appendUint(dst, Integer, uint64(packet.MaxRepetitions))
	case Trap:
		var err error
		if dst, err = packet.appendTrapV1Header(dst); err != nil {
			return nil, err
		}
	default:
		dst = appendInt(dst, Integer, int64(int(packet.RequestID)))
		dst = appendUint(dst, Integer, uint64(packet.Error))
		dst = appendUint(dst, Integer, uint64(packet.ErrorIndex))
	}
	dst, err := packet.appendVBL(dst)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal varbind list: %w", err)
	}
	return ber.End(dst, start), nil
}

// appendTrapV1Header appends the SNMPv1 trap fields before the varbind list:
// enterprise, agent address (see marshalIPAddress), generic and specific trap
// within the int32 range, and the timestamp truncated to 32 bits.
func (packet *SnmpPacket) appendTrapV1Header(dst []byte) ([]byte, error) {
	dst, err := appendObjectIdentifier(dst, packet.Enterprise)
	if err != nil {
		return nil, err
	}
	agentAddress, err := marshalIPAddress(packet.AgentAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 AgentAddress: %w", err)
	}
	dst = appendOctets(dst, IPAddress, agentAddress[:])
	if dst, err = appendInt32(dst, Integer, packet.GenericTrap); err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 GenericTrap: %w", err)
	}
	if dst, err = appendInt32(dst, Integer, packet.SpecificTrap); err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 SpecificTrap: %w", err)
	}
	return appendUint(dst, TimeTicks, uint64(uint32(packet.Timestamp))), nil //nolint:gosec
}

// appendVBL appends the varbind list: a SEQUENCE of varbinds, each a SEQUENCE
// of the name's OBJECT IDENTIFIER and the value (see appendValue).
func (packet *SnmpPacket) appendVBL(dst []byte) ([]byte, error) {
	dst, start := ber.Begin(dst, byte(Sequence))
	for i := range packet.Variables {
		var err error
		if dst, err = appendVarbind(dst, &packet.Variables[i]); err != nil {
			return nil, err
		}
	}
	return ber.End(dst, start), nil
}

// appendVarbind appends one varbind.
func appendVarbind(dst []byte, pdu *SnmpPDU) ([]byte, error) {
	dst, start := ber.Begin(dst, byte(Sequence))
	dst, err := appendObjectIdentifier(dst, pdu.Name)
	if err != nil {
		return nil, err
	}
	if dst, err = appendValue(dst, pdu.Type, pdu.Value); err != nil {
		return nil, err
	}
	return ber.End(dst, start), nil
}
