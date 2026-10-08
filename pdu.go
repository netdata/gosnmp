// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
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

// readInt reads the next field; ok reports whether it is an INTEGER.
func readInt(r *ber.Reader) (v int, ok bool, err error) {
	f, err := readField(r)
	return f.i, f.kind == fieldInt, err
}

// readString reads the next field; ok reports whether it decoded to text.
func readString(r *ber.Reader) (v string, ok bool, err error) {
	f, err := readField(r)
	return f.s, f.kind == fieldString, err
}

// readUint reads the next field; ok reports whether it is TimeTicks.
func readUint(r *ber.Reader) (v uint, ok bool, err error) {
	f, err := readField(r)
	return f.u, f.kind == fieldUint, err
}

// parseRawField reads the field at the start of data for the SNMPv3 header
// and USM decoders. It returns the field as the Go type it decoded to (nil
// for an empty IpAddress) and the length of its encoding.
func parseRawField(data []byte) (any, int, error) {
	r := ber.NewReader(data)
	f, err := readField(&r)
	if err != nil {
		return nil, 0, err
	}
	n := len(data) - r.Len()
	switch f.kind {
	case fieldInt:
		return f.i, n, nil
	case fieldString:
		return f.s, n, nil
	case fieldUint:
		return f.u, n, nil
	default:
		return nil, n, nil
	}
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

// unmarshalVersionFromHeader reads the message SEQUENCE, which must span the
// whole packet, and its version field. It returns the version and the offset
// of the field after it. A version that is not an INTEGER reads as Version1.
func unmarshalVersionFromHeader(packet []byte, response *SnmpPacket) (SnmpVersion, int, error) {
	if len(packet) < 2 {
		return 0, 0, errors.New("cannot unmarshal empty packet")
	}
	if response == nil {
		return 0, 0, errors.New("cannot unmarshal response into nil packet reference")
	}

	response.Variables = make([]SnmpPDU, 0, 5)

	if PDUType(packet[0]) != Sequence {
		return 0, 0, errors.New("invalid packet header")
	}
	msg, err := readWhole(packet)
	if err != nil {
		return 0, 0, fmt.Errorf("error verifying packet sanity: %w", err)
	}

	r := ber.NewReader(msg)
	version, ok, err := readInt(&r)
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing SNMP packet version: %w", err)
	}
	if r.Len() == 0 {
		return 0, 0, errors.New("error parsing SNMP packet: nothing after the version")
	}
	cursor := len(packet) - r.Len()
	if !ok {
		return 0, cursor, nil
	}
	return SnmpVersion(version), cursor, nil //nolint:gosec
}

// unmarshalHeader reads the message header: the version and, for SNMPv1 and
// SNMPv2c, the community, or for SNMPv3 the header and security parameters.
// It returns the offset of the PDU.
func (x *GoSNMP) unmarshalHeader(packet []byte, response *SnmpPacket) (int, error) {
	version, cursor, err := unmarshalVersionFromHeader(packet, response)
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
	community, ok, err := readString(&r)
	if err != nil {
		return 0, fmt.Errorf("error parsing community string: %w", err)
	}
	if ok {
		response.Community = community
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
	if response == nil {
		return errors.New("cannot unmarshal payload response into nil packet reference")
	}

	// Parse SNMP packet type
	requestType := PDUType(packet[cursor])
	switch requestType {
	// known, supported types
	case GetResponse, GetNextRequest, GetBulkRequest, Report, SNMPv2Trap, GetRequest, SetRequest, InformRequest:
		response.PDUType = requestType
		if err := unmarshalResponse(packet[cursor:], response); err != nil {
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
		return fmt.Errorf("unknown PDUType %#x", requestType)
	}
	return nil
}

// unmarshalResponse reads a PDU other than the SNMPv1 trap: the request ID,
// the non-repeaters and max-repetitions of a GetBulkRequest or the error
// status and index of any other PDU, and the varbinds. Fields of another type
// than INTEGER are skipped; error status and index keep their low byte.
func unmarshalResponse(packet []byte, response *SnmpPacket) error {
	pdu, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying Response sanity: %w", err)
	}
	r := ber.NewReader(pdu)

	requestID, ok, err := readInt(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet request ID: %w", err)
	}
	if ok {
		response.RequestID = uint32(requestID) //nolint:gosec
	}

	if response.PDUType == GetBulkRequest {
		nonRepeaters, ok, err := readInt(&r)
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet non repeaters: %w", err)
		}
		if ok {
			response.NonRepeaters = uint8(nonRepeaters) //nolint:gosec
		}

		maxRepetitions, ok, err := readInt(&r)
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet max repetitions: %w", err)
		}
		if ok {
			response.MaxRepetitions = uint32(maxRepetitions & 0x7FFFFFFF)
		}
	} else {
		errorStatus, ok, err := readInt(&r)
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet error: %w", err)
		}
		if ok {
			response.Error = SNMPError(errorStatus) //nolint:gosec
		}

		errorIndex, ok, err := readInt(&r)
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet error index: %w", err)
		}
		if ok {
			response.ErrorIndex = uint8(errorIndex) //nolint:gosec
		}
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

	enterprise, ok, err := readString(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap enterprise: %w", err)
	}
	if ok {
		response.Enterprise = enterprise
	}

	agentAddress, ok, err := readString(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap agent address: %w", err)
	}
	if ok {
		response.AgentAddress = agentAddress
	}

	genericTrap, ok, err := readInt(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap generic trap: %w", err)
	}
	if ok {
		response.GenericTrap = genericTrap
	}

	specificTrap, ok, err := readInt(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap specific trap: %w", err)
	}
	if ok {
		response.SpecificTrap = specificTrap
	}

	timestamp, ok, err := readUint(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap timestamp: %w", err)
	}
	if ok {
		response.Timestamp = timestamp
	}

	return unmarshalVBL(r.Rest(), response)
}

// unmarshalVBL reads a varbind list, which must span all of packet. A varbind
// name may be any text field.
func unmarshalVBL(packet []byte, response *SnmpPacket) error {
	r := ber.NewReader(packet)
	tag, ok := r.Peek()
	if !ok {
		return errors.New("truncated packet when unmarshalling a VBL")
	}
	if PDUType(tag) != Sequence {
		return fmt.Errorf("expected a sequence when unmarshalling a VBL, got %x", tag)
	}
	vbl, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying VBL length: %w", err)
	}

	vbs := ber.NewReader(vbl)
	for vbs.Len() > 0 {
		if tag, _ := vbs.Peek(); PDUType(tag) != Sequence {
			return fmt.Errorf("expected a sequence when unmarshalling a VB, got %x", tag)
		}
		_, vb, err := vbs.Next()
		if err != nil {
			return fmt.Errorf("error reading varbind: %w", err)
		}

		r := ber.NewReader(vb)
		name, ok, err := readString(&r)
		if err != nil {
			return fmt.Errorf("error parsing OID Value: %w", err)
		}
		if !ok {
			return errors.New("varbind name is not an OBJECT IDENTIFIER or text")
		}

		value := r.Rest()
		valueLength, valueCursor, err := ber.Length(value)
		if err != nil {
			return fmt.Errorf("error parsing value TLV in varbind: %w", err)
		}

		var decodedVal variable
		switch {
		case valueLength == len(value):
			if err = decodeValue(value, &decodedVal); err != nil {
				return fmt.Errorf("error decoding value: %w", err)
			}
		case len(value) > 0 &&
			valueLength == len(value)+1 &&
			Asn1BER(value[0]) == OctetString:
			// Some MikroTik responses overdeclare OctetString lengths by one byte.
			// The enclosing varbind provides the content boundary for this case.
			decodedVal = variable{Type: OctetString, Value: value[valueCursor:]}
		default:
			return fmt.Errorf("value TLV length mismatch in varbind (TLV %d, remaining %d)", valueLength, len(value))
		}

		response.Variables = append(response.Variables, SnmpPDU{Name: name, Type: decodedVal.Type, Value: decodedVal.Value})
	}
	return nil
}
