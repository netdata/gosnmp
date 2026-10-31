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

// A message, PDU or SNMPv1 trap header field, or a varbind name, has one rule:
// its tag, then its range once cut to 32 bits; a field that breaks it, or is
// missing, fails the message. The reads take the reader as a parameter and
// keep it nowhere, so that it stays on the caller's stack.

// Errors of a header field that is missing or of another tag than its rule's.
var (
	errNoField    = errors.New("no field left to read")
	errNotInteger = errors.New("not an INTEGER")
	errNotOctets  = errors.New("not an OCTET STRING")
	errNotOID     = errors.New("not an OBJECT IDENTIFIER")
)

// readTagged reads the next field, which must have the tag want; a field of
// another tag fails with notTag before its length is read.
func readTagged(r *ber.Reader, want Asn1BER, notTag error) ([]byte, error) {
	tag, ok := r.Peek()
	switch {
	case !ok:
		return nil, errNoField
	case Asn1BER(tag) != want:
		return nil, notTag
	}
	_, content, err := r.Next()
	return content, err
}

// readInt32 reads the next field, an INTEGER, cut to 32 bits (int32Value).
func readInt32(r *ber.Reader) (int32, error) {
	content, err := readTagged(r, Integer, errNotInteger)
	if err != nil {
		return 0, err
	}
	return int32Value(content)
}

// readOctets reads the next field, an OCTET STRING, whose content aliases the
// input.
func readOctets(r *ber.Reader) ([]byte, error) {
	return readTagged(r, OctetString, errNotOctets)
}

// readOID reads the next field, an OBJECT IDENTIFIER, by the value rule
// (ber.OID).
func readOID(r *ber.Reader) (string, error) {
	content, err := readTagged(r, ObjectIdentifier, errNotOID)
	if err != nil {
		return "", err
	}
	return ber.OID(content)
}

// readCount reads an error index or non-repeaters: an INTEGER (readInt32) that
// is not negative, saturated at 255, the most their one-octet fields hold (RFC
// 3416 allows up to 2147483647: a request of more than 255 varbinds can be
// answered with a larger error index).
func readCount(r *ber.Reader) (uint8, error) {
	v, err := readInt32(r)
	switch {
	case err != nil:
		return 0, err
	case v < 0:
		return 0, fmt.Errorf("%d is negative", v)
	case v > math.MaxUint8:
		return math.MaxUint8, nil
	}
	return uint8(v), nil
}

// readAgentAddress reads an SNMPv1 trap's agent address (RFC 1157's
// NetworkAddress) as dotted text: an IpAddress of four octets, or an OCTET
// STRING of four octets, as some agents send it; an empty IpAddress, from
// buggy agents, reads as "".
func readAgentAddress(r *ber.Reader) (string, error) {
	tag, ok := r.Peek()
	switch {
	case !ok:
		return "", errNoField
	case Asn1BER(tag) != IPAddress && Asn1BER(tag) != OctetString:
		return "", errors.New("not an IpAddress or OCTET STRING")
	}
	_, content, err := r.Next()
	switch {
	case err != nil:
		return "", err
	case len(content) == 4:
		return net.IP(content).String(), nil
	case len(content) == 0 && Asn1BER(tag) == IPAddress:
		return "", nil
	}
	return "", fmt.Errorf("%d octets, not 4", len(content))
}

// readTimestamp reads an SNMPv1 trap's time-stamp: a TimeTicks, or another
// unsigned tag of 32 bits as net-snmp v5.9.4 takes, cut to 32 bits
// (unsigned32); empty content is an error.
func readTimestamp(r *ber.Reader) (uint32, error) {
	tag, ok := r.Peek()
	switch {
	case !ok:
		return 0, errNoField
	case valueRules[tag].kind != kindUnsigned32:
		return 0, errors.New("not TimeTicks or another unsigned type")
	}
	_, content, err := r.Next()
	if err != nil {
		return 0, err
	}
	v, ok := unsigned32(content)
	if !ok {
		return 0, fmt.Errorf("%d octets, not 1 to 8 or 9 with a leading zero", len(content))
	}
	return v, nil
}

// readName reads a varbind name: an OBJECT IDENTIFIER by the value rule, or,
// as some devices send it, an OCTET STRING or an IpAddress of four octets,
// kept as text.
func readName(r *ber.Reader) (string, error) {
	tag, ok := r.Peek()
	if !ok {
		return "", errNoField
	}
	switch Asn1BER(tag) {
	case ObjectIdentifier, OctetString, IPAddress:
	default:
		return "", errors.New("not an OBJECT IDENTIFIER or text")
	}
	_, content, err := r.Next()
	switch {
	case err != nil:
		return "", err
	case Asn1BER(tag) == ObjectIdentifier:
		return ber.OID(content)
	case Asn1BER(tag) == OctetString:
		return string(content), nil
	case len(content) != 4:
		return "", fmt.Errorf("an IpAddress of %d octets, not 4", len(content))
	}
	return net.IP(content).String(), nil
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
var errEmptyPacket = fmt.Errorf("%w: cannot unmarshal empty packet", ErrInvalidPacketLength)

// readVersion reads the message SEQUENCE, which must span the whole packet,
// and its version field, an INTEGER of SNMPv1 (0), SNMPv2c (1) or SNMPv3 (3).
// It returns the version and the offset of the field after it.
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
	version, err := readInt32(&r)
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing SNMP packet version: %w", err)
	}
	if version != int32(Version1) && version != int32(Version2c) && version != int32(Version3) {
		return 0, 0, fmt.Errorf("error parsing SNMP packet version: %d is not 0, 1 or 3", version)
	}
	if r.Len() == 0 {
		return 0, 0, errors.New("error parsing SNMP packet: nothing after the version")
	}
	return SnmpVersion(version), len(packet) - r.Len(), nil //nolint:gosec // 0, 1 or 3
}

// unmarshalHeader reads the message header into response: the version and,
// for SNMPv1 and SNMPv2c, the community, or for SNMPv3 the header (parseV3),
// whose USM fields it returns for security processing, also those that
// decoded before an error. It returns the offset of the PDU, or of the scoped
// PDU. An SNMPv3 header error unwraps to ErrUnknownSecurityModels or
// ErrInvalidMsgs (v3ParseError).
func unmarshalHeader(packet []byte, response *SnmpPacket) (int, v3Wire, error) {
	version, cursor, err := readVersion(packet)
	// Known bug: a packet that is not too short to read presets the variables
	// to an empty list, also when it then fails to decode.
	if !errors.Is(err, errEmptyPacket) {
		response.Variables = make([]SnmpPDU, 0, 5)
	}
	if err != nil {
		return 0, v3Wire{}, err
	}
	response.Version = version

	if response.Version == Version3 {
		var w v3Wire
		if w, err = parseV3(packet, cursor, response); err != nil {
			return 0, w, v3ParseError(err)
		}
		return w.scoped, w, nil
	}

	r := ber.NewReader(packet[cursor:])
	community, err := readOctets(&r)
	if err != nil {
		return 0, v3Wire{}, fmt.Errorf("error parsing community string: %w", err)
	}
	response.Community = string(community)
	return len(packet) - r.Len(), v3Wire{}, nil
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

	requestType := PDUType(packet[cursor])
	if !requestType.known() {
		return fmt.Errorf("unknown PDUType %#x", byte(requestType))
	}
	response.PDUType = requestType
	if requestType == Trap {
		if err := unmarshalTrapV1(packet[cursor:], response); err != nil {
			return fmt.Errorf("error in unmarshalTrapV1: %w", err)
		}
		return nil
	}
	if err := unmarshalResponse(packet[cursor:], requestType, response); err != nil {
		return fmt.Errorf("error in unmarshalResponse: %w", err)
	}
	response.IsInform = requestType == InformRequest
	return nil
}

// readRequestID reads the request ID of the PDU at packet, which must span
// packet, of a type other than the SNMPv1 trap: an Integer32, returned as its
// two's complement, with the reader of the PDU's fields after it.
func readRequestID(packet []byte) (ber.Reader, uint32, error) {
	pdu, err := readWhole(packet)
	if err != nil {
		return ber.Reader{}, 0, fmt.Errorf("error verifying Response sanity: %w", err)
	}
	r := ber.NewReader(pdu)
	requestID, err := readInt32(&r)
	if err != nil {
		return ber.Reader{}, 0, fmt.Errorf("error parsing SNMP packet request ID: %w", err)
	}
	return r, uint32(requestID), nil //nolint:gosec // the Integer32's two's complement
}

// requestIDRead reports whether the PDU at packet[cursor:] decodes as far as
// its request ID (readRequestID), whatever fails after it.
func requestIDRead(packet []byte, cursor int) bool {
	if cursor >= len(packet) {
		return false
	}
	if t := PDUType(packet[cursor]); !t.known() || t == Trap {
		return false
	}
	_, _, err := readRequestID(packet[cursor:])
	return err == nil
}

// unmarshalResponse reads a PDU of pduType other than the SNMPv1 trap: the
// request ID, an Integer32 whose two's complement RequestID holds; the
// non-repeaters (readCount) and the max-repetitions, not negative (RFC 3416), of
// a GetBulkRequest, or the error status, 0..255, and the error index
// (readCount) of any other PDU; and the varbinds. Fields read before an error
// stay set.
func unmarshalResponse(packet []byte, pduType PDUType, response *SnmpPacket) error {
	r, requestID, err := readRequestID(packet)
	if err != nil {
		return err
	}
	response.RequestID = requestID
	if pduType == GetBulkRequest {
		if response.NonRepeaters, err = readCount(&r); err != nil {
			return fmt.Errorf("error parsing SNMP packet non repeaters: %w", err)
		}
		maxRepetitions, err := readInt32(&r)
		if err == nil && maxRepetitions < 0 {
			err = fmt.Errorf("%d is negative", maxRepetitions)
		}
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet max repetitions: %w", err)
		}
		response.MaxRepetitions = uint32(maxRepetitions) //nolint:gosec // not negative
	} else {
		errorStatus, err := readInt32(&r)
		if err == nil && (errorStatus < 0 || errorStatus > math.MaxUint8) {
			err = fmt.Errorf("%d is outside 0..255", errorStatus)
		}
		if err != nil {
			return fmt.Errorf("error parsing SNMP packet error: %w", err)
		}
		response.Error = SNMPError(errorStatus) //nolint:gosec // 0..255
		if response.ErrorIndex, err = readCount(&r); err != nil {
			return fmt.Errorf("error parsing SNMP packet error index: %w", err)
		}
	}
	return unmarshalVBL(r.Rest(), response)
}

// unmarshalTrapV1 reads an SNMPv1 trap PDU: the enterprise, an OBJECT
// IDENTIFIER; the agent address (readAgentAddress); the generic and specific
// trap, INTEGERs cut to 32 bits; the timestamp (readTimestamp); and the
// varbinds. Fields read before an error stay set.
func unmarshalTrapV1(packet []byte, response *SnmpPacket) error {
	pdu, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying Response sanity: %w", err)
	}
	r := ber.NewReader(pdu)

	if response.Enterprise, err = readOID(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap enterprise: %w", err)
	}
	if response.AgentAddress, err = readAgentAddress(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap agent address: %w", err)
	}
	generic, err := readInt32(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap generic trap: %w", err)
	}
	response.GenericTrap = int(generic)
	specific, err := readInt32(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap specific trap: %w", err)
	}
	response.SpecificTrap = int(specific)
	timestamp, err := readTimestamp(&r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap timestamp: %w", err)
	}
	response.Timestamp = uint(timestamp)
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

// readVarbind reads the next varbind: a SEQUENCE of the name (readName) and
// the value TLV, which must span the rest of it.
func readVarbind(r *ber.Reader) (SnmpPDU, error) {
	if tag, _ := r.Peek(); PDUType(tag) != Sequence {
		return SnmpPDU{}, fmt.Errorf("expected a sequence when unmarshalling a VB, got %x", tag)
	}
	_, vb, err := r.Next()
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error reading varbind: %w", err)
	}

	fields := ber.NewReader(vb)
	name, err := readName(&fields)
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error parsing OID Value: %w", err)
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
	overdeclared := tag == OctetString && length == uint64(len(value))+1
	switch {
	case overdeclared:
	case length > uint64(len(value)):
		return SnmpPDU{}, fmt.Errorf("value TLV length mismatch in varbind (TLV %d, remaining %d): %w", length, len(value), ber.ErrTruncated)
	case length < uint64(len(value)):
		return SnmpPDU{}, fmt.Errorf("value TLV length mismatch in varbind (TLV %d, remaining %d)", length, len(value))
	}
	typ, val, err := decodeValue(tag, value[header:])
	if err != nil {
		return SnmpPDU{}, fmt.Errorf("error decoding value: %w", err)
	}
	return SnmpPDU{Name: name, Type: typ, Value: val}, nil
}

// marshalMsg encodes the message: a SEQUENCE of the version, then the
// community and the PDU, or for SNMPv3 the header, the security parameters and
// the scoped PDU; an SNMPv3 message is then authenticated when its flags ask
// for it. The version, which takes one octet, must be SNMPv1, SNMPv2c or
// SNMPv3.
func (packet *SnmpPacket) marshalMsg() ([]byte, error) {
	switch packet.Version {
	case Version1, Version2c, Version3:
	default:
		return nil, fmt.Errorf("unable to marshal SNMP version %d: not 1, 2c or 3", packet.Version)
	}
	dst, start := ber.Begin(make([]byte, 0, packet.sizeHint()), byte(Sequence))
	dst = append(dst, byte(Integer), 1, byte(packet.Version))
	if packet.Version != Version3 {
		msg, err := packet.appendPDU(appendOctets(dst, OctetString, packet.Community))
		if err != nil {
			return nil, err
		}
		return ber.End(msg, start), nil
	}
	dst, auth, err := packet.appendV3(dst)
	if err != nil {
		return nil, err
	}
	dst, auth = ber.EndMoving(dst, start, auth)
	return packet.sign(dst, auth)
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

// appendPDU appends the PDU, of a type the codec knows: the request ID with
// the non-repeaters and max-repetitions (at most 2147483647, RFC 3416) of a
// GetBulkRequest or the error status and index of other PDUs, or the header of
// an SNMPv1 trap, then the varbind list. The request ID is an Integer32 (RFC
// 3416) whose two's complement RequestID holds, so IDs of 2^31 and up encode
// as negative INTEGERs on every platform.
func (packet *SnmpPacket) appendPDU(dst []byte) ([]byte, error) {
	if !packet.PDUType.known() {
		return nil, fmt.Errorf("unable to marshal PDU type %#x: not a PDU type", byte(packet.PDUType))
	}
	if packet.PDUType == GetBulkRequest && packet.MaxRepetitions > math.MaxInt32 {
		return nil, fmt.Errorf("unable to marshal max-repetitions %d: more than %d", packet.MaxRepetitions, math.MaxInt32)
	}
	dst, start := ber.Begin(dst, byte(packet.PDUType))
	requestID := int64(int32(packet.RequestID)) //nolint:gosec // the Integer32's two's complement
	switch packet.PDUType {
	case GetBulkRequest:
		dst = appendInt(dst, Integer, requestID)
		dst = appendUint(dst, Integer, uint64(packet.NonRepeaters))
		dst = appendUint(dst, Integer, uint64(packet.MaxRepetitions))
	case Trap:
		var err error
		if dst, err = packet.appendTrapV1Header(dst); err != nil {
			return nil, err
		}
	default:
		dst = appendInt(dst, Integer, requestID)
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
// enterprise, the agent address (an IPv4 address, RFC 1157's NetworkAddress),
// generic and specific trap within the int32 range, and the timestamp of at
// most 4294967295.
func (packet *SnmpPacket) appendTrapV1Header(dst []byte) ([]byte, error) {
	if uint64(packet.Timestamp) > math.MaxUint32 {
		return nil, fmt.Errorf("unable to marshal SNMPv1 Timestamp: %d overflows uint32", packet.Timestamp)
	}
	dst, err := appendObjectIdentifier(dst, packet.Enterprise)
	if err != nil {
		return nil, err
	}
	agentAddress, n, err := parseIPAddress(packet.AgentAddress)
	if err == nil && n != 4 {
		err = fmt.Errorf("%q is not an IPv4 address", packet.AgentAddress)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 AgentAddress: %w", err)
	}
	dst = appendOctets(dst, IPAddress, agentAddress[:n])
	if dst, err = appendInt32(dst, Integer, packet.GenericTrap); err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 GenericTrap: %w", err)
	}
	if dst, err = appendInt32(dst, Integer, packet.SpecificTrap); err != nil {
		return nil, fmt.Errorf("unable to marshal SNMPv1 SpecificTrap: %w", err)
	}
	return appendUint(dst, TimeTicks, uint64(packet.Timestamp)), nil
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
