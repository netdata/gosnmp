// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"

	"github.com/netdata/gosnmp/internal/ber"
)

// -- Header fields ------------------------------------------------------------

// A message, PDU or SNMPv1 trap header field, or a varbind name, has one rule:
// its tag, then its range; a field that breaks it, or is missing, fails the
// message. An INTEGER field is read whole, up to 64 bits, and never cut to 32
// bits (readInteger), so a value outside its range fails even when its low 32
// bits lie in it; net-snmp v5.9.4 cuts it first. The reads take the reader as
// a parameter and keep it nowhere, so that it stays on the caller's stack.

// Errors of a header field that is missing or of another tag than its rule's.
var (
	errNoField    = errors.New("no field left to read")
	errNotInteger = errors.New("not an INTEGER")
	errNotOctets  = errors.New("not an OCTET STRING")
	errNotOID     = errors.New("not an OBJECT IDENTIFIER")
)

// readTagged reads the next field, which must have the tag want; a field of
// another tag fails with notTag before its length is read.
func readTagged(r *ber.Reader, want ValueType, notTag error) ([]byte, error) {
	tag, ok := r.Peek()
	switch {
	case !ok:
		return nil, errNoField
	case ValueType(tag) != want:
		return nil, notTag
	}
	_, content, err := r.Next()
	return content, err
}

// readInteger reads the next field, an INTEGER of one to eight octets, whole,
// and returns it when it lies in lo..hi, without a cut: the one reader of the
// INTEGER header fields.
func readInteger(r *ber.Reader, lo, hi int64) (int64, error) {
	content, err := readTagged(r, Integer, errNotInteger)
	if err != nil {
		return 0, err
	}
	v, err := ber.Int64(content)
	switch {
	case err != nil:
		return 0, err
	case v < lo || v > hi:
		return 0, fmt.Errorf("%d is outside %d..%d", v, lo, hi)
	}
	return v, nil
}

// readInteger32 reads the next field, an Integer32 (readInteger).
func readInteger32(r *ber.Reader) (int32, error) {
	v, err := readInteger(r, math.MinInt32, math.MaxInt32)
	return int32(v), err //nolint:gosec // -2147483648..2147483647
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

// readCount reads an error index or non-repeaters: an INTEGER of 0..2147483647
// (RFC 3416's max-bindings), saturated at 255, the most their one-octet fields
// hold (a request of more than 255 varbinds can be answered with a larger
// error index).
func readCount(r *ber.Reader) (uint8, error) {
	v, err := readInteger(r, 0, math.MaxInt32)
	if err != nil {
		return 0, err
	}
	return uint8(min(v, math.MaxUint8)), nil //nolint:gosec // 0..255
}

// readAgentAddress reads an SNMPv1 trap's agent address (RFC 1157's
// NetworkAddress): an IpAddress of four octets, or an OCTET STRING of four
// octets, as some agents send it; an empty IpAddress, from buggy agents, reads
// as the zero Addr.
func readAgentAddress(r *ber.Reader) (netip.Addr, error) {
	tag, ok := r.Peek()
	switch {
	case !ok:
		return netip.Addr{}, errNoField
	case ValueType(tag) != IPAddress && ValueType(tag) != OctetString:
		return netip.Addr{}, errors.New("not an IpAddress or OCTET STRING")
	}
	_, content, err := r.Next()
	switch {
	case err != nil:
		return netip.Addr{}, err
	case len(content) == 4:
		return netip.AddrFrom4([4]byte(content)), nil
	case len(content) == 0 && ValueType(tag) == IPAddress:
		return netip.Addr{}, nil
	}
	return netip.Addr{}, fmt.Errorf("%d octets, not 4", len(content))
}

// readTimestamp reads an SNMPv1 trap's time-stamp: a TimeTicks, or another
// unsigned tag of 32 bits as net-snmp v5.9.4 takes, cut to 32 bits
// (unsigned32); empty content is an error.
func readTimestamp(r *ber.Reader) (uint32, error) {
	tag, ok := r.Peek()
	switch {
	case !ok:
		return 0, errNoField
	case valueKinds[tag] != kindUnsigned32:
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
	switch ValueType(tag) {
	case ObjectIdentifier, OctetString, IPAddress:
	default:
		return "", errors.New("not an OBJECT IDENTIFIER or text")
	}
	_, content, err := r.Next()
	switch {
	case err != nil:
		return "", err
	case ValueType(tag) == ObjectIdentifier:
		return ber.OID(content)
	case ValueType(tag) == OctetString:
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
var errEmptyPacket = fmt.Errorf("%w: cannot unmarshal empty packet", ber.ErrInvalidPacketLength)

// readVersion reads the message SEQUENCE, which must span the whole packet,
// and its version field, an INTEGER of SNMPv1 (0), SNMPv2c (1) or SNMPv3 (3).
// It returns the version and the offset of the field after it. Another
// version is ErrBadVersion (RFC 3412 section 4.2.1: the version is known once
// the SEQUENCE's declared extent and the version field parse, octets after the
// message or not), a message that does not parse ErrASNParse.
func readVersion(packet []byte) (Version, int, error) {
	r, version, after, err := readVersionField(packet)
	switch {
	case err != nil:
		return 0, 0, inCategory(ErrASNParse, err)
	case version != int64(Version1) && version != int64(Version2c) && version != int64(Version3):
		return 0, 0, inCategory(ErrBadVersion, fmt.Errorf("error parsing SNMP packet version: %d is not 0, 1 or 3", version))
	case after != 0:
		return 0, 0, inCategory(ErrASNParse, fmt.Errorf("error verifying packet sanity: %d bytes after the TLV", after))
	case r.Len() == 0:
		return 0, 0, inCategory(ErrASNParse, errors.New("error parsing SNMP packet: nothing after the version"))
	}
	return Version(version), len(packet) - r.Len(), nil //nolint:gosec // 0, 1 or 3
}

// readVersionField reads the message SEQUENCE, whose declared length must fit
// the packet, and its first field, an INTEGER of any value (readInteger); it
// returns the reader of the fields after it and the number of octets after the
// SEQUENCE.
func readVersionField(packet []byte) (ber.Reader, int64, int, error) {
	if len(packet) < 2 {
		return ber.Reader{}, 0, 0, errEmptyPacket
	}
	if packet[0] != ber.Sequence {
		return ber.Reader{}, 0, 0, errors.New("invalid packet header")
	}
	whole := ber.NewReader(packet)
	_, msg, err := whole.Next()
	if err != nil {
		return ber.Reader{}, 0, 0, fmt.Errorf("error verifying packet sanity: %w", err)
	}

	r := ber.NewReader(msg)
	version, err := readInteger(&r, math.MinInt64, math.MaxInt64)
	if err != nil {
		return ber.Reader{}, 0, 0, fmt.Errorf("error parsing SNMP packet version: %w", err)
	}
	return r, version, whole.Len(), nil
}

// unmarshalHeader reads the message header into m: the version and,
// for SNMPv1 and SNMPv2c, the community, or for SNMPv3 the header (parseV3),
// whose USM fields it returns for security processing, also those that
// decoded before an error. It returns the offset of the PDU, or of the scoped
// PDU. Its errors have their categories: the version's (readVersion), an
// SNMPv3 header's (v3ParseError), ErrASNParse for the community.
func unmarshalHeader(packet []byte, m *Message) (int, v3Wire, error) {
	version, cursor, err := readVersion(packet)
	if err != nil {
		return 0, v3Wire{}, err
	}
	m.Version = version

	if m.Version == Version3 {
		var w v3Wire
		if w, err = parseV3(packet, cursor, m); err != nil {
			return 0, w, v3ParseError(err)
		}
		return w.scoped, w, nil
	}

	r := ber.NewReader(packet[cursor:])
	community, err := readOctets(&r)
	if err != nil {
		return 0, v3Wire{}, inCategory(ErrASNParse, fmt.Errorf("error parsing community string: %w", err))
	}
	m.Community = string(community)
	return len(packet) - r.Len(), v3Wire{}, nil
}

// unmarshalPayload reads the PDU at packet[cursor:], which must span the rest
// of the packet (readPayload); its errors are ErrASNParse (RFC 3412 section
// 7.2 step 7, an unknown PDU type included, as net-snmp v5.9.4 treats it).
func unmarshalPayload(packet []byte, cursor int, m *Message) error {
	if err := readPayload(packet, cursor, m); err != nil {
		return inCategory(ErrASNParse, err)
	}
	return nil
}

// readPayload reads the PDU at packet[cursor:], which must span the rest of
// the packet.
func readPayload(packet []byte, cursor int, m *Message) error {
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
	m.PDUType = requestType
	if requestType == Trap {
		if err := unmarshalTrapV1(packet[cursor:], m); err != nil {
			return fmt.Errorf("error in the SNMPv1 trap PDU: %w", err)
		}
		return nil
	}
	if err := unmarshalPDU(packet[cursor:], requestType, m); err != nil {
		return fmt.Errorf("error in the PDU: %w", err)
	}
	return nil
}

// readRequestID reads the request ID of the PDU at packet, which must span
// packet, of a type other than the SNMPv1 trap: an Integer32, returned as its
// two's complement, or the same 32 bits sent unsigned (2^31..2^32-1, which
// net-snmp v5.9.4 keeps too), with the reader of the PDU's fields after it.
func readRequestID(packet []byte) (ber.Reader, uint32, error) {
	pdu, err := readWhole(packet)
	if err != nil {
		return ber.Reader{}, 0, fmt.Errorf("error verifying the PDU's length: %w", err)
	}
	r := ber.NewReader(pdu)
	requestID, err := readInteger(&r, math.MinInt32, math.MaxUint32)
	if err != nil {
		return ber.Reader{}, 0, fmt.Errorf("error parsing SNMP packet request ID: %w", err)
	}
	return r, uint32(requestID), nil //nolint:gosec // its 32 bits
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

// unmarshalPDU reads a PDU of pduType other than the SNMPv1 trap: the request
// ID, an Integer32 whose two's complement RequestID holds; the fields after it
// (readBulkFields of a GetBulkRequest, readErrorFields of any other PDU); and
// the varbinds. Fields read before an error stay set.
func unmarshalPDU(packet []byte, pduType PDUType, m *Message) error {
	r, requestID, err := readRequestID(packet)
	if err != nil {
		return err
	}
	m.RequestID = requestID
	if pduType == GetBulkRequest {
		err = readBulkFields(&r, m)
	} else {
		err = readErrorFields(&r, m)
	}
	if err != nil {
		return err
	}
	return unmarshalVBL(r.Rest(), m)
}

// readBulkFields reads a GetBulkRequest's non-repeaters (readCount) and
// max-repetitions, 0..2147483647 (RFC 3416 section 3).
func readBulkFields(r *ber.Reader, m *Message) error {
	var err error
	if m.NonRepeaters, err = readCount(r); err != nil {
		return fmt.Errorf("error parsing SNMP packet non repeaters: %w", err)
	}
	maxRepetitions, err := readInteger(r, 0, math.MaxInt32)
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet max repetitions: %w", err)
	}
	m.MaxRepetitions = uint32(maxRepetitions) //nolint:gosec // 0..2147483647
	return nil
}

// readErrorFields reads a PDU's error status, 0..255, and error index
// (readCount) (RFC 3416 section 3).
func readErrorFields(r *ber.Reader, m *Message) error {
	errorStatus, err := readInteger(r, 0, math.MaxUint8)
	if err != nil {
		return fmt.Errorf("error parsing SNMP packet error: %w", err)
	}
	m.ErrorStatus = ErrorStatus(errorStatus) //nolint:gosec // 0..255
	if m.ErrorIndex, err = readCount(r); err != nil {
		return fmt.Errorf("error parsing SNMP packet error index: %w", err)
	}
	return nil
}

// unmarshalTrapV1 reads an SNMPv1 trap PDU: the enterprise, an OBJECT
// IDENTIFIER; the agent address (readAgentAddress); the generic and specific
// trap, Integer32s; the timestamp (readTimestamp); and the varbinds. Fields
// read before an error stay set.
func unmarshalTrapV1(packet []byte, m *Message) error {
	pdu, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying the PDU's length: %w", err)
	}
	r := ber.NewReader(pdu)

	if m.Enterprise, err = readOID(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap enterprise: %w", err)
	}
	if m.AgentAddress, err = readAgentAddress(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap agent address: %w", err)
	}
	if m.GenericTrap, err = readInteger32(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap generic trap: %w", err)
	}
	if m.SpecificTrap, err = readInteger32(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap specific trap: %w", err)
	}
	if m.Timestamp, err = readTimestamp(&r); err != nil {
		return fmt.Errorf("error parsing SNMPv1 trap timestamp: %w", err)
	}
	return unmarshalVBL(r.Rest(), m)
}

// unmarshalVBL reads a varbind list, which must span all of packet, into
// m.VarBinds, an empty list when it has no varbinds; on an error the
// ones before it stay set.
func unmarshalVBL(packet []byte, m *Message) error {
	if len(packet) == 0 {
		return errors.New("truncated packet when unmarshalling a VBL")
	}
	if packet[0] != ber.Sequence {
		return fmt.Errorf("expected a sequence when unmarshalling a VBL, got %x", packet[0])
	}
	vbl, err := readWhole(packet)
	if err != nil {
		return fmt.Errorf("error verifying VBL length: %w", err)
	}

	m.VarBinds = make([]VarBind, 0, 5)
	r := ber.NewReader(vbl)
	for r.Len() > 0 {
		vb, err := readVarbind(&r)
		if err != nil {
			return err
		}
		m.VarBinds = append(m.VarBinds, vb)
	}
	return nil
}

// errNoValue is the error of a varbind without a value.
var errNoValue = errors.New("error decoding value: zero byte buffer")

// readVarbind reads the next varbind: a SEQUENCE of the name (readName) and
// the value TLV, which must span the rest of it.
func readVarbind(r *ber.Reader) (VarBind, error) {
	if tag, _ := r.Peek(); tag != ber.Sequence {
		return VarBind{}, fmt.Errorf("expected a sequence when unmarshalling a VB, got %x", tag)
	}
	_, vb, err := r.Next()
	if err != nil {
		return VarBind{}, fmt.Errorf("error reading varbind: %w", err)
	}

	fields := ber.NewReader(vb)
	name, err := readName(&fields)
	if err != nil {
		return VarBind{}, fmt.Errorf("error parsing OID Value: %w", err)
	}

	value := fields.Rest()
	if len(value) == 0 {
		return VarBind{}, errNoValue
	}
	length, header, err := ber.Length(value)
	if err != nil {
		return VarBind{}, fmt.Errorf("error parsing value TLV in varbind: %w", err)
	}
	tag := ValueType(value[0])
	// Some MikroTik responses overdeclare OctetString lengths by one byte.
	// The enclosing varbind provides the content boundary for this case.
	overdeclared := tag == OctetString && length == uint64(len(value))+1
	switch {
	case overdeclared:
	case length > uint64(len(value)):
		return VarBind{}, fmt.Errorf("value TLV length mismatch in varbind (TLV %d, remaining %d): %w", length, len(value), ber.ErrTruncated)
	case length < uint64(len(value)):
		return VarBind{}, fmt.Errorf("value TLV length mismatch in varbind (TLV %d, remaining %d)", length, len(value))
	}
	val, err := decodeValue(tag, value[header:])
	if err != nil {
		return VarBind{}, fmt.Errorf("error decoding value: %w", err)
	}
	return VarBind{Name: name, Value: val}, nil
}

// marshalMsg encodes the message: a SEQUENCE of the version, then the
// community and the PDU, or for SNMPv3 the header, the security parameters and
// the scoped PDU, encrypted with keys when its level asks for privacy; an
// SNMPv3 message is then signed with keys when its level asks for
// authentication. The version, which takes one octet, must be SNMPv1, SNMPv2c
// or SNMPv3.
func (m *Message) marshalMsg(keys *usmKeys) ([]byte, error) {
	return m.marshalWith(keys, nil)
}

// marshalWith is marshalMsg with varBinds, when not nil, a varbind list
// encoded already, which it writes as it is instead of VarBinds: a received
// inform's, which a receiver's Response repeats (respond).
func (m *Message) marshalWith(keys *usmKeys, varBinds []byte) ([]byte, error) {
	switch m.Version {
	case Version1, Version2c, Version3:
	default:
		return nil, fmt.Errorf("unable to marshal SNMP version %d: not 1, 2c or 3", m.Version)
	}
	dst, start := ber.Begin(make([]byte, 0, m.sizeHint()+len(varBinds)), ber.Sequence)
	dst = append(dst, byte(Integer), 1, byte(m.Version))
	if m.Version != Version3 {
		msg, err := m.appendPDU(appendOctets(dst, OctetString, m.Community), varBinds)
		if err != nil {
			return nil, err
		}
		return ber.End(msg, start), nil
	}
	dst, auth, err := m.appendV3(dst, keys, varBinds)
	if err != nil {
		return nil, err
	}
	dst, auth = ber.EndMoving(dst, start, auth)
	return m.sign(dst, auth, keys)
}

// sizeHint estimates the encoded size of the message so that marshalMsg
// usually allocates once: room for the headers and the security parameters,
// the text fields, and per varbind its name in dotted form (no shorter than
// its encoding), its headers and an OCTET STRING or Opaque value.
func (m *Message) sizeHint() int {
	n := 64 + len(m.Community) + len(m.ContextEngineID) + len(m.ContextName)
	if m.Version == Version3 {
		n += 128
	}
	for i := range m.VarBinds {
		vb := &m.VarBinds[i]
		n += 16 + len(vb.Name) + len(vb.Value.data) + len(vb.Value.oid)
	}
	return n
}

// appendPDU appends the PDU, of a type the codec knows: the request ID with
// the non-repeaters and max-repetitions (at most 2147483647, RFC 3416) of a
// GetBulkRequest or the error status and index of other PDUs, or the header of
// an SNMPv1 trap, then the varbind list (appendVBL). The request ID is an
// Integer32 (RFC 3416) whose two's complement RequestID holds, so IDs of 2^31
// and up encode as negative INTEGERs on every platform.
func (m *Message) appendPDU(dst, varBinds []byte) ([]byte, error) {
	if !m.PDUType.known() {
		return nil, fmt.Errorf("unable to marshal PDU type %#x: not a PDU type", byte(m.PDUType))
	}
	if m.PDUType == GetBulkRequest && m.MaxRepetitions > math.MaxInt32 {
		return nil, fmt.Errorf("unable to marshal max-repetitions %d: more than %d", m.MaxRepetitions, math.MaxInt32)
	}
	dst, start := ber.Begin(dst, byte(m.PDUType))
	requestID := int64(int32(m.RequestID)) //nolint:gosec // the Integer32's two's complement
	switch m.PDUType {
	case GetBulkRequest:
		dst = appendInt(dst, requestID)
		dst = appendUint(dst, Integer, uint64(m.NonRepeaters))
		dst = appendUint(dst, Integer, uint64(m.MaxRepetitions))
	case Trap:
		var err error
		if dst, err = m.appendTrapV1Header(dst); err != nil {
			return nil, err
		}
	default:
		dst = appendInt(dst, requestID)
		dst = appendUint(dst, Integer, uint64(m.ErrorStatus))
		dst = appendUint(dst, Integer, uint64(m.ErrorIndex))
	}
	dst, err := m.appendVBL(dst, varBinds)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal varbind list: %w", err)
	}
	return ber.End(dst, start), nil
}

// appendTrapV1Header appends the SNMPv1 trap fields before the varbind list:
// enterprise, the agent address (an IPv4 address, an IPv4-mapped one included:
// RFC 1157's NetworkAddress), generic and specific trap and the timestamp.
func (m *Message) appendTrapV1Header(dst []byte) ([]byte, error) {
	dst, err := appendObjectIdentifier(dst, m.Enterprise)
	if err != nil {
		return nil, err
	}
	agentAddress := m.AgentAddress.Unmap()
	switch {
	case !agentAddress.IsValid():
		return nil, errors.New("unable to marshal SNMPv1 AgentAddress: no address")
	case !agentAddress.Is4():
		return nil, fmt.Errorf("unable to marshal SNMPv1 AgentAddress: %v is not an IPv4 address", m.AgentAddress)
	}
	octets := agentAddress.As4()
	dst = appendOctets(dst, IPAddress, octets[:])
	dst = appendInt(dst, int64(m.GenericTrap))
	dst = appendInt(dst, int64(m.SpecificTrap))
	return appendUint(dst, TimeTicks, uint64(m.Timestamp)), nil
}

// appendVBL appends the varbind list: varBinds, a list encoded already, when
// not nil, else a SEQUENCE of VarBinds, each a SEQUENCE of the name's OBJECT
// IDENTIFIER and the value (see appendValue).
func (m *Message) appendVBL(dst, varBinds []byte) ([]byte, error) {
	if varBinds != nil {
		return append(dst, varBinds...), nil
	}
	dst, start := ber.Begin(dst, ber.Sequence)
	for i := range m.VarBinds {
		var err error
		if dst, err = appendVarbind(dst, &m.VarBinds[i]); err != nil {
			return nil, err
		}
	}
	return ber.End(dst, start), nil
}

// appendVarbind appends one varbind.
func appendVarbind(dst []byte, vb *VarBind) ([]byte, error) {
	dst, start := ber.Begin(dst, ber.Sequence)
	dst, err := appendObjectIdentifier(dst, vb.Name)
	if err != nil {
		return nil, err
	}
	if dst, err = appendValue(dst, vb.Value); err != nil {
		return nil, err
	}
	return ber.End(dst, start), nil
}
