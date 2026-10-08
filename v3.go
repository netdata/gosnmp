// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"github.com/netdata/gosnmp/internal/ber"
)

// SnmpV3MsgFlags contains various message flags to describe Authentication, Privacy, and whether a report PDU must be sent.
type SnmpV3MsgFlags uint8

// Possible values of SnmpV3MsgFlags
const (
	NoAuthNoPriv SnmpV3MsgFlags = 0x0 // No authentication, and no privacy
	AuthNoPriv   SnmpV3MsgFlags = 0x1 // Authentication and no privacy
	AuthPriv     SnmpV3MsgFlags = 0x3 // Authentication and privacy
	Reportable   SnmpV3MsgFlags = 0x4 // Report PDU must be sent.
)

//go:generate go tool -modfile=tools/go.mod stringer -type=SnmpV3MsgFlags

// SnmpV3SecurityModel describes the security model used by a SnmpV3 connection
type SnmpV3SecurityModel uint8

// UserSecurityModel is the only SnmpV3SecurityModel currently implemented.
const (
	UserSecurityModel SnmpV3SecurityModel = 3
)

//go:generate go tool -modfile=tools/go.mod stringer -type=SnmpV3SecurityModel

// SnmpV3SecurityParameters is a generic interface type to contain various implementations of SnmpV3SecurityParameters
type SnmpV3SecurityParameters interface {
	Log()
	Copy() SnmpV3SecurityParameters
	Description() string
	SafeString() string
	InitPacket(packet *SnmpPacket) error
	InitSecurityKeys() error
	validate(flags SnmpV3MsgFlags) error
	init(log Logger) error
	discoveryRequired() *SnmpPacket
	getDefaultContextEngineID() string
	setSecurityParameters(in SnmpV3SecurityParameters) error
	marshal(flags SnmpV3MsgFlags) ([]byte, error)
	unmarshal(flags SnmpV3MsgFlags, r *ber.Reader) error
	authenticate(packet []byte) error
	isAuthentic(packetBytes []byte, packet *SnmpPacket) (bool, error)
	encryptPacket(scopedPdu []byte) ([]byte, error)
	decryptPacket(packet []byte, cursor int) ([]byte, error)
	getIdentifier() string
	getLogger() Logger
	setLogger(log Logger)
}

func (x *GoSNMP) validateParametersV3() error {
	// update following code if you implement a new security model
	if x.SecurityModel != UserSecurityModel {
		return errors.New("the SNMPV3 User Security Model is the only SNMPV3 security model currently implemented")
	}
	if x.SecurityParameters == nil {
		return errors.New("SNMPV3 SecurityParameters must be set")
	}

	return x.SecurityParameters.validate(x.MsgFlags)
}

// authenticate the marshalled result of a snmp version 3 packet
func (packet *SnmpPacket) authenticate(msg []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			buf := make([]byte, 8192)
			runtime.Stack(buf, true)
			fmt.Printf("[v3::authenticate]recover: %v. Stack=%v\n", e, string(buf))
		}
	}()
	if packet.Version != Version3 {
		return msg, nil
	}
	if packet.MsgFlags&AuthNoPriv > 0 {
		err := packet.SecurityParameters.authenticate(msg)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

func (x *GoSNMP) testAuthentication(packet []byte, result *SnmpPacket, useResponseSecurityParameters bool) error {
	if x.Version != Version3 {
		return fmt.Errorf("testAuthentication called with non Version3 connection")
	}
	msgFlags := x.MsgFlags
	if useResponseSecurityParameters {
		msgFlags = result.MsgFlags
	}

	// Special case for Engine Discovery (RFC3414 section 4) where we should
	// skip authentication for the discovery packet with the special settings
	// described in the RFC. The discovery package requires
	msgSecParams := result.SecurityParameters.(*UsmSecurityParameters)
	if msgFlags&NoAuthNoPriv == 0 && // NoAuthNoPriv method
		msgSecParams.UserName == "" && // empty username
		msgSecParams.AuthoritativeEngineID == "" && // empty authoritative engine ID
		len(result.Variables) == 0 { // empty variable binding list
		return nil
	}

	if msgFlags&AuthNoPriv > 0 {
		var authentic bool
		var err error
		if useResponseSecurityParameters {
			authentic, err = result.SecurityParameters.isAuthentic(packet, result)
		} else {
			authentic, err = x.SecurityParameters.isAuthentic(packet, result)
		}
		if err != nil {
			return err
		}
		if !authentic {
			return fmt.Errorf("incoming packet is not authentic, discarding")
		}
	}

	return nil
}

func (x *GoSNMP) initPacket(packetOut *SnmpPacket) error {
	if x.MsgFlags&AuthPriv > AuthNoPriv {
		return x.SecurityParameters.InitPacket(packetOut)
	}

	return nil
}

// http://tools.ietf.org/html/rfc2574#section-2.2.3 This code does not
// check if the last message received was more than 150 seconds ago The
// snmpds that this code was tested on emit an 'out of time window'
// error with the new time and this code will retransmit when that is
// received.
func (x *GoSNMP) negotiateInitialSecurityParameters(packetOut *SnmpPacket) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("negotiateInitialSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model defined in packet")
	}

	if discoveryPacket := packetOut.SecurityParameters.discoveryRequired(); discoveryPacket != nil {
		discoveryPacket.ContextName = x.ContextName
		result, err := x.sendOneRequest(discoveryPacket)
		if err != nil {
			// Some devices (e.g. Dell EMC switches) respond to discovery probes with
			// usmStatsUnknownUserNames instead of usmStatsUnknownEngineIDs, yet still
			// include valid engine parameters. Treat it as a valid discovery response.
			if !errors.Is(err, ErrUnknownUsername) || result == nil {
				return err
			}
			usp, ok := result.SecurityParameters.(*UsmSecurityParameters)
			if !ok || usp.AuthoritativeEngineID == "" {
				return err
			}
		}

		err = x.storeSecurityParameters(result)
		if err != nil {
			return err
		}

		err = x.updatePktSecurityParameters(packetOut)
		if err != nil {
			return err
		}
	} else {
		err := packetOut.SecurityParameters.InitSecurityKeys()
		if err == nil {
			return err
		}
	}

	return nil
}

// save the connection security parameters after a request/response
func (x *GoSNMP) storeSecurityParameters(result *SnmpPacket) error {
	if x.Version != Version3 || result.Version != Version3 {
		return fmt.Errorf("storeParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != result.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	if x.ContextEngineID == "" {
		x.ContextEngineID = result.SecurityParameters.getDefaultContextEngineID()
	}

	return x.SecurityParameters.setSecurityParameters(result.SecurityParameters)
}

// update packet security parameters to match connection security parameters
func (x *GoSNMP) updatePktSecurityParameters(packetOut *SnmpPacket) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("updatePktSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	err := packetOut.SecurityParameters.setSecurityParameters(x.SecurityParameters)
	if err != nil {
		return err
	}

	if packetOut.ContextEngineID == "" {
		packetOut.ContextEngineID = x.ContextEngineID
	}

	return nil
}

func (packet *SnmpPacket) marshalV3(buf *bytes.Buffer) (*bytes.Buffer, error) {
	emptyBuffer := new(bytes.Buffer) // used when returning errors

	header, err := packet.marshalV3Header()
	if err != nil {
		return emptyBuffer, err
	}
	buf.Write([]byte{byte(Sequence), byte(len(header))}) //nolint:gosec
	buf.Write(header)

	var securityParameters []byte
	securityParameters, err = packet.SecurityParameters.marshal(packet.MsgFlags)
	if err != nil {
		return emptyBuffer, err
	}

	buf.Write([]byte{byte(OctetString)})
	secParamLen, err := marshalLength(len(securityParameters))
	if err != nil {
		return emptyBuffer, err
	}
	buf.Write(secParamLen)
	buf.Write(securityParameters)

	scopedPdu, err := packet.marshalV3ScopedPDU()
	if err != nil {
		return emptyBuffer, err
	}
	buf.Write(scopedPdu)
	return buf, nil
}

// marshal a snmp version 3 packet header
func (packet *SnmpPacket) marshalV3Header() ([]byte, error) {
	buf := new(bytes.Buffer)

	// msg id
	buf.Write([]byte{byte(Integer), 4})
	err := binary.Write(buf, binary.BigEndian, packet.MsgID)
	if err != nil {
		return nil, err
	}

	// maximum response msg size
	var maxBufSize uint32 = rxBufSize
	if packet.MsgMaxSize != 0 {
		maxBufSize = packet.MsgMaxSize
	}
	maxmsgsize, err := marshalUint32(maxBufSize)
	if err != nil {
		return nil, err
	}
	buf.Write([]byte{byte(Integer), byte(len(maxmsgsize))}) //nolint:gosec
	buf.Write(maxmsgsize)

	// msg flags
	buf.Write([]byte{byte(OctetString), 1, byte(packet.MsgFlags)})

	// msg security model
	buf.Write([]byte{byte(Integer), 1, byte(packet.SecurityModel)})

	return buf.Bytes(), nil
}

// marshal and encrypt (if necessary) a snmp version 3 Scoped PDU
func (packet *SnmpPacket) marshalV3ScopedPDU() ([]byte, error) {
	var b []byte

	scopedPdu, err := packet.prepareV3ScopedPDU()
	if err != nil {
		return nil, err
	}
	pduLen, err := marshalLength(len(scopedPdu))
	if err != nil {
		return nil, err
	}
	b = append([]byte{byte(Sequence)}, pduLen...)
	scopedPdu = append(b, scopedPdu...)
	if packet.MsgFlags&AuthPriv > AuthNoPriv {
		scopedPdu, err = packet.SecurityParameters.encryptPacket(scopedPdu)
		if err != nil {
			return nil, err
		}
	}

	return scopedPdu, nil
}

// prepare the plain text of a snmp version 3 Scoped PDU
func (packet *SnmpPacket) prepareV3ScopedPDU() ([]byte, error) {
	var buf bytes.Buffer

	// ContextEngineID
	if err := marshalOctetString(&buf, packet.ContextEngineID); err != nil {
		return nil, err
	}

	// ContextName
	if err := marshalOctetString(&buf, packet.ContextName); err != nil {
		return nil, err
	}

	data, err := packet.marshalPDU()
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
}

// unmarshalV3Header reads the SNMPv3 header at packet[cursor:]: msgGlobalData
// (message ID, maximum size, flags, security model) and the security
// parameters. The headers of msgGlobalData and of the security parameters are
// skipped without enforcing their declared lengths; the fields are read from
// the rest of the packet. It returns the offset of the scoped PDU.
func (x *GoSNMP) unmarshalV3Header(packet []byte,
	cursor int,
	response *SnmpPacket,
) (int, error) {
	r := ber.NewReader(packet[cursor:])
	if tag, _ := r.Peek(); PDUType(tag) != Sequence {
		return 0, errors.New("invalid SNMPV3 Header")
	}
	if _, err := r.SkipHeader(); err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 header: %w", err)
	}

	msgID, ok, err := readInt(&r)
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 message ID: %w", err)
	}
	if ok {
		response.MsgID = uint32(msgID) //nolint:gosec
	}

	msgMaxSize, ok, err := readInt(&r)
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 msgMaxSize: %w", err)
	}
	if ok {
		response.MsgMaxSize = uint32(msgMaxSize) //nolint:gosec
	}

	msgFlags, ok, err := readString(&r)
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 msgFlags: %w", err)
	}
	if ok && len(msgFlags) > 0 {
		response.MsgFlags = SnmpV3MsgFlags(msgFlags[0])
	}

	secModel, ok, err := readInt(&r)
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 msgSecModel: %w", err)
	}
	tag, more := r.Peek()
	if !more {
		return 0, errors.New("error parsing SNMPV3: nothing after the security model")
	}
	if ok {
		response.SecurityModel = SnmpV3SecurityModel(secModel) //nolint:gosec
	}

	if PDUType(tag) != PDUType(OctetString) {
		return 0, errors.New("invalid SNMPV3 Security Parameters")
	}
	if _, err := r.SkipHeader(); err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 security parameters: %w", err)
	}
	if response.SecurityParameters == nil {
		response.SecurityParameters = &UsmSecurityParameters{Logger: x.Logger}
	}
	if err := response.SecurityParameters.unmarshal(response.MsgFlags, &r); err != nil {
		return 0, err
	}

	return len(packet) - r.Len(), nil
}

// unmarshalScopedPDU reads the scoped PDU at packet[cursor:], decrypting it in
// place first when it is encrypted, and returns the packet and the offset of
// the PDU. A decrypted scoped PDU must fit its declared length, which cuts off
// the padding; a plaintext one is read like the SNMPv3 header, without
// enforcing its declared length.
func unmarshalScopedPDU(packet []byte, cursor int, response *SnmpPacket) ([]byte, int, error) {
	if cursor >= len(packet) {
		return nil, 0, errors.New("error parsing SNMPV3: truncated packet")
	}

	var r ber.Reader
	switch PDUType(packet[cursor]) {
	case PDUType(OctetString):
		var err error
		packet, err = response.SecurityParameters.decryptPacket(packet, cursor)
		if err != nil {
			return nil, 0, err
		}
		pr := ber.NewReader(packet[cursor:])
		_, content, err := pr.Next()
		if err != nil {
			return nil, 0, fmt.Errorf("error parsing SNMPV3 decrypted scoped PDU: %w", err)
		}
		packet = packet[:len(packet)-pr.Len()]
		r = ber.NewReader(content)
	case Sequence:
		r = ber.NewReader(packet[cursor:])
		if _, err := r.SkipHeader(); err != nil {
			return nil, 0, fmt.Errorf("error parsing SNMPV3 scoped PDU: %w", err)
		}
	default:
		return nil, 0, errors.New("error parsing SNMPV3 scoped PDU")
	}

	contextEngineID, ok, err := readString(&r)
	if err != nil {
		return nil, 0, fmt.Errorf("error parsing SNMPV3 contextEngineID: %w", err)
	}
	if ok {
		response.ContextEngineID = contextEngineID
	}

	contextName, ok, err := readString(&r)
	if err != nil {
		return nil, 0, fmt.Errorf("error parsing SNMPV3 contextName: %w", err)
	}
	if ok {
		response.ContextName = contextName
	}

	return packet, len(packet) - r.Len(), nil
}
