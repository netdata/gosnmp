// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
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

// SnmpV3SecurityParameters holds the parameters of an SNMPv3 security model.
// Its only implementation is *UsmSecurityParameters, for the User-based
// Security Model.
type SnmpV3SecurityParameters interface {
	Log()
	Copy() SnmpV3SecurityParameters
	Description() string
	SafeString() string
	InitPacket(packet *SnmpPacket) error
	InitSecurityKeys() error

	// usm returns the parameters of the User-based Security Model. Being
	// unexported, it keeps the interface implemented only in this package.
	usm() *UsmSecurityParameters
}

// usmOf returns the User-based Security Model parameters of sp, or nil when
// sp is nil.
func usmOf(sp SnmpV3SecurityParameters) *UsmSecurityParameters {
	if sp == nil {
		return nil
	}
	return sp.usm()
}

func (x *GoSNMP) validateParametersV3() error {
	// update following code if you implement a new security model
	if x.SecurityModel != UserSecurityModel {
		return errors.New("the SNMPV3 User Security Model is the only SNMPV3 security model currently implemented")
	}
	if x.SecurityParameters == nil {
		return errors.New("SNMPV3 SecurityParameters must be set")
	}

	return x.SecurityParameters.usm().validate(x.MsgFlags)
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
		err := packet.SecurityParameters.usm().authenticate(msg)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// testAuthentication verifies the digest of the SNMPv3 message packet, whose
// header is decoded into result, with result's flags and user when
// useResponseSecurityParameters is set, with the client's otherwise, except
// for engine discovery (RFC 3414 section 4): a message with an empty user name
// and engine ID is accepted without authentication. For the engine's replies
// while the client has no engine ID, and for UnmarshalTrap. Known bug: whatever
// its flags and variable bindings (the bindings are not decoded yet), so any
// such message skips the digest.
func (x *GoSNMP) testAuthentication(packet []byte, result *SnmpPacket, useResponseSecurityParameters bool) error {
	if x.Version != Version3 {
		return fmt.Errorf("testAuthentication called with non Version3 connection")
	}
	msgSecParams := result.SecurityParameters.usm()
	if msgSecParams.UserName == "" && msgSecParams.AuthoritativeEngineID == "" {
		return nil
	}
	if useResponseSecurityParameters {
		return verifyDigest(packet, result, result.MsgFlags, msgSecParams)
	}
	return verifyDigest(packet, result, x.MsgFlags, x.SecurityParameters.usm())
}

// verifyDigest verifies the digest of the SNMPv3 message packet, whose header
// is decoded into result, when flags ask for authentication: the message must
// carry the user name of user, and its digest is checked with result's keys,
// which decoding derived for the engine ID the message carries.
func verifyDigest(packet []byte, result *SnmpPacket, flags SnmpV3MsgFlags, user *UsmSecurityParameters) error {
	if flags&AuthNoPriv > 0 {
		authentic, err := user.isAuthentic(packet, result)
		if err != nil {
			return err
		}
		if !authentic {
			return fmt.Errorf("incoming packet is not authentic, discarding")
		}
	}

	return nil
}

// initPacket draws a new salt when the client uses privacy, and sets it as the
// privacy parameters of the outgoing SNMPv3 packet when the packet asks for
// privacy too (a discovery packet does not); for the engine and
// SnmpEncodePacket.
func (x *GoSNMP) initPacket(packetOut *SnmpPacket) error {
	if x.MsgFlags&AuthPriv > AuthNoPriv {
		return x.SecurityParameters.InitPacket(packetOut)
	}

	return nil
}

// appendV3 appends the SNMPv3 part of a message after the version: the header
// (msgGlobalData), the security parameters in an OCTET STRING and the scoped
// PDU.
func (packet *SnmpPacket) appendV3(dst []byte) ([]byte, error) {
	sp := packet.SecurityParameters.usm()
	if err := sp.checkProtocols(); err != nil {
		return nil, err
	}
	if err := sp.checkLevel(packet.MsgFlags); err != nil {
		return nil, err
	}
	dst = packet.appendV3Header(dst)
	dst, start := ber.Begin(dst, byte(OctetString))
	dst = ber.End(sp.marshal(dst, packet.MsgFlags), start)
	return packet.appendV3ScopedPDU(dst)
}

// appendV3Header appends msgGlobalData: the message ID, which always takes
// four octets (so IDs of 2^31 and up read as negative), the maximum message
// size (rxBufSize unless set), the flags and the security model, each of the
// last two in one octet.
func (packet *SnmpPacket) appendV3Header(dst []byte) []byte {
	dst, start := ber.Begin(dst, byte(Sequence))
	dst = binary.BigEndian.AppendUint32(append(dst, byte(Integer), 4), packet.MsgID)
	maxSize := uint32(rxBufSize)
	if packet.MsgMaxSize != 0 {
		maxSize = packet.MsgMaxSize
	}
	dst = appendUint(dst, Integer, uint64(maxSize))
	dst = append(dst, byte(OctetString), 1, byte(packet.MsgFlags))
	dst = append(dst, byte(Integer), 1, byte(packet.SecurityModel))
	return ber.End(dst, start)
}

// appendV3ScopedPDU appends the scoped PDU: a SEQUENCE of the context engine
// ID, the context name and the PDU, encrypted into an OCTET STRING when the
// flags ask for privacy.
func (packet *SnmpPacket) appendV3ScopedPDU(dst []byte) ([]byte, error) {
	scoped := len(dst)
	dst, start := ber.Begin(dst, byte(Sequence))
	dst = appendOctets(dst, OctetString, packet.ContextEngineID)
	dst = appendOctets(dst, OctetString, packet.ContextName)
	dst, err := packet.appendPDU(dst)
	if err != nil {
		return nil, err
	}
	dst = ber.End(dst, start)
	if packet.MsgFlags&AuthPriv > AuthNoPriv {
		ciphertext, err := packet.SecurityParameters.usm().encryptPacket(dst[scoped:])
		if err != nil {
			return nil, err
		}
		dst = appendOctets(dst[:scoped], OctetString, ciphertext)
	}
	return dst, nil
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
	if err := response.SecurityParameters.usm().unmarshal(response.MsgFlags, &r); err != nil {
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
		packet, err = response.SecurityParameters.usm().decryptPacket(packet, cursor)
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
