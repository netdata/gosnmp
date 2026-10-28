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

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// SnmpV3MsgFlags is the msgFlags octet of an SNMPv3 message: its security
// level, authentication and privacy, and whether the receiver must answer an
// error with a Report.
type SnmpV3MsgFlags uint8

// The security levels and the reportable flag.
const (
	NoAuthNoPriv SnmpV3MsgFlags = 0x0 // No authentication, and no privacy
	AuthNoPriv   SnmpV3MsgFlags = 0x1 // Authentication and no privacy
	AuthPriv     SnmpV3MsgFlags = 0x3 // Authentication and privacy
	Reportable   SnmpV3MsgFlags = 0x4 // Report PDU must be sent.
)

// authFlag reports whether f has the authFlag (bit 0x1, RFC 3412 section 6.4)
// set: the message asks for authentication. A set flag is a request, not
// proof that the message was authenticated.
func (f SnmpV3MsgFlags) authFlag() bool { return f&0x1 != 0 }

// privFlag reports whether f has the privFlag (bit 0x2) set: the message asks
// for privacy. Without the authFlag the combination is invalid (RFC 3412
// section 7.2 step 5 d).
func (f SnmpV3MsgFlags) privFlag() bool { return f&0x2 != 0 }

//go:generate go tool -modfile=tools/go.mod stringer -type=SnmpV3MsgFlags

// SnmpV3SecurityModel is the security model of an SNMPv3 message.
type SnmpV3SecurityModel uint8

// UserSecurityModel is the only SnmpV3SecurityModel currently implemented.
const (
	UserSecurityModel SnmpV3SecurityModel = 3
)

//go:generate go tool -modfile=tools/go.mod stringer -type=SnmpV3SecurityModel

// SnmpV3SecurityParameters holds the parameters of an SNMPv3 security model.
// Its only implementation is *UsmSecurityParameters, for the User-based
// Security Model, which documents the methods.
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

// validateParametersV3 checks the client's SNMPv3 configuration: the
// User-based Security Model, and parameters that fit MsgFlags.
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

// sign writes the digest of the marshalled SNMPv3 message msg into the
// content of its msgAuthenticationParameters, at offset auth, when the flags
// ask for authentication; a key that does not fit the protocol is an error
// (usm.Auth.CheckKey).
func (packet *SnmpPacket) sign(msg []byte, auth int) ([]byte, error) {
	if packet.MsgFlags.authFlag() {
		if err := packet.SecurityParameters.usm().sign(msg, auth); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// testAuthentication verifies the SNMPv3 message packet, whose header is
// decoded into result, for UnmarshalTrap, when the flags ask for
// authentication: the message must name the user and carry a digest that
// checks with result's key, localized to the engine ID the message names. The
// flags and the user are the client's, or the message's own when
// useResponseSecurityParameters is set, so its user name always matches.
// Engine discovery (RFC 3414 section 4): a message with an empty user name and
// engine ID is accepted without authentication. Known bugs: the discovery
// exception holds whatever the message's flags and variable bindings (the
// bindings are not decoded yet), so any such message skips the digest; with
// useResponseSecurityParameters, which the table path sets, a message without
// the authentication flag skips it too, whatever its user requires; the
// client's flags decide only whether a digest is checked, so a message without
// privacy passes a client at authPriv.
func (x *GoSNMP) testAuthentication(packet []byte, result *SnmpPacket, useResponseSecurityParameters bool) error {
	if x.Version != Version3 {
		return fmt.Errorf("testAuthentication called with non Version3 connection")
	}
	msgFlags, verifier := x.MsgFlags, x.SecurityParameters
	if useResponseSecurityParameters {
		msgFlags, verifier = result.MsgFlags, result.SecurityParameters
	}

	msgSecParams := result.SecurityParameters.usm()
	if msgSecParams.UserName == "" && msgSecParams.AuthoritativeEngineID == "" {
		return nil
	}
	if !msgFlags.authFlag() {
		return nil
	}

	authentic, err := verifier.usm().isAuthentic(packet, result)
	if err != nil {
		return err
	}
	if !authentic {
		return errNotAuthentic
	}
	return nil
}

// errNotAuthentic is the error of a message without the authentication it
// needs, or whose user, engine ID or digest does not check.
var errNotAuthentic = errors.New("incoming packet is not authentic, discarding")

// errNoSecurityParameters is the error of an SNMPv3 message to encode
// without security parameters.
var errNoSecurityParameters = errors.New("SNMPv3 message without security parameters")

// appendV3 appends the SNMPv3 part of a message after the version: the header
// (msgGlobalData), the security parameters in an OCTET STRING and the scoped
// PDU. It also returns the offset of the msgAuthenticationParameters content
// in dst, where sign writes the digest. A message the flags encrypt gets the
// next salt of usm.Salts, never the packet's PrivacyParameters, so that no two
// messages share one, whatever the caller copied into the packet.
func (packet *SnmpPacket) appendV3(dst []byte) ([]byte, int, error) {
	sp := usmOf(packet.SecurityParameters)
	if sp == nil {
		return nil, 0, errNoSecurityParameters
	}
	if err := sp.checkProtocols(); err != nil {
		return nil, 0, err
	}
	if err := sp.checkLevel(packet.MsgFlags); err != nil {
		return nil, 0, err
	}
	var salt []byte
	if packet.MsgFlags.privFlag() {
		next := usm.Salts.Next()
		salt = next[:]
	}
	dst = packet.appendV3Header(dst)
	dst, start := ber.Begin(dst, byte(OctetString))
	dst, auth := sp.marshal(dst, packet.MsgFlags, salt)
	dst, auth = ber.EndMoving(dst, start, auth)
	dst, err := packet.appendV3ScopedPDU(dst, sp, salt)
	return dst, auth, err
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
// ID, the context name and the PDU, encrypted with salt into an OCTET STRING
// when there is one (appendV3 draws it when the flags ask for privacy).
func (packet *SnmpPacket) appendV3ScopedPDU(dst []byte, sp *UsmSecurityParameters, salt []byte) ([]byte, error) {
	scoped := len(dst)
	dst, start := ber.Begin(dst, byte(Sequence))
	dst = appendOctets(dst, OctetString, packet.ContextEngineID)
	dst = appendOctets(dst, OctetString, packet.ContextName)
	dst, err := packet.appendPDU(dst)
	if err != nil {
		return nil, err
	}
	dst = ber.End(dst, start)
	if salt != nil {
		ciphertext, err := sp.encryptPacket(dst[scoped:], salt)
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

	var fr fieldReader
	if v, ok := fr.int(&r, "SNMPV3 message ID"); ok {
		response.MsgID = uint32(v) //nolint:gosec
	}
	if v, ok := fr.int(&r, "SNMPV3 msgMaxSize"); ok {
		response.MsgMaxSize = uint32(v) //nolint:gosec
	}
	if v, ok := fr.string(&r, "SNMPV3 msgFlags"); ok && len(v) > 0 {
		response.MsgFlags = SnmpV3MsgFlags(v[0])
	}
	secModel, secModelOK := fr.int(&r, "SNMPV3 msgSecModel")
	if fr.err != nil {
		return 0, fr.err
	}
	// The security model is taken only when anything follows it.
	tag, more := r.Peek()
	if !more {
		return 0, errors.New("error parsing SNMPV3: nothing after the security model")
	}
	if secModelOK {
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

	var fr fieldReader
	if v, ok := fr.string(&r, "SNMPV3 contextEngineID"); ok {
		response.ContextEngineID = v
	}
	if v, ok := fr.string(&r, "SNMPV3 contextName"); ok {
		response.ContextName = v
	}
	if fr.err != nil {
		return nil, 0, fr.err
	}
	return packet, len(packet) - r.Len(), nil
}
