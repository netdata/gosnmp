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

// errNotAuthentic is the error of a message without the authentication it
// needs.
var errNotAuthentic = errors.New("incoming packet is not authentic, discarding")

// categorized is an error of SNMPv3 message processing: it has the text of
// err and unwraps to err and to category, the exported error named after the
// counter of the RFC 3412 or RFC 3414 step that rejected the message
// (ErrInvalidMsgs stands in for snmpInASNParseErrs).
type categorized struct {
	err, category error
}

func (e *categorized) Error() string { return e.err.Error() }

func (e *categorized) Unwrap() []error { return []error{e.err, e.category} }

// inCategory returns err, which unwraps to category too.
func inCategory(category, err error) error {
	return &categorized{err: err, category: category}
}

// The rejections of the security processing (RFC 3414 section 3.2), in the
// order of its steps; the minimum level a trap receiver requires comes after
// them.
var (
	errNoEngineID    = inCategory(ErrUnknownEngineID, errors.New("incoming packet names no authoritative engine ID, discarding"))
	errUnknownUser   = inCategory(ErrUnknownUsername, errNotAuthentic)
	errNoAuthForMsg  = inCategory(ErrUnknownSecurityLevel, errors.New("error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message"))
	errNoPrivForMsg  = inCategory(ErrUnknownSecurityLevel, errors.New("error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message"))
	errWrongDigest   = inCategory(ErrWrongDigest, errNotAuthentic)
	errNotInTime     = inCategory(ErrNotInTimeWindow, errors.New("incoming packet is not in the time window, discarding"))
	errScopedPDUType = inCategory(ErrInvalidMsgs, errors.New("error parsing SNMPV3 scoped PDU: its type does not match the privacy flag"))
	errBelowMinimum  = inCategory(ErrUnknownSecurityLevel, errors.New("incoming packet has a lower security level than its user requires, discarding"))
)

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

// v3Wire is what the header of an SNMPv3 message carries for its security
// processing: the User-based Security Model fields as sent, each with whether
// it decoded (all of them once the parse succeeded; a header that fails keeps
// the ones before the failure), and where msgAuthenticationParameters and
// msgData are.
type v3Wire struct {
	engineID, userName, authParams string
	boots, engineTime              uint32
	privParams                     []byte
	has                            v3WireFields
	// authOff and authLen locate the content of msgAuthenticationParameters;
	// authOff is -1 until it is read.
	authOff, authLen int
	// scoped is the offset of msgData.
	scoped int
}

// v3WireFields records which USM fields of a v3Wire decoded.
type v3WireFields uint8

const (
	hasEngineID v3WireFields = 1 << iota
	hasBoots
	hasEngineTime
	hasUserName
	hasAuthParams
	hasPrivParams
)

// errNotUSM is the error of an SNMPv3 message of another security model than
// the User-based Security Model, the only one the package implements (RFC
// 3412 section 7.2 step 4).
var errNotUSM = errors.New("error parsing SNMPV3: the security model is not USM")

// errMsgFlags is the error of an SNMPv3 msgFlags that is not an OCTET STRING
// of one octet (RFC 3412 section 6).
var errMsgFlags = errors.New("error parsing SNMPV3 msgFlags: not an OCTET STRING of one octet")

// errPrivWithoutAuth is the error of an SNMPv3 msgFlags that asks for privacy
// without authentication (RFC 3412 section 7.2 step 5 d).
var errPrivWithoutAuth = errors.New("error parsing SNMPV3 msgFlags: privacy without authentication")

// v3ParseError returns err, an error of parseV3, unwrapping to the exported
// error of its counter: ErrUnknownSecurityModels for another security model
// (RFC 3412 section 7.2 step 4), ErrInvalidMsgs for the rest.
func v3ParseError(err error) error {
	if errors.Is(err, errNotUSM) {
		return inCategory(ErrUnknownSecurityModels, err)
	}
	return inCategory(ErrInvalidMsgs, err)
}

// parseV3 reads the SNMPv3 header at packet[cursor:]: the message ID, maximum
// size, flags and security model into response, and the USM fields and the
// offsets security processing needs into the v3Wire it returns. It takes
// net-snmp v5.9.4's extents: every declared length must fit what remains; the
// fields of msgGlobalData are read against the rest of the message, whatever
// its declared length; the USM fields are bounded by their SEQUENCE and the
// SEQUENCE by the security parameters' OCTET STRING; msgData starts right
// after msgPrivacyParameters. msgFlags must be an OCTET STRING of one octet,
// the security model the INTEGER 3, and then the flags may not ask for privacy
// without authentication; the USM fields must be of their types and the
// engine boots and time within 0..2147483647 (RFC 3414 section 3.2 step 1), as
// there. Unlike net-snmp, it reads the fields of msgGlobalData leniently (see
// the package documentation) and takes user names longer than 32 octets. It
// writes nothing into packet and derives no key.
func parseV3(packet []byte, cursor int, response *SnmpPacket) (v3Wire, error) {
	w := v3Wire{authOff: -1}
	if PDUType(packet[cursor]) != Sequence {
		return w, errors.New("invalid SNMPV3 Header")
	}
	start, _, err := tlvAt(packet, cursor, len(packet))
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 header: %w", err)
	}

	r := ber.NewReader(packet[start:])
	var fr fieldReader
	if v, ok := fr.int(&r, "SNMPV3 message ID"); ok {
		response.MsgID = uint32(v) //nolint:gosec
	}
	if v, ok := fr.int(&r, "SNMPV3 msgMaxSize"); ok {
		response.MsgMaxSize = uint32(v) //nolint:gosec
	}
	if fr.err != nil {
		return w, fr.err
	}
	tag, _ := r.Peek()
	flags, err := readField(&r)
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 msgFlags: %w", err)
	}
	if Asn1BER(tag) != OctetString || len(flags.s) != 1 {
		return w, errMsgFlags
	}
	response.MsgFlags = SnmpV3MsgFlags(flags.s[0])
	model, err := readField(&r)
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 msgSecModel: %w", err)
	}
	if model.kind != fieldInt || model.i != int(UserSecurityModel) {
		return w, errNotUSM
	}
	if response.MsgFlags.privFlag() && !response.MsgFlags.authFlag() {
		return w, errPrivWithoutAuth
	}
	if r.Len() == 0 {
		return w, errors.New("error parsing SNMPV3: nothing after the security model")
	}
	response.SecurityModel = UserSecurityModel

	if PDUType(packet[len(packet)-r.Len()]) != PDUType(OctetString) {
		return w, errors.New("invalid SNMPV3 Security Parameters")
	}
	params, paramsEnd, err := tlvAt(packet, len(packet)-r.Len(), len(packet))
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 security parameters: %w", err)
	}
	if params == paramsEnd {
		return w, errors.New("error parsing SNMPV3 User Security Model parameters: end of packet")
	}
	if PDUType(packet[params]) != Sequence {
		return w, errors.New("error parsing SNMPV3 User Security Model parameters")
	}
	usmStart, usmEnd, err := tlvAt(packet, params, paramsEnd)
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 User Security Model parameters: %w", err)
	}

	ur := ber.NewReader(packet[usmStart:usmEnd])
	if w.engineID, err = usmString(&ur, "msgAuthoritativeEngineID"); err != nil {
		return w, err
	}
	w.has |= hasEngineID
	if w.boots, err = usmEngineValue(&ur, "msgAuthoritativeEngineBoots"); err != nil {
		return w, err
	}
	w.has |= hasBoots
	if w.engineTime, err = usmEngineValue(&ur, "msgAuthoritativeEngineTime"); err != nil {
		return w, err
	}
	w.has |= hasEngineTime
	if w.userName, err = usmString(&ur, "msgUserName"); err != nil {
		return w, err
	}
	w.has |= hasUserName
	authAt := usmEnd - ur.Len()
	if w.authParams, err = usmString(&ur, "msgAuthenticationParameters"); err != nil {
		return w, err
	}
	authStart, authEnd, _ := tlvAt(packet, authAt, usmEnd) // read above
	w.authOff, w.authLen, w.has = authStart, authEnd-authStart, w.has|hasAuthParams
	privParams, err := usmString(&ur, "msgPrivacyParameters")
	if err != nil {
		return w, err
	}
	w.privParams, w.has = []byte(privParams), w.has|hasPrivParams
	w.scoped = usmEnd - ur.Len()
	return w, nil
}

// usmString reads the next USM field, which must be an OCTET STRING (RFC 3414
// section 2.4).
func usmString(r *ber.Reader, name string) (string, error) {
	tag, _ := r.Peek()
	f, err := readField(r)
	if err != nil {
		return "", fmt.Errorf("error parsing %s%s: %w", usmField, name, err)
	}
	if Asn1BER(tag) != OctetString {
		return "", fmt.Errorf("error parsing %s%s: not an OCTET STRING", usmField, name)
	}
	return f.s, nil
}

// usmEngineValue reads msgAuthoritativeEngineBoots or
// msgAuthoritativeEngineTime: an INTEGER of at most maxEngineValue (RFC 3414
// section 2.4) once cut to 32 bits, as net-snmp v5.9.4 cuts it.
func usmEngineValue(r *ber.Reader, name string) (uint32, error) {
	tag, _ := r.Peek()
	f, err := readField(r)
	if err != nil {
		return 0, fmt.Errorf("error parsing %s%s: %w", usmField, name, err)
	}
	if Asn1BER(tag) != Integer {
		return 0, fmt.Errorf("error parsing %s%s: not an INTEGER", usmField, name)
	}
	v := uint32(f.i) //nolint:gosec // net-snmp's narrowing
	if v > maxEngineValue {
		return 0, fmt.Errorf("error parsing %s%s: %d is above %d", usmField, name, v, maxEngineValue)
	}
	return v, nil
}

// tlvAt returns the extent of the content of the TLV at packet[off:end],
// whose declared length must fit there.
func tlvAt(packet []byte, off, end int) (start, stop int, err error) {
	length, header, err := ber.Length(packet[off:end])
	if err != nil {
		return 0, 0, err
	}
	if length > end-off {
		return 0, 0, ber.ErrTruncated
	}
	return off + header, off + length, nil
}

// unmarshalScopedPDU reads the scoped PDU at packet[cursor:] and returns the
// buffer holding the PDU and its offset there (RFC 3414 section 3.2 step 8):
// an OCTET STRING decrypted into a new buffer when encrypted (the message's
// privFlag), a plaintext SEQUENCE in packet otherwise; packet is not written.
// A scoped PDU of the other type, or a plaintext one that does not parse, is
// ErrInvalidMsgs; a decryption failure, or a decrypted plaintext whose
// SEQUENCE, contextEngineID or contextName does not parse, as with a wrong
// key, ErrDecryption; a key the process cannot decrypt with (usm.Priv.CheckUse)
// neither. A decrypted scoped PDU must fit its declared length, which cuts off
// the padding; a plaintext one is read without enforcing its declared length.
func unmarshalScopedPDU(packet []byte, cursor int, response *SnmpPacket, encrypted bool) ([]byte, int, error) {
	if cursor >= len(packet) {
		return nil, 0, inCategory(ErrInvalidMsgs, errors.New("error parsing SNMPV3: truncated packet"))
	}

	var r ber.Reader
	tag := PDUType(packet[cursor])
	switch {
	case encrypted != (tag == PDUType(OctetString)):
		return nil, 0, errScopedPDUType
	case encrypted:
		sp := response.SecurityParameters.usm()
		if err := sp.PrivacyProtocol.spec().CheckUse(sp.PrivacyKey); err != nil {
			return nil, 0, fmt.Errorf("usm: decrypting: %w", err)
		}
		plaintext, err := sp.decryptPacket(packet, cursor)
		if err != nil {
			return nil, 0, inCategory(ErrDecryption, err)
		}
		pr := ber.NewReader(plaintext)
		_, content, err := pr.Next()
		if err != nil {
			return nil, 0, inCategory(ErrDecryption, fmt.Errorf("error parsing SNMPV3 decrypted scoped PDU: %w", err))
		}
		packet = plaintext[:len(plaintext)-pr.Len()]
		r = ber.NewReader(content)
	case tag == Sequence:
		r = ber.NewReader(packet[cursor:])
		if _, err := r.SkipHeader(); err != nil {
			return nil, 0, inCategory(ErrInvalidMsgs, fmt.Errorf("error parsing SNMPV3 scoped PDU: %w", err))
		}
	default:
		return nil, 0, inCategory(ErrInvalidMsgs, errors.New("error parsing SNMPV3 scoped PDU"))
	}

	var fr fieldReader
	if v, ok := fr.string(&r, "SNMPV3 contextEngineID"); ok {
		response.ContextEngineID = v
	}
	if v, ok := fr.string(&r, "SNMPV3 contextName"); ok {
		response.ContextName = v
	}
	if fr.err != nil {
		if encrypted {
			return nil, 0, inCategory(ErrDecryption, fr.err)
		}
		return nil, 0, inCategory(ErrInvalidMsgs, fr.err)
	}
	return packet, len(packet) - r.Len(), nil
}
