// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// SecurityLevel is the security level of an SNMPv3 message (RFC 3411 section
// 3.4.3): the authFlag and privFlag of its msgFlags octet (RFC 3412 section
// 6.4). The encoder sets the octet's reportableFlag itself, by the PDU type,
// and a decoded message holds the level only.
type SecurityLevel uint8

// The security levels.
const (
	NoAuthNoPriv SecurityLevel = 0x0 // No authentication, and no privacy
	AuthNoPriv   SecurityLevel = 0x1 // Authentication and no privacy
	AuthPriv     SecurityLevel = 0x3 // Authentication and privacy
)

// reportableFlag is the reportableFlag of the msgFlags octet (RFC 3412 section
// 6.4), set for a PDU of the Confirmed Class and clear for the others
// (appendV3Header).
const reportableFlag = 0x4

// authFlag reports whether f has the authFlag (bit 0x1, RFC 3412 section 6.4)
// set: the message asks for authentication. A set flag is a request, not
// proof that the message was authenticated.
func (f SecurityLevel) authFlag() bool { return f&0x1 != 0 }

// privFlag reports whether f has the privFlag (bit 0x2) set: the message asks
// for privacy. Without the authFlag the combination is invalid (RFC 3412
// section 7.2 step 5 d).
func (f SecurityLevel) privFlag() bool { return f&0x2 != 0 }

// valid reports whether f is one of the three security levels.
func (f SecurityLevel) valid() bool { return f == NoAuthNoPriv || f == AuthNoPriv || f == AuthPriv }

//go:generate go tool -modfile=tools/go.mod stringer -type=SecurityLevel

// usmSecurityModel is the msgSecurityModel of the User-based Security Model
// (RFC 3414), the only security model the package implements: the encoder
// writes it, and the decoder accepts no other (RFC 3412 section 7.2 step 4).
const usmSecurityModel = 3

// validateParametersV3 checks the client's SNMPv3 configuration: a user that
// fits SecurityLevel.
func (x *Client) validateParametersV3() error {
	return x.User.validate(x.SecurityLevel)
}

// sign writes the digest of the marshalled SNMPv3 message msg into the
// content of its msgAuthenticationParameters, at offset auth, with keys when
// the level asks for authentication; a key that does not fit the protocol is
// an error (usm.Auth.CheckKey).
func (packet *Message) sign(msg []byte, auth int, keys *usmKeys) ([]byte, error) {
	if packet.SecurityLevel.authFlag() {
		if err := keys.sign(msg, auth); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// errNotAuthentic is the error the rejections of an unknown user and a wrong
// digest wrap: the message is not authentic.
var errNotAuthentic = errors.New("incoming packet is not authentic, discarding")

// The rejections of the security processing (RFC 3414 section 3.2), in the
// order of its steps; the minimum level a receiver requires comes after
// them, and RFC 3412 section 7.2 step 13 a, which counts nothing, last.
var (
	errNoEngineID    = inCategory(ErrUnknownEngineID, errors.New("incoming packet names no authoritative engine ID, discarding"))
	errUnknownEngine = inCategory(ErrUnknownEngineID, errors.New("incoming packet names an engine ID the receiver has no user for, discarding"))
	errUnknownUser   = inCategory(ErrUnknownUsername, errNotAuthentic)
	errNoAuthForMsg  = inCategory(ErrUnknownSecurityLevel, errors.New("error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message"))
	errNoPrivForMsg  = inCategory(ErrUnknownSecurityLevel, errors.New("error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message"))
	errWrongDigest   = inCategory(ErrWrongDigest, errNotAuthentic)
	errNotInTime     = inCategory(ErrNotInTimeWindow, errors.New("incoming packet is not in the time window, discarding"))
	errBelowMinimum  = inCategory(ErrUnknownSecurityLevel, errors.New("incoming packet has a lower security level than its user requires, discarding"))
	// errNotLocalEngine is the error of a request or an inform naming another
	// engine ID than the receiver's: its answer would come from that engine.
	errNotLocalEngine = inCategory(ErrUnknownEngineID, errors.New("incoming packet asks another engine ID than the receiver's for an answer, discarding"))
)

// errScopedPDUType is the error of a scoped PDU whose type does not match the
// privFlag: a SEQUENCE in plaintext, an OCTET STRING encrypted (RFC 3412
// section 6.7, ScopedPduData). The message does not parse, as net-snmp v5.9.4
// counts both cases.
var errScopedPDUType = inCategory(ErrASNParse, errors.New("error parsing SNMPV3 scoped PDU: its type does not match the privacy flag"))

// appendV3 appends the SNMPv3 part of a message after the version: the header
// (msgGlobalData), the security parameters in an OCTET STRING and the scoped
// PDU, once the header fields (checkV3Header) fit and keys has the protocols
// the level needs. It also returns the offset of the
// msgAuthenticationParameters content in dst, where sign writes the digest. A
// message the level encrypts gets the next salt of usm.Salts, never the
// packet's PrivacyParameters, so that no two messages share one, whatever the
// caller copied into the packet.
func (packet *Message) appendV3(dst []byte, keys *usmKeys) ([]byte, int, error) {
	if err := packet.checkV3Header(); err != nil {
		return nil, 0, err
	}
	if err := checkLevel(keys.authProtocol, keys.privProtocol, packet.SecurityLevel); err != nil {
		return nil, 0, err
	}
	if err := packet.SecurityParameters.checkWireFields(); err != nil {
		return nil, 0, err
	}
	var salt []byte
	if packet.SecurityLevel.privFlag() {
		next := usm.Salts.Next()
		salt = next[:]
	}
	dst = packet.appendV3Header(dst)
	dst, start := ber.Begin(dst, byte(OctetString))
	dst, auth := packet.SecurityParameters.marshal(dst, packet.SecurityLevel, keys.authProtocol, salt)
	dst, auth = ber.EndMoving(dst, start, auth)
	dst, err := packet.appendV3ScopedPDU(dst, keys, salt)
	return dst, auth, err
}

// Ranges of the SNMPv3 header fields (RFC 3412 section 6).
const (
	maxMsgID       = 2147483647
	minMsgMaxSize  = 484
	maxMsgMaxSize  = 2147483647
	maxUserNameLen = 32 // msgUserName octets (RFC 3414 section 2.4)
	// The longest msgAuthoritativeEngineID the decoder takes, net-snmp
	// v5.9.4's: twice RFC 3411's 32 octets. net-snmp's agent drops a message
	// naming a longer one without a Report, so a client that took one from a
	// forged answer would never learn that the agent does not know it.
	maxDecodedEngineIDLen = 64
)

// checkV3Header checks the SNMPv3 header fields of an outgoing message: a
// msgID of at most 2147483647, a MsgMaxSize of 0 (the receive buffer's size) or
// 484..2147483647, and one of the three security levels (privacy without
// authentication has its own error).
func (packet *Message) checkV3Header() error {
	switch {
	case packet.MsgID > maxMsgID:
		return fmt.Errorf("unable to marshal SNMPv3 msgID %d: more than %d", packet.MsgID, maxMsgID)
	case packet.MsgMaxSize != 0 && (packet.MsgMaxSize < minMsgMaxSize || packet.MsgMaxSize > maxMsgMaxSize):
		return fmt.Errorf("unable to marshal SNMPv3 msgMaxSize %d: outside %d..%d", packet.MsgMaxSize, minMsgMaxSize, maxMsgMaxSize)
	case packet.SecurityLevel.privFlag() && !packet.SecurityLevel.authFlag():
		return errors.New("unable to marshal SNMPv3 msgFlags: privacy without authentication")
	case !packet.SecurityLevel.valid():
		return fmt.Errorf("unable to marshal SNMPv3 security level %d: not NoAuthNoPriv, AuthNoPriv or AuthPriv", packet.SecurityLevel)
	}
	return nil
}

// appendV3Header appends msgGlobalData: the message ID, the maximum message
// size (rxBufSize unless set), the flags and the security model (3), whose
// ranges checkV3Header checked. The flags octet holds the security level and
// the reportableFlag, set for a PDU of the Confirmed Class and clear for the
// others (RFC 3412 section 6.4).
func (packet *Message) appendV3Header(dst []byte) []byte {
	dst, start := ber.Begin(dst, ber.Sequence)
	dst = appendUint(dst, Integer, uint64(packet.MsgID))
	maxSize := uint32(rxBufSize)
	if packet.MsgMaxSize != 0 {
		maxSize = packet.MsgMaxSize
	}
	dst = appendUint(dst, Integer, uint64(maxSize))
	flags := byte(packet.SecurityLevel)
	if packet.PDUType.confirmed() {
		flags |= reportableFlag
	}
	dst = append(dst, byte(OctetString), 1, flags)
	dst = append(dst, byte(Integer), 1, usmSecurityModel)
	return ber.End(dst, start)
}

// appendV3ScopedPDU appends the scoped PDU: a SEQUENCE of the context engine
// ID, the context name and the PDU, encrypted with keys and salt into an OCTET
// STRING when there is a salt (appendV3 draws it when the level asks for
// privacy).
func (packet *Message) appendV3ScopedPDU(dst []byte, keys *usmKeys, salt []byte) ([]byte, error) {
	scoped := len(dst)
	dst, start := ber.Begin(dst, ber.Sequence)
	dst = appendOctets(dst, OctetString, packet.ContextEngineID)
	dst = appendOctets(dst, OctetString, packet.ContextName)
	dst, err := packet.appendPDU(dst)
	if err != nil {
		return nil, err
	}
	dst = ber.End(dst, start)
	if salt != nil {
		ciphertext, err := keys.encrypt(&packet.SecurityParameters, dst[scoped:], salt)
		if err != nil {
			return nil, err
		}
		dst = appendOctets(dst[:scoped], OctetString, ciphertext)
	}
	return dst, nil
}

// v3Wire is where the parts of an SNMPv3 message are that its security
// processing reads besides the header fields parseV3 writes into the message.
type v3Wire struct {
	// msgIDRead reports that the msgID decoded.
	msgIDRead bool
	// authOff and authLen locate the content of msgAuthenticationParameters;
	// authOff is -1 until it is read.
	authOff, authLen int
	// scoped is the offset of msgData.
	scoped int
	// reportable is the reportableFlag of msgFlags.
	reportable bool
}

// errNotUSM is the error of an SNMPv3 message of another security model than
// the User-based Security Model, the only one the package implements (RFC
// 3412 section 7.2 step 4).
var errNotUSM = errors.New("error parsing SNMPV3: the security model is not USM")

// errInvalidLevel is the error of a client's security level that is not one
// of the three (validate).
var errInvalidLevel = errors.New("validate: SecurityLevel must be populated with an appropriate security level")

// errMsgFlags is the error of an SNMPv3 msgFlags that is not an OCTET STRING
// of one octet (RFC 3412 section 6).
var errMsgFlags = errors.New("error parsing SNMPV3 msgFlags: not an OCTET STRING of one octet")

// errPrivWithoutAuth is the error of an SNMPv3 msgFlags that asks for privacy
// without authentication (RFC 3412 section 7.2 step 5 d).
var errPrivWithoutAuth = errors.New("error parsing SNMPV3 msgFlags: privacy without authentication")

// v3ParseError returns err, an error of parseV3, in the category of its
// counter, as net-snmp v5.9.4 counts it: ErrUnknownSecurityModels for another
// security model (RFC 3412 section 7.2 step 4), ErrInvalidMsgs for privacy
// without authentication (step 5 d), ErrASNParse for the rest, a header field
// outside its range included (step 2, RFC 3414 section 3.2 step 1).
func v3ParseError(err error) error {
	switch {
	case errors.Is(err, errNotUSM):
		return inCategory(ErrUnknownSecurityModels, err)
	case errors.Is(err, errPrivWithoutAuth):
		return inCategory(ErrInvalidMsgs, err)
	}
	return inCategory(ErrASNParse, err)
}

// parseV3 reads the SNMPv3 header at packet[cursor:]: the message ID, maximum
// size, the security level of msgFlags and the USM fields (copies) into
// response, each as it decodes, and the offsets security processing needs into
// the v3Wire it returns. It takes
// net-snmp v5.9.4's extents: every declared length must fit what remains; the
// fields of msgGlobalData are read against the rest of the message, whatever
// its declared length; the USM fields are bounded by their SEQUENCE and the
// SEQUENCE by the security parameters' OCTET STRING; msgData starts right
// after msgPrivacyParameters. It takes net-snmp's field rules (RFC 3412
// section 6, RFC 3414 section 2.4), each range applying once the INTEGER is
// cut to 32 bits: msgID an INTEGER of 0..2147483647, msgMaxSize one of
// 484..2147483647, msgFlags an OCTET STRING of one octet, the security model
// an INTEGER of 1..2147483647, the User-based Security Model's 3 (another
// value is another model), and then the flags may not ask for privacy without
// authentication; the USM fields of their
// types, the engine boots and time within 0..2147483647 (RFC 3414 section 3.2
// step 1) and the user name at most 32 octets. It writes nothing into packet
// and derives no key.
func parseV3(packet []byte, cursor int, response *Message) (v3Wire, error) {
	w := v3Wire{authOff: -1}
	if packet[cursor] != ber.Sequence {
		return w, errors.New("invalid SNMPV3 Header")
	}
	start, _, err := tlvAt(packet, cursor, len(packet))
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 header: %w", err)
	}

	r := ber.NewReader(packet[start:])
	msgID, err := readInt32(&r)
	if err == nil && msgID < 0 {
		err = fmt.Errorf("%d is outside 0..%d", msgID, maxMsgID)
	}
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 message ID: %w", err)
	}
	response.MsgID = uint32(msgID) //nolint:gosec // not negative
	w.msgIDRead = true
	maxSize, err := readInt32(&r)
	if err == nil && maxSize < minMsgMaxSize {
		err = fmt.Errorf("%d is outside %d..%d", maxSize, minMsgMaxSize, maxMsgMaxSize)
	}
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 msgMaxSize: %w", err)
	}
	response.MsgMaxSize = uint32(maxSize) //nolint:gosec // at least minMsgMaxSize
	flags, err := readOctets(&r)
	switch {
	case errors.Is(err, errNotOctets):
		return w, errMsgFlags
	case err != nil:
		return w, fmt.Errorf("error parsing SNMPV3 msgFlags: %w", err)
	case len(flags) != 1:
		return w, errMsgFlags
	}
	// The level: the reportableFlag and the reserved bits stay on the wire.
	response.SecurityLevel = SecurityLevel(flags[0]) & AuthPriv
	w.reportable = flags[0]&reportableFlag != 0
	model, err := readInt32(&r)
	if err == nil && model < 1 {
		err = fmt.Errorf("%d is outside 1..2147483647", model)
	}
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 msgSecModel: %w", err)
	}
	if model != usmSecurityModel {
		return w, errNotUSM
	}
	if response.SecurityLevel.privFlag() && !response.SecurityLevel.authFlag() {
		return w, errPrivWithoutAuth
	}
	if r.Len() == 0 {
		return w, errors.New("error parsing SNMPV3: nothing after the security model")
	}

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
	if packet[params] != ber.Sequence {
		return w, errors.New("error parsing SNMPV3 User Security Model parameters")
	}
	usmStart, usmEnd, err := tlvAt(packet, params, paramsEnd)
	if err != nil {
		return w, fmt.Errorf("error parsing SNMPV3 User Security Model parameters: %w", err)
	}

	ur := ber.NewReader(packet[usmStart:usmEnd])
	h := &response.SecurityParameters
	engineID, err := usmOctets(&ur, "msgAuthoritativeEngineID")
	if err != nil {
		return w, err
	}
	if len(engineID) > maxDecodedEngineIDLen {
		return w, fmt.Errorf("error parsing %smsgAuthoritativeEngineID: %d octets, more than %d", usmField, len(engineID), maxDecodedEngineIDLen)
	}
	h.AuthoritativeEngineID = bytes.Clone(engineID)
	if h.AuthoritativeEngineBoots, err = usmEngineValue(&ur, "msgAuthoritativeEngineBoots"); err != nil {
		return w, err
	}
	if h.AuthoritativeEngineTime, err = usmEngineValue(&ur, "msgAuthoritativeEngineTime"); err != nil {
		return w, err
	}
	userName, err := usmOctets(&ur, "msgUserName")
	if err != nil {
		return w, err
	}
	if len(userName) > maxUserNameLen {
		return w, fmt.Errorf("error parsing %smsgUserName: %d octets, more than %d", usmField, len(userName), maxUserNameLen)
	}
	h.UserName = string(userName)
	authAt := usmEnd - ur.Len()
	authParams, err := usmOctets(&ur, "msgAuthenticationParameters")
	if err != nil {
		return w, err
	}
	h.AuthenticationParameters = bytes.Clone(authParams)
	authStart, authEnd, _ := tlvAt(packet, authAt, usmEnd) // read above
	w.authOff, w.authLen = authStart, authEnd-authStart
	privParams, err := usmOctets(&ur, "msgPrivacyParameters")
	if err != nil {
		return w, err
	}
	h.PrivacyParameters = bytes.Clone(privParams)
	w.scoped = usmEnd - ur.Len()
	return w, nil
}

// usmOctets reads the next USM field, which must be an OCTET STRING (RFC 3414
// section 2.4); the result aliases the input.
func usmOctets(r *ber.Reader, name string) ([]byte, error) {
	v, err := readOctets(r)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s%s: %w", usmField, name, err)
	}
	return v, nil
}

// usmEngineValue reads msgAuthoritativeEngineBoots or
// msgAuthoritativeEngineTime: an INTEGER of at most maxEngineValue (RFC 3414
// section 2.4) once cut to 32 bits, as net-snmp v5.9.4 cuts it.
func usmEngineValue(r *ber.Reader, name string) (uint32, error) {
	v, err := readInt32(r)
	if err == nil && v < 0 {
		err = fmt.Errorf("%d is outside 0..%d", v, maxEngineValue)
	}
	if err != nil {
		return 0, fmt.Errorf("error parsing %s%s: %w", usmField, name, err)
	}
	return uint32(v), nil //nolint:gosec // not negative
}

// tlvAt returns the extent of the content of the TLV at packet[off:end],
// whose declared length must fit there.
func tlvAt(packet []byte, off, end int) (start, stop int, err error) {
	length, header, err := ber.Length(packet[off:end])
	if err != nil {
		return 0, 0, err
	}
	if length > uint64(end-off) { //nolint:gosec // off <= end
		return 0, 0, ber.ErrTruncated
	}
	return off + header, off + int(length), nil //nolint:gosec // at most end-off
}

// unmarshalScopedPDU reads the scoped PDU at packet[cursor:] and returns the
// buffer holding the PDU and its offset there (RFC 3414 section 3.2 step 8):
// an OCTET STRING decrypted with keys into a new buffer when encrypted (the
// message's privFlag), a plaintext SEQUENCE in packet otherwise; packet is not
// written.
// Either must fit the rest of the message, with net-snmp v5.9.4's extents: the
// ciphertext is the OCTET STRING's content, as declared (RFC 3414 section 3.2
// step 8), and octets after it are ignored; a plaintext SEQUENCE's fields are
// read against the rest of the message, whatever its declared length. The
// decrypted plaintext must be a SEQUENCE, which cuts off the padding, and
// contextEngineID and contextName OCTET STRINGs. A scoped PDU of the other
// type, or one that does not parse before decryption, is ErrASNParse; a
// decryption failure, or a decrypted plaintext that does not parse, as with a
// wrong key, ErrDecryption (net-snmp counts the latter as a parse error); a key
// the process cannot decrypt with (usm.Priv.CheckUse) neither.
func unmarshalScopedPDU(packet []byte, cursor int, response *Message, encrypted bool, keys *usmKeys) ([]byte, int, error) {
	if cursor >= len(packet) {
		return nil, 0, inCategory(ErrASNParse, errors.New("error parsing SNMPV3: truncated packet"))
	}

	var r ber.Reader
	tag := packet[cursor]
	if encrypted != (tag == byte(OctetString)) {
		return nil, 0, errScopedPDUType
	}
	if tag != ber.Sequence && tag != byte(OctetString) {
		return nil, 0, inCategory(ErrASNParse, errors.New("error parsing SNMPV3 scoped PDU"))
	}
	start, stop, err := tlvAt(packet, cursor, len(packet))
	if err != nil {
		return nil, 0, inCategory(ErrASNParse, fmt.Errorf("error parsing SNMPV3 scoped PDU: %w", err))
	}
	if encrypted {
		if err := keys.privProtocol.spec().CheckUse(keys.priv); err != nil {
			return nil, 0, fmt.Errorf("usm: decrypting: %w", err)
		}
		plaintext, err := keys.decrypt(&response.SecurityParameters, packet[start:stop])
		if err != nil {
			return nil, 0, inCategory(ErrDecryption, err)
		}
		pr := ber.NewReader(plaintext)
		tag, content, err := pr.Next()
		if err == nil && tag != ber.Sequence {
			err = fmt.Errorf("tag %#x, not a SEQUENCE", tag)
		}
		if err != nil {
			return nil, 0, inCategory(ErrDecryption, fmt.Errorf("error parsing SNMPV3 decrypted scoped PDU: %w", err))
		}
		packet = plaintext[:len(plaintext)-pr.Len()]
		r = ber.NewReader(content)
	} else {
		r = ber.NewReader(packet[start:])
	}

	if err := readContext(&r, response); err != nil {
		if encrypted {
			return nil, 0, inCategory(ErrDecryption, err)
		}
		return nil, 0, inCategory(ErrASNParse, err)
	}
	return packet, len(packet) - r.Len(), nil
}

// readContext reads the scoped PDU's contextEngineID (a copy) and contextName,
// OCTET STRINGs, into response; a field read before an error stays set.
func readContext(r *ber.Reader, response *Message) error {
	engineID, err := readOctets(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 contextEngineID: %w", err)
	}
	response.ContextEngineID = bytes.Clone(engineID)
	name, err := readOctets(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 contextName: %w", err)
	}
	response.ContextName = string(name)
	return nil
}
