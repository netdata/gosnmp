// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// AuthProtocol is the authentication protocol of an SNMPv3 user.
type AuthProtocol uint8

// Authentication protocols: HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414) and the
// HMAC-SHA-2 protocols (RFC 7860). The zero value means unset; other values
// are rejected.
const (
	NoAuth AuthProtocol = 1
	MD5    AuthProtocol = 2
	SHA    AuthProtocol = 3
	SHA224 AuthProtocol = 4
	SHA256 AuthProtocol = 5
	SHA384 AuthProtocol = 6
	SHA512 AuthProtocol = 7
)

//go:generate go tool -modfile=tools/go.mod stringer -type=AuthProtocol

// hash returns the hash of the protocol's HMAC and key derivation: MD5 for
// NoAuth, unset and unknown values.
func (authProtocol AuthProtocol) hash() crypto.Hash {
	if h := authProtocol.spec().Hash; h != 0 {
		return h
	}
	return crypto.MD5
}

// authSpecs describes the authentication protocols by value.
var authSpecs = [...]usm.Auth{ //nolint:gochecknoglobals // a read-only table
	MD5:    {Hash: crypto.MD5, MACLen: 12},
	SHA:    {Hash: crypto.SHA1, MACLen: 12},
	SHA224: {Hash: crypto.SHA224, MACLen: 16},
	SHA256: {Hash: crypto.SHA256, MACLen: 24},
	SHA384: {Hash: crypto.SHA384, MACLen: 32},
	SHA512: {Hash: crypto.SHA512, MACLen: usm.MaxMACLen},
}

// spec describes the protocol; NoAuth, unset and unknown values have no
// description.
func (authProtocol AuthProtocol) spec() usm.Auth {
	if int(authProtocol) < len(authSpecs) {
		return authSpecs[authProtocol]
	}
	return usm.Auth{}
}

// appendMACPlaceholder appends msgAuthenticationParameters as an outgoing
// message carries them until sign writes the digest into their content: an
// OCTET STRING of macLen zeros (empty without authentication).
func appendMACPlaceholder(dst []byte, macLen int) []byte {
	dst = ber.AppendHeader(dst, byte(OctetString), macLen)
	return append(dst, make([]byte, macLen)...)
}

// PrivProtocol is the privacy protocol of an SNMPv3 user.
type PrivProtocol uint8

// Privacy protocols: CBC-DES (RFC 3414), CFB128-AES-128 (RFC 3826) and AES-192
// and AES-256 with the Blumenthal or the Reeder key extension. The zero value
// means unset; other values are rejected.
const (
	NoPriv  PrivProtocol = 1
	DES     PrivProtocol = 2
	AES     PrivProtocol = 3
	AES192  PrivProtocol = 4 // Blumenthal-AES192
	AES256  PrivProtocol = 5 // Blumenthal-AES256
	AES192C PrivProtocol = 6 // Reeder-AES192
	AES256C PrivProtocol = 7 // Reeder-AES256
)

//go:generate go tool -modfile=tools/go.mod stringer -type=PrivProtocol

// privSpecs describes the privacy protocols by value.
var privSpecs = [...]usm.Priv{ //nolint:gochecknoglobals // a read-only table
	DES:     {Cipher: usm.DESCBC, KeyLen: 16},
	AES:     {Cipher: usm.AESCFB, KeyLen: 16},
	AES192:  {Cipher: usm.AESCFB, KeyLen: 24, Extension: usm.Blumenthal},
	AES256:  {Cipher: usm.AESCFB, KeyLen: 32, Extension: usm.Blumenthal},
	AES192C: {Cipher: usm.AESCFB, KeyLen: 24, Extension: usm.Reeder},
	AES256C: {Cipher: usm.AESCFB, KeyLen: 32, Extension: usm.Reeder},
}

// spec describes the protocol; NoPriv, unset and unknown values have no
// description.
func (privProtocol PrivProtocol) spec() usm.Priv {
	if int(privProtocol) < len(privSpecs) {
		return privSpecs[privProtocol]
	}
	return usm.Priv{}
}

// User is an SNMPv3 user of the User-based Security Model (RFC 3414): its
// name and the protocols and passphrases its keys derive from. It holds
// credentials only: the client, the decoders and Message.Encode localize the
// keys to the engine ID at hand (RFC 3414 section 2.6), through the package's
// cache of password-to-key results (see the package documentation, Keys).
type User struct {
	// Name is the user name (msgUserName), 1..32 octets.
	Name string

	// AuthProtocol is the authentication protocol and AuthPassphrase the
	// passphrase its key derives from; zero means unset.
	AuthProtocol   AuthProtocol
	AuthPassphrase string

	// PrivProtocol is the privacy protocol and PrivPassphrase the passphrase
	// its key derives from, with the authentication protocol's hash; zero
	// means unset.
	PrivProtocol   PrivProtocol
	PrivPassphrase string
}

// SecurityParameters are the User-based Security Model parameters of an
// SNMPv3 message (RFC 3414 section 2.4, UsmSecurityParameters). A decoded
// message holds what it carried, copied from its input, the fields read before
// a decoding error included; to encode one, the encoder takes the engine ID,
// boots, time and user name. They hold no secret.
type SecurityParameters struct {
	// The authoritative engine's ID, boots and time (RFC 3414 section 2.2).
	AuthoritativeEngineID    []byte
	AuthoritativeEngineBoots uint32
	AuthoritativeEngineTime  uint32

	// UserName is the user (msgUserName).
	UserName string

	// AuthenticationParameters and PrivacyParameters are the digest and the
	// salt of a decoded message. The encoder uses neither: it signs each
	// authenticated message and draws a new salt for each encrypted one.
	AuthenticationParameters []byte
	PrivacyParameters        []byte
}

// usmKeys are a user's keys localized to one engine ID (RFC 3414 section
// 2.6) and the protocols they serve: an authentication key of the size of its
// protocol's hash, a privacy key of its cipher's key length (DES: 16 octets),
// none for a protocol that is unset, NoAuth or NoPriv. The engine state,
// messages being encoded and the decoders share their slices and never write
// them.
type usmKeys struct {
	authProtocol AuthProtocol
	privProtocol PrivProtocol
	auth, priv   []byte
}

// localize returns u's keys localized to engineID, derived from the
// passphrases (the privacy key with the authentication protocol's hash), after
// checking the protocols; each protocol needs a key that fits it, so a protocol
// without a passphrase is the error of its missing key.
func (u *User) localize(engineID []byte) (usmKeys, error) {
	keys, err := u.keysAt(AuthPriv, engineID)
	if err != nil {
		return usmKeys{}, err
	}
	if u.AuthProtocol > NoAuth {
		if err := u.AuthProtocol.spec().CheckKey(keys.auth); err != nil {
			return usmKeys{}, fmt.Errorf("usm: %w", err)
		}
	}
	if u.PrivProtocol > NoPriv {
		if err := u.PrivProtocol.spec().CheckKey(keys.priv); err != nil {
			return usmKeys{}, fmt.Errorf("usm: %w", err)
		}
	}
	return keys, nil
}

// keysAt returns the keys of u localized to engineID that a message at level
// uses, after checking the protocols: the authentication key when the level
// asks for authentication, the privacy key when it asks for privacy, none
// without a passphrase. It does not check that a key fits its protocol: the
// signer and the cipher do.
func (u *User) keysAt(level SecurityLevel, engineID []byte) (usmKeys, error) {
	if err := u.checkProtocols(); err != nil {
		return usmKeys{}, err
	}
	keys := usmKeys{authProtocol: u.AuthProtocol, privProtocol: u.PrivProtocol}
	var err error
	if level.authFlag() {
		if keys.auth, err = u.authKey(engineID); err != nil {
			return usmKeys{}, err
		}
	}
	if level.privFlag() {
		if keys.priv, err = u.privKey(engineID); err != nil {
			return usmKeys{}, err
		}
	}
	return keys, nil
}

// authKey returns u's authentication key localized to engineID; none without
// an authentication protocol or passphrase.
func (u *User) authKey(engineID []byte) ([]byte, error) {
	if u.AuthProtocol <= NoAuth || u.AuthPassphrase == "" {
		return nil, nil
	}
	return passwordCache.LocalizedKey(u.AuthProtocol.hash(), u.AuthPassphrase, engineID)
}

// privKey returns u's privacy key localized to engineID, which derives with
// the authentication protocol's hash; none without a privacy protocol or
// passphrase.
func (u *User) privKey(engineID []byte) ([]byte, error) {
	if u.PrivProtocol <= NoPriv || u.PrivPassphrase == "" {
		return nil, nil
	}
	return passwordCache.PrivacyKey(u.PrivProtocol.spec(), u.AuthProtocol.hash(), u.PrivPassphrase, engineID)
}

var (
	errAuthProtocolRequired = errors.New("User.AuthProtocol is required")
	errPrivProtocolRequired = errors.New("User.PrivProtocol is required")
)

// checkProtocols rejects authentication and privacy protocol values outside
// the defined sets.
func (u *User) checkProtocols() error {
	if u.AuthProtocol > SHA512 {
		return fmt.Errorf("User.AuthProtocol %v is not supported", u.AuthProtocol)
	}
	if u.PrivProtocol > AES256C {
		return fmt.Errorf("User.PrivProtocol %v is not supported", u.PrivProtocol)
	}
	return nil
}

// missingProtocol reports which protocol the security level needs and the
// protocols auth and priv lack: an authentication protocol for the authFlag, a
// privacy protocol for the privFlag. It is the one rule of what a level needs,
// for outgoing messages (checkLevel, validate) and incoming ones (receiveV3,
// receiveReply).
func missingProtocol(auth AuthProtocol, priv PrivProtocol, level SecurityLevel) (needAuth, needPriv bool) {
	return level.authFlag() && auth <= NoAuth, level.privFlag() && priv <= NoPriv
}

// checkLevel rejects a security level that asks for authentication or privacy
// without a protocol for it among auth and priv, authentication first.
func checkLevel(auth AuthProtocol, priv PrivProtocol, level SecurityLevel) error {
	switch needAuth, needPriv := missingProtocol(auth, priv, level); {
	case needAuth:
		return errAuthProtocolRequired
	case needPriv:
		return errPrivProtocolRequired
	}
	return nil
}

// levelFloor is the security level a trap receiver requires of a message for
// u at the least: authentication when u has an authentication protocol,
// privacy optional.
func (u *User) levelFloor() SecurityLevel {
	if u.AuthProtocol > NoAuth {
		return AuthNoPriv
	}
	return NoAuthNoPriv
}

// validate checks u for the security level: valid protocols, one of the three
// levels, the protocols the level needs, a name of 1..32 octets, and a
// passphrase for each protocol.
func (u *User) validate(level SecurityLevel) error {
	if err := u.checkProtocols(); err != nil {
		return err
	}
	if !level.valid() {
		return errInvalidLevel
	}
	if err := checkLevel(u.AuthProtocol, u.PrivProtocol, level); err != nil {
		return err
	}
	if u.Name == "" {
		return fmt.Errorf("User.Name is required")
	}
	if len(u.Name) > maxUserNameLen {
		return fmt.Errorf("User.Name is %d octets, more than %d", len(u.Name), maxUserNameLen)
	}
	return u.checkPassphrases()
}

// checkPassphrases rejects a protocol without a passphrase to derive its key
// from.
func (u *User) checkPassphrases() error {
	if u.PrivProtocol > NoPriv && u.PrivPassphrase == "" {
		return fmt.Errorf("User.PrivPassphrase is required when a privacy protocol is specified")
	}
	if u.AuthProtocol > NoAuth && u.AuthPassphrase == "" {
		return fmt.Errorf("User.AuthPassphrase is required when an authentication protocol is specified")
	}
	return nil
}

// checkWireFields checks the fields of h an outgoing message carries against
// their ranges (RFC 3414 section 2.4): engine boots and time of at most
// 2147483647 and a user name of at most 32 octets.
func (h *SecurityParameters) checkWireFields() error {
	switch {
	case h.AuthoritativeEngineBoots > maxEngineValue:
		return fmt.Errorf("unable to marshal msgAuthoritativeEngineBoots %d: more than %d", h.AuthoritativeEngineBoots, maxEngineValue)
	case h.AuthoritativeEngineTime > maxEngineValue:
		return fmt.Errorf("unable to marshal msgAuthoritativeEngineTime %d: more than %d", h.AuthoritativeEngineTime, maxEngineValue)
	case len(h.UserName) > maxUserNameLen:
		return fmt.Errorf("unable to marshal msgUserName of %d octets: more than %d", len(h.UserName), maxUserNameLen)
	}
	return nil
}

// passwordCache derives the keys of every user.
var passwordCache = usm.NewCache() //nolint:gochecknoglobals // one cache for every client and receiver

// newDiscoveryPacket returns the request that discovers the authoritative
// engine's ID, boots and time (RFC 3414 section 4): an unauthenticated Get
// without variable bindings and with empty security parameters, which the
// encoder sends reportable as every request.
func newDiscoveryPacket() *Message {
	return &Message{
		Version:       Version3,
		SecurityLevel: NoAuthNoPriv,
		PDUType:       GetRequest,
	}
}

// sign writes the digest of packet, an outgoing message whose
// msgAuthenticationParameters content at offset auth still holds the zeros of
// appendMACPlaceholder, into that content.
func (k *usmKeys) sign(packet []byte, auth int) error {
	msgDigest, err := k.authProtocol.spec().Digest(k.auth, packet)
	if err != nil {
		return err
	}
	copy(packet[auth:], msgDigest)
	return nil
}

// encrypt returns the ciphertext of the scoped PDU of a message whose USM
// parameters are h.
func (k *usmKeys) encrypt(h *SecurityParameters, scopedPdu, salt []byte) ([]byte, error) {
	return k.privProtocol.spec().Encrypt(k.priv, salt, h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime, scopedPdu)
}

// decrypt returns the plaintext of ciphertext, the scoped PDU of a message
// whose USM parameters are h, in a new buffer.
func (k *usmKeys) decrypt(h *SecurityParameters, ciphertext []byte) ([]byte, error) {
	return k.privProtocol.spec().Decrypt(k.priv, h.PrivacyParameters, h.AuthoritativeEngineBoots,
		h.AuthoritativeEngineTime, ciphertext)
}

// marshal appends the User Security Model parameters: a SEQUENCE of the
// authoritative engine ID, boots and time, the user name, the authentication
// parameters (the zero placeholder sign fills in, of the size of the
// authentication protocol's digest when level asks for authentication, or
// empty) and the privacy parameters (the salt, or empty). It also returns the
// offset of the authentication parameters' content in dst.
func (h *SecurityParameters) marshal(dst []byte, level SecurityLevel, auth AuthProtocol, salt []byte) ([]byte, int) {
	dst, start := ber.Begin(dst, ber.Sequence)
	dst = appendOctets(dst, OctetString, h.AuthoritativeEngineID)
	dst = appendUint(dst, Integer, uint64(h.AuthoritativeEngineBoots))
	dst = appendUint(dst, Integer, uint64(h.AuthoritativeEngineTime))
	dst = appendOctets(dst, OctetString, h.UserName)
	macLen := 0
	if level.authFlag() {
		macLen = auth.spec().MACLen
	}
	dst = appendMACPlaceholder(dst, macLen)
	off := len(dst) - macLen
	dst = appendOctets(dst, OctetString, salt)
	return ber.EndMoving(dst, start, off)
}

// tableUser is a user a receiver decodes messages for, with its keys localized
// to the engine ID it is registered for, the only one whose messages it
// decodes (Receiver).
type tableUser struct {
	user User
	keys usmKeys
}

// inbound is an SNMPv3 message in security processing for one user (RFC 3414
// section 3.2): the message, which is never written, where its authentication
// parameters and msgData are, the user and its keys for the message's engine
// ID.
type inbound struct {
	msg  []byte
	wire v3Wire
	user *User
	keys usmKeys
	// derive is set when the keys derive for the message's engine ID: the
	// authentication key in receiveV3, the privacy key to decrypt (scopedPDU).
	derive bool
}

// receiveV3 starts the security processing of the SNMPv3 message msg, whose
// header is in result and w, for user, with keys, user's keys localized to the
// message's engine ID (nil: they derive for it): the checks of RFC
// 3414 section 3.2 made before the digest, valid protocols, and for the keys
// to derive a passphrase for each protocol (local failures); the protocols the
// message's level asks for (step 5, ErrUnknownSecurityLevel); then, to derive,
// the authentication key when the level asks for authentication (to check the
// digest).
func receiveV3(msg []byte, w v3Wire, result *Message, user *User, keys *usmKeys) (inbound, error) {
	in := inbound{msg: msg, wire: w, user: user, derive: keys == nil}
	if err := user.checkProtocols(); err != nil {
		return inbound{}, err
	}
	h := &result.SecurityParameters
	if in.derive {
		if err := user.checkPassphrases(); err != nil {
			return inbound{}, err
		}
	} else {
		in.keys = *keys
	}
	switch needAuth, needPriv := missingProtocol(user.AuthProtocol, user.PrivProtocol, result.SecurityLevel); {
	case needAuth:
		return inbound{}, errNoAuthForMsg
	case needPriv:
		return inbound{}, errNoPrivForMsg
	}
	in.keys.authProtocol, in.keys.privProtocol = user.AuthProtocol, user.PrivProtocol
	if in.derive && result.SecurityLevel.authFlag() {
		key, err := user.authKey(h.AuthoritativeEngineID)
		if err != nil {
			return inbound{}, err
		}
		in.keys.auth = key
	}
	return in, nil
}

// verify checks the digest of a message that asks for authentication with the
// keys (RFC 3414 section 3.2 step 6): errWrongDigest when it does not check, a
// key that does not fit the protocol a local error.
func (in *inbound) verify() error {
	ok, err := in.keys.authProtocol.spec().VerifyField(in.keys.auth, in.msg, in.wire.authOff, in.wire.authLen)
	if err != nil {
		return err
	}
	if !ok {
		return errWrongDigest
	}
	return nil
}

// scopedPDU reads the scoped PDU into result (unmarshalScopedPDU), decrypted
// exactly when the message's privFlag is set, deriving the privacy key for the
// message's engine ID first when the keys derive.
func (in *inbound) scopedPDU(result *Message) ([]byte, int, error) {
	encrypted := result.SecurityLevel.privFlag()
	if encrypted && in.derive && in.wire.scoped < len(in.msg) && PDUType(in.msg[in.wire.scoped]) == PDUType(OctetString) {
		key, err := in.user.privKey(result.SecurityParameters.AuthoritativeEngineID)
		if err != nil {
			return nil, 0, err
		}
		in.keys.priv = key
	}
	return unmarshalScopedPDU(in.msg, in.wire.scoped, result, encrypted, &in.keys)
}

// usmField prefixes the names of the USM fields in decode errors.
const usmField = "SNMPV3 User Security Model "
