// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// SnmpV3AuthProtocol is the authentication protocol of an SNMPv3 user.
type SnmpV3AuthProtocol uint8

// Authentication protocols: HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414) and the
// HMAC-SHA-2 protocols (RFC 7860). The zero value means unset; other values
// are rejected.
const (
	NoAuth SnmpV3AuthProtocol = 1
	MD5    SnmpV3AuthProtocol = 2
	SHA    SnmpV3AuthProtocol = 3
	SHA224 SnmpV3AuthProtocol = 4
	SHA256 SnmpV3AuthProtocol = 5
	SHA384 SnmpV3AuthProtocol = 6
	SHA512 SnmpV3AuthProtocol = 7
)

//go:generate go tool -modfile=tools/go.mod stringer -type=SnmpV3AuthProtocol

// HashType returns the hash of the protocol's HMAC and key derivation: MD5
// for NoAuth, unset and unknown values.
func (authProtocol SnmpV3AuthProtocol) HashType() crypto.Hash {
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
func (authProtocol SnmpV3AuthProtocol) spec() usm.Auth {
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

// SnmpV3PrivProtocol is the privacy protocol of an SNMPv3 user.
type SnmpV3PrivProtocol uint8

// Privacy protocols: CBC-DES (RFC 3414), CFB128-AES-128 (RFC 3826) and AES-192
// and AES-256 with the Blumenthal or the Reeder key extension. The zero value
// means unset; other values are rejected.
const (
	NoPriv  SnmpV3PrivProtocol = 1
	DES     SnmpV3PrivProtocol = 2
	AES     SnmpV3PrivProtocol = 3
	AES192  SnmpV3PrivProtocol = 4 // Blumenthal-AES192
	AES256  SnmpV3PrivProtocol = 5 // Blumenthal-AES256
	AES192C SnmpV3PrivProtocol = 6 // Reeder-AES192
	AES256C SnmpV3PrivProtocol = 7 // Reeder-AES256
)

//go:generate go tool -modfile=tools/go.mod stringer -type=SnmpV3PrivProtocol

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
func (privProtocol SnmpV3PrivProtocol) spec() usm.Priv {
	if int(privProtocol) < len(privSpecs) {
		return privSpecs[privProtocol]
	}
	return usm.Priv{}
}

// UsmSecurityParameters are the parameters of the User-based Security Model
// (RFC 3414): the user's credentials, and the agent's engine parameters the
// client learns. A client keeps them in GoSNMP.SecurityParameters, and each
// message carries a copy.
type UsmSecurityParameters struct {
	// mu serializes key initialization, the engine and logger updates, Copy
	// and Log.
	mu sync.Mutex

	// The authoritative engine's ID, boots and time (RFC 3414 section 2.2),
	// which discovery and answers set; an AuthoritativeEngineID set by the
	// caller skips the discovery.
	AuthoritativeEngineID    string
	AuthoritativeEngineBoots uint32
	AuthoritativeEngineTime  uint32

	// UserName is the user (msgUserName).
	UserName string

	// AuthenticationParameters and PrivacyParameters are the digest and salt
	// decoded from a message. The encoder uses neither: it signs each
	// authenticated message and draws a new salt for each encrypted one.
	AuthenticationParameters string
	PrivacyParameters        []byte

	// The protocols; zero means unset.
	AuthenticationProtocol SnmpV3AuthProtocol
	PrivacyProtocol        SnmpV3PrivProtocol

	// The passphrases the keys derive from.
	AuthenticationPassphrase string
	PrivacyPassphrase        string

	// SecretKey and PrivacyKey are the authentication and privacy keys,
	// localized to AuthoritativeEngineID: an authentication key of the size of
	// its protocol's hash, a privacy key of its cipher's key length (DES: 16
	// octets). InitSecurityKeys derives the missing ones from the passphrases.
	// A new engine ID replaces both with keys derived for it from the
	// passphrases, so parameters with a protocol whose passphrase is empty, a
	// key given without one among them, cannot take another engine ID: as a
	// trap receiver's or SnmpDecodePacket's they decode no message naming
	// another one, and discovery cannot give them one.
	SecretKey  []byte
	PrivacyKey []byte

	// Logger receives Log's output; Connect sets the client's.
	Logger Logger
}

func (sp *UsmSecurityParameters) usm() *UsmSecurityParameters {
	return sp
}

// Description returns the user name, the engine ID in hex, the protocols and
// both passphrases. Use SafeString for anything that may be logged.
func (sp *UsmSecurityParameters) Description() string {
	var sb strings.Builder
	sb.WriteString("user=")
	sb.WriteString(sp.UserName)

	sb.WriteString(",engine=(")
	sb.WriteString(hex.EncodeToString([]byte(sp.AuthoritativeEngineID)))
	sb.WriteString(")")

	if auth := sp.AuthenticationProtocol; auth >= NoAuth && auth <= SHA512 {
		sb.WriteString(",auth=")
		sb.WriteString(strings.ToLower(auth.String()))
	}
	sb.WriteString(",authPass=")
	sb.WriteString(sp.AuthenticationPassphrase)

	if priv := sp.PrivacyProtocol; priv >= NoPriv && priv <= AES256C {
		sb.WriteString(",priv=")
		sb.WriteString(priv.String())
	}
	sb.WriteString(",privPass=")
	sb.WriteString(sp.PrivacyPassphrase)

	return sb.String()
}

// SafeString returns a logging safe (no secrets) string of the UsmSecurityParameters
func (sp *UsmSecurityParameters) SafeString() string {
	return fmt.Sprintf("AuthoritativeEngineID:%s, AuthoritativeEngineBoots:%d, AuthoritativeEngineTimes:%d, UserName:%s, AuthenticationParameters:%s, PrivacyParameters:%v, AuthenticationProtocol:%s, PrivacyProtocol:%s",
		sp.AuthoritativeEngineID,
		sp.AuthoritativeEngineBoots,
		sp.AuthoritativeEngineTime,
		sp.UserName,
		sp.AuthenticationParameters,
		sp.PrivacyParameters,
		sp.AuthenticationProtocol,
		sp.PrivacyProtocol,
	)
}

// Log logs SafeString to the parameters' Logger.
func (sp *UsmSecurityParameters) Log() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.Logger.enabled() {
		sp.Logger.Printf("SECURITY PARAMETERS:%s", sp.SafeString())
	}
}

// Copy returns a copy of the parameters. The key and salt slices are shared
// with the original, not copied.
func (sp *UsmSecurityParameters) Copy() SnmpV3SecurityParameters {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return &UsmSecurityParameters{
		AuthoritativeEngineID:    sp.AuthoritativeEngineID,
		AuthoritativeEngineBoots: sp.AuthoritativeEngineBoots,
		AuthoritativeEngineTime:  sp.AuthoritativeEngineTime,
		UserName:                 sp.UserName,
		AuthenticationParameters: sp.AuthenticationParameters,
		PrivacyParameters:        sp.PrivacyParameters,
		AuthenticationProtocol:   sp.AuthenticationProtocol,
		PrivacyProtocol:          sp.PrivacyProtocol,
		AuthenticationPassphrase: sp.AuthenticationPassphrase,
		PrivacyPassphrase:        sp.PrivacyPassphrase,
		SecretKey:                sp.SecretKey,
		PrivacyKey:               sp.PrivacyKey,
		Logger:                   sp.Logger,
	}
}

// InitSecurityKeys derives the keys the protocols need and the parameters
// lack, from the passphrases and AuthoritativeEngineID, and checks that each
// protocol has a key that fits it (see SecretKey and PrivacyKey). An empty
// passphrase derives no key: a protocol needs a key or a passphrase.
func (sp *UsmSecurityParameters) InitSecurityKeys() error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if err := sp.checkProtocols(); err != nil {
		return err
	}
	if err := sp.deriveKeys(); err != nil {
		return err
	}
	if sp.AuthenticationProtocol > NoAuth {
		if err := sp.AuthenticationProtocol.spec().CheckKey(sp.SecretKey); err != nil {
			return fmt.Errorf("usm: %w", err)
		}
	}
	if sp.PrivacyProtocol > NoPriv {
		if err := sp.PrivacyProtocol.spec().CheckKey(sp.PrivacyKey); err != nil {
			return fmt.Errorf("usm: %w", err)
		}
	}
	return nil
}

// deriveKeys derives the keys the protocols need and the parameters lack from
// their passphrases, localized to AuthoritativeEngineID; a protocol whose
// passphrase is empty keeps its key, or stays without one. The caller holds
// sp.mu or owns sp (a private copy).
func (sp *UsmSecurityParameters) deriveKeys() error {
	if err := sp.deriveAuthKey(); err != nil {
		return err
	}
	return sp.derivePrivKey()
}

// deriveAuthKey is deriveKeys for the authentication key.
func (sp *UsmSecurityParameters) deriveAuthKey() error {
	if sp.AuthenticationProtocol <= NoAuth || len(sp.SecretKey) != 0 || sp.AuthenticationPassphrase == "" {
		return nil
	}
	key, err := passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
		sp.AuthenticationPassphrase, sp.AuthoritativeEngineID)
	if err != nil {
		return err
	}
	sp.SecretKey = key
	return nil
}

// derivePrivKey is deriveKeys for the privacy key, which derives with the
// authentication protocol's hash.
func (sp *UsmSecurityParameters) derivePrivKey() error {
	if sp.PrivacyProtocol <= NoPriv || len(sp.PrivacyKey) != 0 || sp.PrivacyPassphrase == "" {
		return nil
	}
	key, err := passwordCache.PrivacyKey(sp.PrivacyProtocol.spec(),
		sp.AuthenticationProtocol.HashType(), sp.PrivacyPassphrase, sp.AuthoritativeEngineID)
	if err != nil {
		return err
	}
	sp.PrivacyKey = key
	return nil
}

// adoptEngineID takes engineID as the authoritative engine ID and, when it
// differs from the current one, replaces both keys with keys derived for it
// from the passphrases. A key localizes to one engine ID (RFC 3414 section
// 2.6), so parameters with a protocol whose passphrase is empty, as when a key
// was given without one, cannot adopt another engine ID: the error leaves
// them unchanged. The caller holds sp.mu or owns sp (a private copy). Known
// bug: the engine ID is adopted before the keys are derived, so a failed
// derivation leaves it adopted with keys missing.
func (sp *UsmSecurityParameters) adoptEngineID(engineID string) error {
	if sp.AuthoritativeEngineID == engineID {
		return nil
	}
	if err := sp.checkRelocalizable(); err != nil {
		return err
	}
	sp.AuthoritativeEngineID = engineID
	sp.SecretKey = nil
	sp.PrivacyKey = nil
	return sp.deriveKeys()
}

// checkRelocalizable returns the error of localizing the keys to another
// engine ID when a protocol's passphrase is empty, so that its key, given
// without one, serves only the engine ID it was localized to.
func (sp *UsmSecurityParameters) checkRelocalizable() error {
	if sp.AuthenticationProtocol > NoAuth && sp.AuthenticationPassphrase == "" {
		return errAuthKeyBoundToEngine
	}
	if sp.PrivacyProtocol > NoPriv && sp.PrivacyPassphrase == "" {
		return errPrivKeyBoundToEngine
	}
	return nil
}

// setSecurityParameters adopts the engine ID, boots and time of in, deriving
// new keys when the engine ID changes. Known bugs: a failed key derivation
// (adoptEngineID) also leaves boots and time untaken, and the next request
// skips the discovery; boots and time are adopted from any message the client
// accepts, older or outside the time window ones included (RFC 3414 section
// 3.2 step 7 b keeps the latest); the time is kept without the moment it was
// received, so a request sends the engine time of the last message, not the
// current one (RFC 3414 section 3.1 step 6 a), and one after 150 s of silence
// is first answered with notInTimeWindow.
func (sp *UsmSecurityParameters) setSecurityParameters(in *UsmSecurityParameters) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if err := sp.adoptEngineID(in.AuthoritativeEngineID); err != nil {
		return err
	}
	sp.AuthoritativeEngineBoots = in.AuthoritativeEngineBoots
	sp.AuthoritativeEngineTime = in.AuthoritativeEngineTime

	return nil
}

// setEngineTime takes the engine boots and time of in; the engine ID and the
// keys stay.
func (sp *UsmSecurityParameters) setEngineTime(in *UsmSecurityParameters) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	sp.AuthoritativeEngineBoots = in.AuthoritativeEngineBoots
	sp.AuthoritativeEngineTime = in.AuthoritativeEngineTime
}

// errAuthKeyBoundToEngine and errPrivKeyBoundToEngine are the errors of
// adopting another engine ID without the passphrase a protocol's key derives
// from.
var (
	errAuthKeyBoundToEngine = errors.New("usm: without a passphrase, the authentication key cannot be localized to another engine ID")
	errPrivKeyBoundToEngine = errors.New("usm: without a passphrase, the privacy key cannot be localized to another engine ID")
)

var (
	errAuthProtocolRequired = errors.New("securityParameters.AuthenticationProtocol is required")
	errPrivProtocolRequired = errors.New("securityParameters.PrivacyProtocol is required")
)

// checkProtocols rejects authentication and privacy protocol values outside
// the defined sets.
func (sp *UsmSecurityParameters) checkProtocols() error {
	if sp.AuthenticationProtocol > SHA512 {
		return fmt.Errorf("securityParameters.AuthenticationProtocol %v is not supported", sp.AuthenticationProtocol)
	}
	if sp.PrivacyProtocol > AES256C {
		return fmt.Errorf("securityParameters.PrivacyProtocol %v is not supported", sp.PrivacyProtocol)
	}
	return nil
}

// missingProtocol reports which protocol the security level of flags needs
// and sp lacks: an authentication protocol for the authFlag, a privacy
// protocol for the privFlag. It is the one rule of what a level needs, for
// outgoing messages (checkLevel, validate) and incoming ones (receive).
func (sp *UsmSecurityParameters) missingProtocol(flags SnmpV3MsgFlags) (auth, priv bool) {
	return flags.authFlag() && sp.AuthenticationProtocol <= NoAuth, flags.privFlag() && sp.PrivacyProtocol <= NoPriv
}

// levelFloor is the security level a trap receiver requires of a message for
// sp at the least: authentication when sp has an authentication protocol,
// privacy optional.
func (sp *UsmSecurityParameters) levelFloor() SnmpV3MsgFlags {
	if sp.AuthenticationProtocol > NoAuth {
		return AuthNoPriv
	}
	return NoAuthNoPriv
}

// checkLevel rejects message flags that ask for authentication or privacy
// without a protocol for it, authentication first.
func (sp *UsmSecurityParameters) checkLevel(flags SnmpV3MsgFlags) error {
	switch auth, priv := sp.missingProtocol(flags); {
	case auth:
		return errAuthProtocolRequired
	case priv:
		return errPrivProtocolRequired
	}
	return nil
}

// validate checks the parameters for the security level of flags: valid
// protocols, the ones the level needs, a user name, and a passphrase for each
// protocol without a key.
func (sp *UsmSecurityParameters) validate(flags SnmpV3MsgFlags) error {
	if err := sp.checkProtocols(); err != nil {
		return err
	}

	if flags.privFlag() && !flags.authFlag() {
		return fmt.Errorf("validate: MsgFlags must be populated with an appropriate security level")
	}
	if err := sp.checkLevel(flags); err != nil {
		return err
	}
	if sp.UserName == "" {
		return fmt.Errorf("securityParameters.UserName is required")
	}

	if sp.PrivacyProtocol > NoPriv && len(sp.PrivacyKey) == 0 && sp.PrivacyPassphrase == "" {
		return fmt.Errorf("securityParameters.PrivacyPassphrase is required when a privacy protocol is specified")
	}
	if sp.AuthenticationProtocol > NoAuth && len(sp.SecretKey) == 0 && sp.AuthenticationPassphrase == "" {
		return fmt.Errorf("securityParameters.AuthenticationPassphrase is required when an authentication protocol is specified")
	}

	return nil
}

// setLogger sets the logger of Log.
func (sp *UsmSecurityParameters) setLogger(log Logger) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	sp.Logger = log
}

// passwordCache derives the keys of every UsmSecurityParameters.
var passwordCache = usm.NewCache() //nolint:gochecknoglobals // PasswordCaching turns it on and off

// PasswordCaching turns the package's cache of password-to-key results on,
// as it is by default, or off; turning it off empties it. See the package
// documentation.
func PasswordCaching(enable bool) {
	passwordCache.SetEnabled(enable)
}

// InitPacket does nothing and returns nil: the encoder draws a new salt for
// every encrypted message.
//
// Deprecated: there is nothing to initialize before encoding.
func (sp *UsmSecurityParameters) InitPacket(*SnmpPacket) error {
	return nil
}

// discoveryPacket returns the request that discovers the authoritative
// engine's ID, boots and time (RFC 3414 section 4) while sp has no engine ID:
// a reportable, unauthenticated Get without variable bindings and with empty
// security parameters. It returns nil once the engine ID is known.
func (sp *UsmSecurityParameters) discoveryPacket() *SnmpPacket {
	if sp.AuthoritativeEngineID != "" {
		return nil
	}
	return &SnmpPacket{
		Version:            Version3,
		MsgFlags:           Reportable | NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{Logger: sp.Logger},
		PDUType:            GetRequest,
		Logger:             sp.Logger,
	}
}

// sign writes the digest of packet, an outgoing message whose
// msgAuthenticationParameters content at offset auth still holds the zeros of
// appendMACPlaceholder, into that content.
func (sp *UsmSecurityParameters) sign(packet []byte, auth int) error {
	msgDigest, err := sp.AuthenticationProtocol.spec().Digest(sp.SecretKey, packet)
	if err != nil {
		return err
	}
	copy(packet[auth:], msgDigest)
	return nil
}

// encryptPacket returns the ciphertext of the scoped PDU.
func (sp *UsmSecurityParameters) encryptPacket(scopedPdu, salt []byte) ([]byte, error) {
	return sp.PrivacyProtocol.spec().Encrypt(sp.PrivacyKey, salt,
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime, scopedPdu)
}

// decryptPacket returns the plaintext of the OCTET STRING at packet[cursor:],
// a new buffer: the ciphertext is the rest of the packet after the string's
// header, whatever its declared length.
func (sp *UsmSecurityParameters) decryptPacket(packet []byte, cursor int) ([]byte, error) {
	_, cursorTmp, err := ber.Length(packet[cursor:])
	if err != nil {
		return nil, err
	}
	cursorTmp += cursor
	if cursorTmp > len(packet) {
		return nil, errors.New("error decrypting ScopedPDU: truncated packet")
	}

	return sp.PrivacyProtocol.spec().Decrypt(sp.PrivacyKey, sp.PrivacyParameters,
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime, packet[cursorTmp:])
}

// marshal appends the User Security Model parameters: a SEQUENCE of the
// authoritative engine ID, boots and time, the user name, the authentication
// parameters (the zero placeholder sign fills in, or empty) and the
// privacy parameters (the salt, or empty). It also returns the offset of the
// authentication parameters' content in dst.
func (sp *UsmSecurityParameters) marshal(dst []byte, flags SnmpV3MsgFlags, salt []byte) ([]byte, int) {
	dst, start := ber.Begin(dst, byte(Sequence))
	dst = appendOctets(dst, OctetString, sp.AuthoritativeEngineID)
	dst = appendUint(dst, Integer, uint64(sp.AuthoritativeEngineBoots))
	dst = appendUint(dst, Integer, uint64(sp.AuthoritativeEngineTime))
	dst = appendOctets(dst, OctetString, sp.UserName)
	macLen := 0
	if flags.authFlag() {
		macLen = sp.AuthenticationProtocol.spec().MACLen
	}
	dst = appendMACPlaceholder(dst, macLen)
	auth := len(dst) - macLen
	dst = appendOctets(dst, OctetString, salt)
	return ber.EndMoving(dst, start, auth)
}

// receive makes sp, a private copy of a receiver's parameters, the security
// parameters of a message with flags whose USM fields are w: it takes the
// fields that decoded, after the checks of RFC 3414 section 3.2 made before
// the digest: valid protocols (a local failure); with bind, the engine ID rule
// of adoptEngineID, keys given without a passphrase take no other engine ID
// (step 4: the user is looked up by name and engine ID, ErrUnknownUsername);
// the protocols the flags ask for (step 5, ErrUnknownSecurityLevel). Another
// engine ID drops the keys: with bind, derive reports that they derive for it
// from the passphrases when needed, the authentication key here when the
// flags ask for authentication (to check the message, or to answer it with
// the parameters SnmpDecodePacket returns), the privacy key only to decrypt
// (inbound.scopedPDU), which a Reeder-extended protocol caches per engine ID;
// without bind both stay missing, as the answer to a request has no keys for
// another engine.
func (sp *UsmSecurityParameters) receive(flags SnmpV3MsgFlags, w *v3Wire, bind bool) (derive bool, err error) {
	if err := sp.checkProtocols(); err != nil {
		return false, err
	}
	if w.has&hasEngineID != 0 && w.engineID != sp.AuthoritativeEngineID {
		if bind {
			if err := sp.checkRelocalizable(); err != nil {
				return false, inCategory(ErrUnknownUsername, err)
			}
		}
		sp.AuthoritativeEngineID = w.engineID
		sp.SecretKey, sp.PrivacyKey = nil, nil
		if bind && flags.authFlag() {
			if err := sp.deriveAuthKey(); err != nil {
				return false, err
			}
		}
		derive = bind
	}
	if w.has&hasBoots != 0 {
		sp.AuthoritativeEngineBoots = w.boots
	}
	if w.has&hasEngineTime != 0 {
		sp.AuthoritativeEngineTime = w.engineTime
	}
	if w.has&hasUserName != 0 {
		sp.UserName = w.userName
	}
	if w.has&hasAuthParams != 0 {
		sp.AuthenticationParameters = w.authParams
	}
	if w.has&hasPrivParams != 0 {
		sp.PrivacyParameters = w.privParams
	}
	switch auth, priv := sp.missingProtocol(flags); {
	case auth:
		return false, errNoAuthForMsg
	case priv:
		return false, errNoPrivForMsg
	}
	return derive, nil
}

// inbound is an SNMPv3 message in security processing for one receiver (RFC
// 3414 section 3.2): the message, which is never written, its USM fields as
// sent, and the receiver's parameters for it, sp, a private copy that has
// taken them (receive).
type inbound struct {
	msg  []byte
	wire v3Wire
	sp   *UsmSecurityParameters
	// derive is set when sp took another engine ID: its keys derive from the
	// passphrases when needed (receive).
	derive bool
}

// receiveV3 returns the SNMPv3 message msg, whose header is in result and w,
// in security processing with sp, which becomes result's security
// parameters (receive, with the engine ID rule).
func receiveV3(msg []byte, w v3Wire, result *SnmpPacket, sp *UsmSecurityParameters) (inbound, error) {
	derive, err := sp.receive(result.MsgFlags, &w, true)
	if err != nil {
		return inbound{}, err
	}
	result.SecurityParameters = sp
	return inbound{msg: msg, wire: w, sp: sp, derive: derive}, nil
}

// verify checks the digest of a message that asks for authentication with
// sp's key (RFC 3414 section 3.2 step 6), which receive derived for a new
// engine ID: errWrongDigest when it does not check, a key that does not fit
// the protocol a local error.
func (in *inbound) verify() error {
	ok, err := in.sp.AuthenticationProtocol.spec().VerifyField(in.sp.SecretKey, in.msg, in.wire.authOff, in.wire.authLen)
	if err != nil {
		return err
	}
	if !ok {
		return errWrongDigest
	}
	return nil
}

// scopedPDU reads the scoped PDU into result (unmarshalScopedPDU), decrypted
// exactly when the message's privFlag is set, deriving the privacy key for a
// new engine ID first.
func (in *inbound) scopedPDU(result *SnmpPacket) ([]byte, int, error) {
	encrypted := result.MsgFlags.privFlag()
	if encrypted && in.derive && in.wire.scoped < len(in.msg) && PDUType(in.msg[in.wire.scoped]) == PDUType(OctetString) {
		if err := in.sp.derivePrivKey(); err != nil {
			return nil, 0, err
		}
	}
	return unmarshalScopedPDU(in.msg, in.wire.scoped, result, encrypted)
}

// usmField prefixes the names of the USM fields in decode errors.
const usmField = "SNMPV3 User Security Model "
