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
	// key given without one among them, cannot take another engine ID: they
	// decode no message naming another one, and discovery cannot give them one.
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
	var err error
	if sp.AuthenticationProtocol > NoAuth && len(sp.SecretKey) == 0 && sp.AuthenticationPassphrase != "" {
		sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
			sp.AuthenticationPassphrase, sp.AuthoritativeEngineID)
		if err != nil {
			return err
		}
	}
	if sp.PrivacyProtocol > NoPriv && len(sp.PrivacyKey) == 0 && sp.PrivacyPassphrase != "" {
		// The privacy key derives with the authentication protocol's hash.
		sp.PrivacyKey, err = passwordCache.PrivacyKey(sp.PrivacyProtocol.spec(),
			sp.AuthenticationProtocol.HashType(), sp.PrivacyPassphrase, sp.AuthoritativeEngineID)
		if err != nil {
			return err
		}
	}
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
	if sp.AuthenticationProtocol > NoAuth && sp.AuthenticationPassphrase == "" {
		return errAuthKeyBoundToEngine
	}
	if sp.PrivacyProtocol > NoPriv && sp.PrivacyPassphrase == "" {
		return errPrivKeyBoundToEngine
	}
	sp.AuthoritativeEngineID = engineID
	sp.SecretKey = nil
	sp.PrivacyKey = nil
	return sp.deriveKeys()
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

// checkLevel rejects message flags that ask for authentication or privacy
// without a protocol for it.
func (sp *UsmSecurityParameters) checkLevel(flags SnmpV3MsgFlags) error {
	if flags.authFlag() && sp.AuthenticationProtocol <= NoAuth {
		return errAuthProtocolRequired
	}
	if flags.privFlag() && sp.PrivacyProtocol <= NoPriv {
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

	securityLevel := flags & AuthPriv // isolate flags that determine security level

	switch securityLevel {
	case AuthPriv:
		if sp.PrivacyProtocol <= NoPriv {
			return errPrivProtocolRequired
		}
		fallthrough
	case AuthNoPriv:
		if sp.AuthenticationProtocol <= NoAuth {
			return errAuthProtocolRequired
		}
		fallthrough
	case NoAuthNoPriv:
		if sp.UserName == "" {
			return fmt.Errorf("securityParameters.UserName is required")
		}
	default:
		return fmt.Errorf("validate: MsgFlags must be populated with an appropriate security level")
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

// isAuthentic reports whether the message is from the user of sp and carries
// the digest computed with the decoded message's parameters, which need an
// authentication protocol and a key that fits it.
func (sp *UsmSecurityParameters) isAuthentic(packetBytes []byte, packet *SnmpPacket) (bool, error) {
	packetSecParams := packet.SecurityParameters.usm()

	// Verify the username
	if packetSecParams.UserName != sp.UserName {
		return false, nil
	}
	if packetSecParams.AuthenticationProtocol <= NoAuth {
		return false, errAuthProtocolRequired
	}

	// Check the message signature against the computed digest
	signature := []byte(packetSecParams.AuthenticationParameters)
	return packetSecParams.AuthenticationProtocol.spec().Verify(packetSecParams.SecretKey, packetBytes, signature)
}

// isAuthenticAnswer reports whether packet, an answer to a request made with
// sp and whose security parameters are in, is authentic: it names sp's user
// and engine ID, and its digest checks with sp's key, localized to that engine
// ID (RFC 3414 section 3.2 steps 3-6), not with keys derived for the engine ID
// the answer names.
func (sp *UsmSecurityParameters) isAuthenticAnswer(packet []byte, in *UsmSecurityParameters) (bool, error) {
	if in.UserName != sp.UserName || in.AuthoritativeEngineID != sp.AuthoritativeEngineID {
		return false, nil
	}
	if sp.AuthenticationProtocol <= NoAuth {
		return false, errAuthProtocolRequired
	}
	return sp.AuthenticationProtocol.spec().Verify(sp.SecretKey, packet, []byte(in.AuthenticationParameters))
}

// encryptPacket returns the ciphertext of the scoped PDU.
func (sp *UsmSecurityParameters) encryptPacket(scopedPdu, salt []byte) ([]byte, error) {
	return sp.PrivacyProtocol.spec().Encrypt(sp.PrivacyKey, salt,
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime, scopedPdu)
}

// decryptPacket decrypts the OCTET STRING at packet[cursor:] in place: the
// ciphertext is the rest of the packet after the string's header, whatever
// its declared length, and the plaintext replaces the string, header
// included, and the packet is cut after it. Known bug: without a privacy
// protocol the packet is returned unchanged, and the caller reads the string's
// content as a plaintext scoped PDU.
func (sp *UsmSecurityParameters) decryptPacket(packet []byte, cursor int) ([]byte, error) {
	_, cursorTmp, err := ber.Length(packet[cursor:])
	if err != nil {
		return nil, err
	}
	cursorTmp += cursor
	if cursorTmp > len(packet) {
		return nil, errors.New("error decrypting ScopedPDU: truncated packet")
	}

	spec := sp.PrivacyProtocol.spec()
	if spec.Cipher == usm.NoCipher {
		return packet, nil
	}
	plaintext, err := spec.Decrypt(sp.PrivacyKey, sp.PrivacyParameters,
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime, packet[cursorTmp:])
	if err != nil {
		return nil, err
	}
	copy(packet[cursor:], plaintext)
	return packet[:cursor+len(plaintext)], nil
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

// unmarshal reads the USM security parameters from r, which is positioned at
// their SEQUENCE in the rest of the packet. The SEQUENCE header is skipped
// without enforcing its declared length. When the flags ask for
// authentication, the authentication parameters are zeroed in the packet so
// the digest can be verified (readAuthParams). A new engine ID is adopted with
// keys derived for it, or fails the decode (adoptEngineID): sp is the
// decoder's private copy.
// Parameters with an unsupported protocol decode nothing.
func (sp *UsmSecurityParameters) unmarshal(flags SnmpV3MsgFlags, r *ber.Reader) error {
	if err := sp.checkProtocols(); err != nil {
		return err
	}

	tag, ok := r.Peek()
	if !ok {
		return errors.New("error parsing SNMPV3 User Security Model parameters: end of packet")
	}
	if PDUType(tag) != Sequence {
		return errors.New("error parsing SNMPV3 User Security Model parameters")
	}
	if _, err := r.SkipHeader(); err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model parameters: %w", err)
	}

	var fr fieldReader
	if v, ok := fr.string(r, usmField+"msgAuthoritativeEngineID"); ok {
		if err := sp.adoptEngineID(v); err != nil {
			return err
		}
	}
	if v, ok := fr.int(r, usmField+"msgAuthoritativeEngineBoots"); ok {
		sp.AuthoritativeEngineBoots = uint32(v) //nolint:gosec
	}
	if v, ok := fr.int(r, usmField+"msgAuthoritativeEngineTime"); ok {
		sp.AuthoritativeEngineTime = uint32(v) //nolint:gosec
	}
	if v, ok := fr.string(r, usmField+"msgUserName"); ok {
		sp.UserName = v
	}
	if fr.err != nil {
		return fr.err
	}

	if err := sp.readAuthParams(flags, r); err != nil {
		return err
	}

	if v, ok := fr.string(r, usmField+"msgPrivacyParameters"); ok {
		sp.PrivacyParameters = []byte(v)
		if flags.authFlag() && flags.privFlag() && sp.PrivacyProtocol <= NoPriv {
			return errors.New("error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message")
		}
	}
	return fr.err
}

// usmField prefixes the names of the USM fields in decode errors.
const usmField = "SNMPV3 User Security Model "

// readAuthParams reads msgAuthenticationParameters from r. When flags ask for
// authentication, which needs an authentication protocol, it zeroes the field
// in the packet, so the digest can be verified over the message as it was
// signed. Known bug: before any digest check, the zeros go two octets into
// the field whatever its header size and length, up to the expected digest
// length: past the end of a shorter field, over what follows it or past the
// end of the input, which panics when the input has no spare capacity.
func (sp *UsmSecurityParameters) readAuthParams(flags SnmpV3MsgFlags, r *ber.Reader) error {
	field := r.Rest()
	var fr fieldReader
	if v, ok := fr.string(r, usmField+"msgAuthenticationParameters"); ok {
		sp.AuthenticationParameters = v
	}
	if fr.err != nil {
		return fr.err
	}
	if !flags.authFlag() {
		return nil
	}
	if sp.AuthenticationProtocol <= NoAuth {
		return errors.New("error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message")
	}
	clear(field[2 : 2+sp.AuthenticationProtocol.spec().MACLen])
	return nil
}
