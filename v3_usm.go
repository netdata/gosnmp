// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// SnmpV3AuthProtocol describes the authentication protocol in use by an authenticated SnmpV3 connection.
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

// HashType maps the AuthProtocol's hash type to an actual crypto.Hash object:
// MD5 for NoAuth, unset and unknown values.
func (authProtocol SnmpV3AuthProtocol) HashType() crypto.Hash {
	if h := authProtocol.spec().Hash; h != 0 {
		return h
	}
	return crypto.MD5
}

// spec describes the protocol; NoAuth, unset and unknown values have no
// description.
func (authProtocol SnmpV3AuthProtocol) spec() usm.Auth {
	switch authProtocol {
	case MD5:
		return usm.Auth{Hash: crypto.MD5, MACLen: 12}
	case SHA:
		return usm.Auth{Hash: crypto.SHA1, MACLen: 12}
	case SHA224:
		return usm.Auth{Hash: crypto.SHA224, MACLen: 16}
	case SHA256:
		return usm.Auth{Hash: crypto.SHA256, MACLen: 24}
	case SHA384:
		return usm.Auth{Hash: crypto.SHA384, MACLen: 32}
	case SHA512:
		return usm.Auth{Hash: crypto.SHA512, MACLen: usm.MaxMACLen}
	}
	return usm.Auth{}
}

// appendMACPlaceholder appends msgAuthenticationParameters as an outgoing
// message carries them until authenticate writes the digest: an OCTET STRING
// of macLen zeros.
func appendMACPlaceholder(dst []byte, macLen int) []byte {
	dst = ber.AppendHeader(dst, byte(OctetString), macLen)
	return append(dst, make([]byte, macLen)...)
}

// SnmpV3PrivProtocol is the privacy protocol in use by an private SnmpV3 connection.
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

// spec describes the protocol; NoPriv, unset and unknown values have no
// description.
func (privProtocol SnmpV3PrivProtocol) spec() usm.Priv {
	switch privProtocol {
	case DES:
		return usm.Priv{Cipher: usm.DESCBC}
	case AES:
		return usm.Priv{Cipher: usm.AESCFB, KeyLen: 16}
	case AES192:
		return usm.Priv{Cipher: usm.AESCFB, KeyLen: 24, Extension: usm.Blumenthal}
	case AES256:
		return usm.Priv{Cipher: usm.AESCFB, KeyLen: 32, Extension: usm.Blumenthal}
	case AES192C:
		return usm.Priv{Cipher: usm.AESCFB, KeyLen: 24, Extension: usm.Reeder}
	case AES256C:
		return usm.Priv{Cipher: usm.AESCFB, KeyLen: 32, Extension: usm.Reeder}
	}
	return usm.Priv{}
}

// UsmSecurityParameters is an implementation of SnmpV3SecurityParameters for the UserSecurityModel
type UsmSecurityParameters struct {
	// mu guards the salt counters and serializes key initialization, Copy
	// and Log.
	mu           sync.Mutex
	localAESSalt uint64
	localDESSalt uint32

	AuthoritativeEngineID    string
	AuthoritativeEngineBoots uint32
	AuthoritativeEngineTime  uint32
	UserName                 string
	AuthenticationParameters string
	PrivacyParameters        []byte

	AuthenticationProtocol SnmpV3AuthProtocol
	PrivacyProtocol        SnmpV3PrivProtocol

	AuthenticationPassphrase string
	PrivacyPassphrase        string

	SecretKey  []byte
	PrivacyKey []byte

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

// Copy returns a copy of the parameters, the salt counters included. The key
// and salt slices are shared with the original, not copied.
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
		localDESSalt:             sp.localDESSalt,
		localAESSalt:             sp.localAESSalt,
		Logger:                   sp.Logger,
	}
}

// InitSecurityKeys initializes the Priv and Auth keys if needed
func (sp *UsmSecurityParameters) InitSecurityKeys() error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	return sp.initSecurityKeysNoLock()
}

func (sp *UsmSecurityParameters) initSecurityKeysNoLock() error {
	if err := sp.checkProtocols(); err != nil {
		return err
	}

	var err error

	if sp.AuthenticationProtocol > NoAuth && len(sp.SecretKey) == 0 {
		sp.SecretKey, err = passwordCache.LocalizedKey(sp.AuthenticationProtocol.HashType(),
			sp.AuthenticationPassphrase,
			sp.AuthoritativeEngineID)
		if err != nil {
			return err
		}
	}
	if sp.PrivacyProtocol > NoPriv && len(sp.PrivacyKey) == 0 {
		sp.PrivacyKey, err = sp.privacyKey()
		if err != nil {
			return err
		}
	}
	return nil
}

// privacyKey derives the key of the privacy protocol from the privacy
// passphrase, with the hash of the authentication protocol.
func (sp *UsmSecurityParameters) privacyKey() ([]byte, error) {
	key, err := passwordCache.PrivacyKey(sp.PrivacyProtocol.spec(), sp.AuthenticationProtocol.HashType(),
		sp.PrivacyPassphrase,
		sp.AuthoritativeEngineID)
	if short, ok := errors.AsType[*usm.ShortKeyError](err); ok {
		return []byte{}, fmt.Errorf("genlocalPrivKey: privProtocol: %v len(localPrivKey): %d, keylen: %d",
			sp.PrivacyProtocol, short.Len, short.KeyLen)
	}
	return key, err
}

// setSecurityParameters adopts the engine ID, boots and time of in, deriving
// new keys when the engine ID changes.
func (sp *UsmSecurityParameters) setSecurityParameters(in *UsmSecurityParameters) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.AuthoritativeEngineID != in.AuthoritativeEngineID {
		sp.AuthoritativeEngineID = in.AuthoritativeEngineID
		sp.SecretKey = nil
		sp.PrivacyKey = nil

		if err := sp.initSecurityKeysNoLock(); err != nil {
			return err
		}
	}
	sp.AuthoritativeEngineBoots = in.AuthoritativeEngineBoots
	sp.AuthoritativeEngineTime = in.AuthoritativeEngineTime

	return nil
}

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
	if flags&AuthNoPriv > 0 && sp.AuthenticationProtocol <= NoAuth {
		return errAuthProtocolRequired
	}
	if flags&AuthPriv > AuthNoPriv && sp.PrivacyProtocol <= NoPriv {
		return errPrivProtocolRequired
	}
	return nil
}

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

	if sp.PrivacyProtocol > NoPriv && len(sp.PrivacyKey) == 0 {
		if sp.PrivacyPassphrase == "" {
			return fmt.Errorf("securityParameters.PrivacyPassphrase is required when a privacy protocol is specified")
		}
	}

	if sp.AuthenticationProtocol > NoAuth && len(sp.SecretKey) == 0 {
		if sp.AuthenticationPassphrase == "" {
			return fmt.Errorf("securityParameters.AuthenticationPassphrase is required when an authentication protocol is specified")
		}
	}

	return nil
}

// init sets the logger and seeds the salt counter of the privacy protocol with
// random bits.
func (sp *UsmSecurityParameters) init(log Logger) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	var err error

	sp.Logger = log

	switch sp.PrivacyProtocol.spec().Cipher {
	case usm.AESCFB:
		salt := make([]byte, 8)
		_, err = crand.Read(salt)
		if err != nil {
			return fmt.Errorf("error creating a cryptographically secure salt: %w", err)
		}
		sp.localAESSalt = binary.BigEndian.Uint64(salt)
	case usm.DESCBC:
		salt := make([]byte, 4)
		_, err = crand.Read(salt)
		if err != nil {
			return fmt.Errorf("error creating a cryptographically secure salt: %w", err)
		}
		sp.localDESSalt = binary.BigEndian.Uint32(salt)
	}

	return nil
}

// passwordCache derives the keys of every UsmSecurityParameters.
var passwordCache = usm.NewCache() //nolint:gochecknoglobals // PasswordCaching turns it on and off

// PasswordCaching is enabled by default for performance reason. If the cache was disabled then
// re-enabled, the cache is reset.
func PasswordCaching(enable bool) {
	passwordCache.SetEnabled(enable)
}

// usmAllocateNewSalt increments the salt counter of the privacy protocol and
// returns its new value: the 64-bit AES counter (isAES, RFC 3826 section
// 3.1.2.1) or the 32-bit DES counter (RFC 3414 section 8.1.1.1).
func (sp *UsmSecurityParameters) usmAllocateNewSalt() (salt uint64, isAES bool) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.PrivacyProtocol.spec().Cipher == usm.AESCFB {
		sp.localAESSalt++
		return sp.localAESSalt, true
	}
	sp.localDESSalt++
	return uint64(sp.localDESSalt), false
}

// usmSetSalt sets msgPrivacyParameters from a salt counter value: the AES
// counter, or the engine boots followed by the DES counter. The counter must
// be of the family of the parameters' own privacy protocol.
func (sp *UsmSecurityParameters) usmSetSalt(salt uint64, isAES bool) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	switch sp.PrivacyProtocol.spec().Cipher {
	case usm.AESCFB:
		if !isAES {
			return fmt.Errorf("salt provided to usmSetSalt is not the correct type for the AES privacy protocol")
		}
		params := make([]byte, 8)
		binary.BigEndian.PutUint64(params, salt)
		sp.PrivacyParameters = params
	default:
		if isAES {
			return fmt.Errorf("salt provided to usmSetSalt is not the correct type for the DES privacy protocol")
		}
		params := make([]byte, 8)
		binary.BigEndian.PutUint32(params, sp.AuthoritativeEngineBoots)
		binary.BigEndian.PutUint32(params[4:], uint32(salt)) //nolint:gosec // the DES counter is 32 bits wide
		sp.PrivacyParameters = params
	}
	return nil
}

// InitPacket advances the salt counter, for every packet, and sets the
// packet's msgPrivacyParameters from it when the packet asks for privacy.
func (sp *UsmSecurityParameters) InitPacket(packet *SnmpPacket) error {
	salt, isAES := sp.usmAllocateNewSalt()
	if packet.MsgFlags&AuthPriv > AuthNoPriv {
		s := usmOf(packet.SecurityParameters)
		if s == nil {
			return errors.New("param SnmpV3SecurityParameters is not of type *UsmSecurityParameters")
		}
		return s.usmSetSalt(salt, isAES)
	}
	return nil
}

func (sp *UsmSecurityParameters) discoveryRequired() *SnmpPacket {
	if sp.AuthoritativeEngineID == "" {
		var emptyPdus []SnmpPDU

		// send blank packet to discover authoriative engine ID/boots/time
		blankPacket := &SnmpPacket{
			Version:            Version3,
			MsgFlags:           Reportable | NoAuthNoPriv,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: &UsmSecurityParameters{Logger: sp.Logger},
			PDUType:            GetRequest,
			Logger:             sp.Logger,
			Variables:          emptyPdus,
		}

		return blankPacket
	}
	return nil
}

// authenticate writes the digest of the message over the first
// msgAuthenticationParameters placeholder found in it.
func (sp *UsmSecurityParameters) authenticate(packet []byte) error {
	spec := sp.AuthenticationProtocol.spec()
	msgDigest, err := spec.Digest(sp.SecretKey, packet)
	if err != nil {
		return err
	}

	var buf [2 + usm.MaxMACLen]byte
	placeholder := appendMACPlaceholder(buf[:0], spec.MACLen)
	idx := bytes.Index(packet, placeholder)
	if idx < 0 {
		return fmt.Errorf("unable to locate the position in packet to write authentication key")
	}

	copy(packet[idx+2:idx+len(placeholder)], msgDigest)
	return nil
}

// isAuthentic reports whether the message is from the user of sp and carries
// the digest computed with the decoded message's parameters, which need an
// authentication protocol.
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

// encryptPacket returns the ciphertext of the scoped PDU.
func (sp *UsmSecurityParameters) encryptPacket(scopedPdu []byte) ([]byte, error) {
	return sp.PrivacyProtocol.spec().Encrypt(sp.PrivacyKey, sp.PrivacyParameters,
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime, scopedPdu)
}

// decryptPacket decrypts the OCTET STRING at packet[cursor:] in place: the
// plaintext replaces the string, header included, and the packet is cut after
// it. Known bug: without a privacy protocol the packet is returned unchanged,
// and the caller reads the string's content as a plaintext scoped PDU.
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
// parameters (the zero placeholder authenticate fills in, or empty) and the
// privacy parameters (the salt, or empty).
func (sp *UsmSecurityParameters) marshal(dst []byte, flags SnmpV3MsgFlags) []byte {
	dst, start := ber.Begin(dst, byte(Sequence))
	dst = appendOctets(dst, OctetString, sp.AuthoritativeEngineID)
	dst = appendUint(dst, Integer, uint64(sp.AuthoritativeEngineBoots))
	dst = appendUint(dst, Integer, uint64(sp.AuthoritativeEngineTime))
	dst = appendOctets(dst, OctetString, sp.UserName)
	if flags&AuthNoPriv > 0 {
		dst = appendMACPlaceholder(dst, sp.AuthenticationProtocol.spec().MACLen)
	} else {
		dst = append(dst, byte(OctetString), 0)
	}
	if flags&AuthPriv > AuthNoPriv {
		dst = appendOctets(dst, OctetString, sp.PrivacyParameters)
	} else {
		dst = append(dst, byte(OctetString), 0)
	}
	return ber.End(dst, start)
}

// unmarshal reads the USM security parameters from r, which is positioned at
// their SEQUENCE in the rest of the packet. The SEQUENCE header is skipped
// without enforcing its declared length. When the message is authenticated,
// the authentication parameters are zeroed in the packet so the digest can be
// verified. Parameters with an unsupported protocol decode nothing.
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

	engineID, ok, err := readString(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model msgAuthoritativeEngineID: %w", err)
	}
	if ok && sp.AuthoritativeEngineID != engineID {
		sp.AuthoritativeEngineID = engineID
		sp.SecretKey = nil
		sp.PrivacyKey = nil

		if err = sp.initSecurityKeysNoLock(); err != nil {
			return err
		}
	}

	boots, ok, err := readInt(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model msgAuthoritativeEngineBoots: %w", err)
	}
	if ok {
		sp.AuthoritativeEngineBoots = uint32(boots) //nolint:gosec
	}

	engineTime, ok, err := readInt(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model msgAuthoritativeEngineTime: %w", err)
	}
	if ok {
		sp.AuthoritativeEngineTime = uint32(engineTime) //nolint:gosec
	}

	userName, ok, err := readString(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model msgUserName: %w", err)
	}
	if ok {
		sp.UserName = userName
	}

	// authField aliases the packet from the authentication parameters on, so
	// they can be zeroed in place below.
	authField := r.Rest()
	authParams, ok, err := readString(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model msgAuthenticationParameters: %w", err)
	}
	if ok {
		sp.AuthenticationParameters = authParams
	}
	// blank msgAuthenticationParameters to prepare for authentication check later
	if flags&AuthNoPriv > 0 {
		// In case if the authentication protocol is not configured or set to NoAuth, then the packet cannot
		// be processed further
		if sp.AuthenticationProtocol <= NoAuth {
			return errors.New("error parsing SNMPv3 User Security Model: authentication parameters are not configured to parse incoming authenticated message")
		}
		// The zeros go two octets into the field whatever its actual header
		// size, up to the expected digest length.
		clear(authField[2 : 2+sp.AuthenticationProtocol.spec().MACLen])
	}

	privParams, ok, err := readString(r)
	if err != nil {
		return fmt.Errorf("error parsing SNMPV3 User Security Model msgPrivacyParameters: %w", err)
	}
	if ok {
		sp.PrivacyParameters = []byte(privParams)
		if flags&AuthPriv >= AuthPriv {
			if sp.PrivacyProtocol <= NoPriv {
				return errors.New("error parsing SNMPv3 User Security Model: privacy parameters are not configured to parse incoming encrypted message")
			}
		}
	}

	return nil
}
