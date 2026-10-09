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
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	_ "crypto/md5" // Register hash function #2 (MD5)
	crand "crypto/rand"
	_ "crypto/sha1"   // Register hash function #3 (SHA1)
	_ "crypto/sha256" // Register hash function #4 (SHA224), #5 (SHA256)
	_ "crypto/sha512" // Register hash function #6 (SHA384), #7 (SHA512)
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/netdata/gosnmp/internal/ber"
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
	if h := authProtocol.spec().hash; h != 0 {
		return h
	}
	return crypto.MD5
}

// authSpec describes an authentication protocol: the hash of its key
// derivation and HMAC, and the length its HMAC is cut to, which is the length
// of msgAuthenticationParameters.
type authSpec struct {
	hash   crypto.Hash
	macLen int
}

// maxMACLen is the longest macLen, HMAC-SHA-512's.
const maxMACLen = 48

// spec describes the protocol; NoAuth, unset and unknown values have no
// description.
func (authProtocol SnmpV3AuthProtocol) spec() authSpec {
	switch authProtocol {
	case MD5:
		return authSpec{hash: crypto.MD5, macLen: 12}
	case SHA:
		return authSpec{hash: crypto.SHA1, macLen: 12}
	case SHA224:
		return authSpec{hash: crypto.SHA224, macLen: 16}
	case SHA256:
		return authSpec{hash: crypto.SHA256, macLen: 24}
	case SHA384:
		return authSpec{hash: crypto.SHA384, macLen: 32}
	case SHA512:
		return authSpec{hash: crypto.SHA512, macLen: maxMACLen}
	}
	return authSpec{}
}

// digest returns the HMAC of msg keyed with key, cut to the MAC length:
// HMAC-MD5-96 and HMAC-SHA-96 as RFC 3414 sections 6.3.1 and 7.3.1 spell them
// out, the SHA-2 protocols with crypto/hmac (RFC 7860 section 4.2.1).
func (s authSpec) digest(key, msg []byte) ([]byte, error) {
	var mac []byte
	switch s.hash {
	case crypto.MD5, crypto.SHA1:
		var err error
		if mac, err = hmacRFC3414(s.hash, key, msg); err != nil {
			return nil, err
		}
	default:
		h := hmac.New(s.hash.New, key)
		_, _ = h.Write(msg)
		mac = h.Sum(nil)
	}
	return mac[:s.macLen], nil
}

// hmacRFC3414 computes the HMAC of RFC 3414 sections 6.3.1 and 7.3.1: the key
// zero-padded to the 64-octet block (a longer key is cut, not hashed as RFC
// 2104 does), XORed with ipad and opad around two hash passes. Unlike
// crypto/hmac, which panics, it returns the error a hash reports, as MD5 and
// SHA-1 do in FIPS 140-only mode.
func hmacRFC3414(hash crypto.Hash, key, msg []byte) ([]byte, error) {
	var ipad, opad [64]byte
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}

	inner := hash.New()
	if _, err := inner.Write(ipad[:]); err != nil {
		return nil, err
	}
	if _, err := inner.Write(msg); err != nil {
		return nil, err
	}
	outer := hash.New()
	if _, err := outer.Write(opad[:]); err != nil {
		return nil, err
	}
	if _, err := outer.Write(inner.Sum(nil)); err != nil {
		return nil, err
	}
	return outer.Sum(nil), nil
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

// privCipher is the cipher of a privacy protocol.
type privCipher uint8

const (
	noCipher  privCipher = iota
	cipherDES            // CBC-DES (RFC 3414 section 8)
	cipherAES            // CFB128-AES (RFC 3826)
)

// keyExtension is how a privacy protocol extends a localized key shorter than
// its cipher key.
type keyExtension uint8

const (
	noExtension      keyExtension = iota
	extendReeder                  // draft-reeder-snmpv3-usm-3desede
	extendBlumenthal              // draft-blumenthal-aes-usm-04
)

// privSpec describes a privacy protocol: its cipher, its key length and how
// a shorter localized key is extended. A key length of 0 keeps the whole
// localized key, which DES uses as its key and pre-IV.
type privSpec struct {
	cipher    privCipher
	keyLen    int
	extension keyExtension
}

// spec describes the protocol; NoPriv, unset and unknown values have no
// description.
func (privProtocol SnmpV3PrivProtocol) spec() privSpec {
	switch privProtocol {
	case DES:
		return privSpec{cipher: cipherDES}
	case AES:
		return privSpec{cipher: cipherAES, keyLen: 16}
	case AES192:
		return privSpec{cipher: cipherAES, keyLen: 24, extension: extendBlumenthal}
	case AES256:
		return privSpec{cipher: cipherAES, keyLen: 32, extension: extendBlumenthal}
	case AES192C:
		return privSpec{cipher: cipherAES, keyLen: 24, extension: extendReeder}
	case AES256C:
		return privSpec{cipher: cipherAES, keyLen: 32, extension: extendReeder}
	}
	return privSpec{}
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
		sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
			sp.AuthenticationPassphrase,
			sp.AuthoritativeEngineID)
		if err != nil {
			return err
		}
	}
	if sp.PrivacyProtocol > NoPriv && len(sp.PrivacyKey) == 0 {
		sp.PrivacyKey, err = genlocalPrivKey(sp.PrivacyProtocol, sp.AuthenticationProtocol,
			sp.PrivacyPassphrase,
			sp.AuthoritativeEngineID)
		if err != nil {
			return err
		}
	}
	return nil
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

	switch sp.PrivacyProtocol.spec().cipher {
	case cipherAES:
		salt := make([]byte, 8)
		_, err = crand.Read(salt)
		if err != nil {
			return fmt.Errorf("error creating a cryptographically secure salt: %w", err)
		}
		sp.localAESSalt = binary.BigEndian.Uint64(salt)
	case cipherDES:
		salt := make([]byte, 4)
		_, err = crand.Read(salt)
		if err != nil {
			return fmt.Errorf("error creating a cryptographically secure salt: %w", err)
		}
		sp.localDESSalt = binary.BigEndian.Uint32(salt)
	}

	return nil
}

var (
	passwordKeyHashCache = make(map[string][]byte) //nolint:gochecknoglobals
	passwordKeyHashMutex sync.RWMutex              //nolint:gochecknoglobals
	passwordCacheDisable atomic.Bool               //nolint:gochecknoglobals
)

// PasswordCaching is enabled by default for performance reason. If the cache was disabled then
// re-enabled, the cache is reset.
func PasswordCaching(enable bool) {
	oldCacheEnable := !passwordCacheDisable.Load()
	passwordKeyHashMutex.Lock()
	if !enable { // if off
		passwordKeyHashCache = nil
	} else if !oldCacheEnable && enable { // if off then on
		passwordKeyHashCache = make(map[string][]byte)
	}
	passwordCacheDisable.Store(!enable)
	passwordKeyHashMutex.Unlock()
}

func hashPassword(hash hash.Hash, password string) ([]byte, error) {
	if len(password) == 0 {
		return []byte{}, errors.New("hashPassword: password is empty")
	}
	var pi int // password index
	for i := 0; i < 1048576; i += 64 {
		var chunk []byte
		for range 64 {
			chunk = append(chunk, password[pi%len(password)])
			pi++
		}
		if _, err := hash.Write(chunk); err != nil {
			return []byte{}, err
		}
	}
	hashed := hash.Sum(nil)
	return hashed, nil
}

// Common passwordToKey algorithm, "caches" the result to avoid extra computation each reuse
func cachedPasswordToKey(hash hash.Hash, cacheKey, password string) ([]byte, error) {
	cacheDisable := passwordCacheDisable.Load()
	if !cacheDisable {
		passwordKeyHashMutex.RLock()
		value := passwordKeyHashCache[cacheKey]
		passwordKeyHashMutex.RUnlock()

		if value != nil {
			return value, nil
		}
	}

	hashed, err := hashPassword(hash, password)
	if err != nil {
		return nil, err
	}

	if !cacheDisable {
		passwordKeyHashMutex.Lock()
		passwordKeyHashCache[cacheKey] = hashed
		passwordKeyHashMutex.Unlock()
	}

	return hashed, nil
}

func hMAC(hash crypto.Hash, cacheKey, password, engineID string) ([]byte, error) {
	hashed, err := cachedPasswordToKey(hash.New(), cacheKey, password)
	if err != nil {
		return []byte{}, nil
	}

	local := hash.New()
	_, err = local.Write(hashed)
	if err != nil {
		return []byte{}, err
	}

	_, err = local.Write([]byte(engineID))
	if err != nil {
		return []byte{}, err
	}

	_, err = local.Write(hashed)
	if err != nil {
		return []byte{}, err
	}

	final := local.Sum(nil)
	return final, nil
}

func cacheKey(authProtocol SnmpV3AuthProtocol, passphrase string) string {
	if passwordCacheDisable.Load() {
		return ""
	}
	cacheKey := make([]byte, 1+len(passphrase))
	cacheKey = append(cacheKey, 'h'+byte(authProtocol))
	cacheKey = append(cacheKey, []byte(passphrase)...)
	return string(cacheKey)
}

// extendKeyReeder extends a localized privacy key with the Reeder key
// extension (draft-reeder-snmpv3-usm-3desede, used by Cisco and others): the
// key followed by the key localized from it as a passphrase.
func extendKeyReeder(authProtocol SnmpV3AuthProtocol, key []byte, engineID string) ([]byte, error) {
	next, err := hMAC(authProtocol.HashType(), cacheKey(authProtocol, string(key)), string(key), engineID)
	return append(key, next...), err
}

// extendKeyBlumenthal extends a localized privacy key with the Blumenthal key
// extension (draft-blumenthal-aes-usm-04 section 3.1.2.1): the key followed by
// its hash.
func extendKeyBlumenthal(authProtocol SnmpV3AuthProtocol, key []byte) []byte {
	h := authProtocol.HashType().New()
	_, _ = h.Write(key)
	return append(key, h.Sum(nil)...)
}

// genlocalPrivKey derives the key of a privacy protocol: the passphrase
// localized with the authentication protocol's hash, extended once when it is
// shorter than the cipher key, and cut to the cipher key length.
func genlocalPrivKey(privProtocol SnmpV3PrivProtocol, authProtocol SnmpV3AuthProtocol, password, engineID string) ([]byte, error) {
	spec := privProtocol.spec()
	key, err := genlocalkey(authProtocol, password, engineID)
	if err != nil {
		return nil, err
	}
	if spec.keyLen == 0 {
		return key, nil
	}

	if len(key) < spec.keyLen {
		switch spec.extension {
		case extendReeder:
			if key, err = extendKeyReeder(authProtocol, key, engineID); err != nil {
				return nil, err
			}
		case extendBlumenthal:
			key = extendKeyBlumenthal(authProtocol, key)
		}
	}
	if len(key) < spec.keyLen {
		return []byte{}, fmt.Errorf("genlocalPrivKey: privProtocol: %v len(localPrivKey): %d, keylen: %d",
			privProtocol, len(key), spec.keyLen)
	}

	return key[:spec.keyLen], nil
}

func genlocalkey(authProtocol SnmpV3AuthProtocol, passphrase, engineID string) ([]byte, error) {
	var secretKey []byte
	var err error

	secretKey, err = hMAC(authProtocol.HashType(), cacheKey(authProtocol, passphrase), passphrase, engineID)
	if err != nil {
		return []byte{}, err
	}

	return secretKey, nil
}

// usmAllocateNewSalt increments the salt counter of the privacy protocol and
// returns its new value: the 64-bit AES counter (isAES, RFC 3826 section
// 3.1.2.1) or the 32-bit DES counter (RFC 3414 section 8.1.1.1).
func (sp *UsmSecurityParameters) usmAllocateNewSalt() (salt uint64, isAES bool) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.PrivacyProtocol.spec().cipher == cipherAES {
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
	switch sp.PrivacyProtocol.spec().cipher {
	case cipherAES:
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
	msgDigest, err := spec.digest(sp.SecretKey, packet)
	if err != nil {
		return err
	}

	var buf [2 + maxMACLen]byte
	placeholder := appendMACPlaceholder(buf[:0], spec.macLen)
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

	msgDigest, err := packetSecParams.AuthenticationProtocol.spec().digest(packetSecParams.SecretKey, packetBytes)
	if err != nil {
		return false, err
	}

	// Check the message signature against the computed digest
	signature := []byte(packetSecParams.AuthenticationParameters)
	return subtle.ConstantTimeCompare(msgDigest, signature) == 1, nil
}

func (sp *UsmSecurityParameters) encryptPacket(scopedPdu []byte) ([]byte, error) {
	switch sp.PrivacyProtocol.spec().cipher {
	case cipherAES:
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[:], sp.AuthoritativeEngineBoots)
		binary.BigEndian.PutUint32(iv[4:], sp.AuthoritativeEngineTime)
		copy(iv[8:], sp.PrivacyParameters)
		block, err := aes.NewCipher(sp.PrivacyKey)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck // RFC3826 Section 3.1.1.1 specifies CFB-128 mode for AES
		stream := cipher.NewCFBEncrypter(block, iv[:])
		ciphertext := make([]byte, len(scopedPdu))
		stream.XORKeyStream(ciphertext, scopedPdu)
		scopedPdu = appendOctets(nil, OctetString, ciphertext)
	case cipherDES:
		preiv := sp.PrivacyKey[8:]
		var iv [8]byte
		for i := range len(iv) {
			iv[i] = preiv[i] ^ sp.PrivacyParameters[i]
		}
		block, err := des.NewCipher(sp.PrivacyKey[:8]) //nolint:gosec
		if err != nil {
			return nil, err
		}
		mode := cipher.NewCBCEncrypter(block, iv[:])

		pad := make([]byte, des.BlockSize-len(scopedPdu)%des.BlockSize)
		scopedPdu = append(scopedPdu, pad...)

		ciphertext := make([]byte, len(scopedPdu))
		mode.CryptBlocks(ciphertext, scopedPdu)
		scopedPdu = appendOctets(nil, OctetString, ciphertext)
	}

	return scopedPdu, nil
}

func (sp *UsmSecurityParameters) decryptPacket(packet []byte, cursor int) ([]byte, error) {
	_, cursorTmp, err := ber.Length(packet[cursor:])
	if err != nil {
		return nil, err
	}
	cursorTmp += cursor
	if cursorTmp > len(packet) {
		return nil, errors.New("error decrypting ScopedPDU: truncated packet")
	}

	switch sp.PrivacyProtocol.spec().cipher {
	case cipherAES:
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[:], sp.AuthoritativeEngineBoots)
		binary.BigEndian.PutUint32(iv[4:], sp.AuthoritativeEngineTime)
		copy(iv[8:], sp.PrivacyParameters)

		block, err := aes.NewCipher(sp.PrivacyKey)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck // RFC3826 Section 3.1.1.1 specifies CFB-128 mode for AES
		stream := cipher.NewCFBDecrypter(block, iv[:])
		plaintext := make([]byte, len(packet[cursorTmp:]))
		stream.XORKeyStream(plaintext, packet[cursorTmp:])
		copy(packet[cursor:], plaintext)
		packet = packet[:cursor+len(plaintext)]
	case cipherDES:
		if len(packet[cursorTmp:])%des.BlockSize != 0 {
			return nil, errors.New("error decrypting ScopedPDU: not multiple of des block size")
		}
		preiv := sp.PrivacyKey[8:]
		var iv [8]byte
		for i := range len(iv) {
			iv[i] = preiv[i] ^ sp.PrivacyParameters[i]
		}
		block, err := des.NewCipher(sp.PrivacyKey[:8]) //nolint:gosec
		if err != nil {
			return nil, err
		}
		mode := cipher.NewCBCDecrypter(block, iv[:])

		plaintext := make([]byte, len(packet[cursorTmp:]))
		mode.CryptBlocks(plaintext, packet[cursorTmp:])
		copy(packet[cursor:], plaintext)
		// truncate packet to remove extra space caused by the
		// octetstring/length header that was just replaced
		packet = packet[:cursor+len(plaintext)]
	}
	return packet, nil
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
		dst = appendMACPlaceholder(dst, sp.AuthenticationProtocol.spec().macLen)
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
		clear(authField[2 : 2+sp.AuthenticationProtocol.spec().macLen])
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
