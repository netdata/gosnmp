// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
)

// The USM characterization tests pin the observable behavior of the
// User-based Security Model, known bugs included, before it is restructured:
// key derivation for every protocol pair and passphrase/engine ID shape,
// decryption of malformed privacy fields, salts, Copy, the password cache,
// parameter validation and the string forms. TestUSM in the netsnmp module
// checks the same keys, ciphertexts and digests against net-snmp.

var (
	usmAuthProtocols = []SnmpV3AuthProtocol{NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512}
	usmPrivProtocols = []SnmpV3PrivProtocol{NoPriv, DES, AES, AES192, AES256, AES192C, AES256C}
)

const usmCharEngineID = "\x80\x00\x1f\x88\x04codec-engine"

// usmKeyCase is one set of credentials whose localized keys are pinned.
type usmKeyCase struct {
	name     string
	auth     SnmpV3AuthProtocol
	priv     SnmpV3PrivProtocol
	authPass string
	privPass string
	engineID string
}

func usmKeyCases() []usmKeyCase {
	var cases []usmKeyCase
	for _, a := range usmAuthProtocols {
		for _, p := range usmPrivProtocols {
			cases = append(cases, usmKeyCase{
				name: "protocols/" + usmPairName(a, p), auth: a, priv: p,
				authPass: "codec-auth-pass", privPass: "codec-priv-pass", engineID: usmCharEngineID,
			})
		}
	}

	// MD5 with DES, SHA with both AES-256 key extensions, SHA-512 whose key
	// needs no extension.
	pairs := []struct {
		auth SnmpV3AuthProtocol
		priv SnmpV3PrivProtocol
	}{{MD5, DES}, {SHA, AES256}, {SHA, AES256C}, {SHA512, AES}}

	passphrases := []struct{ name, value string }{
		{"empty", ""},
		{"1", "a"},
		{"7", "abcdefg"},
		{"8", "abcdefgh"},
		{"64", strings.Repeat("p", 64)},
		{"65", strings.Repeat("p", 65)},
		{"binary", "\x00\xff\x80\xc3\xa9"},
	}
	engineIDs := []struct{ name, value string }{
		{"empty", ""},
		{"1", "\x80"},
		{"5", "\x80\x00\x1f\x88\x00"},
		{"32", "\x80\x00\x1f\x88\x05" + strings.Repeat("\xa5", 27)},
		{"64", strings.Repeat("\x5a", 64)},
	}
	for _, pair := range pairs {
		name := usmPairName(pair.auth, pair.priv)
		for _, pass := range passphrases {
			cases = append(cases, usmKeyCase{
				name: "passphrase-" + pass.name + "/" + name, auth: pair.auth, priv: pair.priv,
				authPass: pass.value, privPass: pass.value, engineID: usmCharEngineID,
			})
		}
		cases = append(cases,
			usmKeyCase{
				name: "auth-passphrase-empty/" + name, auth: pair.auth, priv: pair.priv,
				authPass: "", privPass: "codec-priv-pass", engineID: usmCharEngineID,
			},
			usmKeyCase{
				name: "priv-passphrase-empty/" + name, auth: pair.auth, priv: pair.priv,
				authPass: "codec-auth-pass", privPass: "", engineID: usmCharEngineID,
			},
		)
		for _, id := range engineIDs {
			cases = append(cases, usmKeyCase{
				name: "engine-id-" + id.name + "/" + name, auth: pair.auth, priv: pair.priv,
				authPass: "codec-auth-pass", privPass: "codec-priv-pass", engineID: id.value,
			})
		}
	}
	return cases
}

func usmPairName(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) string {
	return strings.ToLower(auth.String() + "-" + priv.String())
}

// TestUSMKeysCharacterization pins the keys InitSecurityKeys derives.
func TestUSMKeysCharacterization(t *testing.T) {
	var results []goldenCase
	for _, c := range usmKeyCases() {
		results = append(results, goldenCase{name: c.name, dump: dumpUSMKeys(c)})
	}
	usmGolden.check(t, "keys", results)
}

func dumpUSMKeys(c usmKeyCase) string {
	sp := &UsmSecurityParameters{
		AuthenticationProtocol:   c.auth,
		AuthenticationPassphrase: c.authPass,
		PrivacyProtocol:          c.priv,
		PrivacyPassphrase:        c.privPass,
		AuthoritativeEngineID:    c.engineID,
	}
	var err error
	panicked, wroteStdout := observe(func() { err = sp.InitSecurityKeys() })

	var d dumpWriter
	switch {
	case panicked:
		d.line("init: panic")
	case err != nil:
		d.line("init: " + dumpError(err))
	default:
		d.line("init: ok")
	}
	if wroteStdout {
		d.line("stdout: written")
	}
	d.line("auth-key: " + dumpBytes(sp.SecretKey))
	d.line("priv-key: " + dumpBytes(sp.PrivacyKey))
	return d.String()
}

// usmCharTrap encodes usmCharPacket.
func usmCharTrap(t testing.TB, priv SnmpV3PrivProtocol, salt []byte, variables []SnmpPDU) []byte {
	t.Helper()
	data, err := usmCharPacket(t, priv, salt, variables).MarshalMsg()
	require.NoError(t, err)
	return data
}

// usmCharPacket is an authPriv (authNoPriv without a privacy protocol)
// SNMPv2-Trap from codec-user, the credentials usmDecoder configures, with
// the given privacy protocol and salt and its keys initialized.
func usmCharPacket(t testing.TB, priv SnmpV3PrivProtocol, salt []byte, variables []SnmpPDU) *SnmpPacket {
	t.Helper()

	sp := &UsmSecurityParameters{
		UserName:                 "codec-user",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyProtocol:          priv,
		PrivacyPassphrase:        "codec-priv-pass",
		AuthoritativeEngineID:    usmCharEngineID,
		AuthoritativeEngineBoots: 3,
		AuthoritativeEngineTime:  77,
		PrivacyParameters:        salt,
	}
	require.NoError(t, sp.InitSecurityKeys())
	flags := AuthPriv
	if priv == NoPriv {
		flags = AuthNoPriv
	}
	return &SnmpPacket{
		Version:            Version3,
		MsgFlags:           flags,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		ContextEngineID:    usmCharEngineID,
		ContextName:        "ctx",
		PDUType:            SNMPv2Trap,
		MsgID:              21,
		RequestID:          42,
		Variables:          variables,
	}
}

var usmCharVarbinds = []SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(12345)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.2.3.0.1"},
}

func usmCharSalt(priv SnmpV3PrivProtocol) []byte {
	if priv == DES {
		return []byte{0, 0, 0, 3, 0x0a, 0x0b, 0x0c, 0x0d}
	}
	return []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
}

// v3Message is an SNMPv3 message split into the parts the USM tests change.
type v3Message struct {
	version, header []byte // contents
	usmTags         [6]byte
	usm             [6][]byte // USM field contents; 5 is msgPrivacyParameters
	scopedTag       byte
	scoped          []byte // scoped PDU content, the ciphertext when encrypted
}

func splitV3Message(t *testing.T, data []byte) v3Message {
	t.Helper()

	next := func(r *ber.Reader) (byte, []byte) {
		tag, content, err := r.Next()
		require.NoError(t, err)
		return tag, content
	}
	var m v3Message
	r := ber.NewReader(data)
	_, body := next(&r)
	mr := ber.NewReader(body)
	_, m.version = next(&mr)
	_, m.header = next(&mr)
	_, usmOctets := next(&mr)
	m.scopedTag, m.scoped = next(&mr)
	ur := ber.NewReader(usmOctets)
	_, usm := next(&ur)
	fr := ber.NewReader(usm)
	for i := range m.usm {
		m.usmTags[i], m.usm[i] = next(&fr)
	}
	return m
}

func (m v3Message) bytes() []byte {
	var usm [][]byte
	for i, f := range m.usm {
		usm = append(usm, tlv(m.usmTags[i], f))
	}
	return tlv(0x30,
		tlv(byte(Integer), m.version),
		tlv(0x30, m.header),
		tlv(byte(OctetString), tlv(0x30, usm...)),
		tlv(m.scopedTag, m.scoped))
}

// TestUSMDecryptCharacterization pins what SnmpDecodePacket (which decrypts
// without checking the digest) and UnmarshalTrap (which checks it first) make
// of an authPriv trap whose privacy parameters or ciphertext are malformed,
// or whose receiver has other privacy settings or keys localized to another
// engine ID (a message from a new engine ID replaces the keys with ones
// derived from the passphrases before the digest is checked).
func TestUSMDecryptCharacterization(t *testing.T) {
	var results []goldenCase
	for _, priv := range usmPrivProtocols[1:] {
		data := usmCharTrap(t, priv, usmCharSalt(priv), usmCharVarbinds)
		msg := splitV3Message(t, data)
		require.Equal(t, data, msg.bytes(), "splitV3Message does not round-trip")

		with := func(change func(*v3Message)) []byte {
			m := msg
			change(&m)
			return m.bytes()
		}
		other := DES
		if priv == DES {
			other = AES
		}
		decoder := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")
		name := "decrypt/" + usmPairName(SHA, priv)

		// localized returns a receiver whose keys are localized to engineID,
		// optionally without the passphrases they were derived from.
		localized := func(engineID string, keepPassphrases bool) func() *GoSNMP {
			return func() *GoSNMP {
				x := decoder()
				sp := x.SecurityParameters.(*UsmSecurityParameters)
				sp.AuthoritativeEngineID = engineID
				if err := sp.InitSecurityKeys(); err != nil {
					panic(err)
				}
				if !keepPassphrases {
					sp.AuthenticationPassphrase, sp.PrivacyPassphrase = "", ""
				}
				return x
			}
		}
		const otherEngineID = "\x80\x00\x1f\x88\x04other-engine"

		cases := []decodeCase{
			{name: name + "/ok", in: data, decoder: decoder},
			{name: name + "/salt-empty", in: with(func(m *v3Message) { m.usm[5] = nil }), decoder: decoder},
			{name: name + "/salt-7", in: with(func(m *v3Message) { m.usm[5] = m.usm[5][:7] }), decoder: decoder},
			{name: name + "/salt-9", in: with(func(m *v3Message) { m.usm[5] = append(bytes.Clone(m.usm[5]), 0x99) }), decoder: decoder},
			{name: name + "/ciphertext-empty", in: with(func(m *v3Message) { m.scoped = nil }), decoder: decoder},
			{name: name + "/ciphertext-minus-1", in: with(func(m *v3Message) { m.scoped = m.scoped[:len(m.scoped)-1] }), decoder: decoder},
			{name: name + "/ciphertext-minus-8", in: with(func(m *v3Message) { m.scoped = m.scoped[:len(m.scoped)-8] }), decoder: decoder},
			{name: name + "/receiver-" + strings.ToLower(other.String()), in: data, decoder: usmDecoder(SHA, "codec-auth-pass", other, "codec-priv-pass")},
			{name: name + "/receiver-priv-pass-empty", in: data, decoder: usmDecoder(SHA, "codec-auth-pass", priv, "")},
			{name: name + "/receiver-keys-other-engine", in: data, decoder: localized(otherEngineID, true)},
			{name: name + "/receiver-keys-only", in: data, decoder: localized(usmCharEngineID, false)},
			{name: name + "/receiver-keys-only-other-engine", in: data, decoder: localized(otherEngineID, false)},
		}
		for _, c := range cases {
			results = append(results, goldenCase{name: c.name, dump: dumpDecode(c)})
		}
	}
	usmGolden.check(t, "decrypt", results)
}

// TestUSMPrivacyPadding pins the ciphertext length: DES pads the scoped PDU
// to the next 8-octet block, with a whole block when it is already aligned;
// the AES protocols do not pad.
func TestUSMPrivacyPadding(t *testing.T) {
	for _, priv := range usmPrivProtocols[1:] {
		for n := range 16 {
			vbs := []SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: bytes.Repeat([]byte{'x'}, n)}}
			plain := splitV3Message(t, usmCharTrap(t, NoPriv, nil, vbs))
			secured := splitV3Message(t, usmCharTrap(t, priv, usmCharSalt(priv), vbs))

			plainLen := len(tlv(plain.scopedTag, plain.scoped))
			want := plainLen
			if priv == DES {
				want = plainLen + 8 - plainLen%8
			}
			assert.Equal(t, want, len(secured.scoped), "%v, scoped PDU of %d octets", priv, plainLen)
		}
	}
}

// TestUSMSalts pins how InitPacket allocates msgPrivacyParameters: a counter
// of the parameters it is called on, incremented on every call (also for
// packets without privacy), written to the packet's own parameters; DES
// prefixes the packet's engine boots (RFC 3414 section 8.1.1.1), the AES
// protocols use the 64-bit counter (RFC 3826 section 3.1.2.1). The counters
// start at zero until GoSNMP initializes them with random values.
func TestUSMSalts(t *testing.T) {
	newPacket := func(sp *UsmSecurityParameters, flags SnmpV3MsgFlags) *SnmpPacket {
		return &SnmpPacket{Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp}
	}
	salts := func(t *testing.T, sp *UsmSecurityParameters, flags ...SnmpV3MsgFlags) []string {
		t.Helper()
		var out []string
		for _, f := range flags {
			pktSP := &UsmSecurityParameters{PrivacyProtocol: sp.PrivacyProtocol, AuthoritativeEngineBoots: 9}
			require.NoError(t, sp.InitPacket(newPacket(pktSP, f)))
			out = append(out, dumpBytes(pktSP.PrivacyParameters))
		}
		return out
	}

	t.Run("aes counter", func(t *testing.T) {
		sp := &UsmSecurityParameters{PrivacyProtocol: AES256, AuthoritativeEngineBoots: 5}
		got := salts(t, sp, AuthPriv, AuthNoPriv, AuthPriv, NoAuthNoPriv, AuthPriv)
		assert.Equal(t, []string{"0000000000000001", "nil", "0000000000000003", "nil", "0000000000000005"}, got)
		assert.Nil(t, sp.PrivacyParameters, "the counter's own parameters")
	})
	t.Run("des counter and boots of the packet", func(t *testing.T) {
		sp := &UsmSecurityParameters{PrivacyProtocol: DES, AuthoritativeEngineBoots: 5}
		got := salts(t, sp, AuthPriv, AuthNoPriv, AuthPriv)
		assert.Equal(t, []string{"0000000900000001", "nil", "0000000900000003"}, got)
	})
	t.Run("aes wraps", func(t *testing.T) {
		sp := &UsmSecurityParameters{PrivacyProtocol: AES, localAESSalt: math.MaxUint64 - 1}
		got := salts(t, sp, AuthPriv, AuthPriv)
		assert.Equal(t, []string{"ffffffffffffffff", "0000000000000000"}, got)
	})
	t.Run("des wraps", func(t *testing.T) {
		sp := &UsmSecurityParameters{PrivacyProtocol: DES, localDESSalt: math.MaxUint32 - 1}
		got := salts(t, sp, AuthPriv, AuthPriv)
		assert.Equal(t, []string{"00000009ffffffff", "0000000900000000"}, got)
	})
	t.Run("no privacy protocol uses the DES layout", func(t *testing.T) {
		sp := &UsmSecurityParameters{PrivacyProtocol: NoPriv}
		got := salts(t, sp, AuthPriv)
		assert.Equal(t, []string{"0000000900000001"}, got)
	})
	t.Run("GoSNMP starts the counter at a random value", func(t *testing.T) {
		encode := func() string {
			x := &GoSNMP{
				Version:       Version3,
				MsgFlags:      AuthPriv,
				SecurityModel: UserSecurityModel,
				SecurityParameters: &UsmSecurityParameters{
					UserName:                 "codec-user",
					AuthenticationProtocol:   SHA,
					AuthenticationPassphrase: "codec-auth-pass",
					PrivacyProtocol:          AES,
					PrivacyPassphrase:        "codec-priv-pass",
					AuthoritativeEngineID:    usmCharEngineID,
				},
			}
			require.NoError(t, x.SecurityParameters.InitSecurityKeys())
			data, err := x.SnmpEncodePacket(GetRequest, nil, 0, 0)
			require.NoError(t, err)
			return string(splitV3Message(t, data).usm[5])
		}
		assert.NotEqual(t, encode(), encode())
	})
}

// TestUSMCopy pins Copy: every field is copied, the salt counters too, but
// the key and salt slices are shared with the original.
func TestUSMCopy(t *testing.T) {
	sp := &UsmSecurityParameters{
		localAESSalt:             11,
		localDESSalt:             12,
		AuthoritativeEngineID:    usmCharEngineID,
		AuthoritativeEngineBoots: 3,
		AuthoritativeEngineTime:  77,
		UserName:                 "codec-user",
		AuthenticationParameters: "auth-params",
		PrivacyParameters:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
		AuthenticationProtocol:   SHA,
		PrivacyProtocol:          AES,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyPassphrase:        "codec-priv-pass",
		Logger:                   NewLogger(&testLogger{}),
	}
	require.NoError(t, sp.InitSecurityKeys())

	cp, ok := sp.Copy().(*UsmSecurityParameters)
	require.True(t, ok)
	assert.Equal(t, sp, cp)

	t.Run("slices are shared", func(t *testing.T) {
		cp.SecretKey[0] ^= 0xff
		cp.PrivacyKey[0] ^= 0xff
		cp.PrivacyParameters[0] ^= 0xff
		assert.Equal(t, cp.SecretKey, sp.SecretKey)
		assert.Equal(t, cp.PrivacyKey, sp.PrivacyKey)
		assert.Equal(t, cp.PrivacyParameters, sp.PrivacyParameters)
	})
	t.Run("salt counters are independent", func(t *testing.T) {
		pkt := &SnmpPacket{MsgFlags: AuthPriv, SecurityParameters: &UsmSecurityParameters{PrivacyProtocol: AES}}
		require.NoError(t, cp.InitPacket(pkt))
		assert.Equal(t, uint64(12), cp.localAESSalt)
		assert.Equal(t, uint64(11), sp.localAESSalt)
	})
}

type testLogger struct{}

func (testLogger) Print(...any)          {}
func (testLogger) Printf(string, ...any) {}

// TestUSMPasswordCaching pins that the password-to-key cache does not change
// the keys: with caching on, off, re-enabled, and with concurrent users.
func TestUSMPasswordCaching(t *testing.T) {
	t.Cleanup(func() { PasswordCaching(true) })

	keys := func() []string {
		var out []string
		for _, a := range usmAuthProtocols[1:] {
			for _, p := range usmPrivProtocols[1:] {
				sp := &UsmSecurityParameters{
					AuthenticationProtocol:   a,
					AuthenticationPassphrase: "codec-auth-pass",
					PrivacyProtocol:          p,
					PrivacyPassphrase:        "codec-priv-pass",
					AuthoritativeEngineID:    usmCharEngineID,
				}
				require.NoError(t, sp.InitSecurityKeys())
				out = append(out, fmt.Sprintf("%x/%x", sp.SecretKey, sp.PrivacyKey))
			}
		}
		return out
	}

	PasswordCaching(true)
	cached := keys()
	assert.Equal(t, cached, keys(), "cache hits")

	PasswordCaching(false)
	assert.Equal(t, cached, keys(), "caching disabled")

	PasswordCaching(true)
	assert.Equal(t, cached, keys(), "caching re-enabled")

	var wg sync.WaitGroup
	results := make([][]string, 4)
	for i := range results {
		wg.Go(func() { results[i] = keys() })
	}
	wg.Wait()
	for _, r := range results {
		assert.Equal(t, cached, r, "concurrent users")
	}
}

// TestUSMValidate pins which SNMPv3 settings GoSNMP rejects before decoding
// or encoding, and the messages it rejects them with. The settings that pass
// decode a noAuthNoPriv message; keys given without passphrases are localized
// to its engine ID, since a new engine ID replaces them (decrypt golden).
func TestUSMValidate(t *testing.T) {
	msg := craftedV3NoAuth(craftedScopedResp)
	key := []byte("0123456789abcdef")

	tests := map[string]struct {
		flags   SnmpV3MsgFlags
		model   SnmpV3SecurityModel
		sp      SnmpV3SecurityParameters
		wantErr string
	}{
		"noAuthNoPriv": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{UserName: "u"},
		},
		"noAuthNoPriv without user": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{},
			wantErr: "securityParameters.UserName is required",
		},
		"authNoPriv": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p"},
		},
		"authNoPriv without protocol": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationPassphrase: "p"},
			wantErr: "securityParameters.AuthenticationProtocol is required",
		},
		"authNoPriv without passphrase": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA},
			wantErr: "securityParameters.AuthenticationPassphrase is required when an authentication protocol is specified",
		},
		"authNoPriv with a key instead of a passphrase": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, SecretKey: key, AuthoritativeEngineID: usmCharEngineID,
			},
		},
		"authNoPriv without user": {
			flags: AuthNoPriv, sp: &UsmSecurityParameters{AuthenticationProtocol: SHA, AuthenticationPassphrase: "p"},
			wantErr: "securityParameters.UserName is required",
		},
		"authPriv": {
			flags: AuthPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p",
				PrivacyProtocol: AES, PrivacyPassphrase: "q",
			},
		},
		"authPriv without privacy protocol": {
			flags: AuthPriv, sp: &UsmSecurityParameters{UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p"},
			wantErr: "securityParameters.PrivacyProtocol is required",
		},
		"authPriv without authentication protocol": {
			flags: AuthPriv, sp: &UsmSecurityParameters{UserName: "u", PrivacyProtocol: AES, PrivacyPassphrase: "q"},
			wantErr: "securityParameters.AuthenticationProtocol is required",
		},
		"authPriv without privacy passphrase": {
			flags: AuthPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, AuthenticationPassphrase: "p", PrivacyProtocol: AES,
			},
			wantErr: "securityParameters.PrivacyPassphrase is required when a privacy protocol is specified",
		},
		"authPriv with keys instead of passphrases": {
			flags: AuthPriv, sp: &UsmSecurityParameters{
				UserName: "u", AuthenticationProtocol: SHA, SecretKey: key, PrivacyProtocol: AES, PrivacyKey: key,
				AuthoritativeEngineID: usmCharEngineID,
			},
		},
		"noAuthNoPriv with a privacy protocol and no passphrase": {
			flags: NoAuthNoPriv, sp: &UsmSecurityParameters{UserName: "u", PrivacyProtocol: AES},
			wantErr: "securityParameters.PrivacyPassphrase is required when a privacy protocol is specified",
		},
		"privacy flag without authentication flag": {
			flags: 0x2, sp: &UsmSecurityParameters{UserName: "u"},
			wantErr: "validate: MsgFlags must be populated with an appropriate security level",
		},
		"no security parameters": {
			flags:   NoAuthNoPriv,
			wantErr: "SNMPV3 SecurityParameters must be set",
		},
		"other security model": {
			flags: NoAuthNoPriv, model: 2, sp: &UsmSecurityParameters{UserName: "u"},
			wantErr: "the SNMPV3 User Security Model is the only SNMPV3 security model currently implemented",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			model := tc.model
			if model == 0 {
				model = UserSecurityModel
			}
			x := &GoSNMP{Version: Version3, MsgFlags: tc.flags, SecurityModel: model, SecurityParameters: tc.sp}
			_, err := x.SnmpDecodePacket(bytes.Clone(msg))
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}

// TestUSMStrings pins SafeString and Description, which go to logs.
func TestUSMStrings(t *testing.T) {
	sp := &UsmSecurityParameters{
		AuthoritativeEngineID:    "\x80\x00\x1f\x88\x04e",
		AuthoritativeEngineBoots: 3,
		AuthoritativeEngineTime:  77,
		UserName:                 "codec-user",
		AuthenticationParameters: "",
		PrivacyParameters:        []byte{1, 2},
		AuthenticationProtocol:   SHA256,
		PrivacyProtocol:          AES192C,
		AuthenticationPassphrase: "codec-auth-pass",
		PrivacyPassphrase:        "codec-priv-pass",
	}
	assert.Equal(t, "AuthoritativeEngineID:\x80\x00\x1f\x88\x04e, AuthoritativeEngineBoots:3, AuthoritativeEngineTimes:77, "+
		"UserName:codec-user, AuthenticationParameters:, PrivacyParameters:[1 2], AuthenticationProtocol:SHA256, PrivacyProtocol:AES192C",
		sp.SafeString())
	assert.Equal(t, "user=codec-user,engine=(80001f880465),auth=sha256,authPass=codec-auth-pass,priv=AES192C,privPass=codec-priv-pass",
		sp.Description())

	for _, a := range usmAuthProtocols {
		for _, p := range usmPrivProtocols {
			s := (&UsmSecurityParameters{AuthenticationProtocol: a, PrivacyProtocol: p}).Description()
			assert.Contains(t, s, ",auth="+strings.ToLower(a.String())+",", "%v", a)
			assert.Contains(t, s, ",priv="+p.String()+",", "%v", p)
		}
	}
}
