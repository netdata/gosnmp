// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package netsnmp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/netdata/gosnmp"
)

// TestUSM checks gosnmp's User-based Security Model against net-snmp. For
// each case net-snmp localizes the authentication and privacy keys (with its
// key extension for AES-192/256), encrypts the scoped PDU and computes the
// HMAC of an SNMPv3 trap whose framing (headers and the plaintext scoped PDU)
// comes from gosnmp. The test then requires that gosnmp derives the same keys,
// that MarshalMsg produces exactly the net-snmp-secured message, and that
// UnmarshalTrap authenticates and decrypts it. Without `-tags netsnmp` the
// net-snmp results come from testdata/TestUSM; `-rec` rewrites them. The
// recordings also pin gosnmp's framing, so re-record only for an intended
// change of the wire format.
func TestUSM(t *testing.T) {
	recdir := filepath.Join("testdata", t.Name())
	if *rec {
		if isPlayback() {
			t.Fatal("record mode requires `-tags netsnmp` and libsnmp installed")
		}
		if err := os.MkdirAll(recdir, 0o755); err != nil {
			t.Fatalf("error creating record dir: %s", err)
		}
	}

	for _, c := range usmCases() {
		t.Run(c.name, func(t *testing.T) {
			fname := filepath.Join(recdir, c.name+".txt")

			pkt := c.packet()
			if err := pkt.SecurityParameters.InitSecurityKeys(); err != nil {
				t.Fatal(err)
			}
			sp := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
			got := usmRecording{authKey: sp.SecretKey, privKey: sp.PrivacyKey}
			msg, err := pkt.MarshalMsg()
			if err != nil {
				t.Fatal(err)
			}
			got.message = msg

			var want usmRecording
			if isPlayback() {
				want, err = readUSMRecording(fname)
			} else {
				want, err = c.secureWithNetSnmp()
			}
			if err != nil {
				t.Fatal(err)
			}
			if *rec {
				if err = want.write(fname); err != nil {
					t.Fatal(err)
				}
			}

			// The cipher uses only the proper key length; DES keys carry
			// the pre-IV after the key.
			if c.priv != gosnmp.NoPriv && len(got.privKey) > len(want.privKey) {
				got.privKey = got.privKey[:len(want.privKey)]
			}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(usmRecording{})); diff != "" {
				t.Errorf("gosnmp differs from net-snmp (-net-snmp +gosnmp):\n%s", diff)
			}

			res, err := c.receiver().UnmarshalTrap(bytes.Clone(want.message), false)
			if err != nil {
				t.Fatalf("UnmarshalTrap of the net-snmp-secured message: %v", err)
			}
			wantView := usmTrapView{
				UserName:        usmUser,
				EngineID:        c.engineID,
				ContextEngineID: c.engineID,
				ContextName:     usmContextName,
				PDUType:         gosnmp.SNMPv2Trap,
				RequestID:       usmRequestID,
				Variables:       usmVarbinds,
			}
			if diff := cmp.Diff(wantView, newUSMTrapView(res)); diff != "" {
				t.Errorf("decoded trap differs (-want +got):\n%s", diff)
			}
		})
	}
}

const (
	usmUser        = "oracle-user"
	usmAuthPass    = "oracle-auth-passphrase"
	usmPrivPass    = "oracle-priv-passphrase"
	usmContextName = "oracle-context"
	usmBoots       = 7
	usmTime        = 1234567
	usmMsgID       = 4242
	usmRequestID   = 77
)

// usmEngineID is a net-snmp style engine ID (enterprise 8072, text format).
const usmEngineID = "\x80\x00\x1f\x88\x04oracle-engine"

var usmVarbinds = []gosnmp.SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.2.3.0.1"},
	{Name: ".1.3.6.1.4.1.8072.2.3.2.1", Type: gosnmp.OctetString, Value: []byte("usm-oracle")},
	{Name: ".1.3.6.1.4.1.8072.2.3.2.2", Type: gosnmp.Integer, Value: -7},
}

// usmCase is one set of credentials secured by both libraries.
type usmCase struct {
	name     string
	auth     gosnmp.SnmpV3AuthProtocol
	priv     gosnmp.SnmpV3PrivProtocol
	authPass string
	privPass string
	engineID string
}

// usmCases are every authentication protocol with no privacy and with every
// privacy protocol, then shapes the key derivation handles separately. New
// cases need a recording: run `go test -tags netsnmp -rec -run TestUSM`.
func usmCases() []usmCase {
	auths := []gosnmp.SnmpV3AuthProtocol{gosnmp.MD5, gosnmp.SHA, gosnmp.SHA224, gosnmp.SHA256, gosnmp.SHA384, gosnmp.SHA512}
	privs := []gosnmp.SnmpV3PrivProtocol{gosnmp.NoPriv, gosnmp.DES, gosnmp.AES, gosnmp.AES192, gosnmp.AES256, gosnmp.AES192C, gosnmp.AES256C}

	var cases []usmCase
	for _, a := range auths {
		for _, p := range privs {
			cases = append(cases, usmCase{
				name:     strings.ToLower(a.String() + "-" + p.String()),
				auth:     a,
				priv:     p,
				authPass: usmAuthPass,
				privPass: usmPrivPass,
				engineID: usmEngineID,
			})
		}
	}

	return append(cases,
		// The shortest passphrase net-snmp accepts (RFC 3414 section 11.2).
		usmCase{
			name: "md5-des-passphrase-8", auth: gosnmp.MD5, priv: gosnmp.DES,
			authPass: "12345678", privPass: "abcdefgh", engineID: usmEngineID,
		},
		// Passphrases longer than the 64-octet password-to-key block.
		usmCase{
			name: "sha-aes192-passphrase-100", auth: gosnmp.SHA, priv: gosnmp.AES192,
			authPass: strings.Repeat("0123456789", 10), privPass: strings.Repeat("abcdefghij", 10), engineID: usmEngineID,
		},
		// The same passphrase for authentication and privacy.
		usmCase{
			name: "sha256-aes256-same-passphrase", auth: gosnmp.SHA256, priv: gosnmp.AES256,
			authPass: usmAuthPass, privPass: usmAuthPass, engineID: usmEngineID,
		},
		// The shortest and the longest engine IDs (RFC 3411 SnmpEngineID).
		usmCase{
			name: "md5-aes256-engine-id-5", auth: gosnmp.MD5, priv: gosnmp.AES256,
			authPass: usmAuthPass, privPass: usmPrivPass, engineID: "\x80\x00\x1f\x88\x00",
		},
		usmCase{
			name: "sha-aes256c-engine-id-32", auth: gosnmp.SHA, priv: gosnmp.AES256C,
			authPass: usmAuthPass, privPass: usmPrivPass, engineID: "\x80\x00\x1f\x88\x05" + strings.Repeat("\xa5", 27),
		},
	)
}

// salt is the msgPrivacyParameters the message carries: for DES the engine
// boots and a counter (RFC 3414 section 8.1.1.1), for AES a 64-bit integer
// (RFC 3826 section 3.1.2.1).
func (c usmCase) salt() []byte {
	switch c.priv {
	case gosnmp.NoPriv:
		return nil
	case gosnmp.DES:
		return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, usmBoots), 0x0a0b0c0d)
	default:
		return []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	}
}

func (c usmCase) flags() gosnmp.SnmpV3MsgFlags {
	if c.priv == gosnmp.NoPriv {
		return gosnmp.AuthNoPriv
	}
	return gosnmp.AuthPriv
}

func (c usmCase) usm() *gosnmp.UsmSecurityParameters {
	return &gosnmp.UsmSecurityParameters{
		UserName:                 usmUser,
		AuthenticationProtocol:   c.auth,
		AuthenticationPassphrase: c.authPass,
		PrivacyProtocol:          c.priv,
		PrivacyPassphrase:        c.privPass,
	}
}

// packet is the SNMPv2-Trap the authoritative sender secures, with the salt
// set directly instead of by InitPacket.
func (c usmCase) packet() *gosnmp.SnmpPacket {
	sp := c.usm()
	sp.AuthoritativeEngineID = c.engineID
	sp.AuthoritativeEngineBoots = usmBoots
	sp.AuthoritativeEngineTime = usmTime
	sp.PrivacyParameters = c.salt()
	return &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           c.flags(),
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: sp,
		ContextEngineID:    c.engineID,
		ContextName:        usmContextName,
		PDUType:            gosnmp.SNMPv2Trap,
		MsgID:              usmMsgID,
		RequestID:          usmRequestID,
		Variables:          usmVarbinds,
	}
}

// receiver is a trap receiver configured for the case's user, with keys
// localized to the sender's engine ID when the trap arrives.
func (c usmCase) receiver() *gosnmp.GoSNMP {
	return &gosnmp.GoSNMP{
		Version:            gosnmp.Version3,
		MsgFlags:           c.flags(),
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: c.usm(),
	}
}

// secureWithNetSnmp builds the expected message: gosnmp's framing of the
// trap with the ciphertext and the HMAC computed by net-snmp with net-snmp's
// keys.
func (c usmCase) secureWithNetSnmp() (usmRecording, error) {
	var r usmRecording
	var err error

	if r.authKey, err = netSnmpAuthKey(c.auth, c.authPass, c.engineID); err != nil {
		return r, err
	}

	if r.message, err = c.marshal(c.flags()); err != nil {
		return r, err
	}
	msg, err := parseV3Message(r.message)
	if err != nil {
		return r, err
	}

	if c.priv != gosnmp.NoPriv {
		if r.privKey, err = netSnmpPrivKey(c.auth, c.priv, c.privPass, c.engineID); err != nil {
			return r, err
		}

		// The plaintext scoped PDU is the last element of the same trap
		// sent without privacy.
		var plainMsg, ct []byte
		var plain v3Message
		if plainMsg, err = c.marshal(gosnmp.AuthNoPriv); err != nil {
			return r, err
		}
		if plain, err = parseV3Message(plainMsg); err != nil {
			return r, err
		}
		if ct, err = c.encrypt(r.privKey, plainMsg[plain.scopedPDU.hdr:plain.scopedPDU.end]); err != nil {
			return r, err
		}
		if n := msg.scopedPDU.end - msg.scopedPDU.start; len(ct) != n {
			return r, fmt.Errorf("net-snmp ciphertext is %d octets, gosnmp's %d", len(ct), n)
		}
		copy(r.message[msg.scopedPDU.start:], ct)
	}

	auth := r.message[msg.authParams.start:msg.authParams.end]
	clear(auth)
	mac, err := netSnmpHMAC(c.auth, r.authKey, r.message)
	if err != nil {
		return r, err
	}
	if len(mac) != len(auth) {
		return r, fmt.Errorf("net-snmp HMAC is %d octets, the field %d", len(mac), len(auth))
	}
	copy(auth, mac)

	return r, nil
}

// marshal encodes the case's trap with gosnmp at the given security level.
func (c usmCase) marshal(flags gosnmp.SnmpV3MsgFlags) ([]byte, error) {
	pkt := c.packet()
	pkt.MsgFlags = flags
	if err := pkt.SecurityParameters.InitSecurityKeys(); err != nil {
		return nil, err
	}
	return pkt.MarshalMsg()
}

// encrypt encrypts the scoped PDU with net-snmp. The IVs follow RFC 3414
// section 8.1.1.1 (DES: pre-IV XOR salt) and RFC 3826 section 3.1.2.1 (AES:
// boots, time and salt), as net-snmp's usm_set_salt and usm_set_aes_iv build
// them. DES plaintext is padded as gosnmp pads it (zeros, a whole block when
// already aligned); net-snmp's own padding differs and is not compared.
func (c usmCase) encrypt(key, scopedPDU []byte) ([]byte, error) {
	salt := c.salt()
	if c.priv == gosnmp.DES {
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = key[8+i] ^ salt[i]
		}
		padded := append(bytes.Clone(scopedPDU), make([]byte, 8-len(scopedPDU)%8)...)
		return netSnmpEncrypt(c.priv, key, iv, padded)
	}
	iv := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, usmBoots), usmTime)
	iv = append(iv, salt...)
	return netSnmpEncrypt(c.priv, key, iv, scopedPDU)
}

// usmRecording is what net-snmp computes for a case.
type usmRecording struct {
	authKey []byte
	privKey []byte
	message []byte
}

func (r usmRecording) write(fname string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "auth-key %x\n", r.authKey)
	if len(r.privKey) > 0 {
		fmt.Fprintf(&b, "priv-key %x\n", r.privKey)
	}
	fmt.Fprintf(&b, "message %x\n", r.message)
	return os.WriteFile(fname, []byte(b.String()), 0o600)
}

func readUSMRecording(fname string) (usmRecording, error) {
	var r usmRecording

	f, err := os.Open(fname)
	if err != nil {
		if os.IsNotExist(err) {
			return r, fmt.Errorf("%w; run `go test -tags netsnmp -rec -run TestUSM` to record it", err)
		}
		return r, err
	}
	defer f.Close()

	fields := map[string]*[]byte{"auth-key": &r.authKey, "priv-key": &r.privKey, "message": &r.message}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		dst := fields[key]
		if !ok || dst == nil {
			return r, fmt.Errorf("%s: unexpected line %q", fname, sc.Text())
		}
		if *dst, err = hex.DecodeString(value); err != nil {
			return r, fmt.Errorf("%s: %s: %w", fname, key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return r, err
	}
	if r.authKey == nil || r.message == nil {
		return r, fmt.Errorf("%s: incomplete recording", fname)
	}
	return r, nil
}

// usmTrapView is the part of a decoded trap TestUSM compares.
type usmTrapView struct {
	UserName        string
	EngineID        string
	ContextEngineID string
	ContextName     string
	PDUType         gosnmp.PDUType
	RequestID       uint32
	Variables       []gosnmp.SnmpPDU
}

func newUSMTrapView(p *gosnmp.SnmpPacket) usmTrapView {
	v := usmTrapView{
		ContextEngineID: p.ContextEngineID,
		ContextName:     p.ContextName,
		PDUType:         p.PDUType,
		RequestID:       p.RequestID,
		Variables:       p.Variables,
	}
	if sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		v.UserName = sp.UserName
		v.EngineID = sp.AuthoritativeEngineID
	}
	return v
}

// tlv locates one BER element in a message: the offsets of its tag, its
// content and the end of the content.
type tlv struct {
	tag             byte
	hdr, start, end int
}

// v3Message are the SNMPv3 message elements TestUSM rewrites.
type v3Message struct {
	authParams tlv
	scopedPDU  tlv
}

// parseV3Message finds msgAuthenticationParameters and the (possibly
// encrypted) scoped PDU in an SNMPv3 message, independently of gosnmp's
// decoder.
func parseV3Message(b []byte) (v3Message, error) {
	var m v3Message

	top, err := readTLV(b, 0)
	if err != nil {
		return m, err
	}
	msg, err := readChildren(b, top)
	if err != nil {
		return m, err
	}
	if len(msg) != 4 {
		return m, fmt.Errorf("SNMPv3 message has %d elements, want 4", len(msg))
	}
	usmSeq, err := readTLV(b, msg[2].start)
	if err != nil {
		return m, err
	}
	usm, err := readChildren(b, usmSeq)
	if err != nil {
		return m, err
	}
	if len(usm) != 6 {
		return m, fmt.Errorf("USM parameters have %d elements, want 6", len(usm))
	}
	m.authParams = usm[4]
	m.scopedPDU = msg[3]
	return m, nil
}

func readTLV(b []byte, off int) (tlv, error) {
	if off+2 > len(b) {
		return tlv{}, errors.New("truncated TLV header")
	}
	t := tlv{tag: b[off], hdr: off}
	n, i := int(b[off+1]), off+2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 || i+k > len(b) {
			return tlv{}, fmt.Errorf("unsupported length octets at %d", off)
		}
		n = 0
		for _, o := range b[i : i+k] {
			n = n<<8 | int(o)
		}
		i += k
	}
	if i+n > len(b) {
		return tlv{}, fmt.Errorf("TLV at %d overruns the message", off)
	}
	t.start, t.end = i, i+n
	return t, nil
}

func readChildren(b []byte, parent tlv) ([]tlv, error) {
	var out []tlv
	for off := parent.start; off < parent.end; {
		t, err := readTLV(b, off)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		off = t.end
	}
	return out, nil
}
