// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestDecodeCharacterization pins what SnmpDecodePacket returns for every
// fixture, crafted edge case and fuzz corpus entry: the error (by exported
// sentinel only) or the complete packet with the Go type of every value,
// whether the input buffer was modified, and what MarshalMsg makes of the
// result. Partial results returned together with an error are not pinned.
func TestDecodeCharacterization(t *testing.T) {
	cases := slices.Concat(decodeFixtureCases(t), decodeCraftedCases(), decodeFuzzCorpusCases(t))

	results := make([]goldenCase, 0, len(cases))
	for _, c := range cases {
		results = append(results, goldenCase{name: c.name, dump: dumpDecode(c)})
	}
	checkGolden(t, "decode", results)
}

// decodeCase is one SnmpDecodePacket input and the decoder configuration.
type decodeCase struct {
	name    string
	in      []byte
	decoder func() *GoSNMP // nil means a zero GoSNMP
}

func dumpDecode(c decodeCase) string {
	x := &GoSNMP{}
	if c.decoder != nil {
		x = c.decoder()
	}

	in := bytes.Clone(c.in)
	var p *SnmpPacket
	var err error
	panicked, wroteStdout := observe(func() { p, err = x.SnmpDecodePacket(in) })

	var d dumpWriter
	switch {
	case panicked:
		d.line("decode: panic")
	case err != nil:
		d.line("decode: " + dumpError(err))
	default:
		d.line("decode: ok")
	}
	if wroteStdout {
		d.line("stdout: written")
	}
	if panicked || err != nil {
		dumpUnmarshalTrap(&d, c)
		return d.String()
	}

	if !bytes.Equal(in, c.in) {
		d.line("input: modified " + dumpBytes(in))
	}
	dumpPacket(&d, p)
	dumpReencode(&d, p, c.in)
	dumpUnmarshalTrap(&d, c)
	return d.String()
}

// dumpUnmarshalTrap records, for cases decoded with SNMPv3 credentials, what
// UnmarshalTrap returns for the same input. It is the public decode path that
// verifies the authentication digest, at the security level the decoder's
// credentials imply.
func dumpUnmarshalTrap(d *dumpWriter, c decodeCase) {
	if c.decoder == nil {
		return
	}
	x := c.decoder()
	sp, ok := x.SecurityParameters.(*UsmSecurityParameters)
	if !ok {
		return
	}
	x.Version = Version3
	x.SecurityModel = UserSecurityModel
	switch {
	case sp.PrivacyProtocol > NoPriv:
		x.MsgFlags = AuthPriv
	case sp.AuthenticationProtocol > NoAuth:
		x.MsgFlags = AuthNoPriv
	}

	var err error
	panicked, wroteStdout := observe(func() { _, err = x.UnmarshalTrap(bytes.Clone(c.in), false) })
	switch {
	case panicked:
		d.line("unmarshal-trap: panic")
	case err != nil:
		d.line("unmarshal-trap: " + dumpError(err))
	default:
		d.line("unmarshal-trap: ok")
	}
	if wroteStdout {
		d.line("unmarshal-trap-stdout: written")
	}
}

// dumpWriter collects dump lines.
type dumpWriter struct {
	lines []string
}

func (d *dumpWriter) line(s string) { d.lines = append(d.lines, s) }

func (d *dumpWriter) linef(format string, args ...any) { d.line(fmt.Sprintf(format, args...)) }

func (d *dumpWriter) String() string { return strings.Join(d.lines, "\n") }

func dumpPacket(d *dumpWriter, p *SnmpPacket) {
	d.linef("version: %d (%s)", p.Version, p.Version)
	d.linef("community: %q", p.Community)
	if p.Version == Version3 || p.MsgID != 0 || p.MsgMaxSize != 0 || p.MsgFlags != 0 || p.SecurityModel != 0 ||
		p.ContextEngineID != "" || p.ContextName != "" {
		d.linef("v3: msg-id=%d max-size=%d flags=0x%02x security-model=%d context-engine-id=%x context-name=%q",
			p.MsgID, p.MsgMaxSize, uint8(p.MsgFlags), uint8(p.SecurityModel), p.ContextEngineID, p.ContextName)
	}
	switch sp := p.SecurityParameters.(type) {
	case nil:
	case *UsmSecurityParameters:
		d.linef("usm: engine-id=%x boots=%d time=%d user=%q auth-params=%x priv-params=%x",
			sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime, sp.UserName,
			sp.AuthenticationParameters, sp.PrivacyParameters)
	default:
		d.linef("security-parameters: %T", sp)
	}
	d.linef("pdu: 0x%02x (%s) request-id=%d error=%d (%s) error-index=%d non-repeaters=%d max-repetitions=%d",
		byte(p.PDUType), p.PDUType, p.RequestID, uint8(p.Error), p.Error, p.ErrorIndex, p.NonRepeaters, p.MaxRepetitions)
	if p.Enterprise != "" || p.AgentAddress != "" || p.GenericTrap != 0 || p.SpecificTrap != 0 || p.Timestamp != 0 {
		d.linef("trap-v1: enterprise=%q agent-address=%q generic=%d specific=%d timestamp=%d",
			p.Enterprise, p.AgentAddress, p.GenericTrap, p.SpecificTrap, p.Timestamp)
	}
	if p.IsInform {
		d.line("inform: true")
	}
	if p.SnmpTrap.Variables != nil {
		d.linef("trap-variables: %d", len(p.SnmpTrap.Variables))
	}
	if p.Variables == nil {
		d.line("varbinds: nil")
	} else {
		d.linef("varbinds: %d", len(p.Variables))
	}
	for i, v := range p.Variables {
		d.linef("vb[%d]: %s 0x%02x (%s) %s", i, v.Name, byte(v.Type), v.Type, dumpValue(v.Value))
	}
}

// dumpValue prints a decoded value with its exact Go type.
func dumpValue(v any) string {
	switch v := v.(type) {
	case nil:
		return "<nil>"
	case []byte:
		if v == nil {
			return "[]uint8 nil"
		}
		return fmt.Sprintf("[]uint8 len=%d %x", len(v), v)
	case string:
		return fmt.Sprintf("string %q", v)
	case float32:
		return fmt.Sprintf("float32 %v (0x%08x)", v, math.Float32bits(v))
	case float64:
		return fmt.Sprintf("float64 %v (0x%016x)", v, math.Float64bits(v))
	default:
		return fmt.Sprintf("%T %v", v, v)
	}
}

func dumpReencode(d *dumpWriter, p *SnmpPacket, original []byte) {
	var out []byte
	var err error
	panicked, wroteStdout := observe(func() { out, err = p.MarshalMsg() })
	switch {
	case panicked:
		d.line("reencode: panic")
	case err != nil:
		d.line("reencode: " + dumpError(err))
	case bytes.Equal(out, original):
		d.line("reencode: identical")
	default:
		d.line("reencode: " + dumpBytes(out))
	}
	if wroteStdout {
		d.line("reencode-stdout: written")
	}
}

// -- fixtures -----------------------------------------------------------------

func decodeFixtureCases(t testing.TB) []decodeCase {
	t.Helper()

	var fixtures []func() []byte
	for _, tc := range testsUnmarshal {
		fixtures = append(fixtures, tc.in)
	}
	for _, tc := range testsUnmarshalErr {
		fixtures = append(fixtures, tc.in)
	}
	for _, tc := range testsEnmarshal {
		fixtures = append(fixtures, tc.goodBytes)
	}

	var cases []decodeCase
	seen := make(map[string]bool)
	for _, f := range fixtures {
		name := "fixture/" + fixtureFuncName(f)
		if seen[name] {
			continue
		}
		seen[name] = true
		cases = append(cases, decodeCase{name: name, in: f()})
	}
	for i, s := range testsInvalidSNMPResponses {
		in, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, decodeCase{name: fmt.Sprintf("fixture/invalidSNMPResponse/%d", i), in: in})
	}
	for _, f := range []struct {
		in      func() []byte
		decoder func() *GoSNMP
	}{
		{v3AuthNoPrivSHAResponse, usmDecoder(SHA, "codec-auth-pass", NoPriv, "")},
		{v3AuthPrivSHAAESResponse, usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")},
		{v3AuthPrivMD5DESResponse, usmDecoder(MD5, "codec-auth-pass", DES, "codec-priv-pass")},
	} {
		cases = append(cases, decodeCase{name: "fixture/" + fixtureFuncName(f.in), in: f.in(), decoder: f.decoder})
	}
	for _, f := range v3Fixtures {
		in, err := hex.DecodeString(f.hex)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, decodeCase{
			name:    "fixture/v3/" + f.name,
			in:      in,
			decoder: usmDecoder(f.auth, "codec-auth-pass", f.priv, "codec-priv-pass"),
		})
	}
	return cases
}

func fixtureFuncName(f func() []byte) string {
	name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	return name[strings.LastIndex(name, ".")+1:]
}

// decodeFuzzCorpusCases returns the checked-in FuzzUnmarshal corpus.
func decodeFuzzCorpusCases(t testing.TB) []decodeCase {
	t.Helper()

	dir := filepath.Join("testdata", "fuzz", "FuzzUnmarshal")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}

	var cases []decodeCase
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		in, err := parseFuzzCorpusBytes(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		cases = append(cases, decodeCase{name: "fuzz/" + e.Name(), in: in})
	}
	return cases
}

// parseFuzzCorpusBytes reads a corpus file of a fuzz target with one []byte
// argument. Like the go command, it accepts CRLF line endings (a Windows
// checkout converts them) and blank lines.
func parseFuzzCorpusBytes(data []byte) ([]byte, error) {
	version, rest, _ := strings.Cut(string(data), "\n")
	if version = strings.TrimSuffix(version, "\r"); version != "go test fuzz v1" {
		return nil, fmt.Errorf("unknown corpus encoding version %q", version)
	}
	var values []string
	for line := range strings.Lines(rest) {
		if line = strings.TrimSpace(line); line != "" {
			values = append(values, line)
		}
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("want one corpus value, got %d", len(values))
	}
	lit, ok := strings.CutPrefix(values[0], "[]byte(")
	if !ok {
		return nil, fmt.Errorf("unexpected corpus value %q", values[0])
	}
	lit, ok = strings.CutSuffix(lit, ")")
	if !ok {
		return nil, fmt.Errorf("unexpected corpus value %q", values[0])
	}
	s, err := strconv.Unquote(lit)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// -- crafted inputs -----------------------------------------------------------

// tlv builds a BER TLV with a minimal definite length.
func tlv(tag byte, content ...[]byte) []byte {
	c := bytes.Join(content, nil)
	return append(buildTLVHeader(tag, len(c)), c...)
}

// cat concatenates raw byte fragments, for malformed encodings.
func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// intContent is the minimal two's complement encoding of v.
func intContent(v int64) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(v))
	for len(b) > 1 && ((b[0] == 0x00 && b[1]&0x80 == 0) || (b[0] == 0xff && b[1]&0x80 != 0)) {
		b = b[1:]
	}
	return b
}

func intTLV(v int64) []byte { return tlv(byte(Integer), intContent(v)) }

func octets(s string) []byte { return tlv(byte(OctetString), []byte(s)) }

// craftedOID is .1.3.6.1.2.1.1.5.0 (sysName.0).
var craftedOID = tlv(byte(ObjectIdentifier), []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00})

func craftedVB(value []byte) []byte { return tlv(0x30, craftedOID, value) }

func craftedVBL(vbs ...[]byte) []byte { return tlv(0x30, vbs...) }

// craftedPDU builds a request or response PDU with request-id 1, error-status 0 and error-index 0.
func craftedPDU(tag PDUType, vbl []byte) []byte {
	return tlv(byte(tag), intTLV(1), intTLV(0), intTLV(0), vbl)
}

func craftedMsg(version int64, pdu []byte) []byte {
	return tlv(0x30, intTLV(version), octets("public"), pdu)
}

// craftedValue wraps one varbind value TLV in a v2c GetResponse.
func craftedValue(value []byte) []byte {
	return craftedMsg(1, craftedPDU(GetResponse, craftedVBL(craftedVB(value))))
}

// craftedV1Trap builds a v1 Trap message from its header fields and varbind list.
func craftedV1Trap(enterprise, agentAddress, generic, specific, timestamp, vbl []byte) []byte {
	return craftedMsg(0, tlv(byte(Trap), enterprise, agentAddress, generic, specific, timestamp, vbl))
}

var (
	craftedEnterprise   = tlv(byte(ObjectIdentifier), []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x9f, 0x14}) // .1.3.6.1.4.1.20372
	craftedAgentAddress = tlv(byte(IPAddress), []byte{192, 0, 2, 1})
	craftedTimestamp    = tlv(byte(TimeTicks), []byte{0x01, 0x00})
)

// craftedV3 builds an SNMPv3 message from its header fields, USM parameters and scoped PDU.
func craftedV3(msgID, maxSize, flags, model, usm, scoped []byte) []byte {
	return tlv(0x30, intTLV(3), tlv(0x30, msgID, maxSize, flags, model), tlv(byte(OctetString), usm), scoped)
}

func craftedUSM(engineID, boots, engineTime, user, authParams, privParams []byte) []byte {
	return tlv(0x30, engineID, boots, engineTime, user, authParams, privParams)
}

var (
	craftedEngineID   = tlv(byte(OctetString), []byte("\x80\x00\x1f\x88\x04codec-engine"))
	craftedNoAuthUSM  = craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets(""))
	craftedScopedResp = tlv(0x30, craftedEngineID, octets("ctx"), craftedPDU(GetResponse, craftedVBL(craftedVB(intTLV(5)))))
)

func craftedV3NoAuth(scoped []byte) []byte {
	return craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), craftedNoAuthUSM, scoped)
}

// usmDecoder returns a decoder configured for the synthetic codec-user credentials.
func usmDecoder(auth SnmpV3AuthProtocol, authPass string, priv SnmpV3PrivProtocol, privPass string) func() *GoSNMP {
	return func() *GoSNMP {
		return &GoSNMP{SecurityParameters: &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: authPass,
			PrivacyProtocol:          priv,
			PrivacyPassphrase:        privPass,
		}}
	}
}

// usmDecoderLocalized returns a decoder whose credentials are already
// localized to the fixtures' engine ID, as they are after discovery.
func usmDecoderLocalized(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) func() *GoSNMP {
	return func() *GoSNMP {
		x := usmDecoder(auth, "codec-auth-pass", priv, "codec-priv-pass")()
		sp := x.SecurityParameters.(*UsmSecurityParameters)
		sp.AuthoritativeEngineID = "\x80\x00\x1f\x88\x04codec-engine"
		if err := sp.InitSecurityKeys(); err != nil {
			panic(err)
		}
		return x
	}
}

// usmDecoderEngineIDWithoutKeys returns a decoder that knows the fixtures'
// engine ID but has no localized keys.
func usmDecoderEngineIDWithoutKeys(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) func() *GoSNMP {
	return func() *GoSNMP {
		x := usmDecoder(auth, "codec-auth-pass", priv, "codec-priv-pass")()
		x.SecurityParameters.(*UsmSecurityParameters).AuthoritativeEngineID = "\x80\x00\x1f\x88\x04codec-engine"
		return x
	}
}

func decodeCraftedCases() []decodeCase {
	long200 := strings.Repeat("a", 200)
	long300 := strings.Repeat("b", 300)
	nullVB := craftedVB(tlv(byte(Null)))
	okMsg := craftedValue(intTLV(5))

	return []decodeCase{
		// Message framing.
		{name: "crafted/msg/empty", in: []byte{}},
		{name: "crafted/msg/one-byte", in: []byte{0x30}},
		{name: "crafted/msg/empty-sequence", in: []byte{0x30, 0x00}},
		{name: "crafted/msg/not-sequence", in: cat([]byte{0x31}, okMsg[1:])},
		{name: "crafted/msg/trailing-byte", in: cat(okMsg, []byte{0x00})},
		{name: "crafted/msg/truncated", in: okMsg[:len(okMsg)-1]},
		{name: "crafted/msg/long-form-length", in: cat([]byte{0x30, 0x81, okMsg[1]}, okMsg[2:])},
		{name: "crafted/msg/long-form-length-2-octets", in: cat([]byte{0x30, 0x82, 0x00, okMsg[1]}, okMsg[2:])},
		{name: "crafted/msg/indefinite-length", in: cat([]byte{0x30, 0x80}, okMsg[2:], []byte{0x00, 0x00})},
		{name: "crafted/msg/length-9-octets", in: cat([]byte{0x30, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, okMsg[1]}, okMsg[2:])},
		{name: "crafted/msg/length-4-octets-max", in: cat([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, okMsg[2:])},
		{name: "crafted/msg/length-missing", in: []byte{0x30, 0x81}},

		// Version and community.
		{name: "crafted/version/0", in: craftedMsg(0, craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/2", in: craftedMsg(2, craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/3-with-community", in: craftedMsg(3, craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/256", in: craftedMsg(256, craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/-1", in: craftedMsg(-1, craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/octet-string", in: tlv(0x30, octets("\x01"), octets("public"), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/empty-integer", in: tlv(0x30, tlv(byte(Integer)), octets("public"), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/version/only", in: tlv(0x30, intTLV(1))},
		{name: "crafted/community/empty", in: tlv(0x30, intTLV(1), octets(""), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/community/integer", in: tlv(0x30, intTLV(1), intTLV(5), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/community/long-200", in: tlv(0x30, intTLV(1), octets(long200), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/community/binary", in: tlv(0x30, intTLV(1), octets("\xff\x00\x80"), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/community/oid", in: tlv(0x30, intTLV(1), craftedOID, craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/community/ipaddress", in: tlv(0x30, intTLV(1), tlv(byte(IPAddress), []byte{192, 0, 2, 1}), craftedPDU(GetResponse, craftedVBL(nullVB)))},
		{name: "crafted/community/missing-pdu", in: tlv(0x30, intTLV(1), octets("public"))},

		// PDU types and header fields.
		{name: "crafted/pdu/get-request", in: craftedMsg(1, craftedPDU(GetRequest, craftedVBL(nullVB)))},
		{name: "crafted/pdu/get-next-request", in: craftedMsg(1, craftedPDU(GetNextRequest, craftedVBL(nullVB)))},
		{name: "crafted/pdu/set-request", in: craftedMsg(1, craftedPDU(SetRequest, craftedVBL(craftedVB(intTLV(7)))))},
		{name: "crafted/pdu/getbulk-request", in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(9), intTLV(1), intTLV(10), craftedVBL(nullVB)))},
		{name: "crafted/pdu/getbulk-non-repeaters-300", in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(9), intTLV(300), intTLV(10), craftedVBL(nullVB)))},
		{name: "crafted/pdu/getbulk-max-repetitions-negative", in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(9), intTLV(0), intTLV(-1), craftedVBL(nullVB)))},
		{name: "crafted/pdu/getbulk-max-repetitions-2^31", in: craftedMsg(1, tlv(byte(GetBulkRequest), intTLV(9), intTLV(0), intTLV(1<<31), craftedVBL(nullVB)))},
		{name: "crafted/pdu/inform-request", in: craftedMsg(1, craftedPDU(InformRequest, craftedVBL(nullVB)))},
		{name: "crafted/pdu/snmpv2-trap", in: craftedMsg(1, craftedPDU(SNMPv2Trap, craftedVBL(nullVB)))},
		{name: "crafted/pdu/report-in-v2c", in: craftedMsg(1, craftedPDU(Report, craftedVBL(nullVB)))},
		{name: "crafted/pdu/unknown-tag", in: craftedMsg(1, tlv(0xa9, intTLV(1), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/sequence-tag", in: craftedMsg(1, tlv(0x30, intTLV(1), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/length-short", in: craftedMsg(1, cat([]byte{byte(GetResponse), 0x05}, intTLV(1), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/request-id-negative", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(-1), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/request-id-2^31", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1<<31), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/request-id-2^32", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1<<32), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/request-id-9-octets", in: craftedMsg(1, tlv(byte(GetResponse), tlv(byte(Integer), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/request-id-octet-string", in: craftedMsg(1, tlv(byte(GetResponse), octets("\x01"), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/request-id-empty", in: craftedMsg(1, tlv(byte(GetResponse), tlv(byte(Integer)), intTLV(0), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/error-status-5", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1), intTLV(5), intTLV(1), craftedVBL(nullVB)))},
		{name: "crafted/pdu/error-status-256", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1), intTLV(256), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/error-status-negative", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1), intTLV(-1), intTLV(0), craftedVBL(nullVB)))},
		{name: "crafted/pdu/error-index-300", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1), intTLV(0), intTLV(300), craftedVBL(nullVB)))},
		{name: "crafted/pdu/error-index-octet-string", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1), intTLV(0), octets("\x01"), craftedVBL(nullVB)))},

		// Varbind list and varbind framing.
		{name: "crafted/vbl/empty", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL()))},
		{name: "crafted/vbl/missing", in: craftedMsg(1, tlv(byte(GetResponse), intTLV(1), intTLV(0), intTLV(0)))},
		{name: "crafted/vbl/not-sequence", in: craftedMsg(1, craftedPDU(GetResponse, tlv(0x31, nullVB)))},
		{name: "crafted/vbl/length-exceeds", in: craftedMsg(1, craftedPDU(GetResponse, cat([]byte{0x30, byte(len(nullVB) + 1)}, nullVB)))},
		{name: "crafted/vbl/trailing-garbage", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(nullVB, []byte{0x00})))},
		{name: "crafted/vbl/100-varbinds", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(slices.Repeat([][]byte{nullVB}, 100)...)))},
		{name: "crafted/vb/not-sequence", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x31, craftedOID, tlv(byte(Null))))))},
		{name: "crafted/vb/empty-sequence", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30))))},
		{name: "crafted/vb/name-octet-string", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, octets("abc"), tlv(byte(Null))))))},
		{name: "crafted/vb/name-ipaddress", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(IPAddress), []byte{192, 0, 2, 1}), tlv(byte(Null))))))},
		{name: "crafted/vb/name-ipaddress-empty", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(IPAddress)), tlv(byte(Null))))))},
		{name: "crafted/vb/name-integer", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, intTLV(5), tlv(byte(Null))))))},
		{name: "crafted/vb/missing-value", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, craftedOID))))},
		{name: "crafted/vb/two-values", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, craftedOID, intTLV(1), intTLV(2)))))},
		{name: "crafted/vb/length-exceeds-vbl", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(cat([]byte{0x30, byte(len(craftedOID) + 3)}, craftedOID, tlv(byte(Null))))))},

		// Varbind names.
		{name: "crafted/oid/empty", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier)), tlv(byte(Null))))))},
		{name: "crafted/oid/single-byte", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), []byte{0x2b}), tlv(byte(Null))))))},
		{name: "crafted/oid/first-arc-2", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), []byte{0x88, 0x37, 0x01}), tlv(byte(Null))))))},
		{name: "crafted/oid/arc-max-uint32", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), []byte{0x2b, 0x8f, 0xff, 0xff, 0xff, 0x7f}), tlv(byte(Null))))))},
		{name: "crafted/oid/arc-2^32", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), []byte{0x2b, 0x90, 0x80, 0x80, 0x80, 0x00}), tlv(byte(Null))))))},
		{name: "crafted/oid/truncated-arc", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), []byte{0x2b, 0x06, 0x81}), tlv(byte(Null))))))},
		{name: "crafted/oid/non-minimal-arc", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), []byte{0x2b, 0x80, 0x06}), tlv(byte(Null))))))},
		{name: "crafted/oid/130-arcs", in: craftedMsg(1, craftedPDU(GetResponse, craftedVBL(tlv(0x30, tlv(byte(ObjectIdentifier), cat([]byte{0x2b}, bytes.Repeat([]byte{0x81, 0x01}, 129))), tlv(byte(Null))))))},

		// Integer values.
		{name: "crafted/value/integer/empty", in: craftedValue(tlv(byte(Integer)))},
		{name: "crafted/value/integer/0", in: craftedValue(intTLV(0))},
		{name: "crafted/value/integer/-1", in: craftedValue(intTLV(-1))},
		{name: "crafted/value/integer/255-non-minimal", in: craftedValue(tlv(byte(Integer), []byte{0x00, 0x00, 0xff}))},
		{name: "crafted/value/integer/max-int32", in: craftedValue(intTLV(math.MaxInt32))},
		{name: "crafted/value/integer/min-int32", in: craftedValue(intTLV(math.MinInt32))},
		{name: "crafted/value/integer/2^31", in: craftedValue(intTLV(1 << 31))},
		{name: "crafted/value/integer/2^32", in: craftedValue(intTLV(1 << 32))},
		{name: "crafted/value/integer/max-int64", in: craftedValue(intTLV(math.MaxInt64))},
		{name: "crafted/value/integer/min-int64", in: craftedValue(intTLV(math.MinInt64))},
		{name: "crafted/value/integer/9-octets", in: craftedValue(tlv(byte(Integer), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}))},
		{name: "crafted/value/integer/over-declared-by-1", in: craftedValue([]byte{byte(Integer), 0x02, 0x05})},

		// Unsigned values.
		{name: "crafted/value/counter32/empty", in: craftedValue(tlv(byte(Counter32)))},
		{name: "crafted/value/counter32/0", in: craftedValue(tlv(byte(Counter32), []byte{0x00}))},
		{name: "crafted/value/counter32/0xff", in: craftedValue(tlv(byte(Counter32), []byte{0xff}))},
		{name: "crafted/value/counter32/max-uint32", in: craftedValue(tlv(byte(Counter32), []byte{0x00, 0xff, 0xff, 0xff, 0xff}))},
		{name: "crafted/value/counter32/max-uint32-4-octets", in: craftedValue(tlv(byte(Counter32), []byte{0xff, 0xff, 0xff, 0xff}))},
		{name: "crafted/value/counter32/2^32", in: craftedValue(tlv(byte(Counter32), []byte{0x01, 0x00, 0x00, 0x00, 0x00}))},
		{name: "crafted/value/counter32/10-octets", in: craftedValue(tlv(byte(Counter32), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}))},
		{name: "crafted/value/gauge32/max-uint32", in: craftedValue(tlv(byte(Gauge32), []byte{0x00, 0xff, 0xff, 0xff, 0xff}))},
		{name: "crafted/value/gauge32/2^32", in: craftedValue(tlv(byte(Gauge32), []byte{0x01, 0x00, 0x00, 0x00, 0x00}))},
		{name: "crafted/value/timeticks/empty", in: craftedValue(tlv(byte(TimeTicks)))},
		{name: "crafted/value/timeticks/max-uint32", in: craftedValue(tlv(byte(TimeTicks), []byte{0x00, 0xff, 0xff, 0xff, 0xff}))},
		{name: "crafted/value/timeticks/2^32", in: craftedValue(tlv(byte(TimeTicks), []byte{0x01, 0x00, 0x00, 0x00, 0x00}))},
		{name: "crafted/value/uinteger32/1", in: craftedValue(tlv(byte(Uinteger32), []byte{0x01}))},
		{name: "crafted/value/uinteger32/2^32", in: craftedValue(tlv(byte(Uinteger32), []byte{0x01, 0x00, 0x00, 0x00, 0x00}))},
		{name: "crafted/value/uinteger32/0xff", in: craftedValue(tlv(byte(Uinteger32), []byte{0xff}))},
		{name: "crafted/value/uinteger32/empty", in: craftedValue(tlv(byte(Uinteger32)))},
		{name: "crafted/value/counter64/empty", in: craftedValue(tlv(byte(Counter64)))},
		{name: "crafted/value/counter64/0", in: craftedValue(tlv(byte(Counter64), []byte{0x00}))},
		{name: "crafted/value/counter64/max-uint64", in: craftedValue(tlv(byte(Counter64), cat([]byte{0x00}, bytes.Repeat([]byte{0xff}, 8))))},
		{name: "crafted/value/counter64/max-uint64-8-octets", in: craftedValue(tlv(byte(Counter64), bytes.Repeat([]byte{0xff}, 8)))},
		{name: "crafted/value/counter64/2^64", in: craftedValue(tlv(byte(Counter64), cat([]byte{0x01}, make([]byte, 8))))},
		{name: "crafted/value/counter64/10-octets", in: craftedValue(tlv(byte(Counter64), cat([]byte{0x01}, make([]byte, 9))))},

		// Octet strings.
		{name: "crafted/value/octet-string/empty", in: craftedValue(octets(""))},
		{name: "crafted/value/octet-string/long-200", in: craftedValue(octets(long200))},
		{name: "crafted/value/octet-string/long-300", in: craftedValue(octets(long300))},
		{name: "crafted/value/octet-string/over-declared-by-1", in: craftedValue(cat([]byte{byte(OctetString), 0x06}, []byte("hello")))},
		{name: "crafted/value/octet-string/over-declared-by-2", in: craftedValue(cat([]byte{byte(OctetString), 0x07}, []byte("hello")))},
		{name: "crafted/value/octet-string/under-declared", in: craftedValue(cat([]byte{byte(OctetString), 0x04}, []byte("hello")))},
		{name: "crafted/value/octet-string/length-9-octets", in: craftedValue(cat([]byte{byte(OctetString), 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}))},
		{name: "crafted/value/octet-string/length-missing", in: craftedValue([]byte{byte(OctetString)})},

		// Other value types.
		{name: "crafted/value/null/with-content", in: craftedValue(tlv(byte(Null), []byte{0x00}))},
		{name: "crafted/value/oid/normal", in: craftedValue(tlv(byte(ObjectIdentifier), []byte{0x2b, 0x06, 0x01, 0x04, 0x01}))},
		{name: "crafted/value/oid/empty", in: craftedValue(tlv(byte(ObjectIdentifier)))},
		{name: "crafted/value/oid/truncated-arc", in: craftedValue(tlv(byte(ObjectIdentifier), []byte{0x2b, 0x86}))},
		{name: "crafted/value/ip-address/4-octets", in: craftedValue(tlv(byte(IPAddress), []byte{192, 0, 2, 1}))},
		{name: "crafted/value/ip-address/empty", in: craftedValue(tlv(byte(IPAddress)))},
		{name: "crafted/value/ip-address/3-octets", in: craftedValue(tlv(byte(IPAddress), []byte{192, 0, 2}))},
		{name: "crafted/value/ip-address/5-octets", in: craftedValue(tlv(byte(IPAddress), []byte{192, 0, 2, 1, 7}))},
		{name: "crafted/value/ip-address/16-octets", in: craftedValue(tlv(byte(IPAddress), []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}))},
		{name: "crafted/value/opaque/raw", in: craftedValue(tlv(byte(Opaque), []byte{0x01, 0x02}))},
		{name: "crafted/value/opaque/empty", in: craftedValue(tlv(byte(Opaque)))},
		{name: "crafted/value/opaque/float", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x78, 0x04, 0x41, 0x20, 0x00, 0x00}))},
		{name: "crafted/value/opaque/float-nan", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x78, 0x04, 0x7f, 0xc0, 0x00, 0x01}))},
		{name: "crafted/value/opaque/float-truncated", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x78, 0x04, 0x41, 0x20, 0x00}))},
		{name: "crafted/value/opaque/float-long", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x78, 0x05, 0x41, 0x20, 0x00, 0x00, 0x00}))},
		{name: "crafted/value/opaque/double", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x79, 0x08, 0x40, 0x24, 0, 0, 0, 0, 0, 0}))},
		{name: "crafted/value/opaque/double-truncated", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x79, 0x08, 0x40, 0x24, 0, 0, 0, 0, 0}))},
		{name: "crafted/value/opaque/inner-counter64", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x76, 0x01, 0x05}))},
		{name: "crafted/value/opaque/inner-int64", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x7a, 0x01, 0x05}))},
		{name: "crafted/value/opaque/inner-tag-only", in: craftedValue(tlv(byte(Opaque), []byte{0x9f}))},
		{name: "crafted/value/opaque/extension-two-octets", in: craftedValue(tlv(byte(Opaque), []byte{0x9f, 0x78}))},
		{name: "crafted/value/nsap-address", in: craftedValue(tlv(byte(NsapAddress), []byte{0x01, 0x02}))},
		{name: "crafted/value/boolean", in: craftedValue(tlv(byte(Boolean), []byte{0xff}))},
		{name: "crafted/value/bit-string", in: craftedValue(tlv(byte(BitString), []byte{0x00, 0xff}))},
		{name: "crafted/value/object-description", in: craftedValue(tlv(byte(ObjectDescription), []byte("d")))},
		{name: "crafted/value/no-such-object", in: craftedValue(tlv(byte(NoSuchObject)))},
		{name: "crafted/value/no-such-instance", in: craftedValue(tlv(byte(NoSuchInstance)))},
		{name: "crafted/value/end-of-mib-view", in: craftedValue(tlv(byte(EndOfMibView)))},
		{name: "crafted/value/no-such-object-with-content", in: craftedValue(tlv(byte(NoSuchObject), []byte{0x00}))},
		{name: "crafted/value/no-such-instance-with-content", in: craftedValue(tlv(byte(NoSuchInstance), []byte{0x00}))},
		{name: "crafted/value/end-of-mib-view-with-content", in: craftedValue(tlv(byte(EndOfMibView), []byte{0x00}))},
		{name: "crafted/value/context-tag-3", in: craftedValue(tlv(0x83))},
		{name: "crafted/value/tag-0", in: craftedValue(tlv(0x00))},
		{name: "crafted/value/high-tag-number", in: craftedValue(cat([]byte{0x1f, 0x22, 0x00}))},
		{name: "crafted/value/constructed-context-tag", in: craftedValue(tlv(0xa0))},
		{name: "crafted/value/sequence", in: craftedValue(tlv(0x30, intTLV(1)))},

		// v1 Trap.
		{name: "crafted/trap-v1/basic", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(42), craftedTimestamp, craftedVBL(craftedVB(intTLV(5))))},
		{name: "crafted/trap-v1/empty-vbl", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(0), intTLV(0), craftedTimestamp, craftedVBL())},
		{name: "crafted/trap-v1/missing-vbl", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(0), intTLV(0), craftedTimestamp, nil)},
		{name: "crafted/trap-v1/agent-address-empty", in: craftedV1Trap(craftedEnterprise, tlv(byte(IPAddress)), intTLV(6), intTLV(1), craftedTimestamp, craftedVBL(nullVB))},
		{name: "crafted/trap-v1/agent-address-16-octets", in: craftedV1Trap(craftedEnterprise, tlv(byte(IPAddress), make([]byte, 16)), intTLV(6), intTLV(1), craftedTimestamp, craftedVBL(nullVB))},
		{name: "crafted/trap-v1/agent-address-octet-string", in: craftedV1Trap(craftedEnterprise, octets("\xc0\x00\x02\x01"), intTLV(6), intTLV(1), craftedTimestamp, craftedVBL(nullVB))},
		{name: "crafted/trap-v1/enterprise-octet-string", in: craftedV1Trap(octets("x"), craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, craftedVBL(nullVB))},
		{name: "crafted/trap-v1/generic-octet-string", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, octets("\x06"), intTLV(1), craftedTimestamp, craftedVBL(nullVB))},
		{name: "crafted/trap-v1/specific-negative", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(-1), craftedTimestamp, craftedVBL(nullVB))},
		{name: "crafted/trap-v1/timestamp-2^32", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), tlv(byte(TimeTicks), []byte{0x01, 0, 0, 0, 0}), craftedVBL(nullVB))},
		{name: "crafted/trap-v1/timestamp-integer", in: craftedV1Trap(craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), intTLV(256), craftedVBL(nullVB))},
		{name: "crafted/trap-v1/in-v2c-message", in: craftedMsg(1, tlv(byte(Trap), craftedEnterprise, craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, craftedVBL(nullVB)))},

		// SNMPv3 framing (noAuthNoPriv, zero decoder).
		{name: "crafted/v3/no-auth-response", in: craftedV3NoAuth(craftedScopedResp)},
		{name: "crafted/v3/flags-empty", in: craftedV3(intTLV(42), intTLV(65507), octets(""), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/flags-two-octets", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00\x00"), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/flags-two-octets-reportable", in: craftedV3(intTLV(42), intTLV(65507), octets("\x04\x00"), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/flags-integer", in: craftedV3(intTLV(42), intTLV(65507), intTLV(0), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/security-model-2", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(2), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/msg-id-negative", in: craftedV3(intTLV(-1), intTLV(65507), octets("\x00"), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/max-size-octet-string", in: craftedV3(intTLV(42), octets("\x01"), octets("\x00"), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{name: "crafted/v3/usm-not-sequence", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), tlv(0x31, craftedEngineID), craftedScopedResp)},
		{name: "crafted/v3/usm-empty", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), nil, craftedScopedResp)},
		{name: "crafted/v3/usm-boots-octet-string", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), craftedUSM(craftedEngineID, octets("\x07"), intTLV(1234), octets("codec-user"), octets(""), octets("")), craftedScopedResp)},
		{name: "crafted/v3/usm-engine-id-200", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), craftedUSM(octets(long200), intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets("")), craftedScopedResp)},
		{name: "crafted/v3/usm-user-name-200", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets(long200), octets(""), octets("")), craftedScopedResp)},
		{name: "crafted/v3/usm-empty-engine-id", in: craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3), craftedUSM(octets(""), intTLV(0), intTLV(0), octets(""), octets(""), octets("")), craftedScopedResp)},
		{name: "crafted/v3/scoped-pdu-octet-string-no-priv", in: craftedV3NoAuth(octets("\x30\x00"))},
		{name: "crafted/v3/scoped-pdu-missing", in: tlv(0x30, intTLV(3), tlv(0x30, intTLV(42), intTLV(65507), octets("\x00"), intTLV(3)), tlv(byte(OctetString), craftedNoAuthUSM))},
		{name: "crafted/v3/context-engine-id-integer", in: craftedV3NoAuth(tlv(0x30, intTLV(1), octets("ctx"), craftedPDU(GetResponse, craftedVBL(nullVB))))},
		{name: "crafted/v3/context-name-missing", in: craftedV3NoAuth(tlv(0x30, craftedEngineID))},
		{name: "crafted/v3/auth-flag-zero-decoder", in: craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), craftedNoAuthUSM, craftedScopedResp)},
		{
			name:    "crafted/v3/auth-params-integer",
			in:      craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), intTLV(5), octets("")), craftedScopedResp),
			decoder: usmDecoder(SHA, "codec-auth-pass", NoPriv, ""),
		},

		// SNMPv3 with authentication and privacy.
		{
			name:    "crafted/v3/auth-no-priv-sha/wrong-auth-pass",
			in:      v3AuthNoPrivSHAResponse(),
			decoder: usmDecoder(SHA, "wrong-auth-pass", NoPriv, ""),
		},
		{name: "crafted/v3/auth-no-priv-sha/zero-decoder", in: v3AuthNoPrivSHAResponse()},
		{
			name:    "crafted/v3/auth-priv-sha-aes/wrong-priv-pass",
			in:      v3AuthPrivSHAAESResponse(),
			decoder: usmDecoder(SHA, "codec-auth-pass", AES, "wrong-priv-pass"),
		},
		{
			name:    "crafted/v3/auth-priv-sha-aes/no-priv-decoder",
			in:      v3AuthPrivSHAAESResponse(),
			decoder: usmDecoder(SHA, "codec-auth-pass", NoPriv, ""),
		},
		{
			name:    "crafted/v3/auth-priv-sha-aes/localized-decoder",
			in:      v3AuthPrivSHAAESResponse(),
			decoder: usmDecoderLocalized(SHA, AES),
		},
		{
			name:    "crafted/v3/auth-priv-sha-aes/engine-id-without-keys",
			in:      v3AuthPrivSHAAESResponse(),
			decoder: usmDecoderEngineIDWithoutKeys(SHA, AES),
		},
		{
			name:    "crafted/v3/auth-priv-md5-des/localized-decoder",
			in:      v3AuthPrivMD5DESResponse(),
			decoder: usmDecoderLocalized(MD5, DES),
		},
		{
			name:    "crafted/v3/auth-priv-md5-des/engine-id-without-keys",
			in:      v3AuthPrivMD5DESResponse(),
			decoder: usmDecoderEngineIDWithoutKeys(MD5, DES),
		},
		{
			name:    "crafted/v3/auth-no-priv-sha/localized-decoder",
			in:      v3AuthNoPrivSHAResponse(),
			decoder: usmDecoderLocalized(SHA, NoPriv),
		},
		{
			name:    "crafted/v3/auth-priv-md5-des/wrong-priv-pass",
			in:      v3AuthPrivMD5DESResponse(),
			decoder: usmDecoder(MD5, "codec-auth-pass", DES, "wrong-priv-pass"),
		},
	}
}

// The v3 fixtures are GetResponse messages made by MarshalMsg (after
// InitPacket) for user "codec-user", engine ID 80001f8804"codec-engine",
// boots 7, time 1234, context "codec-context", authentication passphrase
// "codec-auth-pass" and privacy passphrase "codec-priv-pass". They carry
// sysName.0 = "codec-host" and sysUpTime.0 = 98765.

func v3AuthNoPrivSHAResponse() []byte {
	return []byte{
		0x30, 0x81, 0xac, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x00, 0x00, 0x10, 0x92, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x01, 0x02, 0x01, 0x03, 0x04, 0x38, 0x30, 0x36, 0x04, 0x11, 0x80,
		0x00, 0x1f, 0x88, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65,
		0x02, 0x01, 0x07, 0x02, 0x02, 0x04, 0xd2, 0x04, 0x0a, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x75,
		0x73, 0x65, 0x72, 0x04, 0x0c, 0x11, 0x54, 0x40, 0x2d, 0x7e, 0x48, 0xd7, 0xe3, 0xee, 0xef, 0xd1,
		0x68, 0x04, 0x00, 0x30, 0x5a, 0x04, 0x11, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x63, 0x6f, 0x64, 0x65,
		0x63, 0x2d, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x04, 0x0d, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d,
		0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0xa2, 0x36, 0x02, 0x03, 0x01, 0xe2, 0x40, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x30, 0x29, 0x30, 0x16, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
		0x05, 0x00, 0x04, 0x0a, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x0f,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x03, 0x01, 0x81, 0xcd,
	}
}

func v3AuthPrivSHAAESResponse() []byte {
	return []byte{
		0x30, 0x81, 0xb6, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x00, 0x00, 0x10, 0x92, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x03, 0x02, 0x01, 0x03, 0x04, 0x40, 0x30, 0x3e, 0x04, 0x11, 0x80,
		0x00, 0x1f, 0x88, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65,
		0x02, 0x01, 0x07, 0x02, 0x02, 0x04, 0xd2, 0x04, 0x0a, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x75,
		0x73, 0x65, 0x72, 0x04, 0x0c, 0x3b, 0x68, 0xdb, 0x89, 0x0b, 0x9a, 0xb4, 0x4e, 0xbb, 0x8c, 0xd7,
		0x18, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x5c, 0xcd, 0x93, 0x70,
		0xed, 0x7d, 0xa6, 0x07, 0x8b, 0x60, 0xe0, 0xf6, 0x21, 0xda, 0x87, 0xc2, 0x22, 0x88, 0x45, 0xa0,
		0xcb, 0x4d, 0x3c, 0xf6, 0xc8, 0xe5, 0xf2, 0xe3, 0xd1, 0x7a, 0x2b, 0x89, 0xb0, 0x75, 0x89, 0x78,
		0x8c, 0x00, 0x22, 0xcb, 0x6a, 0x25, 0x12, 0xc2, 0x35, 0x74, 0x09, 0x6d, 0x0a, 0x43, 0x27, 0xa8,
		0x97, 0xde, 0x0d, 0x25, 0xe6, 0x17, 0xdd, 0x88, 0xfe, 0x58, 0xa4, 0xc4, 0x8d, 0x98, 0xf8, 0x00,
		0x3c, 0x49, 0xb1, 0x79, 0xa8, 0x6f, 0xcb, 0x28, 0x78, 0xbc, 0x25, 0xe5, 0x8a, 0x39, 0xcf, 0x1e,
		0xff, 0x96, 0x3d, 0x68, 0xba, 0x64, 0xcb, 0x79, 0x0f,
	}
}

func v3AuthPrivMD5DESResponse() []byte {
	return []byte{
		0x30, 0x81, 0xba, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x00, 0x00, 0x10, 0x92, 0x02, 0x03,
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x03, 0x02, 0x01, 0x03, 0x04, 0x40, 0x30, 0x3e, 0x04, 0x11, 0x80,
		0x00, 0x1f, 0x88, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65,
		0x02, 0x01, 0x07, 0x02, 0x02, 0x04, 0xd2, 0x04, 0x0a, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x2d, 0x75,
		0x73, 0x65, 0x72, 0x04, 0x0c, 0x74, 0xdb, 0x1c, 0x45, 0x02, 0x3e, 0x69, 0x07, 0x8a, 0xe0, 0xcc,
		0x77, 0x04, 0x08, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x04, 0x60, 0x42, 0x19, 0x2a,
		0xa5, 0x5e, 0x9e, 0x17, 0x77, 0x8b, 0xf4, 0x03, 0x13, 0x90, 0xb5, 0xb0, 0x5c, 0x44, 0x03, 0xcb,
		0x8e, 0x5e, 0x68, 0x8f, 0x03, 0xad, 0xce, 0xdb, 0x06, 0x78, 0x7f, 0xed, 0x32, 0xd1, 0x34, 0x20,
		0xca, 0xa8, 0xd7, 0xed, 0xda, 0x1e, 0xc7, 0xc5, 0x40, 0xa0, 0xc8, 0x6f, 0x22, 0x6d, 0x3c, 0x95,
		0x03, 0x9c, 0x11, 0x8a, 0x77, 0x76, 0xba, 0xf7, 0x44, 0x49, 0x4c, 0x71, 0xff, 0x31, 0x5f, 0x7d,
		0x5b, 0x8f, 0x27, 0x54, 0xfe, 0x46, 0x1c, 0x8a, 0x9f, 0xa0, 0x1d, 0x66, 0xdd, 0xef, 0x43, 0xbb,
		0x41, 0xd3, 0x59, 0x4f, 0xa5, 0x09, 0x48, 0x3f, 0xf3, 0xe7, 0xed, 0x34, 0x91,
	}
}

// v3Fixtures are more GetResponse messages made the same way: one per
// authentication protocol, and scoped PDUs long enough (4 and 20 varbinds of
// sysName-like OctetStrings) to need long-form lengths in plaintext and
// encrypted form.
var v3Fixtures = []struct {
	name string
	auth SnmpV3AuthProtocol
	priv SnmpV3PrivProtocol
	hex  string
}{
	{"md5-no-priv", MD5, NoPriv, "3081b70201033011020400001092020300ffe304010102010304383036041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d75736572040cc80d165de740913804ce588604003065041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a241020301e2400201000201003034301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31"},
	{"sha224-no-priv", SHA224, NoPriv, "3081bb0201033011020400001092020300ffe3040101020103043c303a041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d757365720410fcf61f262134fa3c911049016d89a09004003065041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a241020301e2400201000201003034301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31"},
	{"sha256-no-priv", SHA256, NoPriv, "3081c30201033011020400001092020300ffe304010102010304443042041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d757365720418307c1e97c620111e5ebdc21007b1271df911388f95f2ebe504003065041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a241020301e2400201000201003034301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31"},
	{"sha384-no-priv", SHA384, NoPriv, "3081cb0201033011020400001092020300ffe3040101020103044c304a041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d7573657204209455c83f9f6742b448b51d7f0ae761d522809c79d329f7093acc8dd18d8dc81204003065041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a241020301e2400201000201003034301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31"},
	{"sha512-no-priv", SHA512, NoPriv, "3081db0201033011020400001092020300ffe3040101020103045c305a041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d7573657204304b4cbcb73771a64a01869451863f2da738abfab179be611e72da2fe9437734fe7dadf119eac0b90336c589cc7b1799f104003065041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a241020301e2400201000201003034301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31"},
	{"sha256-aes256c", SHA256, AES256C, "3081cd0201033011020400001092020300ffe3040103020103044c304a041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d75736572041857106f4372af877a899fc8c4fbdf7ce752e77dbdc5d8a0210408000000000000000104674fc68877d36da6b9eeab43480a55a6366ee5474d8fd8628d0617de801917d38d2f1fc6cff9b9c079b2cf09efab05b4f0eb5fea9a7b90582c16a7e409eff5c9e1d9d7014d5933e6ed7caf5896cc3a1029146fc1a17445141c02df92e7d58abb95d9ec5f2afc52ee"},
	{"sha512-des", SHA512, DES, "3081e60201033011020400001092020300ffe304010302010304643062041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d757365720430dd204b253ce4ae9d001c83dd1dd86dfdb03bed93221671d991433bfba0d46ab7271d284f6fc9ab3bf73dc0cf0bf282d5040800000007000000010468b26ef8f086f974f7f182853c691c3b0b7896dd33926b61c192e9a86f089607c16709d7e59d4548c5476d49889170744381bab8d0a7da5277636b4bf92d9b69ae29e55948ee615d57591645adc4400d90b73abd77e569871bd6a76a038ea6a2b6d16bb3de2ccb2dcf"},
	{"no-auth-no-priv-20-varbinds", NoAuth, NoPriv, "3082028f0201033011020400001092020300ffe3040100020103042c302a041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d757365720400040030820247041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a2820221020301e24002010002010030820212301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31301806082b06010201010502040c636f6465632d686f73742d32301806082b06010201010503040c636f6465632d686f73742d33301806082b06010201010504040c636f6465632d686f73742d34301806082b06010201010505040c636f6465632d686f73742d35301806082b06010201010506040c636f6465632d686f73742d36301806082b06010201010507040c636f6465632d686f73742d37301806082b06010201010508040c636f6465632d686f73742d38301806082b06010201010509040c636f6465632d686f73742d39301906082b0601020101050a040d636f6465632d686f73742d3130301906082b0601020101050b040d636f6465632d686f73742d3131301906082b0601020101050c040d636f6465632d686f73742d3132301906082b0601020101050d040d636f6465632d686f73742d3133301906082b0601020101050e040d636f6465632d686f73742d3134301906082b0601020101050f040d636f6465632d686f73742d3135301906082b06010201010510040d636f6465632d686f73742d3136301906082b06010201010511040d636f6465632d686f73742d3137301906082b06010201010512040d636f6465632d686f73742d3138301906082b06010201010513040d636f6465632d686f73742d3139"},
	{"sha-no-priv-20-varbinds", SHA, NoPriv, "3082029b0201033011020400001092020300ffe304010102010304383036041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d75736572040ceabeb49e32f5cfc9f624a2ff040030820247041180001f8804636f6465632d656e67696e65040d636f6465632d636f6e74657874a2820221020301e24002010002010030820212301806082b06010201010500040c636f6465632d686f73742d30301806082b06010201010501040c636f6465632d686f73742d31301806082b06010201010502040c636f6465632d686f73742d32301806082b06010201010503040c636f6465632d686f73742d33301806082b06010201010504040c636f6465632d686f73742d34301806082b06010201010505040c636f6465632d686f73742d35301806082b06010201010506040c636f6465632d686f73742d36301806082b06010201010507040c636f6465632d686f73742d37301806082b06010201010508040c636f6465632d686f73742d38301806082b06010201010509040c636f6465632d686f73742d39301906082b0601020101050a040d636f6465632d686f73742d3130301906082b0601020101050b040d636f6465632d686f73742d3131301906082b0601020101050c040d636f6465632d686f73742d3132301906082b0601020101050d040d636f6465632d686f73742d3133301906082b0601020101050e040d636f6465632d686f73742d3134301906082b0601020101050f040d636f6465632d686f73742d3135301906082b06010201010510040d636f6465632d686f73742d3136301906082b06010201010511040d636f6465632d686f73742d3137301906082b06010201010512040d636f6465632d686f73742d3138301906082b06010201010513040d636f6465632d686f73742d3139"},
	{"sha-aes-4-varbinds", SHA, AES, "3081f70201033011020400001092020300ffe30401030201030440303e041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d75736572040ca592ad7567bfa5f69550daff0408000000000000000104819ccd48edf8ec26181cec87fa2adb818c6abcb0091d6ad11dcabaf69d00fd4afbcce2e3848fa787b4d273097131d3b9abb7bef77df1c00becc23cef80f4fa45ee4030ab936cfdc12bff1af79a641ec4c467a4f6d06e7d9e80ef9a5b193c653a0e3cb26c7eac379eacd6ab0525f3f3bd611e4de1fa7b2a8c225fced3a784d7112415c11d094559dbfbd3c57473f0eb484af116526d539d1bb002949de5f1"},
	{"sha-aes-20-varbinds", SHA, AES, "308202a70201033011020400001092020300ffe30401030201030440303e041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d75736572040c29d727b83d33ffbed3d8823a040800000000000000010482024bcd4b76bbf9b798037b0b9d26d0808a2437d82520d6d383ecf63a7e08f73a55013949b6e6d15811980c99cacec0210e695aebc59d530d32dfb490452f4f8ba1bcfd47b8008f501df7c95aaa368be28c40e07f18d1788ffc5bcbb3670ee4a732b50e347219cbd442df7f48f5a756d51a14bd9775fea1c25642a2918deb4ce60740b8e98e82ab24cd375112a633b3e86a4ae47b6339921bc76cf23986d447785c36d997470ded6e7920a76bf629b3bbd06598fa3a888e6e20b84408d51f5e560771da645af1993232f2d2f473bed4c549e29d9e6d4390c9da86fba3d53fb59da6fc0fa8ae3a9e28dbf8e003ef78971084bb7b1e2a28a0bb9c11730773cd180e09a2b74c1d99da96089ff3a3ef3b2b4ed12e8cd60939e469c81efce042a5588f9b4a4a7055702b687c9fff2de8b0c9a01f43904e1055a0ba926b26f95430ba75765982aa6e0b196ec32e5836f84ec58002d4dc2ad26f2986555ca4a43bf8b49342b3316fdaa9d98f96c5567f3060a141399e9e45f76abec1aa020dba5d86d7aa643ab83d192010f66e30081d9cccbb262ca81887f194c67901f2a72f8995d4a5b634349e48c980473bf18c7ea0652a4f8f59c9980c625d4b9eed559a5a9420e7b83249d3a4a427beb5c103915297c0e0e16adf58381e4954dfafca7861620986816cce6ee784037e77d12829bcdfdeb8d70ac8d60324f08ae89e4866fa6772232f68e4dc16afa08740742461211e737f0e671e042437885491ff997c35d7bbda95adf45de0f7a9fa49c7062c3ae4eef95055ba3ce8b5fe63bad8cd97b865a9abb05b0de7ad5a5f03c9c2446611"},
	{"md5-des-20-varbinds", MD5, DES, "308202ac0201033011020400001092020300ffe30401030201030440303e041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d75736572040c8272fa62ec3c65f3b9f6f1e60408000000070000000104820250eec67b647b57a50d90fc19e0462405c859c90f401fe0e69dda94014d0b1b7403e2ff8229a80d1fa97e0795239c3720d1bd05d063760200d944a8f8f5f3a660f57bd42913f43bcd954e2b50c64b1f5e79890f78d01b8426f89c4181ba9a3418ab61dd1d9f2f42ffade8347d6ef5d902f6ab1d2fc4a187a289a1a652462dcd2abceafaa18e9b3e11acdd0ad60634541268fbfb768ed3d9bbceaeca6c5c4ba31ad8ee4b32ec3a59636e114842ad0cf5441f598990be9a17e4bb2073ff346defbbc69f0cbe81fcbbf09796b93fcf6cbda5a6702913842c1a035f6b9162ec58bb86a5f4b38dd689688c9385e92de422d3c8203511876ec9e0d8c8c623b60b169b36818f44b8f671d09890a2694940654b756f78d91c5e0530e883b26a6b70a9ad0c0cadc989340bb60f18eb8127f73697f475a2c7fa244904d68faeb3411daf93b33277a47f3c60cd29f02f21d7a47c940996e48337d7d0c202bdeeea924c7bf81e805874b3f6c7c1b30802aa19f1793e85543d4fcc7760e59a5a29c954a633a2da657e1bda7f5a0a7649424c222fd9edebaf867b6a29bf0d5c64663c383df7a56781372e81cedb6f6509d71be3b8e141cc4d321f76b86ace3d63fb687d8ea07b802b924b6c598b6620f9092e0150cbc9914d9c05854becd119b07820206d9b8100b7d2a686b6db8792edfaace78fc37bde60b0db351f14a7773ef73f26b8864afed49eabcb352b688f0c19ee308aa03f0d00acb64161048c6c4c5a225659c8565f71d1c8a1866e1343f1eccd0e54247e31cf9058bb652b595dc0954f38761f4da222e8ce2013f3be97b2bfc8e4fa37cb00c3"},
	{"sha512-aes-20-varbinds", SHA512, AES, "308202cb0201033011020400001092020300ffe304010302010304643062041180001f8804636f6465632d656e67696e65020107020204d2040a636f6465632d7573657204308adadfef3510a12fb3aef738bf16fd41c04ad66dbe741838f04c93ca56fa4ec7359206a877aa79f24ed85d70554ab2d7040800000000000000010482024bb7b7684c9e593309401907f2a99e1fd826e76149021a2309860d5a2457cf13aaea30d8b2ecffd52839058bb0ceb2acfa24d6ff4052843b652d8476167523ad147cb2c809174ab983cf20ef6587e6663a65aa9e8a246fe347c8db76540582b90c4aa6abcd5e5ae444d940e4ececc8c22884c6485607232ca63ab230e5c7ed29528450bd466102b5d0fed12305285359532872425f6bd927c756b8862216526eab0090785c4f07745652992faa616ba30b999f10a9bedbf4b8c07a5f9354ba933251ee739d21f000a2812c47f6f9f048c511acc753304ae0b20be27724954e9c3e3e1cbaf38e1e6fcebc00e127838ddbcf881f6c851f89576c5a6265722196cc1896a16bad8e2aa02d25b5f0e2d3a92335c8348b9f1293ccc28772e7b05b7502650e7379cca4cd8c411182611f0c2fba427ba90723c82b9c9f405a612aed24e850892736c14043b7456b196686979a780ef5c8b60d4431964e9ff866ef29f055faf5a487d7269ba4dcc5b613e4fa4f288626029f62419057879eb0c16703ea21e63419c5d4a56d1e4921609f6b950ac6bf0c02cceb7cc1189bc5b2a85fdb8303b6fbd1461f19bf923113e7ae8a3efc176ae5ce28314723eae14ebbbeb1cfed052a8067b1f12010f3c288b7e68c4d23056c9ec5b29b63a99284a0a4e5ecdda3308920506051664e85112ae5f9bc703c1228d3648777a9dddaea53e64a76f6736e3e83236b74eaa027e6f272a00662e775fbba3fcd6b69dc9943fb3515fa1dd5073e6efd349f9e185292ac45fed2c2d77329f6f3bf40b3813528048c121f60a89068c0686a78e0f10b791d276a"},
}
