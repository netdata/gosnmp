// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	codecref "github.com/netdata/gosnmp/internal/codecref"
)

// The differential tests compare the codec with the frozen copy of the
// library in internal/codecref at the level the decode golden pins: the
// decode verdict (errors by the exported sentinels they match), panics and
// stdout writes, changes to the input, the exported packet fields with their
// Go types, MarshalMsg on the decoded packet, and the UnmarshalTrap verdict.
// Error text and partial results on error are not compared.

// TestDecodeDifferential decodes every decode golden input with every decoder
// configuration the golden uses and compares the results with the frozen copy.
func TestDecodeDifferential(t *testing.T) {
	inputs, decoders := diffSeeds(t)
	for _, in := range inputs {
		for _, d := range decoders {
			if got, want := diffDump(diffCurrent, d, in.data), diffDump(diffFrozen, d, in.data); got != want {
				t.Errorf("%s, decoder %s: differs from the frozen copy\n--- frozen\n%s\n--- current\n%s",
					in.name, d, want, got)
			}
		}
	}
	t.Logf("compared %d inputs x %d decoders", len(inputs), len(decoders))
}

// FuzzDecodeDifferential compares the codec with the frozen copy on arbitrary
// input, decoded with one of the decode golden's decoder configurations.
func FuzzDecodeDifferential(f *testing.F) {
	inputs, decoders := diffSeeds(f)
	for _, in := range inputs {
		f.Add(in.decoder, in.data)
		if in.decoder != 0 {
			f.Add(uint8(0), in.data)
		}
	}

	f.Fuzz(func(t *testing.T, decoder uint8, data []byte) {
		d := decoders[int(decoder)%len(decoders)]
		if got, want := diffDump(diffCurrent, d, data), diffDump(diffFrozen, d, data); got != want {
			t.Fatalf("decoder %s, input %x: differs from the frozen copy\n--- frozen\n%s\n--- current\n%s",
				d, data, want, got)
		}
	})
}

// diffDecoder is a decoder configuration of the decode golden: SNMPv3 USM
// credentials, optionally localized to an engine ID. nil is a zero decoder.
type diffDecoder struct {
	auth      SnmpV3AuthProtocol
	authPass  string
	priv      SnmpV3PrivProtocol
	privPass  string
	engineID  string
	localized bool
}

func (d *diffDecoder) String() string {
	if d == nil {
		return "zero"
	}
	return fmt.Sprintf("usm(%s/%s engine-id=%x localized=%v)", d.auth, d.priv, d.engineID, d.localized)
}

// diffInput is a decode golden input and the index of its decoder.
type diffInput struct {
	name    string
	data    []byte
	decoder uint8
}

// diffSeeds returns the decode golden inputs and the distinct decoder
// configurations they use; decoders[0] is the zero decoder.
func diffSeeds(tb testing.TB) ([]diffInput, []*diffDecoder) {
	tb.Helper()

	decoders := []*diffDecoder{nil}
	var inputs []diffInput
	for _, c := range slices.Concat(decodeFixtureCases(tb), decodeCraftedCases(), decodeFuzzCorpusCases(tb)) {
		d := diffDecoderOf(tb, c)
		i := slices.IndexFunc(decoders, func(x *diffDecoder) bool {
			return x == d || (x != nil && d != nil && *x == *d)
		})
		if i < 0 {
			i = len(decoders)
			decoders = append(decoders, d)
		}
		if i > math.MaxUint8 {
			tb.Fatalf("more than %d decoder configurations", math.MaxUint8+1)
		}
		inputs = append(inputs, diffInput{name: c.name, data: c.in, decoder: uint8(i)})
	}
	return inputs, decoders
}

// diffDecoderOf captures the decoder of a decode case, failing if the case
// configures anything a diffDecoder cannot reproduce.
func diffDecoderOf(tb testing.TB, c decodeCase) *diffDecoder {
	tb.Helper()

	if c.decoder == nil {
		return nil
	}
	x := c.decoder()
	sp, ok := x.SecurityParameters.(*UsmSecurityParameters)
	if !ok {
		tb.Fatalf("%s: unsupported security parameters %T", c.name, x.SecurityParameters)
	}
	d := &diffDecoder{
		auth:      sp.AuthenticationProtocol,
		authPass:  sp.AuthenticationPassphrase,
		priv:      sp.PrivacyProtocol,
		privPass:  sp.PrivacyPassphrase,
		engineID:  sp.AuthoritativeEngineID,
		localized: sp.SecretKey != nil || sp.PrivacyKey != nil,
	}
	if got, want := dumpExported(reflect.ValueOf(diffCurrent.decoder(d))), dumpExported(reflect.ValueOf(x)); got != want {
		tb.Fatalf("%s: decoder not reproducible\n--- case\n%s\n--- rebuilt\n%s", c.name, want, got)
	}
	return d
}

// diffImpl runs the codec of one library copy.
type diffImpl struct {
	decoder       func(d *diffDecoder) any
	decode        func(decoder any, in []byte) (packet any, err error)
	reencode      func(packet any) ([]byte, error)
	unmarshalTrap func(decoder any, in []byte) error
	sentinels     []sentinel
}

var diffCurrent = diffImpl{
	decoder: func(d *diffDecoder) any {
		if d == nil {
			return &GoSNMP{}
		}
		sp := &UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthenticationProtocol:   d.auth,
			AuthenticationPassphrase: d.authPass,
			PrivacyProtocol:          d.priv,
			PrivacyPassphrase:        d.privPass,
			AuthoritativeEngineID:    d.engineID,
		}
		if d.localized {
			if err := sp.InitSecurityKeys(); err != nil {
				panic(err)
			}
		}
		return &GoSNMP{SecurityParameters: sp}
	},
	decode: func(x any, in []byte) (any, error) {
		return x.(*GoSNMP).SnmpDecodePacket(in)
	},
	reencode: func(p any) ([]byte, error) {
		return p.(*SnmpPacket).MarshalMsg()
	},
	unmarshalTrap: func(x any, in []byte) error {
		g := x.(*GoSNMP)
		if sp, ok := g.SecurityParameters.(*UsmSecurityParameters); ok {
			g.Version = Version3
			g.SecurityModel = UserSecurityModel
			switch {
			case sp.PrivacyProtocol > NoPriv:
				g.MsgFlags = AuthPriv
			case sp.AuthenticationProtocol > NoAuth:
				g.MsgFlags = AuthNoPriv
			}
		}
		_, err := g.UnmarshalTrap(in, false)
		return err
	},
	sentinels: codecSentinels,
}

var diffFrozen = diffImpl{
	decoder: func(d *diffDecoder) any {
		if d == nil {
			return &codecref.GoSNMP{}
		}
		sp := &codecref.UsmSecurityParameters{
			UserName:                 "codec-user",
			AuthenticationProtocol:   codecref.SnmpV3AuthProtocol(d.auth),
			AuthenticationPassphrase: d.authPass,
			PrivacyProtocol:          codecref.SnmpV3PrivProtocol(d.priv),
			PrivacyPassphrase:        d.privPass,
			AuthoritativeEngineID:    d.engineID,
		}
		if d.localized {
			if err := sp.InitSecurityKeys(); err != nil {
				panic(err)
			}
		}
		return &codecref.GoSNMP{SecurityParameters: sp}
	},
	decode: func(x any, in []byte) (any, error) {
		return x.(*codecref.GoSNMP).SnmpDecodePacket(in)
	},
	reencode: func(p any) ([]byte, error) {
		return p.(*codecref.SnmpPacket).MarshalMsg()
	},
	unmarshalTrap: func(x any, in []byte) error {
		g := x.(*codecref.GoSNMP)
		if sp, ok := g.SecurityParameters.(*codecref.UsmSecurityParameters); ok {
			g.Version = codecref.Version3
			g.SecurityModel = codecref.UserSecurityModel
			switch {
			case sp.PrivacyProtocol > codecref.NoPriv:
				g.MsgFlags = codecref.AuthPriv
			case sp.AuthenticationProtocol > codecref.NoAuth:
				g.MsgFlags = codecref.AuthNoPriv
			}
		}
		_, err := g.UnmarshalTrap(in, false)
		return err
	},
	sentinels: frozenSentinels,
}

// frozenSentinels are codecSentinels in the frozen copy, in the same order.
var frozenSentinels = []sentinel{
	{"ErrBase128IntegerTooLarge", codecref.ErrBase128IntegerTooLarge},
	{"ErrBase128IntegerTruncated", codecref.ErrBase128IntegerTruncated},
	{"ErrFloatBufferTooShort", codecref.ErrFloatBufferTooShort},
	{"ErrFloatTooLarge", codecref.ErrFloatTooLarge},
	{"ErrIntegerTooLarge", codecref.ErrIntegerTooLarge},
	{"ErrInvalidOidLength", codecref.ErrInvalidOidLength},
	{"ErrInvalidPacketLength", codecref.ErrInvalidPacketLength},
	{"ErrZeroByteBuffer", codecref.ErrZeroByteBuffer},
	{"ErrZeroLenInteger", codecref.ErrZeroLenInteger},
	{"ErrDecryption", codecref.ErrDecryption},
	{"ErrInvalidMsgs", codecref.ErrInvalidMsgs},
	{"ErrNotInTimeWindow", codecref.ErrNotInTimeWindow},
	{"ErrUnknownEngineID", codecref.ErrUnknownEngineID},
	{"ErrUnknownPDUHandlers", codecref.ErrUnknownPDUHandlers},
	{"ErrUnknownReportPDU", codecref.ErrUnknownReportPDU},
	{"ErrUnknownSecurityLevel", codecref.ErrUnknownSecurityLevel},
	{"ErrUnknownSecurityModels", codecref.ErrUnknownSecurityModels},
	{"ErrUnknownUsername", codecref.ErrUnknownUsername},
	{"ErrWrongDigest", codecref.ErrWrongDigest},
}

func TestDecodeDifferentialSentinels(t *testing.T) {
	var current, frozen []string
	for _, s := range codecSentinels {
		current = append(current, s.name)
	}
	for _, s := range frozenSentinels {
		frozen = append(frozen, s.name)
	}
	if !slices.Equal(current, frozen) {
		t.Fatalf("frozenSentinels do not match codecSentinels:\nfrozen:  %v\ncurrent: %v", frozen, current)
	}
}

// diffDump describes what the codec of one library copy does with data.
func diffDump(impl diffImpl, d *diffDecoder, data []byte) string {
	var w dumpWriter
	verdict := func(step string, panicked, wroteStdout bool, err error) {
		switch {
		case panicked:
			w.line(step + ": panic")
		case err != nil:
			w.line(step + ": " + dumpErrorBy(err, impl.sentinels))
		default:
			w.line(step + ": ok")
		}
		if wroteStdout {
			w.line(step + "-stdout: written")
		}
	}

	in := bytes.Clone(data)
	var p any
	var err error
	panicked, wroteStdout := observe(func() { p, err = impl.decode(impl.decoder(d), in) })
	verdict("decode", panicked, wroteStdout, err)
	if !panicked && err == nil {
		if !bytes.Equal(in, data) {
			w.line("input: modified " + dumpBytes(in))
		}
		w.line("packet: " + dumpExported(reflect.ValueOf(p)))

		var out []byte
		panicked, wroteStdout = observe(func() { out, err = impl.reencode(p) })
		verdict("reencode", panicked, wroteStdout, err)
		if !panicked && err == nil {
			w.line("reencoded: " + dumpBytes(out))
		}
	}

	panicked, wroteStdout = observe(func() { err = impl.unmarshalTrap(impl.decoder(d), bytes.Clone(data)) })
	verdict("unmarshal-trap", panicked, wroteStdout, err)
	return w.String()
}

// dumpExported prints the exported fields reachable from v with their Go
// types. The frozen copy keeps the package name gosnmp, so the type names of
// both copies print the same.
func dumpExported(v reflect.Value) string {
	var sb strings.Builder
	dumpExportedTo(&sb, v)
	return sb.String()
}

func dumpExportedTo(sb *strings.Builder, v reflect.Value) {
	switch v.Kind() {
	case reflect.Invalid:
		sb.WriteString("<nil>")
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			sb.WriteString("nil")
			return
		}
		if v.Kind() == reflect.Interface {
			sb.WriteString(v.Elem().Type().String() + " ")
		} else {
			sb.WriteString("&")
		}
		dumpExportedTo(sb, v.Elem())
	case reflect.Struct:
		t := v.Type()
		sb.WriteString(t.String() + "{")
		for i := range t.NumField() {
			if !t.Field(i).IsExported() {
				continue
			}
			sb.WriteString(t.Field(i).Name + ":")
			dumpExportedTo(sb, v.Field(i))
			sb.WriteString(" ")
		}
		sb.WriteString("}")
	case reflect.Slice:
		if v.IsNil() {
			sb.WriteString("nil")
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			fmt.Fprintf(sb, "%x", v.Bytes())
			return
		}
		sb.WriteString("[")
		for i := range v.Len() {
			dumpExportedTo(sb, v.Index(i))
			sb.WriteString(",")
		}
		sb.WriteString("]")
	case reflect.Map:
		var entries []string
		for k, e := range v.Seq2() {
			entries = append(entries, dumpExported(k)+"="+dumpExported(e))
		}
		slices.Sort(entries)
		sb.WriteString("map[" + strings.Join(entries, ",") + "]")
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		sb.WriteString(strconv.FormatBool(!v.IsNil()))
	case reflect.Float32:
		fmt.Fprintf(sb, "%#08x", math.Float32bits(v.Convert(reflect.TypeFor[float32]()).Interface().(float32)))
	case reflect.Float64:
		fmt.Fprintf(sb, "%#016x", math.Float64bits(v.Float()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sb.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		sb.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.String:
		sb.WriteString(strconv.Quote(v.String()))
	case reflect.Bool:
		sb.WriteString(strconv.FormatBool(v.Bool()))
	default:
		sb.WriteString("<" + v.Kind().String() + ">")
	}
}
