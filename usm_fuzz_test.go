// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"runtime/debug"
	"testing"
	"time"

	"github.com/netdata/gosnmp/internal/usm"
)

// The FuzzDecodeV3 receivers.
const (
	fuzzDecode        = "SnmpDecodePacket"
	fuzzSingle        = "UnmarshalTrap single user"
	fuzzTable         = "UnmarshalTrap table"
	fuzzTableKeysOnly = "UnmarshalTrap table, keys only"
)

// usmFuzzPair is the credentials of one FuzzDecodeV3 receiver.
type usmFuzzPair struct {
	auth SnmpV3AuthProtocol
	priv SnmpV3PrivProtocol
}

func (p usmFuzzPair) usm() *UsmSecurityParameters {
	return usmDecoder(p.auth, "codec-auth-pass", p.priv, "codec-priv-pass")().SecurityParameters.(*UsmSecurityParameters)
}

func (p usmFuzzPair) flags() SnmpV3MsgFlags {
	switch {
	case p.priv != NoPriv:
		return AuthPriv
	case p.auth != NoAuth:
		return AuthNoPriv
	default:
		return NoAuthNoPriv
	}
}

// usmFuzzPairs are noAuthNoPriv and every authentication protocol with no
// privacy and with every privacy protocol.
func usmFuzzPairs() []usmFuzzPair {
	pairs := []usmFuzzPair{{NoAuth, NoPriv}}
	for _, a := range usmAuthProtocols[1:] {
		for _, p := range usmPrivProtocols {
			pairs = append(pairs, usmFuzzPair{a, p})
		}
	}
	return pairs
}

// FuzzDecodeV3 decodes input with the SNMPv3 credentials of the pair the
// first argument selects: SnmpDecodePacket, which decrypts without checking
// the digest, and UnmarshalTrap for a single user and through a credentials
// table, the latter also with keys localized to another engine ID and no
// passphrases. Each must return within a second, must not panic and must not
// write into its input. Seeds are a secured trap for every pair and malformed
// variants of it.
func FuzzDecodeV3(f *testing.F) {
	pairs := usmFuzzPairs()
	index := make(map[usmFuzzPair]uint8, len(pairs))
	for i, p := range pairs {
		index[p] = uint8(i)
	}

	for i, p := range pairs {
		pkt := usmCharPacket(f, p.priv, usmCharVarbinds)
		sp := pkt.SecurityParameters.(*UsmSecurityParameters)
		sp.AuthenticationProtocol = p.auth
		sp.SecretKey, sp.PrivacyKey = nil, nil
		if p.auth == NoAuth {
			pkt.MsgFlags = NoAuthNoPriv
		}
		if err := sp.InitSecurityKeys(); err != nil {
			f.Fatal(err)
		}
		usm.Salts.Set(usmCharSalt(p.priv))
		data, err := pkt.MarshalMsg()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(i), data)
	}
	for _, priv := range usmPrivProtocols[1:] {
		msg := splitV3Message(f, usmCharTrap(f, priv, usmCharVarbinds))
		short := msg
		short.usm[5] = short.usm[5][:7]
		truncated := msg
		truncated.scoped = truncated.scoped[:len(truncated.scoped)-1]
		sel := index[usmFuzzPair{SHA, priv}]
		f.Add(sel, short.bytes())
		f.Add(sel, truncated.bytes())
		f.Add(sel, usmFlagsTrap(f, priv, usmPrivacyFlag, 8))
		f.Add(sel, usmFlagsTrap(f, priv, usmPrivacyFlag, 7))
		f.Add(sel, usmFlagsTrap(f, priv, NoAuthNoPriv, 7))
		f.Add(sel, short.withModel(f, 2).bytes())
	}
	f.Add(uint8(0), usmMalformedV3Header)
	usmFields := craftedUSM(octets(usmCharEngineID), intTLV(0), intTLV(0), octets("codec-user"), octets(""), nil)
	f.Add(index[usmFuzzPair{SHA, NoPriv}], craftedV3(intTLV(42), intTLV(65507), octets("\x01"), intTLV(3), usmFields, nil))

	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		p := pairs[int(sel)%len(pairs)]
		receivers := []struct {
			name   string
			decode func(data []byte) error
		}{
			{fuzzDecode, func(data []byte) error {
				_, err := (&GoSNMP{SecurityParameters: p.usm()}).SnmpDecodePacket(data)
				return err
			}},
			{fuzzSingle, func(data []byte) error {
				x := &GoSNMP{Version: Version3, MsgFlags: p.flags(), SecurityModel: UserSecurityModel, SecurityParameters: p.usm()}
				_, err := x.UnmarshalTrap(data, false)
				return err
			}},
			{fuzzTable, func(data []byte) error {
				table := NewSnmpV3SecurityParametersTable(Logger{})
				if err := table.Add("codec-user", p.usm()); err != nil {
					return err
				}
				_, err := (&GoSNMP{Version: Version3, TrapSecurityParametersTable: table}).UnmarshalTrap(data, false)
				return err
			}},
			{fuzzTableKeysOnly, func(data []byte) error {
				table := NewSnmpV3SecurityParametersTable(Logger{})
				if err := table.Add("codec-user", usmKeysOnly(p.usm(), usmOtherEngineID)); err != nil {
					return err
				}
				_, err := (&GoSNMP{Version: Version3, TrapSecurityParametersTable: table}).UnmarshalTrap(data, false)
				return err
			}},
		}

		for _, r := range receivers {
			start := time.Now()
			// No spare capacity, so a write past the input panics.
			in := bytes.Clone(data)[:len(data):len(data)]
			if v, stack := recoverPanic(func() { _ = r.decode(in) }); v != nil {
				t.Fatalf("%s with %v/%v credentials panicked: %v\ninput: %x\n%s", r.name, p.auth, p.priv, v, data, stack)
			}
			if !bytes.Equal(in, data) {
				t.Fatalf("%s with %v/%v credentials wrote into its input: %x", r.name, p.auth, p.priv, data)
			}
			if e := time.Since(start); e > time.Second {
				t.Errorf("%s took %s", r.name, e)
			}
		}
	})
}

// recoverPanic runs fn and returns the value it panicked with and the stack
// of the panic, or nil.
func recoverPanic(fn func()) (v any, stack string) {
	defer func() {
		if v = recover(); v != nil {
			stack = string(debug.Stack())
		}
	}()
	fn()
	return nil, ""
}
