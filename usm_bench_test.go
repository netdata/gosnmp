// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"
)

// BenchmarkUSMKeys measures localizing the keys of an AES-256 user (whose key
// MD5 and SHA extend), through the password-to-key cache.
func BenchmarkUSMKeys(b *testing.B) {
	for _, auth := range []AuthProtocol{MD5, SHA, SHA512} {
		b.Run(auth.String(), func(b *testing.B) {
			user := usmUser(auth, "codec-auth-pass", AES256, "codec-priv-pass")
			localize := func() {
				if _, err := user.localize([]byte(usmCharEngineID)); err != nil {
					b.Fatal(err)
				}
			}
			localize() // fills the cache
			b.ReportAllocs()
			for b.Loop() {
				localize()
			}
		})
	}
}

// usmBenchPrivProtocols are the privacy protocols the USM message benchmarks
// use with SHA authentication.
var usmBenchPrivProtocols = []PrivProtocol{NoPriv, DES, AES, AES256, AES256C}

// BenchmarkUSMEncode measures Message.Encode of a secured SNMPv3 trap, which
// localizes the user's keys to the trap's engine ID.
func BenchmarkUSMEncode(b *testing.B) {
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			pkt := usmCharPacket(b, priv, usmCharVarbinds)
			user := usmCharUser(priv)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := pkt.Encode(&user); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUSMDecode measures UnmarshalTrap of a secured SNMPv3 trap by a
// single-user receiver, which localizes its user's keys to the sender's engine
// ID.
func BenchmarkUSMDecode(b *testing.B) {
	useEngineTimes(b)
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			data := usmCharTrap(b, priv, usmCharVarbinds)
			x := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")()
			x.Version = Version3
			x.SecurityLevel = AuthPriv
			if priv == NoPriv {
				x.SecurityLevel = AuthNoPriv
			}
			in := make([]byte, len(data))
			b.ReportAllocs()
			for b.Loop() {
				copy(in, data)
				if _, err := x.UnmarshalTrap(in, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUSMDecodeTable measures UnmarshalTrap of a secured SNMPv3 trap
// through a credentials table whose user has two entries, the second one
// decoding it: another authentication passphrase registered for another
// engine ID first, then the sender's credentials registered for its engine ID.
func BenchmarkUSMDecodeTable(b *testing.B) {
	useEngineTimes(b)
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			data := usmCharTrap(b, priv, usmCharVarbinds)
			table := NewSnmpV3SecurityParametersTable()
			if err := table.Add(usmUser(SHA, "other-auth-pass", priv, "codec-priv-pass"), []byte(usmOtherEngineID)); err != nil {
				b.Fatal(err)
			}
			if err := table.Add(usmCharUser(priv), []byte(usmCharEngineID)); err != nil {
				b.Fatal(err)
			}
			x := &Client{Version: Version3, TrapSecurityParametersTable: table}
			in := make([]byte, len(data))
			b.ReportAllocs()
			for b.Loop() {
				copy(in, data)
				if _, err := x.UnmarshalTrap(in, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
