// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"
)

// BenchmarkUSMKeys measures InitSecurityKeys for an AES-256 user (whose key
// MD5 and SHA extend), with and without the password-to-key cache.
func BenchmarkUSMKeys(b *testing.B) {
	for _, cached := range []bool{true, false} {
		for _, auth := range []SnmpV3AuthProtocol{MD5, SHA, SHA512} {
			name := auth.String() + "/cached"
			if !cached {
				name = auth.String() + "/uncached"
			}
			b.Run(name, func(b *testing.B) {
				PasswordCaching(cached)
				b.Cleanup(func() { PasswordCaching(true) })
				initKeys := func() {
					sp := &UsmSecurityParameters{
						AuthenticationProtocol:   auth,
						AuthenticationPassphrase: "codec-auth-pass",
						PrivacyProtocol:          AES256,
						PrivacyPassphrase:        "codec-priv-pass",
						AuthoritativeEngineID:    usmCharEngineID,
					}
					if err := sp.InitSecurityKeys(); err != nil {
						b.Fatal(err)
					}
				}
				initKeys() // fills the cache when it is enabled
				b.ReportAllocs()
				for b.Loop() {
					initKeys()
				}
			})
		}
	}
}

// usmBenchPrivProtocols are the privacy protocols the USM message benchmarks
// use with SHA authentication.
var usmBenchPrivProtocols = []SnmpV3PrivProtocol{NoPriv, DES, AES, AES256, AES256C}

// BenchmarkUSMEncode measures MarshalMsg of a secured SNMPv3 trap.
func BenchmarkUSMEncode(b *testing.B) {
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			pkt := usmCharPacket(b, priv, usmCharSalt(priv), usmCharVarbinds)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := pkt.MarshalMsg(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUSMDecode measures UnmarshalTrap of a secured SNMPv3 trap by a
// receiver whose keys are localized to the sender's engine ID.
func BenchmarkUSMDecode(b *testing.B) {
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			data := usmCharTrap(b, priv, usmCharSalt(priv), usmCharVarbinds)
			x := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")()
			x.Version = Version3
			x.SecurityModel = UserSecurityModel
			x.MsgFlags = AuthPriv
			if priv == NoPriv {
				x.MsgFlags = AuthNoPriv
			}
			sp := x.SecurityParameters.(*UsmSecurityParameters)
			sp.AuthoritativeEngineID = usmCharEngineID
			if err := sp.InitSecurityKeys(); err != nil {
				b.Fatal(err)
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
