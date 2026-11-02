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

// BenchmarkUSMDecode measures Receiver.Receive of a secured SNMPv3 trap by a
// receiver with one user, registered for the sender's engine ID, whose keys it
// localized when it was built.
func BenchmarkUSMDecode(b *testing.B) {
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			data := usmCharTrap(b, priv, usmCharVarbinds)
			r := receiverAt(b, []byte(usmCharEngineID), usmCharUser(priv))
			in := make([]byte, len(data))
			b.ReportAllocs()
			for b.Loop() {
				copy(in, data)
				if _, err := r.Receive(in); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUSMDecodeTable measures Receiver.Receive of a secured SNMPv3 trap
// by a receiver whose user name has two users for the sender's engine ID, the
// second one decoding it: another authentication passphrase first, then the
// sender's credentials.
func BenchmarkUSMDecodeTable(b *testing.B) {
	for _, priv := range usmBenchPrivProtocols {
		b.Run(priv.String(), func(b *testing.B) {
			data := usmCharTrap(b, priv, usmCharVarbinds)
			r := receiverAt(b, []byte(usmCharEngineID),
				usmUser(SHA, "other-auth-pass", priv, "codec-priv-pass"), usmCharUser(priv))
			in := make([]byte, len(data))
			b.ReportAllocs()
			for b.Loop() {
				copy(in, data)
				if _, err := r.Receive(in); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
