// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"io"
	"log"
	"slices"
	"testing"
	"time"

	"github.com/netdata/gosnmp/internal/ber"
	"github.com/netdata/gosnmp/internal/usm"
)

// codecFuzzSeeds returns every fixture and crafted decode input, and the
// checked-in FuzzUnmarshal corpus.
func codecFuzzSeeds(tb testing.TB) [][]byte {
	var seeds [][]byte
	for _, c := range slices.Concat(decodeFixtureCases(tb), decodeCraftedCases(), decodeFuzzCorpusCases(tb)) {
		seeds = append(seeds, c.in)
	}
	return seeds
}

// FuzzUnmarshal checks that SnmpDecodePacket returns quickly, does not panic
// and does not write into its input. Its corpus in testdata/fuzz/FuzzUnmarshal
// is also pinned by TestDecodeCharacterization.
func FuzzUnmarshal(f *testing.F) {
	for _, seed := range codecFuzzSeeds(f) {
		f.Add(seed)
	}

	vhandle := GoSNMP{}
	vhandle.Logger = NewLogger(log.New(io.Discard, "", 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		stime := time.Now()
		in := bytes.Clone(data)
		_, _ = vhandle.SnmpDecodePacket(in)

		if e := time.Since(stime); e > (time.Second * 1) {
			t.Errorf("SnmpDecodePacket() took too long: %s", e)
		}
		if !bytes.Equal(in, data) {
			t.Errorf("SnmpDecodePacket() wrote into its input: %x", data)
		}
	})
}

// FuzzDecodeReencode checks that the decoder takes no value or field the
// encoder refuses but the named quirks (decodeQuirk): MarshalMsg encodes what
// SnmpDecodePacket accepts, the bytes it produces decode again, and a second
// decode and encode pass, drawing the same salt, reproduces them exactly.
// Decoding the re-encoded bytes does not always return the original values
// (the quirks and the values the decoder cuts, pinned by
// TestDecodeCharacterization).
func FuzzDecodeReencode(f *testing.F) {
	for _, seed := range codecFuzzSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := (&GoSNMP{}).SnmpDecodePacket(bytes.Clone(data))
		if err != nil {
			return
		}
		usm.Salts.Set(1)
		encoded, err := first.MarshalMsg()
		if err != nil {
			if decodeQuirk(first) {
				return
			}
			t.Fatalf("decoded packet does not encode: %v\ninput: %x", err, data)
		}

		second, err := (&GoSNMP{}).SnmpDecodePacket(bytes.Clone(encoded))
		if err != nil {
			t.Fatalf("re-encoded packet does not decode: %v\ninput:      %x\nre-encoded: %x", err, data, encoded)
		}
		usm.Salts.Set(1)
		reencoded, err := second.MarshalMsg()
		if err != nil {
			t.Fatalf("second encode failed: %v\ninput:      %x\nre-encoded: %x", err, data, encoded)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("second encode differs:\ninput:  %x\nfirst:  %x\nsecond: %x", data, encoded, reencoded)
		}
	})
}

// decodeQuirk reports whether p holds what the decoder takes from devices
// and the encoder refuses: a value of UnknownType (an unknown tag, or an
// unsigned value that does not decode), an empty IpAddress value or SNMPv1
// agent address, or a varbind name sent as text that is not an OID.
func decodeQuirk(p *SnmpPacket) bool {
	if p.PDUType == Trap && p.AgentAddress == "" {
		return true
	}
	return slices.ContainsFunc(p.Variables, func(v SnmpPDU) bool {
		if _, err := ber.AppendOID(nil, v.Name); err != nil {
			return true
		}
		return v.Type == UnknownType || v.Type == IPAddress && v.Value == nil
	})
}
