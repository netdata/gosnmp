// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"io"
	"log"
	"math"
	"slices"
	"strconv"
	"testing"
	"time"
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

// FuzzUnmarshal checks that SnmpDecodePacket returns quickly and does not
// panic. Its corpus in testdata/fuzz/FuzzUnmarshal is also pinned by
// TestDecodeCharacterization.
func FuzzUnmarshal(f *testing.F) {
	for _, seed := range codecFuzzSeeds(f) {
		f.Add(seed)
	}

	vhandle := GoSNMP{}
	vhandle.Logger = NewLogger(log.New(io.Discard, "", 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		stime := time.Now()
		_, _ = vhandle.SnmpDecodePacket(data)

		if e := time.Since(stime); e > (time.Second * 1) {
			t.Errorf("SnmpDecodePacket() took too long: %s", e)
		}
	})
}

// FuzzDecodeReencode checks what holds for the packets SnmpDecodePacket
// accepts today: MarshalMsg does not panic on them, the bytes MarshalMsg
// produces decode again, and a second decode and encode pass reproduces
// them exactly. Decoding the re-encoded bytes does not always return the
// original values (known codec bugs, pinned by TestDecodeCharacterization).
func FuzzDecodeReencode(f *testing.F) {
	for _, seed := range codecFuzzSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := (&GoSNMP{}).SnmpDecodePacket(bytes.Clone(data))
		if err != nil || reencodeKnownBug(first) {
			return
		}
		encoded, err := first.MarshalMsg()
		if err != nil {
			return
		}

		second, err := (&GoSNMP{}).SnmpDecodePacket(bytes.Clone(encoded))
		if err != nil {
			t.Fatalf("re-encoded packet does not decode: %v\ninput:      %x\nre-encoded: %x", err, data, encoded)
		}
		reencoded, err := second.MarshalMsg()
		if err != nil {
			t.Fatalf("second encode failed: %v\ninput:      %x\nre-encoded: %x", err, data, encoded)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("second encode differs:\ninput:  %x\nfirst:  %x\nsecond: %x", data, encoded, reencoded)
		}
	})
}

// reencodeKnownBug reports packets that hit known codec bugs breaking the
// FuzzDecodeReencode properties: on 32-bit platforms a Uinteger32 above
// MaxInt32 re-encodes to five octets, which the decoder, reading Uinteger32
// as a signed int, rejects. Fixing the bug removes the case.
func reencodeKnownBug(p *SnmpPacket) bool {
	return strconv.IntSize == 32 && slices.ContainsFunc(p.Variables, func(v SnmpPDU) bool {
		u, ok := v.Value.(uint32)
		return ok && v.Type == Uinteger32 && u > math.MaxInt32
	})
}
