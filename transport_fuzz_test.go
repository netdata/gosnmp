// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"
)

// FuzzReadMessage checks readMessage on any TCP stream, split into reads of
// any sizes: it does not panic, and the messages it returns, until it fails,
// each frame exactly and follow one another from the stream's start.
func FuzzReadMessage(f *testing.F) {
	msg := seqMessage(3)
	for _, seed := range [][]byte{
		msg,
		slices.Concat(msg, seqMessage(200), msg),
		slices.Concat(msg, []byte{byte(OctetString), 1, 0}),
		{byte(Sequence), 0x82, 0x00, 0x03, 7, 8, 9},
		{byte(Sequence), 0x80, 0, 0},
		{byte(Sequence), 0x84, 0x00, 0x01, 0x00, 0x00},
		seqMessage(rxBufSize - 4),
	} {
		f.Add(seed, uint64(len(seed)))
	}
	f.Fuzz(func(t *testing.T, stream []byte, seed uint64) {
		rng := rand.New(rand.NewPCG(seed, seed))
		conn := &streamConn{}
		for rest := stream; len(rest) > 0; {
			n := 1 + rng.IntN(min(len(rest), 1<<rng.IntN(17)))
			conn.reads = append(conn.reads, streamRead{data: rest[:n]})
			rest = rest[n:]
		}
		rx := new(receiveBuffer)
		var read []byte
		for {
			m, err := rx.readMessage(conn)
			if err != nil {
				break
			}
			if size, err := frame(m); err != nil || size != uint64(len(m)) {
				t.Fatalf("message % x frames as %d, %v", m, size, err)
			}
			read = append(read, m...)
		}
		if !bytes.HasPrefix(stream, read) {
			t.Fatalf("the messages read are not the stream's start")
		}
	})
}
