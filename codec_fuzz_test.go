// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
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

// FuzzUnmarshal checks that DecodeMessage returns quickly, does not panic
// and does not write into its input, and that its errors and those of a
// receiver each have one category and come without a message: for an SNMPv3
// input whose header reads, a receiver of a user without protocols named as
// its user, registered for its engine ID (codecFuzzReceiver). Its
// corpus in testdata/fuzz/FuzzUnmarshal is also pinned by
// TestDecodeCharacterization.
// codecFuzzReceiver returns, for an SNMPv3 datagram whose header reads and
// names an engine ID and a valid user name, a receiver of a user of that name
// without protocols registered for the engine ID, which takes the message
// through the security processing (a noAuthNoPriv one to its PDU); otherwise
// noUsers.
func codecFuzzReceiver(t *testing.T, noUsers *Receiver, datagram []byte) *Receiver {
	e, err := ReadEnvelope(datagram)
	if err != nil || e.Version != Version3 || len(e.SecurityParameters.AuthoritativeEngineID) == 0 {
		return noUsers
	}
	user := User{Name: e.SecurityParameters.UserName}
	if user.checkName() != nil {
		return noUsers
	}
	return receiverAt(t, e.SecurityParameters.AuthoritativeEngineID, user)
}

func FuzzUnmarshal(f *testing.F) {
	for _, seed := range codecFuzzSeeds(f) {
		f.Add(seed)
	}

	vhandle := Client{}
	noUsers, _ := newTestReceiver(f, ReceiverConfig{})
	f.Fuzz(func(t *testing.T, data []byte) {
		stime := time.Now()
		in := bytes.Clone(data)
		msg, err := vhandle.DecodeMessage(in)
		checkCategory(t, "DecodeMessage", err)
		checkNoMessage(t, "DecodeMessage", msg, err)
		msg, err = usmFuzzReceive(codecFuzzReceiver(t, noUsers, data), bytes.Clone(data))
		checkCategory(t, "Receive", err)
		checkNoMessage(t, "Receive", msg, err)

		if e := time.Since(stime); e > (time.Second * 1) {
			t.Errorf("DecodeMessage() took too long: %s", e)
		}
		if !bytes.Equal(in, data) {
			t.Errorf("DecodeMessage() wrote into its input: %x", data)
		}
	})
}

// FuzzDecodeReencode checks that the decoder takes no value or field the
// encoder refuses but the named quirks (decodeQuirk): Message.Encode encodes what
// DecodeMessage accepts, the bytes it produces decode again, and a second
// decode and encode pass, drawing the same salt, reproduces them exactly.
// Decoding the re-encoded bytes does not always return the original values
// (the quirks and the values the decoder cuts, pinned by
// TestDecodeCharacterization).
func FuzzDecodeReencode(f *testing.F) {
	for _, seed := range codecFuzzSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := (&Client{}).DecodeMessage(bytes.Clone(data))
		if err != nil {
			return
		}
		usm.Salts.Set(1)
		encoded, err := first.Encode(nil)
		if err != nil {
			if decodeQuirk(first) {
				return
			}
			t.Fatalf("decoded packet does not encode: %v\ninput: %x", err, data)
		}

		second, err := (&Client{}).DecodeMessage(bytes.Clone(encoded))
		if err != nil {
			t.Fatalf("re-encoded packet does not decode: %v\ninput:      %x\nre-encoded: %x", err, data, encoded)
		}
		usm.Salts.Set(1)
		reencoded, err := second.Encode(nil)
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
func decodeQuirk(p *Message) bool {
	if p.PDUType == Trap && !p.AgentAddress.IsValid() {
		return true
	}
	return slices.ContainsFunc(p.VarBinds, func(v VarBind) bool {
		if _, err := ber.AppendOID(nil, v.Name); err != nil {
			return true
		}
		ip, isIP := v.Value.IP()
		return v.Value.Type() == UnknownType || isIP && !ip.IsValid()
	})
}
