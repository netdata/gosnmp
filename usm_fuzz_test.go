// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"runtime/debug"
	"testing"
	"time"

	"github.com/netdata/gosnmp/internal/usm"
)

// The FuzzDecodeV3 receivers.
const (
	fuzzDecode     = "DecodeMessage"
	fuzzRegistered = "Receive, the user registered for the seeds' engine ID"
	fuzzLearning   = "Receive, the user learned for the message's engine ID"
	fuzzLocal      = "Receive, the user registered for its own engine, the seeds' engine ID"
)

// usmFuzzMaxLearned is the MaxLearned of the FuzzDecodeV3 learning receiver,
// more than an input can make it learn.
const usmFuzzMaxLearned = 1 << 16

// usmFuzzPair is the credentials of one FuzzDecodeV3 receiver.
type usmFuzzPair struct {
	auth AuthProtocol
	priv PrivProtocol
}

func (p usmFuzzPair) user() User {
	return usmUser(p.auth, "codec-auth-pass", p.priv, "codec-priv-pass")
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
// first argument selects: DecodeMessage, which decrypts without checking
// the digest, and Receiver.Receive by a receiver with the user registered for
// the seeds' engine ID, whose keys it localized when it was built, and by one
// that may learn the user, whose keys derive for the message's engine ID (RFC
// 3414 section 3.2 step 3). Each must return within a second, must not panic,
// must not write into its input and must return no message with an error.
// Seeds are a secured trap for every pair and malformed variants of it.
func FuzzDecodeV3(f *testing.F) {
	pairs := usmFuzzPairs()
	index := make(map[usmFuzzPair]uint8, len(pairs))
	for i, p := range pairs {
		index[p] = uint8(i)
	}

	for i, p := range pairs {
		pkt := usmCharPacket(f, p.priv, usmCharVarbinds)
		user := usmCharUser(p.priv)
		user.AuthProtocol = p.auth
		if p.auth == NoAuth {
			pkt.SecurityLevel = NoAuthNoPriv
		}
		usm.Salts.Set(usmCharSalt(p.priv))
		data, err := pkt.Encode(&user)
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
			decode func(data []byte) (*Message, error)
		}{
			{fuzzDecode, func(data []byte) (*Message, error) {
				return mustClient(Config{User: p.user()}).DecodeMessage(data)
			}},
			{fuzzRegistered, func(data []byte) (*Message, error) {
				return usmFuzzReceive(t, receiverAt(t, []byte(usmCharEngineID), p.user()), data)
			}},
			{fuzzLearning, func(data []byte) (*Message, error) {
				r, _ := newTestReceiver(t, ReceiverConfig{LearnUsers: []User{p.user()}, MaxLearned: usmFuzzMaxLearned})
				return usmFuzzReceive(t, r, data)
			}},
			{fuzzLocal, func(data []byte) (*Message, error) {
				r, _ := newTestReceiver(t, ReceiverConfig{
					EngineID: []byte(usmCharEngineID), EngineBoots: 3,
					Users: []EngineUser{{EngineID: []byte(usmCharEngineID), User: p.user()}},
				})
				return usmFuzzReceive(t, r, data)
			}},
		}

		for _, r := range receivers {
			start := time.Now()
			// No spare capacity, so a write past the input panics.
			in := bytes.Clone(data)[:len(data):len(data)]
			var msg *Message
			var err error
			if v, stack := recoverPanic(func() { msg, err = r.decode(in) }); v != nil {
				t.Fatalf("%s with %v/%v credentials panicked: %v\ninput: %x\n%s", r.name, p.auth, p.priv, v, data, stack)
			}
			if !bytes.Equal(in, data) {
				t.Fatalf("%s with %v/%v credentials wrote into its input: %x", r.name, p.auth, p.priv, data)
			}
			checkCategory(t, r.name, err)
			checkNoMessage(t, r.name, msg, err)
			if e := time.Since(start); e > time.Second {
				t.Errorf("%s took %s", r.name, e)
			}
		}
	})
}

// usmFuzzReceive returns what r.Receive returns for data: the notification's
// message, or nil when there is no notification, and the error; it checks the
// response (checkAnswer).
func usmFuzzReceive(t *testing.T, r *Receiver, data []byte) (*Message, error) {
	n, response, err := r.Receive(data)
	checkAnswer(t, data, n, response, err)
	if n == nil {
		return nil, err
	}
	return &n.Message, err
}

// checkAnswer checks what Receive returned for data against its contract: a
// response to exactly an accepted SNMPv2c or SNMPv3 inform, a Response, but
// for an SNMPv3 inform whose msgMaxSize even a tooBig Response could exceed
// (one no longer than the inform but for a few octets of its own header
// fields), or else only with ErrUnknownEngineID or ErrNotInTimeWindow, a
// Report; each one decodes.
func checkAnswer(t *testing.T, data []byte, n *Notification, response []byte, err error) {
	t.Helper()
	inform := n != nil && n.Message.PDUType == InformRequest && n.Message.Version != Version1
	switch {
	case n != nil && !inform && response != nil:
		t.Fatalf("Receive answered %d octets to %+v", len(response), n)
	case inform && response == nil && (n.Message.Version != Version3 || int(n.Message.MsgMaxSize) >= len(data)+16):
		t.Fatalf("Receive answered nothing to %+v", n)
	}
	if response == nil {
		return
	}
	want := Response
	if n == nil {
		want = Report
		if !errors.Is(err, ErrUnknownEngineID) && !errors.Is(err, ErrNotInTimeWindow) {
			t.Fatalf("Receive reported %v", err)
		}
	}
	e, eerr := ReadEnvelope(response)
	if eerr == nil && e.SecurityLevel != NoAuthNoPriv {
		return // an authenticated answer decodes with its user's keys only
	}
	got, derr := new(Client).DecodeMessage(response)
	if derr != nil || got.PDUType != want {
		t.Fatalf("Receive answered %x: %v, %v, %v", response, got, eerr, derr)
	}
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
