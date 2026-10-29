// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// timelyMessage is a message of a timeliness sequence: a trap, or an inform,
// from user at the sequence's engine with the engine boots and time it
// carries, sent after wait.
type timelyMessage struct {
	user        string // codec-user when empty
	boots, time uint32
	inform      bool
	wait        time.Duration
	accepted    bool
}

// encodeTimely encodes m from engineID: codec-user and other-user at
// authPriv (SHA, AES) with their own passphrases, plain-user at noAuthNoPriv.
func encodeTimely(t *testing.T, engineID string, m timelyMessage) []byte {
	t.Helper()
	sp := &UsmSecurityParameters{
		UserName: m.user, AuthoritativeEngineID: engineID,
		AuthoritativeEngineBoots: m.boots, AuthoritativeEngineTime: m.time,
	}
	flags := AuthPriv
	switch m.user {
	case "", "codec-user":
		sp.UserName = "codec-user"
		sp.AuthenticationProtocol, sp.AuthenticationPassphrase = SHA, "codec-auth-pass"
		sp.PrivacyProtocol, sp.PrivacyPassphrase = AES, "codec-priv-pass"
	case "other-user":
		sp.AuthenticationProtocol, sp.AuthenticationPassphrase = SHA, "other-auth-pass"
		sp.PrivacyProtocol, sp.PrivacyPassphrase = AES, "other-priv-pass"
	default:
		flags = NoAuthNoPriv
	}
	require.NoError(t, sp.InitSecurityKeys())
	pdu := SNMPv2Trap
	if m.inform {
		flags, pdu = flags|Reportable, InformRequest
	}
	data, err := (&SnmpPacket{
		Version: Version3, MsgFlags: flags, SecurityModel: UserSecurityModel, SecurityParameters: sp,
		PDUType: pdu, RequestID: 1, Variables: usmPlainVars,
	}).MarshalMsg()
	require.NoError(t, err)
	return data
}

// timelyReceivers are the trap receivers of the timeliness sequences: a table
// with the three users of encodeTimely, and a single user, codec-user.
var timelyReceivers = []struct {
	name     string
	receiver func(t *testing.T) *GoSNMP
	users    []string // the users the receiver knows
}{
	{"table", func(t *testing.T) *GoSNMP {
		tb := NewSnmpV3SecurityParametersTable(Logger{})
		require.NoError(t, tb.Add("codec-user", usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")().SecurityParameters))
		require.NoError(t, tb.Add("other-user", usmDecoder(SHA, "other-auth-pass", AES, "other-priv-pass")().SecurityParameters))
		require.NoError(t, tb.Add("plain-user", &UsmSecurityParameters{UserName: "plain-user"}))
		return &GoSNMP{Version: Version3, TrapSecurityParametersTable: tb}
	}, []string{"", "codec-user", "other-user", "plain-user"}},
	{"single", func(*testing.T) *GoSNMP {
		x := usmDecoder(SHA, "codec-auth-pass", AES, "codec-priv-pass")()
		x.Version, x.MsgFlags, x.SecurityModel = Version3, AuthPriv, UserSecurityModel
		return x
	}, []string{"", "codec-user"}},
}

// TestTrapTimeliness pins which traps and informs a receiver accepts by the
// engine boots and time they carry (RFC 3414 section 3.2 step 7), in sequences
// from one sender engine, each on its own engine ID. The receiver keeps no
// record of a sender's engine time: every message is accepted.
func TestTrapTimeliness(t *testing.T) {
	const maxBoots = 2147483647
	ok := func(boots, time uint32) timelyMessage { return timelyMessage{boots: boots, time: time, accepted: true} }
	after := func(wait time.Duration, m timelyMessage) timelyMessage { m.wait = wait; return m }
	inform := func(m timelyMessage) timelyMessage { m.inform = true; return m }
	from := func(user string, m timelyMessage) timelyMessage { m.user = user; return m }

	tests := map[string][]timelyMessage{
		"the latest again, at once":            {ok(3, 1000), ok(3, 1000)},
		"the latest again, 151 s later":        {ok(3, 1000), after(151*time.Second, ok(3, 1000))},
		"lower boots":                          {ok(5, 100), ok(4, 999)},
		"150 s older than the latest":          {ok(3, 1000), ok(3, 850)},
		"151 s older than the latest":          {ok(3, 1000), ok(3, 849)},
		"the local notion advanced 200 s, 150": {ok(3, 1000), after(200*time.Second, ok(3, 1050))},
		"the local notion advanced 200 s, 151": {ok(3, 1000), after(200*time.Second, ok(3, 1049))},
		"a reboot, then the old boots":         {ok(3, 1000), ok(4, 5), ok(3, 2000)},
		"boots 2147483647, twice":              {ok(maxBoots, 10), ok(maxBoots, 20)},
		"boots above 2147483647, then low":     {ok(maxBoots+1, 10), ok(1, 1)},
		"time above 2147483647, then low":      {ok(1, maxBoots+1), ok(1, 1)},
		"informs, then a trap":                 {inform(ok(3, 1000)), inform(ok(2, 1)), ok(1, 1)},
		"unauthenticated, then authenticated":  {from("plain-user", ok(100, 100)), ok(3, 77)},
		"another credential, lower boots":      {ok(9, 9), from("other-user", ok(1, 1))},
	}
	// advance would move the receiver's clock: it has none.
	advance := func(time.Duration) {}

	var seq int
	for name, msgs := range tests {
		for _, r := range timelyReceivers {
			t.Run(name+"/"+r.name, func(t *testing.T) {
				for _, m := range msgs {
					known := false
					for _, u := range r.users {
						known = known || u == m.user
					}
					if !known {
						t.Skip("the receiver does not know " + m.user)
					}
					if strconv.IntSize == 32 && max(m.boots, m.time) > maxBoots {
						t.Skip("a 32-bit int does not decode a value above 2147483647")
					}
				}
				seq++
				engineID := fmt.Sprintf("\x80\x00\x1f\x88\x04tl-%d", seq)
				x := r.receiver(t)
				for i, m := range msgs {
					advance(m.wait)
					_, err := x.UnmarshalTrap(encodeTimely(t, engineID, m), false)
					if m.accepted {
						assert.NoError(t, err, "message %d", i)
					} else {
						assert.Error(t, err, "message %d", i)
					}
				}
			})
		}
	}
}
