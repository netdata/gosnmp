// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Socket-free trap and inform round trips: packets made by Message.Encode, the
// way an agent sends them, are decoded by a Receiver.

const (
	rtUser     = "trap-user"
	rtAuthPass = "trap-auth-pass"
	rtPrivPass = "trap-priv-pass"
	rtEngineID = "\x80\x00\x1f\x88\x04trap-sender"
)

// rtVarbinds are the varbinds of every round-trip packet. Their values are
// built as Receive decodes them, so the decoded list must equal them.
var rtVarbinds = []VarBind{
	{Name: ".1.3.6.1.2.1.1.3.0", Value: TimeTicksValue(12345)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Value: ObjectIdentifierValue(".1.3.6.1.4.1.20372.1.2")},
	{Name: ".1.3.6.1.4.1.20372.1.2.1", Value: OctetStringValue([]byte("trap-payload"))},
	{Name: ".1.3.6.1.4.1.20372.1.2.2", Value: IntegerValue(-7)},
}

var (
	rtAuthProtocols = []AuthProtocol{NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512}
	rtPrivProtocols = []PrivProtocol{NoPriv, DES, AES, AES192, AES192C, AES256, AES256C}
)

// rtCredentials are the USM settings of a sender or a receiver.
type rtCredentials struct {
	user     string
	auth     AuthProtocol
	authPass string
	priv     PrivProtocol
	privPass string
}

func rtCreds(auth AuthProtocol, priv PrivProtocol) rtCredentials {
	return rtCredentials{user: rtUser, auth: auth, authPass: rtAuthPass, priv: priv, privPass: rtPrivPass}
}

// flags is the security level the credentials imply.
func (c rtCredentials) flags() SecurityLevel {
	switch {
	case c.priv != NoPriv:
		return AuthPriv
	case c.auth != NoAuth:
		return AuthNoPriv
	default:
		return NoAuthNoPriv
	}
}

// asUser returns the credentials as a User.
func (c rtCredentials) asUser() User {
	return User{
		Name:           c.user,
		AuthProtocol:   c.auth,
		AuthPassphrase: c.authPass,
		PrivProtocol:   c.priv,
		PrivPassphrase: c.privPass,
	}
}

// rtEncodeV3 makes an SNMPv3 SNMPv2-Trap or InformRequest. The sender is the
// authoritative engine: its keys are localized to its own engine ID. Only
// informs are reportable (RFC 3412 section 6.4).
func rtEncodeV3(t *testing.T, sender rtCredentials, pduType PDUType) []byte {
	t.Helper()

	pkt := &Message{
		Version:       Version3,
		SecurityLevel: sender.flags(),

		SecurityParameters: SecurityParameters{
			AuthoritativeEngineID:    []byte(rtEngineID),
			AuthoritativeEngineBoots: 3,
			AuthoritativeEngineTime:  77,
			UserName:                 sender.user,
		},
		ContextEngineID: []byte(rtEngineID),
		ContextName:     "trap-context",
		PDUType:         pduType,
		MsgID:           21,
		RequestID:       42,
		VarBinds:        rtVarbinds,
	}
	user := sender.asUser()
	data, err := pkt.Encode(&user)
	require.NoError(t, err)
	return data
}

// rtReceiver builds the receiver of the given credentials.
type rtReceiver func(t *testing.T, creds ...rtCredentials) *Receiver

// rtRegistered returns a receiver of the credentials, each registered for
// engineID, as the Netdata trap receiver registers its users for each engine.
func rtRegistered(engineID string) rtReceiver {
	return func(t *testing.T, creds ...rtCredentials) *Receiver {
		t.Helper()
		users := make([]User, len(creds))
		for i, c := range creds {
			users[i] = c.asUser()
		}
		return receiverAt(t, []byte(engineID), users...)
	}
}

// rtLearning returns a receiver that learns the credentials for any engine.
func rtLearning(t *testing.T, creds ...rtCredentials) *Receiver {
	t.Helper()
	config := ReceiverConfig{MaxLearned: 1}
	for _, c := range creds {
		config.LearnUsers = append(config.LearnUsers, c.asUser())
	}
	r, _ := newTestReceiver(t, config)
	return r
}

var rtReceivers = []struct {
	name    string
	receive rtReceiver
	informs bool // the receiver accepts informs; a learning one learns none
}{
	{"registered", rtRegistered(rtEngineID), true},
	{"learning", rtLearning, false},
}

// trapView is the part of a decoded trap the round-trip tests compare.
type trapView struct {
	Version         Version
	SecurityLevel   SecurityLevel
	UserName        string
	EngineID        string
	ContextEngineID string
	ContextName     string
	Community       string
	PDUType         PDUType
	RequestID       uint32
	Enterprise      string
	AgentAddress    netip.Addr
	GenericTrap     int32
	SpecificTrap    int32
	Timestamp       uint32
	VarBinds        []VarBind
}

func newTrapView(p *Message) trapView {
	return trapView{
		Version:         p.Version,
		SecurityLevel:   p.SecurityLevel,
		UserName:        p.SecurityParameters.UserName,
		EngineID:        string(p.SecurityParameters.AuthoritativeEngineID),
		ContextEngineID: string(p.ContextEngineID),
		ContextName:     p.ContextName,
		Community:       p.Community,
		PDUType:         p.PDUType,
		RequestID:       p.RequestID,
		Enterprise:      p.Enterprise,
		AgentAddress:    p.AgentAddress,
		GenericTrap:     p.GenericTrap,
		SpecificTrap:    p.SpecificTrap,
		Timestamp:       p.Timestamp,
		VarBinds:        p.VarBinds,
	}
}

func TestTrapRoundTripV1V2c(t *testing.T) {
	tests := map[string]struct {
		pkt  *Message
		want trapView
	}{
		"v1 trap": {
			pkt: &Message{
				Version:      Version1,
				Community:    "public",
				PDUType:      Trap,
				Enterprise:   ".1.3.6.1.4.1.20372",
				AgentAddress: netip.MustParseAddr("192.0.2.1"),
				GenericTrap:  6,
				SpecificTrap: 42,
				Timestamp:    12345,
				VarBinds:     rtVarbinds[2:],
			},
			want: trapView{
				Version:      Version1,
				Community:    "public",
				PDUType:      Trap,
				Enterprise:   ".1.3.6.1.4.1.20372",
				AgentAddress: netip.MustParseAddr("192.0.2.1"),
				GenericTrap:  6,
				SpecificTrap: 42,
				Timestamp:    12345,
				VarBinds:     rtVarbinds[2:],
			},
		},
		"v2c trap": {
			pkt:  &Message{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 42, VarBinds: rtVarbinds},
			want: trapView{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 42, VarBinds: rtVarbinds},
		},
		"v2c inform": {
			pkt: &Message{Version: Version2c, Community: "public", PDUType: InformRequest, RequestID: 42, VarBinds: rtVarbinds},
			want: trapView{
				Version:   Version2c,
				Community: "public",
				PDUType:   InformRequest,
				RequestID: 42,
				VarBinds:  rtVarbinds,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := tc.pkt.Encode(nil)
			require.NoError(t, err)

			r, _ := newTestReceiver(t, ReceiverConfig{})
			got, err := receiveMessage(r, data)
			require.NoError(t, err)
			assert.Equal(t, tc.want, newTrapView(got))
		})
	}
}

// TestTrapRoundTripV3 decodes a trap and an inform for every authentication
// and privacy protocol combination with each kind of receiver: a learning
// receiver rejects the inform, whose engine it does not learn.
func TestTrapRoundTripV3(t *testing.T) {
	for _, auth := range rtAuthProtocols {
		for _, priv := range rtPrivProtocols {
			if auth == NoAuth && priv != NoPriv {
				continue
			}
			creds := rtCreds(auth, priv)
			for _, pduType := range []PDUType{SNMPv2Trap, InformRequest} {
				want := trapView{
					Version:         Version3,
					SecurityLevel:   creds.flags(),
					UserName:        rtUser,
					EngineID:        rtEngineID,
					ContextEngineID: rtEngineID,
					ContextName:     "trap-context",
					PDUType:         pduType,
					RequestID:       42,
					VarBinds:        rtVarbinds,
				}

				for _, r := range rtReceivers {
					t.Run(fmt.Sprintf("%v-%v/%v/%s", auth, priv, pduType, r.name), func(t *testing.T) {
						data := rtEncodeV3(t, creds, pduType)

						got, err := receiveMessage(r.receive(t, creds), data)
						if pduType == InformRequest && !r.informs {
							require.ErrorIs(t, err, ErrUnknownEngineID)
							assert.Nil(t, got)
							return
						}
						require.NoError(t, err)
						assert.Equal(t, want, newTrapView(got))
					})
				}
			}
		}
	}
}

// TestTrapSecurityOutcomes pins whether a receiver accepts an SNMPv3 trap
// whose credentials or security level differ from its user's: a user with an
// authentication protocol needs an authenticated trap, privacy optional; a
// learned user the same, and an unauthenticated trap a no-auth user only.
func TestTrapSecurityOutcomes(t *testing.T) {
	withUser := func(c rtCredentials, user string) rtCredentials { c.user = user; return c }
	withAuthPass := func(c rtCredentials, pass string) rtCredentials { c.authPass = pass; return c }
	withPrivPass := func(c rtCredentials, pass string) rtCredentials { c.privPass = pass; return c }

	sha := rtCreds(SHA, NoPriv)
	shaAES := rtCreds(SHA, AES)
	noAuth := rtCreds(NoAuth, NoPriv)
	registered := rtRegistered(rtEngineID)

	tests := map[string]struct {
		sender    rtCredentials
		receiver  rtReceiver
		receivers []rtCredentials
		accepted  bool
		wantErr   error
	}{
		"wrong auth passphrase": {
			sender: sha, receiver: registered, receivers: []rtCredentials{withAuthPass(sha, "other-pass")},
			wantErr: ErrWrongDigest,
		},
		"wrong privacy passphrase": {
			sender: shaAES, receiver: registered, receivers: []rtCredentials{withPrivPass(shaAES, "other-pass")},
			wantErr: ErrDecryption,
		},
		"unknown user": {
			sender: sha, receiver: registered, receivers: []rtCredentials{withUser(sha, "other-user")},
			wantErr: ErrUnknownUsername,
		},
		"noAuthNoPriv trap for an authNoPriv user": {
			sender: noAuth, receiver: registered, receivers: []rtCredentials{sha},
			wantErr: ErrUnknownSecurityLevel,
		},
		"authNoPriv trap for an authPriv user": {
			sender: sha, receiver: registered, receivers: []rtCredentials{shaAES},
			accepted: true,
		},
		"authPriv trap for an authNoPriv user": {
			sender: shaAES, receiver: registered, receivers: []rtCredentials{sha},
			wantErr: ErrUnknownSecurityLevel,
		},
		"same user name twice, second credentials match": {
			sender:    shaAES,
			receiver:  registered,
			receivers: []rtCredentials{withPrivPass(withAuthPass(rtCreds(MD5, DES), "other-pass"), "other-pass"), shaAES},
			accepted:  true,
		},
		"a user of another engine ID": {
			sender: shaAES, receiver: rtRegistered("\x80\x00\x1f\x88\x04other-engine"), receivers: []rtCredentials{shaAES},
			wantErr: ErrUnknownEngineID,
		},
		"learned, wrong auth passphrase": {
			sender: sha, receiver: rtLearning, receivers: []rtCredentials{withAuthPass(sha, "other-pass")},
			wantErr: ErrWrongDigest,
		},
		"learned, noAuthNoPriv trap for an authNoPriv user": {
			sender: noAuth, receiver: rtLearning, receivers: []rtCredentials{sha},
			wantErr: ErrUnknownSecurityLevel,
		},
		"learned, noAuthNoPriv trap for a no-auth user": {
			sender: noAuth, receiver: rtLearning, receivers: []rtCredentials{noAuth},
			accepted: true,
		},
		"learned, authPriv trap": {
			sender: shaAES, receiver: rtLearning, receivers: []rtCredentials{sha, shaAES},
			accepted: true,
		},
		"learned, unknown user": {
			sender: sha, receiver: rtLearning, receivers: []rtCredentials{withUser(sha, "other-user")},
			wantErr: ErrUnknownEngineID,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			data := rtEncodeV3(t, tc.sender, SNMPv2Trap)

			got, err := receiveMessage(tc.receiver(t, tc.receivers...), data)
			if !tc.accepted {
				require.ErrorIs(t, err, tc.wantErr, "trap accepted or another error")
				assert.Nil(t, got, "a message with the error")
				return
			}
			require.NoError(t, err, "trap rejected")
			assert.Equal(t, rtVarbinds, got.VarBinds)
		})
	}
}

// TestReceiveFailureNoMessage pins that Receive returns no message on the
// failures that come before a user decodes the message: the engine ID and the
// user lookup.
func TestReceiveFailureNoMessage(t *testing.T) {
	scoped := func(engineID []byte) []byte {
		return tlv(0x30, engineID, octets(""), craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5)))))
	}
	trap := craftedV3NoAuth(scoped(craftedEngineID))
	noEngineID := craftedV3(intTLV(42), intTLV(65507), octets("\x00"), intTLV(3),
		craftedUSM(octets(""), intTLV(7), intTLV(1234), octets("codec-user"), octets(""), octets("")), scoped(octets("")))
	tests := map[string]struct {
		r       *Receiver
		in      []byte
		wantErr error
	}{
		"no engine ID": {
			r:       receiverFor(t, trap, User{Name: "codec-user"}),
			in:      noEngineID,
			wantErr: ErrUnknownEngineID,
		},
		"no user for the engine ID": {
			r:       receiverAt(t, []byte("\x80\x00\x1f\x88\x04other-engine"), User{Name: "codec-user"}),
			in:      trap,
			wantErr: ErrUnknownEngineID,
		},
		"no user of the name for the engine ID": {
			r:       receiverFor(t, trap, User{Name: "other-user"}),
			in:      trap,
			wantErr: ErrUnknownUsername,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tc.r.Receive(tc.in)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Nil(t, got)
		})
	}
}
