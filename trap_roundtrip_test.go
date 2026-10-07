// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Socket-free trap and inform round trips: packets made by MarshalMsg, the
// way an agent sends them, are decoded by UnmarshalTrap the way trap
// receivers use it.

const (
	rtUser     = "trap-user"
	rtAuthPass = "trap-auth-pass"
	rtPrivPass = "trap-priv-pass"
	rtEngineID = "\x80\x00\x1f\x88\x04trap-sender"
)

// rtVarbinds are the varbinds of every round-trip packet. Their Go types are
// the ones UnmarshalTrap returns, so the decoded list must equal them.
var rtVarbinds = []SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(12345)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: ObjectIdentifier, Value: ".1.3.6.1.4.1.20372.1.2"},
	{Name: ".1.3.6.1.4.1.20372.1.2.1", Type: OctetString, Value: []byte("trap-payload")},
	{Name: ".1.3.6.1.4.1.20372.1.2.2", Type: Integer, Value: -7},
}

var (
	rtAuthProtocols = []SnmpV3AuthProtocol{NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512}
	rtPrivProtocols = []SnmpV3PrivProtocol{NoPriv, DES, AES, AES192, AES192C, AES256, AES256C}
)

// rtCredentials are the USM settings of a sender or a receiver.
type rtCredentials struct {
	user     string
	auth     SnmpV3AuthProtocol
	authPass string
	priv     SnmpV3PrivProtocol
	privPass string
}

func rtCreds(auth SnmpV3AuthProtocol, priv SnmpV3PrivProtocol) rtCredentials {
	return rtCredentials{user: rtUser, auth: auth, authPass: rtAuthPass, priv: priv, privPass: rtPrivPass}
}

// flags is the security level the credentials imply.
func (c rtCredentials) flags() SnmpV3MsgFlags {
	switch {
	case c.priv != NoPriv:
		return AuthPriv
	case c.auth != NoAuth:
		return AuthNoPriv
	default:
		return NoAuthNoPriv
	}
}

func (c rtCredentials) usm(engineID string) *UsmSecurityParameters {
	return &UsmSecurityParameters{
		UserName:                 c.user,
		AuthenticationProtocol:   c.auth,
		AuthenticationPassphrase: c.authPass,
		PrivacyProtocol:          c.priv,
		PrivacyPassphrase:        c.privPass,
		AuthoritativeEngineID:    engineID,
	}
}

// rtEncodeV3 makes an SNMPv3 SNMPv2-Trap or InformRequest. The sender is the
// authoritative engine: its keys are localized to its own engine ID, and
// InitPacket sets the privacy salt. Only informs are reportable (RFC 3412
// section 6.4).
func rtEncodeV3(t *testing.T, sender rtCredentials, pduType PDUType) []byte {
	t.Helper()

	sp := sender.usm(rtEngineID)
	sp.AuthoritativeEngineBoots = 3
	sp.AuthoritativeEngineTime = 77
	if sender.auth != NoAuth {
		require.NoError(t, sp.InitSecurityKeys())
	}
	flags := sender.flags()
	if pduType == InformRequest {
		flags |= Reportable
	}
	pkt := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           flags,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		ContextEngineID:    rtEngineID,
		ContextName:        "trap-context",
		PDUType:            pduType,
		MsgID:              21,
		RequestID:          42,
		Variables:          rtVarbinds,
	}
	require.NoError(t, sp.InitPacket(pkt))
	data, err := pkt.MarshalMsg()
	require.NoError(t, err)
	return data
}

// rtReceiver builds the GoSNMP that calls UnmarshalTrap for the given credentials.
type rtReceiver func(t *testing.T, creds ...rtCredentials) *GoSNMP

// rtSingleUser configures one user and the security level it requires on the
// receiving GoSNMP itself, without a credentials table.
func rtSingleUser(t *testing.T, creds ...rtCredentials) *GoSNMP {
	t.Helper()
	require.Len(t, creds, 1)
	return &GoSNMP{
		Version:            Version3,
		MsgFlags:           creds[0].flags(),
		SecurityModel:      UserSecurityModel,
		SecurityParameters: creds[0].usm(""),
	}
}

// rtTable returns a receiver with a credentials table, as the Netdata trap
// receiver builds it, with the table entries localized to engineID.
func rtTable(engineID string) rtReceiver {
	return func(t *testing.T, creds ...rtCredentials) *GoSNMP {
		t.Helper()
		table := NewSnmpV3SecurityParametersTable(Logger{})
		for _, c := range creds {
			require.NoError(t, table.Add(c.user, c.usm(engineID)))
		}
		return &GoSNMP{Version: Version3, TrapSecurityParametersTable: table}
	}
}

var rtReceivers = []struct {
	name    string
	receive rtReceiver
}{
	{"single-user", rtSingleUser},
	{"table", rtTable("")},
	{"table-localized", rtTable(rtEngineID)},
}

// trapView is the part of a decoded trap the round-trip tests compare.
type trapView struct {
	Version         SnmpVersion
	MsgFlags        SnmpV3MsgFlags
	UserName        string
	EngineID        string
	ContextEngineID string
	ContextName     string
	Community       string
	PDUType         PDUType
	RequestID       uint32
	IsInform        bool
	Enterprise      string
	AgentAddress    string
	GenericTrap     int
	SpecificTrap    int
	Timestamp       uint
	Variables       []SnmpPDU
}

func newTrapView(p *SnmpPacket) trapView {
	v := trapView{
		Version:         p.Version,
		MsgFlags:        p.MsgFlags,
		ContextEngineID: p.ContextEngineID,
		ContextName:     p.ContextName,
		Community:       p.Community,
		PDUType:         p.PDUType,
		RequestID:       p.RequestID,
		IsInform:        p.IsInform,
		Enterprise:      p.Enterprise,
		AgentAddress:    p.AgentAddress,
		GenericTrap:     p.GenericTrap,
		SpecificTrap:    p.SpecificTrap,
		Timestamp:       p.Timestamp,
		Variables:       p.Variables,
	}
	if sp, ok := p.SecurityParameters.(*UsmSecurityParameters); ok {
		v.UserName = sp.UserName
		v.EngineID = sp.AuthoritativeEngineID
	}
	return v
}

func TestTrapRoundTripV1V2c(t *testing.T) {
	tests := map[string]struct {
		pkt  *SnmpPacket
		want trapView
	}{
		"v1 trap": {
			pkt: &SnmpPacket{
				Version:      Version1,
				Community:    "public",
				PDUType:      Trap,
				Enterprise:   ".1.3.6.1.4.1.20372",
				AgentAddress: "192.0.2.1",
				GenericTrap:  6,
				SpecificTrap: 42,
				Timestamp:    12345,
				Variables:    rtVarbinds[2:],
			},
			want: trapView{
				Version:      Version1,
				Community:    "public",
				PDUType:      Trap,
				Enterprise:   ".1.3.6.1.4.1.20372",
				AgentAddress: "192.0.2.1",
				GenericTrap:  6,
				SpecificTrap: 42,
				Timestamp:    12345,
				Variables:    rtVarbinds[2:],
			},
		},
		"v2c trap": {
			pkt:  &SnmpPacket{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 42, Variables: rtVarbinds},
			want: trapView{Version: Version2c, Community: "public", PDUType: SNMPv2Trap, RequestID: 42, Variables: rtVarbinds},
		},
		"v2c inform": {
			pkt: &SnmpPacket{Version: Version2c, Community: "public", PDUType: InformRequest, RequestID: 42, Variables: rtVarbinds},
			want: trapView{
				Version:   Version2c,
				Community: "public",
				PDUType:   InformRequest,
				RequestID: 42,
				IsInform:  true,
				Variables: rtVarbinds,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := tc.pkt.MarshalMsg()
			require.NoError(t, err)

			got, err := (&GoSNMP{}).UnmarshalTrap(data, false)
			require.NoError(t, err)
			assert.Equal(t, tc.want, newTrapView(got))
		})
	}
}

// TestTrapRoundTripV3 decodes a trap and an inform for every authentication
// and privacy protocol combination with each kind of receiver.
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
					MsgFlags:        creds.flags(),
					UserName:        rtUser,
					EngineID:        rtEngineID,
					ContextEngineID: rtEngineID,
					ContextName:     "trap-context",
					PDUType:         pduType,
					RequestID:       42,
					IsInform:        pduType == InformRequest,
					Variables:       rtVarbinds,
				}
				if pduType == InformRequest {
					want.MsgFlags |= Reportable
				}

				for _, r := range rtReceivers {
					t.Run(fmt.Sprintf("%v-%v/%v/%s", auth, priv, pduType, r.name), func(t *testing.T) {
						data := rtEncodeV3(t, creds, pduType)

						got, err := r.receive(t, creds).UnmarshalTrap(data, false)
						require.NoError(t, err)
						assert.Equal(t, want, newTrapView(got))
					})
				}
			}
		}
	}
}

// TestTrapSecurityOutcomes pins whether UnmarshalTrap accepts an SNMPv3 trap
// whose credentials or security level differ from the receiver's. Cases with
// a knownBug note record wrong behavior that the bug-fix phase changes.
func TestTrapSecurityOutcomes(t *testing.T) {
	withUser := func(c rtCredentials, user string) rtCredentials { c.user = user; return c }
	withAuthPass := func(c rtCredentials, pass string) rtCredentials { c.authPass = pass; return c }
	withPrivPass := func(c rtCredentials, pass string) rtCredentials { c.privPass = pass; return c }

	sha := rtCreds(SHA, NoPriv)
	shaAES := rtCreds(SHA, AES)
	noAuth := rtCreds(NoAuth, NoPriv)

	tests := map[string]struct {
		sender    rtCredentials
		receiver  rtReceiver
		receivers []rtCredentials
		accepted  bool
		knownBug  string
	}{
		"wrong auth passphrase, single user": {
			sender: sha, receiver: rtSingleUser, receivers: []rtCredentials{withAuthPass(sha, "other-pass")},
		},
		"wrong auth passphrase, table": {
			sender: sha, receiver: rtTable(""), receivers: []rtCredentials{withAuthPass(sha, "other-pass")},
		},
		"wrong privacy passphrase, single user": {
			sender: shaAES, receiver: rtSingleUser, receivers: []rtCredentials{withPrivPass(shaAES, "other-pass")},
		},
		"wrong privacy passphrase, table": {
			sender: shaAES, receiver: rtTable(""), receivers: []rtCredentials{withPrivPass(shaAES, "other-pass")},
		},
		"unknown user, single user": {
			sender: sha, receiver: rtSingleUser, receivers: []rtCredentials{withUser(sha, "other-user")},
		},
		"unknown user, table": {
			sender: sha, receiver: rtTable(""), receivers: []rtCredentials{withUser(sha, "other-user")},
		},
		"noAuthNoPriv trap for an authNoPriv user, single user": {
			sender: noAuth, receiver: rtSingleUser, receivers: []rtCredentials{sha},
		},
		"noAuthNoPriv trap for an authNoPriv user, table": {
			sender: noAuth, receiver: rtTable(""), receivers: []rtCredentials{sha},
			accepted: true, knownBug: "the table path takes the security level from the packet",
		},
		"authNoPriv trap for an authPriv user, single user": {
			sender: sha, receiver: rtSingleUser, receivers: []rtCredentials{shaAES},
			accepted: true, knownBug: "only the authentication flag of the required level is checked",
		},
		"authNoPriv trap for an authPriv user, table": {
			sender: sha, receiver: rtTable(""), receivers: []rtCredentials{shaAES},
			accepted: true, knownBug: "the table path takes the security level from the packet",
		},
		"authPriv trap for an authNoPriv user, single user": {
			sender: shaAES, receiver: rtSingleUser, receivers: []rtCredentials{sha},
		},
		"authPriv trap for an authNoPriv user, table": {
			sender: shaAES, receiver: rtTable(""), receivers: []rtCredentials{sha},
		},
		"same user name twice, second credentials match, table": {
			sender:    shaAES,
			receiver:  rtTable(""),
			receivers: []rtCredentials{withPrivPass(withAuthPass(rtCreds(MD5, DES), "other-pass"), "other-pass"), shaAES},
			accepted:  true,
		},
		"table entry localized to another engine ID": {
			sender: shaAES, receiver: rtTable("\x80\x00\x1f\x88\x04other-engine"), receivers: []rtCredentials{shaAES},
			accepted: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			data := rtEncodeV3(t, tc.sender, SNMPv2Trap)

			got, err := tc.receiver(t, tc.receivers...).UnmarshalTrap(data, false)
			if !tc.accepted {
				assert.Error(t, err, "trap accepted")
				return
			}
			require.NoError(t, err, "trap rejected (known bug: %q)", tc.knownBug)
			assert.Equal(t, rtVarbinds, got.Variables)
		})
	}
}
