// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snmpUser is an SNMPv3 user of the end-to-end tests' agent, read from
// testdata/snmp_users.txt, from which snmp_users.sh creates the users in
// snmpd.
type snmpUser struct {
	name     string
	auth     SnmpV3AuthProtocol
	authPass string
	priv     SnmpV3PrivProtocol
	privPass string
}

// msgFlags is the security level of u's requests.
func (u snmpUser) msgFlags() SnmpV3MsgFlags {
	switch {
	case u.priv > NoPriv:
		return AuthPriv
	case u.auth > NoAuth:
		return AuthNoPriv
	}
	return NoAuthNoPriv
}

func (u snmpUser) securityParameters() *UsmSecurityParameters {
	return &UsmSecurityParameters{
		UserName:                 u.name,
		AuthenticationProtocol:   u.auth,
		AuthenticationPassphrase: u.authPass,
		PrivacyProtocol:          u.priv,
		PrivacyPassphrase:        u.privPass,
	}
}

// loadSnmpUsers reads testdata/snmp_users.txt.
func loadSnmpUsers(tb testing.TB) []snmpUser {
	tb.Helper()
	data, err := os.ReadFile("testdata/snmp_users.txt")
	require.NoError(tb, err)

	auths := make(map[string]SnmpV3AuthProtocol, len(usmAuthProtocols))
	for _, a := range usmAuthProtocols {
		auths[a.String()] = a
	}
	privs := make(map[string]SnmpV3PrivProtocol, len(usmPrivProtocols))
	for _, p := range usmPrivProtocols {
		privs[p.String()] = p
	}
	pass := func(s string) string {
		if s == "-" {
			return ""
		}
		return s
	}

	var users []snmpUser
	for n, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		require.Len(tb, fields, 5, "line %d: %q", n+1, line)
		auth, ok := auths[fields[1]]
		require.True(tb, ok, "line %d: authentication protocol %q", n+1, fields[1])
		priv, ok := privs[fields[3]]
		require.True(tb, ok, "line %d: privacy protocol %q", n+1, fields[3])
		users = append(users, snmpUser{
			name: fields[0], auth: auth, authPass: pass(fields[2]), priv: priv, privPass: pass(fields[4]),
		})
	}
	return users
}

// TestSnmpUsers checks that the end-to-end users cover every authentication
// and privacy protocol pair once, with a passphrase exactly where a protocol
// needs one.
func TestSnmpUsers(t *testing.T) {
	type pair struct {
		auth SnmpV3AuthProtocol
		priv SnmpV3PrivProtocol
	}
	want := map[pair]int{{NoAuth, NoPriv}: 1}
	for _, a := range usmAuthProtocols[1:] {
		for _, p := range usmPrivProtocols {
			want[pair{a, p}] = 1
		}
	}

	got := map[pair]int{}
	names := map[string]bool{}
	for _, u := range loadSnmpUsers(t) {
		got[pair{u.auth, u.priv}]++
		assert.False(t, names[u.name], "user %q defined twice", u.name)
		names[u.name] = true
		assert.Equal(t, u.auth > NoAuth, u.authPass != "", "user %q: authentication passphrase", u.name)
		assert.Equal(t, u.priv > NoPriv, u.privPass != "", "user %q: privacy passphrase", u.name)
		assert.NoError(t, newTestGoSNMPv3(u.msgFlags(), u.securityParameters()).validateParameters(), "user %q", u.name)
	}
	assert.Equal(t, want, got)
}
