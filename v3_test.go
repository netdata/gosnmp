// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSecurityLevelPredicates pins the flag each predicate reads, the authFlag
// and the privFlag bits (RFC 3412 section 6.4), and the three valid levels.
func TestSecurityLevelPredicates(t *testing.T) {
	type flags struct{ auth, priv, valid bool }
	tests := map[string]struct {
		in   SecurityLevel
		want flags
	}{
		"noAuthNoPriv":                   {in: NoAuthNoPriv, want: flags{valid: true}},
		"authNoPriv":                     {in: AuthNoPriv, want: flags{auth: true, valid: true}},
		"privacy without authentication": {in: AuthPriv &^ AuthNoPriv, want: flags{priv: true}},
		"authPriv":                       {in: AuthPriv, want: flags{auth: true, priv: true, valid: true}},
		"the reportableFlag's bit":       {in: reportableFlag, want: flags{}},
		"authPriv and another bit":       {in: AuthPriv | reportableFlag, want: flags{auth: true, priv: true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, flags{auth: tc.in.authFlag(), priv: tc.in.privFlag(), valid: tc.in.valid()})
		})
	}
}
