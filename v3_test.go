// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMsgFlagsPredicates pins the flag each predicate reads: the authFlag and
// the privFlag bits (RFC 3412 section 6.4), whatever the others hold.
func TestMsgFlagsPredicates(t *testing.T) {
	type flags struct{ auth, priv bool }
	tests := map[string]struct {
		in   SnmpV3MsgFlags
		want flags
	}{
		"noAuthNoPriv":                    {in: NoAuthNoPriv, want: flags{}},
		"authNoPriv":                      {in: AuthNoPriv, want: flags{auth: true}},
		"privacy without authentication":  {in: AuthPriv &^ AuthNoPriv, want: flags{priv: true}},
		"authPriv":                        {in: AuthPriv, want: flags{auth: true, priv: true}},
		"reportable noAuthNoPriv":         {in: Reportable, want: flags{}},
		"reportable authPriv":             {in: AuthPriv | Reportable, want: flags{auth: true, priv: true}},
		"reportable privacy without auth": {in: AuthPriv&^AuthNoPriv | Reportable, want: flags{priv: true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, flags{auth: tc.in.authFlag(), priv: tc.in.privFlag()})
		})
	}
}
