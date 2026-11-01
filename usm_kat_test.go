// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUSMKeysRFC3414 checks key localization against RFC 3414 appendix A.3.1
// (MD5) and A.3.2 (SHA): passphrase "maplesyrup" localized to the engine ID
// 00 00 00 00 00 00 00 00 00 00 00 02. The privacy key of DES uses the same
// algorithm. The netsnmp module compares every other protocol with net-snmp.
func TestUSMKeysRFC3414(t *testing.T) {
	engineID := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	tests := map[string]struct {
		auth AuthProtocol
		want string
	}{
		"MD5": {auth: MD5, want: "526f5eed9fcce26f8964c2930787d82b"},
		"SHA": {auth: SHA, want: "6695febc9288e36282235fc7151f128497b38f3f"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user := User{AuthProtocol: tc.auth, AuthPassphrase: "maplesyrup", PrivProtocol: DES, PrivPassphrase: "maplesyrup"}
			keys, err := user.localize(engineID)
			require.NoError(t, err)

			assert.Equal(t, tc.want, hex.EncodeToString(keys.auth), "authentication key")
			// The DES key is the localized key's first 16 octets (RFC 3414
			// section 8.1.1.1).
			assert.Equal(t, tc.want[:32], hex.EncodeToString(keys.priv), "privacy key")
		})
	}
}
