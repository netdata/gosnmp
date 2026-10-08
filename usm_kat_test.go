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
	engineID := string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	tests := map[string]struct {
		auth SnmpV3AuthProtocol
		want string
	}{
		"MD5": {auth: MD5, want: "526f5eed9fcce26f8964c2930787d82b"},
		"SHA": {auth: SHA, want: "6695febc9288e36282235fc7151f128497b38f3f"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sp := &UsmSecurityParameters{
				AuthenticationProtocol:   tc.auth,
				AuthenticationPassphrase: "maplesyrup",
				PrivacyProtocol:          DES,
				PrivacyPassphrase:        "maplesyrup",
				AuthoritativeEngineID:    engineID,
			}
			require.NoError(t, sp.InitSecurityKeys())

			assert.Equal(t, tc.want, hex.EncodeToString(sp.SecretKey), "authentication key")
			assert.Equal(t, tc.want, hex.EncodeToString(sp.PrivacyKey), "privacy key")
		})
	}
}
