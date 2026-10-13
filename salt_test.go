// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReencodeDrawsNewSalt checks that a packet built from a decoded message,
// as an inform response is (Netdata's trap receiver copies the inform's
// security parameters), is encrypted with a salt of its own: each encoding
// draws a new one, neither the received salt nor the previous encoding's.
func TestReencodeDrawsNewSalt(t *testing.T) {
	for _, priv := range []SnmpV3PrivProtocol{DES, AES, AES256C} {
		t.Run(priv.String(), func(t *testing.T) {
			data := usmCharTrap(t, priv, usmCharVarbinds)
			inSalt := splitV3Message(t, data).usm[5]

			decoder := usmDecoder(SHA, "codec-auth-pass", priv, "codec-priv-pass")()
			in, err := decoder.SnmpDecodePacket(bytes.Clone(data))
			require.NoError(t, err)
			require.Equal(t, inSalt, in.SecurityParameters.usm().PrivacyParameters)

			respond := func() []byte {
				t.Helper()
				resp := *in
				resp.PDUType = GetResponse
				resp.SecurityParameters = in.SecurityParameters.Copy()
				out, marshalErr := resp.MarshalMsg()
				require.NoError(t, marshalErr)
				return out
			}
			first, second := respond(), respond()
			firstSalt, secondSalt := splitV3Message(t, first).usm[5], splitV3Message(t, second).usm[5]
			assert.Len(t, firstSalt, 8)
			assert.NotEqual(t, inSalt, firstSalt, "the received salt reused")
			assert.NotEqual(t, firstSalt, secondSalt, "one salt for two messages")

			// The response decrypts with its own salt.
			got, err := decoder.SnmpDecodePacket(first)
			require.NoError(t, err)
			assert.Equal(t, usmCharVarbinds, got.Variables)
		})
	}
}
