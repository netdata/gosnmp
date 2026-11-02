// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"testing"

	"github.com/netdata/gosnmp/internal/ber"
)

// errorCategories are the exported categories of the errors of incoming
// messages, by name.
var errorCategories = []struct {
	name string
	err  error
}{
	{"ErrASNParse", ErrASNParse},
	{"ErrBadVersion", ErrBadVersion},
	{"ErrUnknownSecurityModels", ErrUnknownSecurityModels},
	{"ErrInvalidMsgs", ErrInvalidMsgs},
	{"ErrUnknownEngineID", ErrUnknownEngineID},
	{"ErrUnknownUsername", ErrUnknownUsername},
	{"ErrUnknownSecurityLevel", ErrUnknownSecurityLevel},
	{"ErrWrongDigest", ErrWrongDigest},
	{"ErrNotInTimeWindow", ErrNotInTimeWindow},
	{"ErrDecryption", ErrDecryption},
	{"ErrUnknownPDUHandlers", ErrUnknownPDUHandlers},
	{"ErrUnknownReportPDU", ErrUnknownReportPDU},
	{"ErrUnmatchedReply", ErrUnmatchedReply},
}

// decodeDetails are the unexported errors a decode error can wrap besides its
// category, which the goldens print as details of its cause.
var decodeDetails = []struct {
	name string
	err  error
}{
	{"ber.ErrBase128IntegerTooLarge", ber.ErrBase128IntegerTooLarge},
	{"ber.ErrBase128IntegerTruncated", ber.ErrBase128IntegerTruncated},
	{"ber.ErrFloatBufferTooShort", ber.ErrFloatBufferTooShort},
	{"ber.ErrFloatTooLarge", ber.ErrFloatTooLarge},
	{"ber.ErrIntegerTooLarge", ber.ErrIntegerTooLarge},
	{"ber.ErrInvalidOidLength", ber.ErrInvalidOidLength},
	{"ber.ErrInvalidPacketLength", ber.ErrInvalidPacketLength},
	{"ber.ErrZeroLenInteger", ber.ErrZeroLenInteger},
	{"errNoValue", errNoValue},
}

// categoriesOf returns the names of the categories err matches.
func categoriesOf(err error) []string {
	var names []string
	for _, c := range errorCategories {
		if errors.Is(err, c.err) {
			names = append(names, c.name)
		}
	}
	return names
}

// checkCategory fails t unless err, an error of an incoming message or nil,
// matches exactly one category. The fuzz targets that call it decode with
// valid users outside FIPS 140-only mode (their seeds derive MD5 keys), so no
// local failure is expected.
func checkCategory(t *testing.T, what string, err error) {
	t.Helper()
	if names := categoriesOf(err); err != nil && len(names) != 1 {
		t.Errorf("%s: %q matches the categories %v, not exactly one", what, err, names)
	}
}

// checkNoMessage fails a call that returned a message with an error: a failed
// call returns no result.
func checkNoMessage(t *testing.T, what string, msg *Message, err error) {
	t.Helper()
	if err != nil && msg != nil {
		t.Errorf("%s: returned a message with the error %q", what, err)
	}
}

// TestRejectionCategories pins the category of rejections no golden reaches
// through its entry point: UnmarshalTrap's version check and the PDU of an
// SNMPv1 and an SNMPv2c trap and of an SNMPv3 trap past security processing,
// on both paths, and an encrypted message without its scoped PDU.
func TestRejectionCategories(t *testing.T) {
	useEngineTimes(t)
	user := usmUser(NoAuth, "", NoPriv, "")
	single := func(data []byte) error {
		_, err := (&Client{Version: Version3, User: user}).UnmarshalTrap(data, true)
		return err
	}
	table := func(data []byte) error {
		tb := NewSnmpV3SecurityParametersTable()
		if err := tb.Add(user, nil); err != nil {
			return err
		}
		_, err := (&Client{Version: Version3, TrapSecurityParametersTable: tb}).UnmarshalTrap(data, false)
		return err
	}
	decode := func(data []byte) error {
		_, err := (&Client{User: usmUser(SHA, "codec-auth-pass", AES, "codec-priv-pass")}).DecodeMessage(data)
		return err
	}
	// A PDU whose error status is missing.
	badPDU := tlv(byte(SNMPv2Trap), intTLV(1))
	v3Trap := craftedV3NoAuth(tlv(0x30, craftedEngineID, octets(""), badPDU))
	authPrivWithoutScopedPDU := craftedV3(intTLV(42), intTLV(65507), octets("\x03"), intTLV(3),
		craftedUSM(craftedEngineID, intTLV(7), intTLV(1234), octets("codec-user"), octets(string(make([]byte, 12))),
			octets(string(make([]byte, 8)))), nil)

	tests := map[string]struct {
		decode func([]byte) error
		in     []byte
		want   string
	}{
		"trap of version 2":             {single, craftedMsg(2, craftedPDU(SNMPv2Trap, craftedVBL(craftedVB(intTLV(5))))), "ErrBadVersion"},
		"SNMPv1 trap PDU":               {single, craftedV1Trap(octets("x"), craftedAgentAddress, intTLV(6), intTLV(1), craftedTimestamp, craftedVBL()), "ErrASNParse"},
		"SNMPv2c trap PDU":              {single, craftedMsg(1, badPDU), "ErrASNParse"},
		"SNMPv3 trap PDU, single path":  {single, v3Trap, "ErrASNParse"},
		"SNMPv3 trap PDU, table path":   {table, v3Trap, "ErrASNParse"},
		"authPriv without a scoped PDU": {decode, authPrivWithoutScopedPDU, "ErrASNParse"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.decode(tc.in)
			if got := categoriesOf(err); len(got) != 1 || got[0] != tc.want {
				t.Errorf("%q: categories %v, want [%s]", err, got, tc.want)
			}
		})
	}
}

// TestUnmatchedReplyReasons checks that every reason a request discards a
// decoded reply for is ErrUnmatchedReply, the one of a msgID that names no
// attempt included, which never reaches a caller (rankOf records no message
// that names no attempt).
func TestUnmatchedReplyReasons(t *testing.T) {
	for _, reason := range []error{
		errOtherVersion, errOtherMessage, errNotAnswer, errOtherRequestID,
		errOtherLevel, errOtherUser, errOtherEngine, errOtherContext,
	} {
		if got := categoriesOf(reason); len(got) != 1 || got[0] != "ErrUnmatchedReply" {
			t.Errorf("%q: categories %v, want [ErrUnmatchedReply]", reason, got)
		}
	}
}
