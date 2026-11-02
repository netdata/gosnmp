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
