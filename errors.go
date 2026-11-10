// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import "errors"

// The categories of the errors of incoming messages. Each error of decoding a
// message, of its security processing and of matching a reply to a request
// unwraps (errors.Is) to exactly one of them, and a request answered by an
// SNMPv3 Report fails with an error that unwraps to the one of the Report's
// counter (and to ErrAnswered). Each but
// ErrUnknownReportPDU and ErrUnmatchedReply is named after the counter of RFC
// 3412, RFC 3414 or RFC 3418 that counts the message (see the package
// documentation, Errors). A local failure, such as a configuration error, a
// key that does not derive or a protocol FIPS 140-only mode refuses, matches
// none of them.
//
// They are variables only so that errors.Is can match them; do not assign to
// them. The library makes some of its errors with their values when the
// package is initialized and others when the error occurs, so after an
// assignment its errors match the old value or the new one.
var (
	// ErrASNParse is a message that does not parse, of any version: its
	// encoding, a header field, the USM parameters, a plaintext scoped PDU, the
	// PDU or a varbind, an unknown PDU type included (snmpInASNParseErrs, RFC
	// 3412 section 7.2 steps 2 and 7, RFC 3414 section 3.2 step 1; net-snmp
	// v5.9.4 counts msgPrivacyParameters that do not parse in
	// usmStatsDecryptionErrors).
	ErrASNParse = errors.New("ASN.1 parse error")
	// ErrBadVersion is a message of another version than SNMPv1, SNMPv2c and
	// SNMPv3 (snmpInBadVersions, RFC 3412 section 4.2.1; net-snmp v5.9.4 counts
	// a negative one in snmpInASNParseErrs too).
	ErrBadVersion = errors.New("bad version")
	// ErrUnknownSecurityModels is an SNMPv3 message of another security model
	// than the User-based Security Model (RFC 3412 section 7.2 step 4).
	ErrUnknownSecurityModels = errors.New("unknown security models")
	// ErrInvalidMsgs is an SNMPv3 message that asks for privacy without
	// authentication (RFC 3412 section 7.2 step 5 d).
	ErrInvalidMsgs = errors.New("invalid messages")
	// ErrUnknownEngineID is an SNMPv3 message whose engine ID the receiver
	// does not know (RFC 3414 section 3.2 step 3).
	ErrUnknownEngineID = errors.New("unknown engine id")
	// ErrUnknownUsername is an SNMPv3 message of a user the receiver does not
	// know (step 4).
	ErrUnknownUsername = errors.New("unknown username")
	// ErrUnknownSecurityLevel is an SNMPv3 message at a level its user does
	// not support (step 5), or below the level a receiver requires.
	ErrUnknownSecurityLevel = errors.New("unknown security level")
	// ErrWrongDigest is an SNMPv3 message whose digest does not check (step
	// 6).
	ErrWrongDigest = errors.New("wrong digest")
	// ErrNotInTimeWindow is an authentic SNMPv3 message outside the time
	// window (step 7).
	ErrNotInTimeWindow = errors.New("not in time window")
	// ErrDecryption is an SNMPv3 message that does not decrypt (step 8), or
	// whose decrypted plaintext is not a SEQUENCE of a contextEngineID and a
	// contextName (a PDU that does not parse after them is ErrASNParse).
	ErrDecryption = errors.New("decryption error")
	// ErrUnknownPDUHandlers is a Report of snmpUnknownPDUHandlers (RFC 3412).
	ErrUnknownPDUHandlers = errors.New("unknown pdu handlers")
	// ErrUnknownReportPDU is a Report of a counter the library does not know,
	// or of none.
	ErrUnknownReportPDU = errors.New("unknown report pdu")
	// ErrUnmatchedReply is a reply a request discards because it does not
	// answer it: of another version, naming no attempt of the request, neither
	// a Response nor a Report, or with another request ID, security level,
	// user name, engine ID or context than the request's (RFC 3412 section 7.2
	// steps 10 a and 12 b).
	ErrUnmatchedReply = errors.New("unmatched reply")
)

// ErrAnswered marks the error of a request that the agent's answer ended: an
// SNMPv3 Report that answers it, whose error also matches the category of the
// Report's counter, or a discovery answer that names no engine ID (an error that
// also matches ErrUnknownEngineID). It is not a category: the error keeps its
// own, and its text. The library marks no error of a request that ended
// without an answer: a timeout or the context's deadline, also after discarded
// replies, whose category the error then matches; the context, Close, a
// transport error, a panic, or a local failure such as a configuration error, a
// key that does not derive or a protocol FIPS 140-only mode refuses. Errors of
// the caller's own code (the errors of a Conn or context the caller gave, the
// value one panics with) pass through unchanged. Only a request's error is
// marked, not one of decoding a message (DecodeMessage, Receive).
//
// It is a variable only so that errors.Is can match it; do not assign to it.
var ErrAnswered = errors.New("the agent answered")

// categorized is an error with the text of err that unwraps to err and to
// mark: the category of an error of an incoming message (inCategory), or
// ErrAnswered (answered).
type categorized struct {
	// errs holds err and mark, so that Unwrap allocates nothing.
	errs [2]error
}

func (e *categorized) Error() string { return e.errs[0].Error() }

func (e *categorized) Unwrap() []error { return e.errs[:] }

// inCategory returns err, which unwraps to category too.
func inCategory(category, err error) error {
	return &categorized{errs: [2]error{err, category}}
}

// answered returns err, the error of a request an answer ended, which unwraps
// to ErrAnswered too.
func answered(err error) error {
	return &categorized{errs: [2]error{err, ErrAnswered}}
}
