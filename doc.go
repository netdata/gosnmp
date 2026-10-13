// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Package gosnmp is an SNMP client: it sends Get, GetNext, GetBulk and Set
// requests and walks subtrees over SNMPv1, SNMPv2c and SNMPv3 (the User-based
// Security Model), and decodes received traps and informs.
//
// # Lifecycle
//
// A client is a [GoSNMP] whose exported fields configure it: a literal, the
// shared [Default], or [NewHandler] for code that takes the [Handler]
// interface. [GoSNMP.Connect] fills in defaults (UDP, [MaxOids], a background
// Context), checks the SNMPv3 configuration, opens the connection, seeds the
// request IDs and allocates the receive buffer; every request needs it.
// [GoSNMP.Close] closes the connection. Connect may be called again after
// Close.
//
// # Concurrency
//
// A GoSNMP is not safe for concurrent use: its requests share the connection
// and its deadline, the receive buffer and the SNMPv3 engine state, so run one
// request at a time, or give each goroutine its own client. The hooks run on
// the goroutine of the request. A [SnmpV3SecurityParametersTable] and the key
// cache of [PasswordCaching] are safe for concurrent use.
//
// # Attempts and timeouts
//
// A request makes up to Retries+1 attempts. Each sends the request with a new
// request ID (and SNMPv3 msgID) and waits up to Timeout for an answer, or
// until the Context's deadline when that comes first; ExponentialTimeout
// doubles the timeout before each retry. An answer to any earlier attempt of
// the same request answers it too. A write or read error, a timeout, a reply
// that does not decode or authenticate, and a TCP connection the agent closed
// (the client reopens it) start the next attempt. An answer ends the request,
// and so do an encoding error, a Context that is done before an attempt
// starts, a failure to set the deadline and a failed TCP reconnect. When the
// attempts run out, the request fails with the last attempt's error, except
// that a timeout gives an error whose text starts with "request timeout", and
// a reconnect one that starts with "max retries"; the Context's deadline
// ending an attempt gives [context.DeadlineExceeded]. An answer's error status
// ([SnmpPacket].Error) is not an error of the request. Connect's dial uses
// Timeout and the Context too. Known bugs: a cancellation is noticed only when
// the attempt's deadline passes, and in the last attempt it ends as a request
// timeout; a Response without varbinds or error status, or with request ID 0,
// answers a request whatever its request ID.
//
// # Hooks
//
// In each attempt, PreSend runs after the request is encoded, OnSent after it
// is written, and OnRecv after each reply is read, before it is decoded.
// OnRetry runs after an attempt that failed in a way the next attempt may
// cure, OnFinish when an exchange ends without an error. An SNMPv3 request can
// make up to three exchanges, each with its own hooks: the engine discovery,
// the request, and one resend (see below).
//
// # SNMPv3
//
// Before a request, a client that does not know the agent's engine ID
// (SecurityParameters' AuthoritativeEngineID) discovers it (RFC 3414 section
// 4): it sends an unauthenticated, empty Get, takes the engine ID, boots and
// time from the answer, derives its keys for that engine ID, and takes the
// engine ID as ContextEngineID when that is empty. The answer is usually a
// usmStatsUnknownEngineIDs Report; a usmStatsUnknownUserNames Report that
// carries an engine ID, as some devices send, serves too. A client given the
// engine ID derives its keys instead.
//
// The client stores the engine ID, boots and time of each answer whose digest
// it checked, and, when it does not authenticate, of each answer but Reports.
// A Report that says the request's engine ID or time is out of date
// (usmStatsUnknownEngineIDs, usmStatsNotInTimeWindows) makes the client send
// the request once more, with the engine parameters the Report carries when it
// was authenticated. An unauthenticated Report lends them to that resend only:
// to a request without authentication; to an authenticated read request only
// the boots and time of a usmStatsNotInTimeWindows Report naming the request's
// engine ID. So an authenticated request to an agent whose engine ID changed
// ends with [ErrUnknownEngineID]. Any other Report, or a second
// resynchronizing one, ends the discovery or the request with the error of its
// counter, [ErrUnknownUsername] or [ErrWrongDigest] for example, and
// [ErrUnknownReportPDU] for a counter the library does not know; a request,
// unlike the discovery, returns the Report with the error.
//
// Known bugs a client meets: once the agent's engine ID is known, a change of
// it fails every authenticated request with [ErrUnknownEngineID], while a
// client without authentication takes the new engine ID but keeps the old
// context engine ID; the engine time is not advanced locally, so a request
// after 150 s of silence is first answered with usmStatsNotInTimeWindows and
// resent.
//
// # Walks
//
// [GoSNMP.Walk] and [GoSNMP.BulkWalk] pass each value of a subtree to a
// function, in order; [GoSNMP.WalkAll] and [GoSNMP.BulkWalkAll] collect them.
// Their docs say how a walk starts and ends.
//
// # Values
//
// A varbind ([SnmpPDU]) holds its value as an any whose Go type depends on its
// Type. Decoding gives:
//
//   - Integer: int; Uinteger32: uint32; Counter32, Gauge32: uint; TimeTicks:
//     uint32; Counter64: uint64
//   - OctetString, Opaque: []byte; OpaqueFloat: float32, OpaqueDouble: float64
//     (net-snmp's floats, wrapped in an Opaque)
//   - ObjectIdentifier: a dotted string with a leading dot
//   - IPAddress: an IPv4 or IPv6 address as a string, or nil when empty
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: nil
//   - any other type, Boolean and BitString included, and a Counter32,
//     Gauge32, TimeTicks or Counter64 that does not decode: UnknownType, nil
//
// Encoding takes an int within the int32 range for Integer; uint32 or uint
// (cut to 32 bits) for Counter32, Gauge32, TimeTicks and Uinteger32; uint64
// for Counter64; []byte or string for OctetString, BitString and Opaque; a
// dotted string for ObjectIdentifier; []byte, or a string whose address keeps
// its last four bytes, for IPAddress; float32 and float64 for OpaqueFloat and
// OpaqueDouble; anything, ignored, for Null and the exceptions. [ToBigInt]
// converts the integer types.
//
// # Decoding
//
// The decoder accepts some malformed messages, because devices send them: a
// header field of another field type (INTEGER, OCTET STRING, OBJECT
// IDENTIFIER, IpAddress, TimeTicks) than the one expected is skipped, so a
// version of such a type reads as SNMPv1, the declared lengths of the SNMPv3
// header, security parameters and plaintext scoped PDU are not enforced, an
// OctetString may declare one octet more than its varbind holds (seen from
// MikroTik devices), an IPAddress may be empty, and a varbind name may be an
// OCTET STRING or an IpAddress, kept as text. INTEGER values decode into the
// platform's int, so 32-bit platforms reject what 64-bit ones accept.
//
// [GoSNMP.SnmpDecodePacket] and [GoSNMP.UnmarshalTrap] (unless it uses a
// table) decode in place: they zero the digest of an authenticated SNMPv3
// message in the input, and decrypt an encrypted scoped PDU over it.
// OctetString and Opaque values alias the decoded buffer. Pass a copy to keep
// the input. The answers to requests are copied from the receive buffer, so
// their values stay valid.
//
// Known bug: some malformed SNMPv3 messages make SnmpDecodePacket and
// UnmarshalTrap panic, among them a DES salt shorter than eight octets, an
// authenticated message too short for the digest it should carry, and, on the
// table path, a header that fails before its security parameters; AES panics
// in FIPS 140-only mode. Recover around them when decoding untrusted input.
//
// # Keys
//
// Deriving an SNMPv3 key starts with hashing a megabyte of the passphrase (RFC
// 3414 appendix A.2.1). The package caches that result for every client, by
// passphrase and hash, until [PasswordCaching] turns the cache off; it holds
// the passphrases in memory meanwhile.
//
// # Traps
//
// [GoSNMP.UnmarshalTrap] decodes a received trap or inform: an SNMPv3 message
// with the client's SecurityParameters, or, when TrapSecurityParametersTable
// is set, with the parameter sets the table holds for the message's user name,
// tried in the order they were added. Its doc says when the digest is checked,
// and which messages pass unchecked (known bugs). The library does not listen
// for traps or answer informs.
package gosnmp
