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
// Context), checks the SNMPv3 configuration and opens the connection, which
// replaces the client's (a failed Connect keeps it); a client may instead be
// given a Conn. The client owns its connection: [GoSNMP.Close] closes it, and
// so does a Connect that replaces it; a connection the caller or a hook
// replaces in Conn is the caller's again. Connect may be called again after
// Close.
// A request reads the client's configuration when it starts and does not
// change it: a change a hook or the Logger makes applies from the next
// request. Exceptions: the Logger itself is used as it is set, the SNMPv3
// engine state the client learns (in SecurityParameters and ContextEngineID)
// is the running request's too, and each attempt uses the connection Conn
// holds when it starts. A TCP connection whose write or read fails otherwise
// than by the attempt's deadline or a close ([net.ErrClosed]), as when the
// agent closed or reset it, is lost while Conn holds it: the next attempt, of
// the same request or a later one, opens it again before writing, within the
// request's Timeout and Context, with the settings it was opened with (a Conn
// the caller set: with the request's Transport, Target, Port, LocalAddr and
// Control), and replaces it; a failed reopen keeps it, still lost, for the
// attempt after. A request over an unconnected UDP socket, also one the caller
// set, writes to the agent's address the last successful Connect in
// unconnected mode resolved, which Close keeps and a Connect in connected mode
// clears: a request resolves no name. The request IDs and msgIDs start at a
// random value on first use unless [GoSNMP.SetRequestID] and
// [GoSNMP.SetMsgID] set them, and Connect does not reset them.
//
// # Concurrency
//
// A GoSNMP is not safe for concurrent use: its requests share the connection
// and its deadline, the receive buffer and the SNMPv3 engine state, so run one
// request at a time, or give each goroutine its own client. Close is the
// exception: any goroutine may call it at any time, also to end a running
// request: it interrupts the running attempt, whatever connection the attempt
// uses, as a done Context does. Once Close has run, a request whose attempt
// ends without a reply fails with an error wrapping [net.ErrClosed], whatever
// else ended the attempt, a done Context included, and so do later requests
// until Connect opens a connection or Conn is set. Close does not cut the dial
// of a TCP reopen short; the dial's timeout and the Context bound it. The
// hooks run on the goroutine of the request. A
// [SnmpV3SecurityParametersTable] and the key cache of [PasswordCaching] are
// safe for concurrent use.
//
// # Attempts and timeouts
//
// A request makes up to Retries+1 attempts. Each sends the request with a new
// request ID (and SNMPv3 msgID) and waits up to Timeout for an answer, or
// until the Context's deadline when that comes first; ExponentialTimeout
// doubles the timeout before each retry. An answer to any earlier attempt of
// the same request answers it too. A timeout (a write or read error matching
// [os.ErrDeadlineExceeded]), another write or read error (except
// [net.ErrClosed]), a reply that does not decode or authenticate, and a TCP
// connection the agent closed ([io.EOF]) start the next attempt, unless the
// Context is done, which ends the request with the Context's error, or the
// attempt timed out at the Context's deadline, which ends it with
// [context.DeadlineExceeded] even before the Context reports its deadline. A
// Context that is done during an attempt ends its write or wait at once. An
// answer ends the request, and so do a connection closed under it
// ([net.ErrClosed]), a client closed by Close, an encoding error, a Context
// that is done before an attempt starts, a failure to set the deadline and a
// failed TCP reopen (a done Context fails it with an error that matches the
// Context's).
// When the attempts run out, the request fails with the last attempt's error,
// except that after a timeout the error's text is "request timeout (after N
// retries)" and after the agent closed the TCP connection "max retries (N)
// exceeded"; both unwrap to the attempt's reason (the timeout, a [net.Error];
// [io.EOF]). An answer's error status ([SnmpPacket].Error) is not an error of
// the request. Connect uses Timeout and the Context too, for its name lookups
// and its dial together. Known bugs: a Response without varbinds or error
// status, or with request ID 0, answers a request whatever its request ID.
//
// # Hooks
//
// In each attempt, PreSend runs after the request is encoded, OnSent after it
// is written, and OnRecv after each reply is read, before it is decoded.
// OnRetry runs before each retry, after the decision to make one, and
// OnFinish when an exchange ends without an error. An SNMPv3 request can
// make up to three exchanges, each with its own hooks: the engine discovery,
// the request, and one resend (see below). A request calls the hooks set when
// it starts.
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
// context engine ID; the engine time is not advanced locally, so an
// authenticated request after 150 s of silence is first answered with
// usmStatsNotInTimeWindows, and resent when the rules above allow it.
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
// version of such a type reads as SNMPv1, the declared length of a plaintext
// scoped PDU is not enforced, an OctetString may declare one octet more than
// its varbind holds (seen from MikroTik devices), an IPAddress may be empty,
// and a varbind name may be an OCTET STRING or an IpAddress, kept as text.
// INTEGER values decode into the platform's int, so 32-bit platforms reject
// what 64-bit ones accept. The SNMPv3 header takes net-snmp's extents and two
// of its field rules: msgFlags must be an OCTET STRING of one octet, the
// security model the User-based Security Model's, and every declared length
// must fit what remains (a msgGlobalData declared shorter than its fields, or
// security parameters declared to cover the scoped PDU, are read).
//
// The decoders never write their input. [GoSNMP.SnmpDecodePacket] and
// [GoSNMP.UnmarshalTrap] return OctetString and Opaque values that alias the
// input, or, in an encrypted message, the buffer the scoped PDU is decrypted
// into: copy them to reuse the input. The answers to requests are copied from
// the receive buffer, so their values stay valid.
//
// # Keys
//
// An SNMPv3 key fits its protocol: an authentication key is the size of the
// protocol's hash (RFC 3414, RFC 7860), a privacy key the cipher's key (AES's,
// or DES's 16 octets of key and pre-IV); the salt of an encrypted message is 8
// octets. Signing, verifying, encrypting and decrypting refuse anything else,
// and AES-CFB in FIPS 140-only mode, with an error. Keys derive from non-empty
// passphrases of any length (RFC 3414 section 11.2 asks for at least 8 octets);
// a key given without a passphrase serves only the engine ID it was localized
// to: parameters holding one decode no trap, inform or SnmpDecodePacket message
// naming another engine ID, whatever its security level, and take none from
// discovery. Decoding derives keys for another engine ID a message names only
// on those paths, the authentication key when the message asks for
// authentication or the receiver checks it, the privacy key only to decrypt;
// decoding a reply derives none, while discovery and, without authentication, a
// stored answer or a lent Report localize the client's keys to the engine ID it
// names. Deriving a key starts with hashing a megabyte of the passphrase (RFC
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
