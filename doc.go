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
// A request reads the client's configuration when it starts and does not change
// it: a change a hook or the Logger makes applies from the next request.
// Exceptions: the Logger itself is used as it is set, the SNMPv3 engine state
// the client learns during a request serves the rest of it (see SNMPv3), and
// each attempt uses the connection Conn holds when it starts. A TCP connection
// whose write or read fails otherwise than by the attempt's deadline or a close
// ([net.ErrClosed]), as when the agent closed or reset it, is lost while Conn
// holds it: the next attempt, of the same request or a later one, opens it
// again before writing, within the request's Timeout and Context, with the
// settings it was opened with (a Conn the caller set: with the request's
// Transport, Target, Port, LocalAddr and Control), and replaces it; a failed
// reopen keeps it, still lost, for the attempt after. A request over an
// unconnected UDP socket, also one the caller set, writes to the agent's
// address the last successful Connect in unconnected mode resolved, which Close
// keeps and a Connect in connected mode clears: a request resolves no name. The
// request IDs and msgIDs start at a random value on first use unless
// [GoSNMP.SetRequestID] and [GoSNMP.SetMsgID] set them, and Connect does not
// reset them.
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
// The client keeps what it knows of the agent's engine, its engine state (RFC
// 3414 section 2.3): the engine ID, the user's keys localized to it, the
// engine boots and time, and the context engine ID of requests. Every request
// reads it; only an answer that matched a request changes it, whole, once the
// new state is valid. A request without an engine ID first discovers it (RFC
// 3414 section 4): it sends an unauthenticated, empty Get and takes the engine
// ID, boots and time of the answer, with keys derived for that engine ID. The
// answer is usually a usmStatsUnknownEngineIDs Report; a
// usmStatsUnknownUserNames Report that carries an engine ID, as some devices
// send, serves too. An answer without an engine ID ends the request with an
// error that matches [ErrUnknownEngineID]: the client learns nothing, and the
// next request discovers again. Keys that do not derive (FIPS 140-only mode
// refuses MD5 and SHA-1) end the request with the derivation's error, before
// any discovery. A client given the engine ID derives its keys instead.
//
// The engine boots and time are a clock: the latest values received and when,
// advancing with the local clock (RFC 3414 section 2.3); each attempt of a
// request carries its current values, wrapping into the next boots past
// 2147483647. A clock from an authenticated answer signs every request; one
// from discovery, an unauthenticated answer or the caller signs read requests
// (Get, GetNext, GetBulk) and requests without authentication only, and an
// authenticated write then carries boots and time zero, which the agent
// answers with an authenticated usmStatsNotInTimeWindows Report carrying its
// own (RFC 3414 section 4: one more round trip; net-snmp signs writes with
// unauthenticated time too). A request without authentication carries the
// clock's values (as net-snmp; RFC 3414 section 3.1 step 6 c sends zeros).
//
// The engine state shows in the client's fields: the engine ID, boots, time and
// keys of SecurityParameters, and ContextEngineID, which requests take from the
// engine ID unless the caller sets one. The boots and time fields show the
// latest values received, not the advancing ones. The client writes a field
// only while it holds what the client last wrote or read there. A field the
// caller changed, also from a hook or the Logger during a request, is the
// caller's from the next request on: an engine ID (empty: discover again;
// another one has no clock until an answer gives one), boots and time (a clock
// received then, as an unauthenticated one; zeros: none), a key, which must be
// localized to the engine ID (empty: derive), a context engine ID (empty: the
// engine ID again). Another SecurityParameters value is the caller's whole, and
// a changed protocol or passphrase derives the keys the client derived again.
// A value the caller sets that equals the client's is the client's; a
// SecurityParameters value serves one client.
//
// A reply goes through the security processing of RFC 3414 section 3.2 by its
// own flags before it answers: it names the request's user, or the empty user
// of discovery, which has no protocols; its user has the protocols the reply
// asks for; a reply that asks for authentication names the request's engine ID
// and carries a digest that checks with the request's key, whatever the
// request's level, and is in the time window of the clock (section 3.2 step 7
// b, below); a request that asks for authentication takes no other reply but
// an unauthenticated Report; a reply is decrypted exactly when it asks for
// privacy. A reply that fails is treated as one that does not decode: the
// request is sent again, and after the retries its error matches the step's,
// [ErrNotInTimeWindow] for the time window.
//
// The client takes the engine ID of each answer whose digest it checked
// (another engine ID than its own only from a resend an unauthenticated Report
// lent it to, with keys derived for it and a new clock) and, to a request
// without authentication, of each answer but Reports: such a client follows an
// agent whose engine ID changed (net-snmp keeps the first engine ID), with keys
// derived for it, and an answer whose engine ID gives no valid state answers
// without changing the state. An authenticated answer's boots and time update
// the clock when they are newer than the latest or equal to them (net-snmp; an
// answer matches a request, so it replays nothing), and one with lower boots,
// or a time more than 150 s behind the clock's, is outside the time window, as
// is every answer carrying boots 2147483647, whose engine must be reconfigured
// (RFC 3414 section 3.2 step 7 b; net-snmp accepts one such answer, then
// none); the first authenticated answer sets the clock. An unauthenticated answer
// sets the clock only while no authenticated one did. A Report that says the
// request's engine ID or time is out of date (usmStatsUnknownEngineIDs,
// usmStatsNotInTimeWindows) makes the client send the request once more, with
// the engine parameters the Report carries when it was authenticated; an
// authenticated usmStatsNotInTimeWindows Report sets the clock, whatever the
// order of its boots and time, for agents whose boots do not go up when they
// restart (a deviation from RFC 3414 section 3.2 step 7 b and net-snmp). An
// unauthenticated Report lends them to that resend only: to a request without
// authentication; to an authenticated read request only the boots and time of
// a usmStatsNotInTimeWindows Report naming the request's engine ID, and when
// the authenticated answer to that resend is outside the time window but has
// the lent boots and a time within 150 s of the lent time, it sets the clock:
// agents that restart without raising their boots and report
// usmStatsNotInTimeWindows without authentication so recover (net-snmp locks
// them out). So an authenticated request to an agent whose engine ID changed
// ends with [ErrUnknownEngineID]. Any other Report, or a second resynchronizing
// one, ends the discovery or the request with the error of its counter,
// [ErrUnknownUsername] or [ErrWrongDigest] for example, and
// [ErrUnknownReportPDU] for a counter the library does not know, and a
// usmStatsUnknownEngineIDs Report without an engine ID with an error that
// matches [ErrUnknownEngineID]; a request, unlike the discovery, returns the
// Report with the error.
//
// An application that expects a replaced device clears the engine ID to
// discover again. Requests that keep failing with [ErrNotInTimeWindow] can
// come from a device whose authenticated answers stay outside the time window
// and that does not report it: one that does not check the time of requests and
// whose engine time went back without its boots going up (a restart, a
// stepped wall clock), or whose boots went down (a failover pair sharing an
// engine ID); net-snmp rejects them too. Setting the engine boots and time to
// zero drops the clock, and the next authenticated answer sets it.
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
//   - Integer: int, within the int32 range; Uinteger32: uint32; Counter32,
//     Gauge32: uint, below 2^32; TimeTicks: uint32; Counter64: uint64
//   - OctetString, Opaque: []byte, empty included; OpaqueFloat: float32,
//     OpaqueDouble: float64 (net-snmp's floats, wrapped in an Opaque)
//   - ObjectIdentifier: a dotted string with a leading dot
//   - IPAddress: an IPv4 or IPv6 address as a string, or nil when empty
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: nil
//   - any other type, Boolean and BitString included, and a Uinteger32,
//     Counter32, Gauge32, TimeTicks or Counter64 that is empty or too long:
//     UnknownType, nil
//
// Encoding takes an int within the int32 range for Integer; uint32, or uint up
// to 4294967295, for Counter32, Gauge32, TimeTicks and Uinteger32; uint64 for
// Counter64; []byte or string for OctetString and Opaque; a dotted string for
// ObjectIdentifier; for IPAddress, []byte of 4 or 16 octets or an address as
// text (an IPv4 address, an IPv4-mapped one included, in 4 octets, another IPv6
// address in 16); float32 and float64 for OpaqueFloat and OpaqueDouble;
// anything, ignored, for Null and the exceptions. Other types are errors,
// BitString included: SMIv2 sends BITS as an OctetString. [ToBigInt] converts
// the integer types.
//
// The encoder also checks the message's fields: SNMPv1, SNMPv2c or SNMPv3; a
// PDU type the package knows; max-repetitions up to 2147483647; an SNMPv1
// trap's agent address an IPv4 address and its timestamp up to 4294967295; for
// SNMPv3, the User-based Security Model, a msgID up to 2147483647, a
// MsgMaxSize of 0 or 484..2147483647, a security level that does not ask for
// privacy without authentication, engine boots and time up to 2147483647 and a
// user name of at most 32 octets (RFC 3412 section 6, RFC 3414 section 2.4).
// It writes the request ID as the Integer32 whose two's complement RequestID
// holds, and the reportable flag of an SNMPv3 message by its PDU type (RFC
// 3412 section 6.4): set for requests and informs, clear for responses,
// reports and traps, whatever MsgFlags holds besides the security level.
//
// # Decoding
//
// The decoder applies one rule per value type and header field, with the same
// results on every platform. An INTEGER, value or header field, has one to
// eight octets and is cut to 32 bits by two's complement (an Integer32, RFC
// 2578 section 7.1.1); Uinteger32, Counter32, Gauge32 and TimeTicks values are
// unsigned, of one to eight octets or nine with a leading zero, and keep their
// low 32 bits; an OBJECT IDENTIFIER has at most 128 arcs. A header field must
// be of its type and, once cut, within its range, or it fails the message, as
// a missing one does: the version SNMPv1, SNMPv2c or SNMPv3; the community,
// contextEngineID and contextName OCTET STRINGs; the error status 0..255; the
// error index and non-repeaters not negative, read as 255 above it (the most
// their fields hold); max-repetitions not negative; an SNMPv1 trap's
// enterprise an OBJECT IDENTIFIER, its agent address four octets, an IpAddress
// or an OCTET STRING, and its timestamp TimeTicks or another unsigned type, as
// net-snmp v5.9.4 takes it. The SNMPv3 header takes net-snmp's field rules
// (RFC 3412 section 6, RFC 3414 section 2.4): msgID 0..2147483647, msgMaxSize
// 484..2147483647, msgFlags an OCTET STRING of one octet, the User-based
// Security Model's number, flags that do not ask for privacy without
// authentication, the USM fields of their types, engine boots and time within
// 0..2147483647 and a user name of at most 32 octets. A length needs its
// length octet, takes at most eight long-form ones, and must fit what remains;
// bytes after the message, the PDU, the varbind list or a varbind's value fail
// it. As net-snmp does, the decoder reads the SNMPv3 header and a plaintext
// scoped PDU against the rest of the message (a msgGlobalData declared shorter
// than its fields, security parameters declared to cover the scoped PDU, and a
// scoped PDU declared shorter than its content, are read), and decrypts the
// content an encrypted scoped PDU declares, ignoring octets after it.
//
// It accepts some malformed values, because devices send them: an OctetString
// may declare one octet more than its varbind holds (seen from MikroTik
// devices), an IPAddress value may be empty or of 16 octets, an SNMPv1 agent
// address an empty IpAddress, a varbind name an OCTET STRING or an IpAddress,
// kept as text, and an unsigned value that is empty or too long decodes as
// UnknownType with a nil value instead of failing its message. Other
// differences from net-snmp v5.9.4:
//
//   - an empty OBJECT IDENTIFIER reads as .0.0, not .0
//   - an INTEGER outside the int32 range keeps its low 32 bits as an int32
//     (3000000000 reads -1294967296), where net-snmp keeps them unsigned
//     above it and negates them below it
//   - the community and context fields take OCTET STRINGs only, and an SNMPv1
//     agent address four octets or an empty IpAddress, where net-snmp takes
//     other string types (of up to four octets for the agent address)
//   - the error status, the error index, non-repeaters and max-repetitions
//     are checked against their ranges
//   - a length takes at most eight long-form octets, where net-snmp takes as
//     many as its long holds
//   - bytes after a TLV inside its container fail the message (see above),
//     where net-snmp ignores them
//   - BIT STRING and NsapAddress values decode as UnknownType and net-snmp's
//     Opaque-wrapped 64-bit values as raw Opaque, which net-snmp decodes, and
//     other unknown value types as UnknownType, where net-snmp fails the
//     message
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
// naming another engine ID, whatever its security level, and a client holding
// one takes no engine ID but the first one the caller gives it: discovery, or
// the caller giving it another one, ends the request with an error. A key its
// passphrase derives counts as one the client derived: other credentials derive
// it again. Decoding derives keys for another engine ID a message names only on
// those paths, the authentication key when the message asks for authentication,
// the privacy key only to decrypt it (on the trap paths, once its digest
// checked); decoding a reply derives none, while discovery and, without
// authentication, an answer the client takes or a lent Report localize the
// client's keys to the engine ID it names. The SecurityParameters of a
// request's packet and answer share the client's keys: do not write into them.
// Deriving a key starts with hashing a megabyte of the passphrase (RFC 3414
// appendix A.2.1). The package caches that result for every client, by
// passphrase and hash, until [PasswordCaching] turns the cache off; it holds
// the passphrases in memory meanwhile.
//
// # Traps
//
// [GoSNMP.UnmarshalTrap] decodes a received trap or inform: an SNMPv3 message
// with the client's SecurityParameters, or, when TrapSecurityParametersTable
// is set, with the parameter sets the table holds for the message's user name,
// tried in the order they were added. Its doc gives the security processing
// and the minimum level a receiver requires. The library does not listen for
// traps or answer informs.
//
// An authenticated SNMPv3 trap, any message whose PDU is not of the Confirmed
// Class (a request or an inform), whatever its reportable flag (RFC 3412
// section 6.4), must be in the time window of its engine (RFC 3414 section 3.2
// step 7 b), or it is rejected with [ErrNotInTimeWindow]. For
// each engine and credential that authenticated a trap, the package keeps the
// latest engine boots and time received and when, for all clients: a trap
// newer than the latest updates them and is accepted; one with lower boots, an
// older one more than 150 seconds behind the latest advanced by the time
// since, and any of an engine whose boots reached 2147483647 are rejected, so
// an exact copy of a trap is rejected after 150 seconds. Like snmptrapd, a
// receiver then loses the traps of a device whose engine time does not advance
// in real time, whose boots do not increase when it restarts, or that shares
// its engine ID with another, until the process restarts. Informs are neither
// checked nor recorded (an inform's receiver is the authoritative engine,
// whose time the library does not keep), nor are unauthenticated traps. The
// package keeps at most 65536 records, replacing the least recently updated
// one, of whatever engine and credential: a holder of one credential who sends
// traps from that many engine IDs makes the package forget another
// credential's records, whose traps it then accepts as first contacts.
//
// # Errors
//
// The errors named after the counters a Report carries ([ErrUnknownUsername],
// [ErrWrongDigest] and the others) are also the categories of the library's
// own rejections of a message: an error of decoding an SNMPv3 message, a trap
// or a reply, unwraps ([errors.Is]) to the counter of the RFC 3412 section 7.2
// or RFC 3414 section 3.2 step that rejected it, with its own text:
// [ErrUnknownSecurityModels] for another security model, [ErrInvalidMsgs] for
// privacy without authentication and, in place of snmpInASNParseErrs, which
// has no error of its own, for a header or a scoped PDU that does not parse
// before decryption, [ErrUnknownEngineID] through [ErrDecryption] for the
// security processing, [ErrUnknownSecurityLevel] for a trap receiver's minimum
// level too. A decode error also unwraps to [ErrInvalidPacketLength] when a
// length caused it, besides its category: after a wrong privacy key, a
// decrypted scoped PDU whose length runs past its plaintext matches both
// [ErrDecryption] and [ErrInvalidPacketLength]. A request whose attempts ran
// out after discarded replies fails with the last one's error, so it matches
// these errors without a Report. A local failure, such as a key that does not
// fit its protocol, matches none of them.
package gosnmp
