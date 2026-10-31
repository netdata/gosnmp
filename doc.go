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
// ([net.ErrClosed]), as when the agent closed or reset it, or whose stream
// cannot be read on (see Attempts and timeouts), is lost while Conn holds it:
// the next attempt, of the same request or a later one, opens it again before
// writing, within the request's Timeout and Context, with the settings it was
// opened with (a Conn the caller set: with the request's Transport, Target,
// Port, LocalAddr and Control), and replaces it; a failed reopen keeps it,
// still lost, for the attempt after. A request over an unconnected UDP socket,
// also one the caller set, writes to the agent's address the last successful
// Connect in unconnected mode resolved, which Close keeps and a Connect in
// connected mode clears: a request resolves no name. The request IDs and msgIDs
// start at a random value on first use unless [GoSNMP.SetRequestID] and
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
// doubles the timeout before each retry. An answer is a GetResponse of the
// request's SNMP version with the request ID of one of its attempts, or an
// SNMPv3 Report (see SNMPv3 below): an answer to any earlier attempt of the
// same request answers it too. A message read that does not decode or
// authenticate, or that is no answer, is discarded, and the attempt goes on
// waiting (RFC 3412 section 7.2). The client reads one message per datagram;
// over TCP it reads the stream one message at a time, by each message's BER
// length (RFC 3430 section 2.1): the octets after a message, and a message a
// timeout cuts short, stay for the next read, in the same request or a later
// one, while the client reads that connection. A message takes at most 65535
// octets, the msgMaxSize SNMPv3 requests advertise: a longer one, and a
// datagram that fills them and may have been cut short, fail the attempt with
// "response buffer too small". Over TCP, such a message and octets that cannot
// start a message (not a SEQUENCE, or a length the decoder refuses) leave the
// stream unreadable: the attempt fails and the connection is lost, its rest
// unread. A timeout (a write or read error matching [os.ErrDeadlineExceeded]),
// another write or read error (except [net.ErrClosed]) and a TCP connection the
// agent closed ([io.EOF]) start the next attempt, unless the Context is done,
// which ends the request with the Context's error, or the attempt timed out at
// the Context's deadline, which ends it with [context.DeadlineExceeded] even
// before the Context reports its deadline. A Context that is done during an
// attempt ends its write or wait at once. An answer ends the request, and so do
// a connection closed under it ([net.ErrClosed]), a client closed by Close, an
// encoding error, a Context that is done before an attempt starts, a failure to
// set the deadline and a failed TCP reopen (a done Context fails it with an
// error that matches the Context's).
// When the attempts run out, the request fails with the last attempt's error,
// except that after a timeout the error's text is "request timeout (after N
// retries)" and after the agent closed the TCP connection "max retries (N)
// exceeded"; both match the attempt's reason with [errors.Is] and [errors.As]
// (the timeout, a [net.Error]; [io.EOF]). When the request discarded
// messages, such an error, and one at the Context's deadline, also matches the
// reason of the one that came closest to answering it (the last authentic reply
// naming the request, by its SNMPv3 msgID, else the last naming it, by that
// msgID or as an SNMPv1 or SNMPv2c GetResponse with one of its request IDs,
// else the last one whose ID could not be read, as one of another SNMP
// version; messages to other requests do not count), and its text ends with
// ": last discarded reply: " and that reason's text. An answer's error status
// ([SnmpPacket].Error) is not an error of the request. Connect uses Timeout
// and the Context too, for its name lookups and its dial together.
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
// A panic in the code a request runs on its own goroutine ends the request: in
// a hook, in the Logger, or in a method of a Conn or Context the caller gave
// that the request calls. The request returns no packet and an error whose
// text starts with "request panicked: " and that wraps the panic's value when
// it is an error, so that [errors.Is] and [errors.As] reach it (a
// [runtime.Error] included); the client stays usable. Other panics are not
// recovered: they reach the caller, or end the process when they run on a
// goroutine of their own. That is a panic in a [WalkFunc], or in the Logger
// when a walk logs between its requests; in Control when a dial runs it on
// goroutines of its own, racing the IPv4 and IPv6 addresses of a name; in a
// Conn's SetDeadline when Close or a done Context interrupts an attempt; in a
// Context's methods that the context package calls; and in Connect and Close.
//
// # SNMPv3
//
// The client keeps what it knows of the agent's engine, its engine state (RFC
// 3414 section 2.3): the engine ID, the user's keys localized to it, the engine
// boots and time, and the context engine ID of requests. Every request reads
// it; only an answer that matched a request changes it, whole, once the new
// state is valid. A request without an engine ID first discovers it (RFC 3414
// section 4): it sends an unauthenticated, empty Get and takes the engine ID,
// boots and time of the answer, with keys derived for that engine ID. The
// answer is usually a usmStatsUnknownEngineIDs Report; a
// usmStatsUnknownUserNames Report that carries an engine ID, as some devices
// send, serves too (a GetResponse answers discovery only with neither an engine
// ID nor a context engine ID: see below). An answer without an engine ID ends
// the request with an error that matches [ErrUnknownEngineID]: the client
// learns nothing, and the next request discovers again. Keys that do not derive
// (FIPS 140-only mode refuses MD5 and SHA-1) end the request with the
// derivation's error, before any discovery. A client given the engine ID
// derives its keys instead.
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
// A reply whose msgID names none of the request's attempts is discarded before
// security processing. A reply then goes through the security processing of RFC
// 3414 section 3.2 by its own flags: it names the request's user, or the empty
// user of discovery, which has no protocols; its user has the protocols the
// reply asks for; a reply that asks for authentication names the request's
// engine ID and carries a digest that checks with the request's key, whatever
// the request's level, and is in the time window of the clock (section 3.2 step
// 7 b, below); a reply is decrypted exactly when it asks for privacy. A Report
// then answers whatever its request ID, level and context, by the counter its
// first varbind names, with one instance sub-identifier of any value (as
// net-snmp). A GetResponse answers
// only with the request ID of the attempt whose msgID it carries and the
// request's security level (its authentication and privacy flags), user name,
// engine ID, context engine ID and context name (RFC 3412 section 7.2 step 12
// b; one that differs leaves the request outstanding, as in net-snmp). A reply
// that fails is discarded like one that does not decode; the error of a request
// that then times out, loses its TCP connection or ends at the Context's
// deadline also matches the step's, [ErrNotInTimeWindow] for the time window
// (see Attempts and timeouts).
//
// The client takes the engine ID of each answer whose digest it checked and of
// each GetResponse, which name the request's (security processing, the rule
// above); of an unauthenticated Report only in discovery, and it lends one to a
// resend (with keys derived for it and a new clock), whose answers name it. It
// follows an agent whose engine ID changed through a usmStatsUnknownEngineIDs
// Report only (net-snmp keeps the first engine ID), and an answer whose engine
// ID gives no valid state answers without changing the state. An authenticated
// answer's boots and time update the clock when they are newer than the latest
// or equal to them (net-snmp; an answer matches a request, so it replays
// nothing), and one with lower boots, or a time more than 150 s behind the
// clock's, is outside the time window, as is every answer carrying boots
// 2147483647, whose engine must be reconfigured (RFC 3414 section 3.2 step 7 b;
// net-snmp accepts one such answer, then none); the first authenticated answer
// sets the clock. An unauthenticated answer sets the clock only while no
// authenticated one did. A Report that says the request's engine ID or time is
// out of date (usmStatsUnknownEngineIDs, usmStatsNotInTimeWindows) makes the
// client send the request once more, with the engine parameters the Report
// carries when it was authenticated; an authenticated usmStatsNotInTimeWindows
// Report sets the clock, whatever the order of its boots and time, for agents
// whose boots do not go up when they restart (a deviation from RFC 3414 section
// 3.2 step 7 b and net-snmp). An unauthenticated Report lends them to that
// resend only: to a request without authentication; to an authenticated read
// request only the boots and time of a usmStatsNotInTimeWindows Report naming
// the request's engine ID, and when the authenticated answer to that resend is
// outside the time window but has the lent boots and a time within 150 s of the
// lent time, it sets the clock: agents that restart without raising their boots
// and report usmStatsNotInTimeWindows without authentication so recover
// (net-snmp locks them out). So an authenticated request to an agent whose
// engine ID changed ends with [ErrUnknownEngineID]. Any other Report, or a
// second resynchronizing one, ends the discovery or the request with the error
// of its counter, [ErrUnknownUsername] or [ErrWrongDigest] for example, and
// [ErrUnknownReportPDU] for a counter the library does not know or none, and a
// usmStatsUnknownEngineIDs Report without an engine ID with an error that
// matches [ErrUnknownEngineID]; a request, unlike the discovery, returns the
// Report with the error.
//
// A request that discarded an authentic answer outside the time window and
// ends without an answer (its attempts ran out, the Context ended it, Close,
// or a failure; not a panic) drops the clock: the next request carries boots
// and time zero, which
// an agent that checks the time window answers with an authenticated
// usmStatsNotInTimeWindows Report carrying its own, and the next authenticated
// answer of one that does not sets the clock. So a device that does not check
// the time of requests and whose engine time went back without its boots going
// up (a restart, a stepped wall clock), or whose boots went down (a failover
// pair sharing an engine ID), costs one request that fails with
// [ErrNotInTimeWindow] (a deviation from RFC 3414 section 3.2 step 7 b and
// net-snmp, which reject it until their cached time is cleared).
//
// An application that expects a replaced device clears the engine ID to
// discover again.
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
// [ErrDecryption] and [ErrInvalidPacketLength]. A request that times out,
// loses its TCP connection or ends at the Context's deadline after discarded
// replies fails with an error that also matches the reason of the one that
// came closest to answering it (see Attempts and timeouts), so it matches
// these errors without a Report. A local failure, such as a key that does not
// fit its protocol, matches none of them.
package gosnmp
