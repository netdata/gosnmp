// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Package gosnmp is an SNMP client: it sends Get requests and walks subtrees
// with GetNext or GetBulk requests over UDP, with SNMPv1, SNMPv2c and SNMPv3
// (the User-based Security Model), and decodes received traps and informs and
// makes their answers. It writes no log or other output and never exits the
// process: its functions report through their results and errors. A call that
// fails returns no result with its error, but a walk, which also returns the
// values it collected before the error, and Receive, whose Report to a
// rejected message comes with the error (see Notifications).
//
// # Lifecycle
//
// A client is a [Client] whose exported fields configure it: a literal, or
// [NewHandler] for code that takes the [Handler] interface. [Client.Connect]
// fills in defaults ([MaxOids], a background Context), checks the SNMPv3
// configuration and opens the connection, a UDP socket connected to Target and
// Port, which replaces the client's (a failed Connect keeps it); a client may
// instead be given a Conn. The client owns its connection: [Client.Close]
// closes it, and so does a Connect that replaces it; a connection the caller or
// a hook replaces in Conn is the caller's again. Connect may be called again
// after Close. A request reads the client's configuration when it starts and
// does not change it: a change a hook makes applies from the next request.
// Exceptions: the SNMPv3 engine state the client learns during a request serves
// the rest of it (see SNMPv3), and each attempt uses the connection Conn holds
// when it starts. A request resolves no name: Connect looks up Target, and a
// request writes to the peer of the connection it uses. The request IDs and
// msgIDs start at a random value on first use unless [Client.SetRequestID] and
// [Client.SetMsgID] set them, and Connect does not reset them.
//
// # Concurrency
//
// A Client is not safe for concurrent use: its requests share the connection
// and its deadline, the receive buffer and the SNMPv3 engine state, so run one
// request at a time, or give each goroutine its own client. Close is the
// exception: any goroutine may call it at any time, also to end a running
// request: it interrupts the running attempt, whatever connection the attempt
// uses, as a done Context does. Once Close has run, a request whose attempt
// ends without a reply fails with an error wrapping [net.ErrClosed], whatever
// else ended the attempt, a done Context included, and so do later requests
// until Connect opens a connection or Conn is set. The hooks run on the
// goroutine of the request. A [Receiver] and the package's key cache are safe
// for concurrent use.
//
// # Attempts and timeouts
//
// A request makes up to Retries+1 attempts. Each sends the request with a new
// request ID (and SNMPv3 msgID) and waits up to Timeout for an answer, or until
// the Context's deadline when that comes first. An answer is a Response of
// the request's SNMP version with the request ID of one of its attempts, or an
// SNMPv3 Report (see SNMPv3 below): an answer to any earlier attempt of the
// same request answers it too. A message read that does not decode or
// authenticate, or that is no answer, is discarded, and the attempt goes on
// waiting (RFC 3412 section 7.2). The client reads one message per datagram,
// and one per read from a Conn the caller set that is not a [net.PacketConn]. A
// message takes less than 65535 octets, the msgMaxSize SNMPv3 requests
// advertise: a datagram that fills them may have been cut short, and fails the
// attempt with "response buffer too small". A timeout (a write or read error
// matching [os.ErrDeadlineExceeded]) and another write or read error (except
// [net.ErrClosed]) start the next attempt, unless the Context is done, which
// ends the request with the Context's error, or the attempt timed out at the
// Context's deadline, which ends it with [context.DeadlineExceeded] even before
// the Context reports its deadline. A Context that is done during an attempt
// ends its write or wait at once. An answer ends the request, and so do a
// connection closed under it ([net.ErrClosed]), a client closed by Close, an
// encoding error, a Context that is done before an attempt starts and a failure
// to set the deadline. When the attempts run out, the request fails with the
// last attempt's error, except that after a timeout the error's text is
// "request timeout (after N retries)", which matches the attempt's reason with
// [errors.Is] and [errors.As] (the timeout, a [net.Error]). When the request
// discarded messages, such an error, and one at the Context's deadline, also
// matches the reason, and so the category (see Errors), of the one that came
// closest to answering it (the last authentic reply naming the request, by its
// SNMPv3 msgID, else the last naming it, by that msgID or as an SNMPv1 or
// SNMPv2c Response with one of its request IDs, else the last one whose ID
// could not be read, as one of another SNMP version; messages to other
// requests do not count), and its text ends with ": last discarded reply: "
// and that reason's text. An answer's error status ([Message].ErrorStatus) is
// not an error of the request. Connect uses Timeout and the Context too, for
// its lookup of Target and its dial together.
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
// a hook, or in a method of a Conn or Context the caller gave that the request
// calls. The request returns no message and an error whose text starts with
// "request panicked: " and that wraps the panic's value when it is an error, so
// that [errors.Is] and [errors.As] reach it (a [runtime.Error] included); the
// client stays usable. Other panics are not recovered: they reach the caller,
// or end the process when they run on a goroutine of their own. That is a panic
// in a Conn's SetDeadline when Close or a done Context interrupts an attempt;
// in a Context's methods that the context package calls on goroutines of its
// own; and in Connect and Close.
//
// # SNMPv3
//
// The client's configuration holds the user ([User]: name, protocols and
// passphrases), the security level and the context name. What the client
// learns of the agent's engine is its engine state (RFC 3414 section 2.3),
// internal to it: the engine ID, the user's keys localized to it and the engine
// boots and time; requests take the engine ID as their context engine ID. Every
// request reads it; only an answer that matched a request changes it, whole,
// once the new state is valid. A request without an engine ID first discovers
// it (RFC 3414 section 4): it sends an unauthenticated, empty Get and takes the
// engine ID, boots and time of the answer, with keys derived for that engine
// ID. The answer is usually a usmStatsUnknownEngineIDs Report; a
// usmStatsUnknownUserNames Report that carries an engine ID, as some devices
// send, serves too (a Response answers discovery only with neither an engine
// ID nor a context engine ID: see below). An answer without an engine ID ends
// the request with an error that matches [ErrUnknownEngineID]: the client
// learns nothing, and the next request discovers again. Keys that do not derive
// (a protocol without a passphrase; FIPS 140-only mode refuses MD5 and SHA-1)
// end the request with the derivation's error, before any discovery.
//
// The engine boots and time are a clock: the latest values received and when,
// advancing with the local clock (RFC 3414 section 2.3); each attempt of a
// request carries its current values, wrapping into the next boots past
// 2147483647. Every request the client sends is a read request (Get, GetNext,
// GetBulk), which a copy replayed on path could only repeat, so any clock signs
// it: one from an authenticated answer, discovery or an unauthenticated answer
// (net-snmp signs with unauthenticated time too). A request without
// authentication carries the clock's values (as net-snmp; RFC 3414 section 3.1
// step 6 c sends zeros).
//
// A request takes the configuration into the engine state at its start: another
// User, also one a hook set during the last request, keeps the engine ID and
// clock and derives its keys for the engine ID. [Client.ForgetEngine] makes the
// next request start over and discover the engine again; a request that is
// running keeps the state it has.
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
// net-snmp). A Response answers
// only with the request ID of the attempt whose msgID it carries and the
// request's security level (its authentication and privacy flags), user name,
// engine ID, context engine ID and context name (RFC 3412 section 7.2 step 12
// b; one that differs leaves the request outstanding, as in net-snmp). A reply
// that fails is discarded like one that does not decode; the error of a request
// that then times out or ends at the Context's deadline also matches the
// step's, [ErrNotInTimeWindow] for the time window, and [ErrUnmatchedReply]
// for a reply that does not answer (see Attempts and timeouts).
//
// The client takes the engine ID of each answer whose digest it checked and of
// each Response, which name the request's (security processing, the rule
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
// engine ID changed ends with an error that matches [ErrUnknownEngineID]. Any
// other Report, or a second resynchronizing one, ends the discovery or the
// request with an error that matches its counter's, [ErrUnknownUsername] or
// [ErrWrongDigest] for example, or [ErrUnknownReportPDU] for a counter the
// library does not know or none, and a usmStatsUnknownEngineIDs Report without
// an engine ID with an error that matches [ErrUnknownEngineID]; each such error
// also matches [ErrAnswered].
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
// So the client never leaves an engine ID by itself: after a request that fails
// with [ErrUnknownEngineID], an application calls [Client.ForgetEngine], which
// recovers both a replaced device and an engine ID a forged discovery answer
// gave the client (the agent answers the authenticated request with a
// usmStatsUnknownEngineIDs Report).
//
// # Walks
//
// [Client.WalkAll] and [Client.BulkWalkAll] return the values of a subtree, in
// order. Their docs say how a walk starts and ends.
//
// # Values
//
// A varbind ([VarBind]) holds a [Value]: its type and one Go type per type,
// the same on every platform, read through the type's accessor (each returns
// false for a value of another type):
//
//   - Integer: int32 ([Value.Int32])
//   - Counter32, Gauge32, TimeTicks, Uinteger32: uint32 ([Value.Uint32])
//   - Counter64: uint64 ([Value.Uint64])
//   - OctetString, Opaque: []byte, empty included ([Value.Bytes])
//   - ObjectIdentifier: a dotted string, with a leading dot when decoded
//     ([Value.OID])
//   - IPAddress: a netip.Addr ([Value.IP]): an IPv4 address, or what some
//     devices send instead: the zero Addr for an empty one, an IPv6 address
//     for 16 octets (an IPv4-mapped one reads as the IPv4 address)
//   - OpaqueFloat: float32 ([Value.Float32]); OpaqueDouble: float64
//     ([Value.Float64]); net-snmp's floats, wrapped in an Opaque
//   - Null, NoSuchObject, NoSuchInstance, EndOfMibView: no value
//   - UnknownType, the zero Value: no value; the decoder gives it for a type
//     it does not decode (ASN.1's BOOLEAN or BIT STRING: SMIv2 sends BITS as an
//     OctetString) and for a Uinteger32, Counter32, Gauge32, TimeTicks or
//     Counter64 that is empty or too long
//
// [Value.Int64] and [Value.Uint64] read every integer type that fits them,
// [Value.Float64] both floats. A Value is built by its type's constructor
// ([IntegerValue], [Counter32Value], and so on), so it holds its Go type; the
// encoder refuses UnknownType, an IPAddress that is not 4 or 16 octets (the
// zero Addr) and an ObjectIdentifier that does not encode.
// [Value.String] prints a value as fmt's %v printed it before values were
// typed: numbers in decimal, octets as a byte list ("[1 2]"), an
// ObjectIdentifier dotted, an address as text, and "<nil>" for an empty
// IpAddress and the types without a value.
//
// The encoder also checks the message's fields: SNMPv1, SNMPv2c or SNMPv3; a
// PDU type the package knows; max-repetitions up to 2147483647; an SNMPv1
// trap's agent address an IPv4 address (an IPv4-mapped one included); for
// SNMPv3, a msgID up to 2147483647, a MsgMaxSize of 0 or 484..2147483647, one
// of the three security levels, engine boots and time up to 2147483647 and a
// user name of at most 32 octets (RFC 3412 section 6, RFC 3414 section 2.4).
// It writes the request ID as the Integer32 whose two's complement RequestID
// holds, the security model of an SNMPv3 message as the User-based Security
// Model's (3), and its reportable flag by its PDU type (RFC 3412 section 6.4):
// set for requests and informs, clear for responses, reports and traps.
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
// 0..2147483647 and a user name of at most 32 octets; a decoded message keeps
// the security level of msgFlags, not its reportableFlag or reserved bits. A
// length needs its length octet, takes at most eight long-form ones, and must
// fit what remains; bytes after the message, the PDU, the varbind list or a
// varbind's value fail it. As net-snmp does, the decoder reads the SNMPv3
// header and a plaintext scoped PDU against the rest of the message (a
// msgGlobalData declared shorter than its fields, security parameters declared
// to cover the scoped PDU, and a scoped PDU declared shorter than its content,
// are read), and decrypts the content an encrypted scoped PDU declares,
// ignoring octets after it.
//
// It accepts some malformed values, because devices send them: an OctetString
// may declare one octet more than its varbind holds (seen from MikroTik
// devices), an IPAddress value may be empty or of 16 octets, an SNMPv1 agent
// address an empty IpAddress, a varbind name an OCTET STRING or an IpAddress,
// kept as text, and an unsigned value that is empty or too long decodes as
// UnknownType, with no value, instead of failing its message. Other
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
// The decoders never write their input. [Client.DecodeMessage] and
// [Receiver.Receive] return OctetString, Opaque and IPAddress values that
// alias the input, or, in an encrypted message, the buffer the scoped PDU is
// decrypted into: copy the octets ([Value.Bytes]) and read the addresses
// ([Value.IP]) before reusing the input. A decoded message's SecurityParameters
// and ContextEngineID are copies. The answers to requests are copied from the
// receive buffer, so their values stay valid.
//
// # Keys
//
// An SNMPv3 key fits its protocol: an authentication key is the size of the
// protocol's hash (RFC 3414, RFC 7860), a privacy key the cipher's key (AES's,
// or DES's 16 octets of key and pre-IV); the salt of an encrypted message is 8
// octets. Signing, verifying, encrypting and decrypting refuse anything else,
// and AES-CFB in FIPS 140-only mode, with an error. A [User] holds
// passphrases, not keys: the keys derive from non-empty passphrases of any
// length (RFC 3414 section 11.2 asks for at least 8 octets), localized to the
// engine ID at hand (RFC 3414 section 2.6). A client derives them when its
// engine state takes an engine ID (discovery, an answer it takes, a Report lent
// to a resend) or another User; decoding a reply derives none.
// [Client.DecodeMessage] derives them for the engine ID a message names, the
// authentication key when the message asks for authentication, the privacy key
// only to decrypt it. A [Receiver] derives its users' keys for their engine IDs
// when it is made (and a LearnUser's once, to check they derive), and a user it
// learns the authentication key for the
// message's engine ID to check the digest, the privacy key only once the
// digest checked, and every learned user's keys once it registers them.
// [Message.Encode] derives them for the message's engine ID. No
// message carries keys or passphrases. Deriving a key starts with hashing a
// megabyte of the passphrase (RFC 3414 appendix A.2.1). The package caches that
// result for every client and receiver, by passphrase and hash, for the life of
// the process; it holds the passphrases in memory meanwhile. The Reeder key
// extension (AES192C, AES256C) hashes the localized key the same way, so it
// adds a result per user and engine ID, and DecodeMessage, which decrypts
// without checking the digest, one per engine ID its messages name; a
// receiver's, one per user it has, learns or may learn, and one per engine ID
// an authentic message of a LearnUser names when the receiver does not learn
// it (an unreportable inform or request, a message that does not decrypt or
// whose PDU does not parse; one outside the time window is not decrypted).
//
// # Notifications
//
// A [Receiver] decodes received traps and informs and makes the answers the
// RFCs give them: built once from its users and its own engine
// ([NewReceiver]), it is safe for concurrent use, and [Receiver.Receive] takes
// each datagram the caller read and returns the notification, or an error, and
// the datagram to send back to its sender, if any. The library does not listen
// for notifications or send answers. [ReadEnvelope] reads a datagram's header,
// unauthenticated, for a caller's checks before it receives one, or to
// describe one it rejected.
//
// A receiver holds the SNMPv3 users of each engine ID, as the usmUserTable of
// RFC 3414 does: a message is decoded with the users registered for its user
// name and engine ID only, in the order they were added, so a user's keys are
// never localized to another engine ID than its own. An agent's traps name its
// own engine ID; an inform names its receiver's, so the users that send informs
// are registered for the receiver's engine ID. A receiver may also learn the
// users of a new engine (RFC 3414 section 3.2 step 3): the LearnUsers of a
// message's user name decode an unreportable message whose name and engine ID
// it has no user for, and the first message one of them accepts, at the user's
// own level, registers them all for its engine ID, up to MaxLearned names; an
// inform is never learned, nor the receiver's own engine. Receive gives the
// security processing and the minimum level a receiver requires.
//
// A receiver is the authoritative engine (RFC 3414 section 1.5.1) of the
// messages that name its own engine ID (ReceiverConfig.EngineID): informs. The
// caller keeps the engine ID and the engine boots across restarts and raises
// the boots at each; the receiver counts its engine time from its
// construction. Such a message is decoded with the users registered for the
// local engine ID, and an authenticated one must be in the local engine's time
// window (RFC 3414 section 3.2 step 7 a), or it is rejected with
// [ErrNotInTimeWindow]: its boots must be the local boots, which must not be
// 2147483647, and its time within 150 seconds of the local engine time; a
// trap naming the local engine ID too. A request or an inform naming another
// engine ID is rejected with [ErrUnknownEngineID] once decoded (RFC 3412
// section 7.2 step 13 a); a reportable message naming an engine ID the
// receiver has no user for (a discovery request names none) is rejected with
// it before any key is used.
//
// The answers. An accepted inform, SNMPv2c or SNMPv3, gets its Response (RFC
// 3416 section 4.2.7): its request ID and varbinds; for SNMPv3 from the local
// engine (its engine ID, boots and time), by the user that accepted the inform,
// at its level, with its msgID and context; with tooBig instead of the
// varbinds when it would exceed the inform's msgMaxSize. A rejected SNMPv3
// message whose reportableFlag is set gets a Report (RFC 3412 section 7.1 step
// 3) for two errors: an unknown engine ID (step 3, usmStatsUnknownEngineIDs,
// unauthenticated), which answers discovery and gives a sender that holds
// another engine ID the local one; and the local engine's time window (step 7
// a, usmStatsNotInTimeWindows, at authNoPriv, signed by the user whose digest
// checked), which gives a sender with stale boots, or one synchronizing with
// boots and time zero (RFC 3414 section 4), the local engine's. A Report comes
// from the local engine with the message's msgID and user name, the request ID
// of a plaintext PDU (0 for an encrypted one) and the receiver's count of the
// error. A message is answered only when its msgData is what its flags say: a
// plaintext scoped PDU whose PDU decodes and is of the Confirmed Class, or an
// encrypted one, an OCTET STRING. Unlike RFC 3412 section 7.2 step 6 a and
// net-snmp, a receiver reports no unknown user name, unsupported security
// level, wrong digest or decryption error: such Reports would tell any sender
// which user names the receiver has and at which levels, and none lets a
// sender recover by itself. Without a local engine, a receiver takes no SNMPv3
// inform and sends no Report. A Report answers a datagram whose source anyone
// can forge, so the caller decides whether to send it, and how often.
//
// An authenticated SNMPv3 message naming another engine ID, an agent's trap,
// whatever its PDU and reportable flag, must be in the time window of its
// engine (RFC 3414 section 3.2 step 7 b), or it is rejected with
// [ErrNotInTimeWindow]. For each engine and authentication credential that
// authenticated a message, a receiver keeps the latest engine boots and time
// received and when: a message newer than the latest updates them and is
// accepted; one with lower boots, an older one more than 150 seconds behind
// the latest advanced by the time since, and any of an engine whose boots
// reached 2147483647 are rejected, so an exact copy of a trap is rejected after
// 150 seconds. Like snmptrapd, a receiver then loses the traps of a device
// whose engine time does not advance in real time, whose boots do not increase
// when it restarts, or that shares its engine ID with another, for as long as
// the receiver lives; a new receiver starts with no records, and accepts a copy
// of each engine's latest trap once more. A trap of a user the receiver is
// learning is decided on the record of its engine and credential when another
// user's traps made one; without one, it makes none unless the user is
// learned, so a trap at the maximum boots is rejected and leaves none, and the
// next authentic trap is a first contact. Step 7 comes before decryption, as
// the RFC orders it: a message outside its window is rejected without being
// decrypted. Unauthenticated messages are neither checked nor recorded, and the
// local engine keeps no record. The records are at most one per user and
// engine ID, since only a receiver's users authenticate a message, each for its
// own engine ID.
//
// # Errors
//
// Every error of an incoming message unwraps ([errors.Is]) to exactly one
// category, an exported error named after the counter RFC 3412, RFC 3414 or
// RFC 3418 counts the message in, as net-snmp v5.9.4 counts it, with a text of
// its own: an error of DecodeMessage, of Receive, of ReadEnvelope, and the reason a
// request discards a reply for. The categories:
//
//   - [ErrASNParse] (snmpInASNParseErrs): the message does not parse, of any
//     version: its encoding, a header field of another type or outside its
//     range, the USM parameters (RFC 3414 section 3.2 step 1; net-snmp counts
//     msgPrivacyParameters that do not parse in usmStatsDecryptionErrors), a
//     scoped PDU of the other type than the privFlag asks for or one that does
//     not parse in plaintext, the PDU, an unknown PDU type and a varbind (RFC
//     3412 section 7.2 steps 2 and 7);
//   - [ErrBadVersion] (snmpInBadVersions): a version other than SNMPv1, SNMPv2c
//     and SNMPv3 (RFC 3412 section 4.2.1; net-snmp counts a negative one in
//     snmpInASNParseErrs too);
//   - [ErrUnknownSecurityModels]: another security model (step 4);
//   - [ErrInvalidMsgs]: privacy without authentication (step 5 d);
//   - [ErrUnknownEngineID] through [ErrDecryption]: the security processing
//     (RFC 3414 section 3.2 steps 3 to 8), [ErrUnknownEngineID] for a request
//     or an inform a receiver decodes for another engine too (RFC 3412 section
//     7.2 step 13 a, which counts it nowhere), [ErrUnknownSecurityLevel] for a
//     receiver's minimum level, and [ErrDecryption] for a decrypted
//     plaintext that is not a SEQUENCE of a contextEngineID and a contextName,
//     as a wrong privacy key yields (net-snmp counts it in snmpInASNParseErrs;
//     a PDU that does not parse after them is [ErrASNParse]);
//   - [ErrUnmatchedReply]: a reply that does not answer the request: of another
//     version, naming none of its attempts, neither a Response nor a Report,
//     or with another request ID, security level, user name, engine ID or
//     context (RFC 3412 section 7.2 steps 10 a and 12 b).
//
// A request answered by an SNMPv3 Report fails with an error that matches the
// Report's counter, the same errors ([ErrUnknownPDUHandlers] too), or
// [ErrUnknownReportPDU] for a counter the library does not know. A request
// that times out or ends at the Context's deadline after discarded replies
// fails with an error that also matches the category of the one that came
// closest to answering it (see Attempts and timeouts). So a category says why
// a message was rejected, by the agent or by the library, not who rejected
// it. A local failure, such as a configuration error, a key that does not
// derive or fit its protocol, or a protocol FIPS 140-only mode refuses,
// matches none of them, nor does a transport error or a timeout without a
// discarded reply.
//
// [ErrAnswered] says whether the agent's answer ended a request: the error of
// a request (a walk's included) that a Report or a discovery answer without an
// engine ID ended also matches it, besides the answer's category, while the
// library marks no error of a request that ended without an answer, a timeout
// after discarded replies included; errors of the caller's own code (a hook's
// panic, a Conn or Context it gave) pass through unchanged. A failed request
// returns no message, so this is how a caller tells an agent that answered from
// one that did not.
//
// The categories are variables only so that errors.Is can match them; do not
// assign to them. The library makes some of its errors with their values when
// the package is initialized and others when the error occurs, so after an
// assignment its errors match the old value or the new one.
package gosnmp
