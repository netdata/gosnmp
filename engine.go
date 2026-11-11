// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// send runs the request packetOut (request) within ctx and returns its
// answer, or no message with the error of a request that fails, marked with
// ErrAnswered when an answer ended it (the message request returns beside its
// error), and with requestPanicked's error for one that panics. A nil ctx
// fails the request before it starts. The library prevents panics of its
// own: the recover is for the caller's code the request runs on its
// goroutine (the methods of the context it calls) and for bugs, which would
// otherwise end the process of a caller that runs requests on a goroutine
// without a recover. A flag, not recover's value, tells that the request
// panicked: under GODEBUG=panicnil=1, recover returns nil for panic(nil).
//
// packetOut is a request of the Read Class (RFC 3411 section 2.8.1), a Get,
// GetNext or GetBulk, as every request the client sends: the SNMPv3 engine
// clock signs it whatever the clock's source (sourcedClock.timeFor, mayLend),
// which a request that changes the agent must not take.
func (x *Client) send(ctx context.Context, packetOut *Message) (result *Message, err error) {
	if ctx == nil {
		return nil, errNilContext
	}
	completed := false
	defer func() {
		if !completed {
			err = requestPanicked(recover())
		}
	}()
	result, err = x.request(ctx, packetOut)
	completed = true
	if err != nil {
		if result != nil {
			err = answered(err)
		}
		return nil, err
	}
	return result, nil
}

// request runs a request within ctx: for SNMPv3 it first takes the
// configuration into the engine state and discovers the agent's engine when it
// has none, then sends the request, whose answer commits the engine parameters
// it carries, and sends the request once more when the answer is a Report that
// resynchronizes the client with the agent's engine. With an error it returns
// the answer that ended the request, a Report or the discovery's answer, and
// no message when none did: send marks the error by it.
func (x *Client) request(ctx context.Context, packetOut *Message) (result *Message, err error) {
	cfg := x.prepareRequest(ctx)
	if _, err = x.connection(); err != nil {
		return nil, err
	}
	// sec is the engine clock and the keys the attempts carry.
	var sec attemptSecurity
	if packetOut.Version == Version3 {
		// The engine state takes the configuration at the request's start.
		if err = x.startEngine(); err != nil {
			return nil, err
		}
		if result, err = x.negotiateInitialSecurityParameters(&cfg, packetOut); err != nil {
			return result, err
		}
		sec = attemptSecurity{clock: x.engine.clock, keys: x.engine.keys}
	}

	var stored bool
	result, stored, err = x.sendOneRequest(&cfg, packetOut, false, sec)
	kind := resyncKindOf(result)
	if !kind.resync {
		return result, err
	}

	// Resynchronize: send the request again, with the engine clock the
	// client committed from an authenticated Report, or with the engine
	// parameters of an unauthenticated one in the request only, when mayLend
	// allows it: the answer brings the agent's, which the client commits. A
	// committed Report named the request's engine ID (receiveReply), so the
	// engine ID and keys stay. A Report that cannot resynchronize the request
	// ends it with its error, and so does a resync Report answering the
	// retransmission.
	if stored {
		sec.clock = x.engine.clock
	} else if !mayLend(packetOut, result, kind) {
		return result, kind.err
	} else if sec, err = x.lendEngineParameters(packetOut, result, kind, sec); err != nil {
		return result, err
	}
	result, _, err = x.sendOneRequest(&cfg, packetOut, false, sec)
	if kind = resyncKindOf(result); kind.resync {
		return result, kind.err
	}
	return result, err
}

// requestPanicked returns the error of a request that panicked with v (nil
// for panic(nil) under GODEBUG=panicnil=1): its text names v, and it wraps v
// when v is an error, a runtime.Error included.
func requestPanicked(v any) error {
	if err, ok := v.(error); ok {
		return fmt.Errorf("request panicked: %w", err)
	}
	return fmt.Errorf("request panicked: %v", v)
}

// resyncKindOf returns the kind of result, an answer, when it is a Report;
// its resync field marks one that resynchronizes the client with the agent's
// engine.
func resyncKindOf(result *Message) reportKind {
	if result == nil {
		return reportKind{}
	}
	kind, _ := reportKindOf(result)
	return kind
}

// requestConfig is the client's configuration as a request reads it, once, at
// its start, with the request's context: a change the caller makes to the
// client during the request applies from the next one. The packet carries the
// rest (version, security level, user name, context name), and the SNMPv3
// engine state takes the user at the same time (startEngine). Not part of it:
// the connection, which each attempt takes from the client (connection).
type requestConfig struct {
	ctx     context.Context
	timeout time.Duration
	retries int
}

// prepareRequest reads the request configuration, with ctx and no negative
// retries, and allocates the receive buffer at the client's first request.
func (x *Client) prepareRequest(ctx context.Context) requestConfig {
	if x.rx == nil {
		x.rx = new(receiveBuffer)
	}
	return requestConfig{
		ctx:     ctx,
		timeout: x.Timeout,
		retries: max(x.Retries, 0),
	}
}

// exchange is one request on its way through the attempts sendOneRequest
// makes.
type exchange struct {
	x      *Client
	packet *Message
	// cfg is a copy of the request's configuration: escape analysis is
	// field-insensitive, so a pointer beside packet would move the request's
	// configuration to the heap.
	cfg requestConfig

	// contextDeadline is set when the context's deadline ends the current
	// attempt, at or before its timeout: endErr then reports
	// context.DeadlineExceeded whether or not the context reports its
	// deadline yet.
	contextDeadline bool
	// discovery marks the engine discovery's exchange, whose answer gives the
	// engine state its engine ID (settle).
	discovery bool
	// sec is the engine clock and the keys the attempts of an SNMPv3 request
	// carry (encode) and check answers with (decode).
	sec attemptSecurity

	// discarded is the reason of the discarded message that came closest to
	// answering the request, of rank discardedRank (discard).
	discarded     error
	discardedRank discardRank
	// outOfWindow marks an exchange that discarded an authentic answer
	// outside the time window (settle).
	outOfWindow bool
}

// discardRank orders the messages an exchange discards by how close they came
// to answering it, by the ID that names its attempts: the msgID of an SNMPv3
// request, the request ID of another. Zero is a message that answers another
// request, whose reason is not recorded.
type discardRank uint8

const (
	// rankUnread: a message whose ID could not be read.
	rankUnread discardRank = iota + 1
	// rankNamed: a message with the ID of one of the exchange's attempts that
	// did not authenticate.
	rankNamed
	// rankAuthentic: an authentic message with the msgID of one of the
	// exchange's attempts.
	rankAuthentic
)

// attemptKind is how an attempt ended.
type attemptKind uint8

const (
	// attemptReply: a reply answered the request, with the error of a Report
	// that answers it, if any.
	attemptReply attemptKind = iota
	// attemptTimeout: the deadline passed before an answer; the write or the
	// read failed with an error matching os.ErrDeadlineExceeded.
	attemptTimeout
	// attemptTransportError: the write or the read failed otherwise.
	attemptTransportError
	// attemptClosed: the write or the read failed on a closed connection
	// (net.ErrClosed), or Close closed the client.
	attemptClosed
	// attemptContextDone: the context was done when the attempt would start.
	attemptContextDone
	// attemptFailed: the client had no connection, or setting the deadline or
	// encoding the request failed.
	attemptFailed
)

// retryable reports whether another attempt may cure an attempt that ended
// so.
func (k attemptKind) retryable() bool {
	switch k {
	case attemptTimeout, attemptTransportError:
		return true
	}
	return false
}

// attemptOutcome is how an attempt ended, and with what: the reply and its
// error, or the reason the attempt failed.
type attemptOutcome struct {
	packet *Message
	err    error
	kind   attemptKind
	// verified reports that packet's digest checked against the request
	// (exchange.decode).
	verified bool
	// committed reports that packet's engine parameters were committed into
	// the engine state (exchange.settle).
	committed bool
}

// ioFailure is the outcome of an attempt whose write or read failed with err.
func ioFailure(err error) attemptOutcome {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return attemptOutcome{kind: attemptTimeout, err: err}
	case errors.Is(err, net.ErrClosed):
		return attemptOutcome{kind: attemptClosed, err: err}
	}
	return attemptOutcome{kind: attemptTransportError, err: err}
}

// attemptsError is the error of a request whose attempts ran out after a
// timeout, or that the context's deadline ended after a discard: a text
// callers know, unwrapping to the last attempt's reason (the write's or the
// read's deadline error, a timeout net.Error; context.DeadlineExceeded) and to
// the reason of the discard the exchange recorded, if any, whose text it ends
// with.
type attemptsError struct {
	text string
	// errs holds the reason and the recorded discard, or nil.
	errs [2]error
}

func (e *attemptsError) Error() string { return e.text }

func (e *attemptsError) Unwrap() []error {
	if e.errs[1] == nil {
		return e.errs[:1]
	}
	return e.errs[:]
}

// attemptSecurity is what the attempts of an SNMPv3 request sign, encrypt and
// check answers with: the engine clock their boots and time come from and the
// user's keys localized to the request's engine ID, the engine state's, or a
// resend's that a Report lent them; none for the discovery.
type attemptSecurity struct {
	clock sourcedClock
	keys  usmKeys
}

// sentIDs are the request ID and the msgID an attempt sent the request with.
type sentIDs struct {
	requestID, msgID uint32
}

// sendOneRequest sends packetOut, the engine discovery's request when
// discovery is set, an SNMPv3 one with the engine boots and time of sec's clock
// and its keys, and returns the reply that answers it, and whether the reply's
// engine parameters were committed into the engine state, retrying up to
// cfg.retries times. Once Close closed the client, an attempt that ends
// without a reply ends the request with net.ErrClosed, whatever else ended it.
// An exchange that ends without an answer goes through unanswered.
func (x *Client) sendOneRequest(cfg *requestConfig, packetOut *Message, discovery bool, sec attemptSecurity) (*Message, bool, error) {
	e := exchange{x: x, packet: packetOut, cfg: *cfg, discovery: discovery, sec: sec}
	// The IDs of the attempts before the current one, in a local array, not a
	// field of exchange, so that eight of them stay on the stack: a field
	// would always escape to the heap, and a slice made for cfg.retries+1 of
	// them escapes beyond 32 bytes.
	var sent [8]sentIDs
	earlier := sent[:0]
	for n := 0; ; n++ {
		out := e.attempt(earlier)
		if out.kind != attemptReply && x.isClosed() {
			out = attemptOutcome{kind: attemptClosed, err: errClosed}
		}
		if !out.kind.retryable() {
			if out.kind != attemptReply {
				out.err = e.unanswered(out.err)
			}
			return out.packet, out.committed, out.err
		}
		// A retryable attempt has stamped the packet with its IDs.
		earlier = append(earlier, sentIDs{packetOut.RequestID, packetOut.MsgID})
		if err := e.endErr(n, out); err != nil {
			return nil, false, e.unanswered(err)
		}
	}
}

// endErr decides whether another attempt follows attempt n (counted from 0),
// which ended with out, a failure another attempt may cure: it returns the
// request's error when none follows. A done context ends the request with its
// error, a timeout at the context's deadline with context.DeadlineExceeded,
// and the last attempt with its own error, or, after a timeout, with an
// attemptsError.
func (e *exchange) endErr(n int, out attemptOutcome) error {
	if err := e.cfg.ctx.Err(); err != nil {
		return err
	}
	if out.kind == attemptTimeout && e.contextDeadline {
		return context.DeadlineExceeded
	}
	if n < e.cfg.retries {
		return nil
	}
	if out.kind == attemptTimeout {
		return e.attemptsError(fmt.Sprintf("request timeout (after %d retries)", n), out.err)
	}
	return out.err
}

// attemptsError returns the attemptsError with text and the attempt's reason,
// and the discard the exchange recorded, whose text text ends with.
func (e *exchange) attemptsError(text string, reason error) *attemptsError {
	if e.discarded == nil {
		return &attemptsError{text: text, errs: [2]error{reason}}
	}
	return &attemptsError{text: text + ": last discarded reply: " + e.discarded.Error(), errs: [2]error{reason, e.discarded}}
}

// unanswered returns err, the error of an exchange that ends without an
// answer: an error at the context's deadline that also unwraps to the discard
// the exchange recorded, if any (attemptsError); any other error unchanged.
// After a discarded authentic answer outside the time window it drops the
// engine clock, however the exchange ended (forgetEngineTime); a panic, which
// send recovers, does not get here.
func (e *exchange) unanswered(err error) error {
	if e.outOfWindow {
		e.x.forgetEngineTime()
	}
	if _, ended := err.(*attemptsError); e.discarded != nil && !ended && errors.Is(err, context.DeadlineExceeded) {
		return e.attemptsError(err.Error(), err)
	}
	return err
}

// attempt sends the request once, on the client's connection, and reads until
// a reply answers it, the attempt's deadline passes or the context is done. A
// reply to an earlier attempt, one of earlier, answers it too.
func (e *exchange) attempt(earlier []sentIDs) attemptOutcome {
	x := e.x
	if err := e.cfg.ctx.Err(); err != nil {
		return attemptOutcome{kind: attemptContextDone, err: err}
	}
	conn, err := x.connection()
	if err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	var deadline time.Time
	deadline, e.contextDeadline = attemptDeadline(e.cfg.ctx, e.cfg.timeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	// The context interrupts the attempt from here on, after its deadline: an
	// interrupt before it would be undone by it. Close, at any time, closes
	// the attempt's connection, on which the attempt fails.
	defer x.interruptible(e.cfg.ctx, conn).end()

	e.packet.RequestID = x.nextRequestID()
	// An encoding failure is not retried: another attempt would fail the same
	// way.
	outBuf, err := e.encode()
	if err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}

	if _, err = conn.Write(outBuf); err != nil {
		return ioFailure(err)
	}
	return e.await(conn, earlier)
}

// attemptDeadline returns when an attempt with timeout ends: after the
// timeout, or at the context's deadline if that comes first or at the same
// time (byContext): the context's deadline has then passed when the attempt
// times out.
func attemptDeadline(ctx context.Context, timeout time.Duration) (deadline time.Time, byContext bool) {
	deadline = time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && !ctxDeadline.After(deadline) {
		return ctxDeadline, true
	}
	return deadline, false
}

// encode marshals the request, for SNMPv3 with a new message ID and the
// engine boots and time the exchange's clock gives at this attempt
// (sourcedClock.timeFor; the encoder draws the salt of an encrypted message).
// An authenticated request is signed with the exchange's key, which must fit
// its protocol (usm.Auth.CheckKey).
func (e *exchange) encode() ([]byte, error) {
	x, p := e.x, e.packet
	if p.Version == Version3 {
		p.MsgID = x.nextMsgID()
		h := &p.SecurityParameters
		h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime = e.sec.clock.timeFor(time.Now())
	}
	out, err := p.marshalMsg(&e.sec.keys)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return out, nil
}

// await reads replies on conn until one answers the request. A message that does
// not decode or authenticate (decode), does not answer the request (answers)
// or that the commit rejects is discarded, its reason recorded (discard), and
// the read goes on until the attempt's deadline (RFC 3412 section 7.2).
func (e *exchange) await(conn transport, earlier []sentIDs) attemptOutcome {
	x := e.x
	for {
		resp, err := receive(conn, x.rx)
		if err != nil {
			return ioFailure(err)
		}

		reply, verified, err := e.decode(resp, earlier)
		answered := false
		if err == nil {
			answered, err = e.answers(reply, earlier)
		}
		if !answered {
			e.discard(err, e.rankOf(reply, verified, earlier))
			continue
		}
		out, rejected := e.settle(attemptOutcome{kind: attemptReply, packet: reply, err: err, verified: verified})
		if rejected == nil {
			return out
		}
		// The commit rejects only an authentic answer outside the time window.
		e.outOfWindow = true
		e.discard(rejected, rankAuthentic)
	}
}

// discard records err, the reason a message of rank was discarded, when it
// came closer to answering the request than the discards before it, or as
// close and later.
func (e *exchange) discard(err error, rank discardRank) {
	if rank != 0 && rank >= e.discardedRank {
		e.discarded, e.discardedRank = err, rank
	}
}

// rankOf returns the rank of a discarded message: read is the message as far
// as decode read it when it read the ID that names the request's attempts, and
// verified reports that its digest checked. A message that names none of the
// exchange's attempts (attemptOf) answers another request: rank zero; so does
// an SNMPv1 or SNMPv2c message other than a Response, whose request ID
// names no request. A verified request or inform (the Confirmed Class), such
// as the request sent back unchanged, proves the client's key, not the
// agent's: it ranks as a named message, below an authentic reply.
func (e *exchange) rankOf(read *Message, verified bool, earlier []sentIDs) discardRank {
	if read == nil {
		return rankUnread
	}
	if !e.named(read, earlier) || e.packet.Version != Version3 && read.PDUType != Response {
		return 0
	}
	if verified && !read.PDUType.confirmed() {
		return rankAuthentic
	}
	return rankNamed
}

// attemptOf returns the IDs the exchange's attempt that reply names sent the
// request with, the current attempt's or one of earlier: by the msgID for an
// SNMPv3 request (RFC 3412 section 7.2 step 10 a), else by the request ID;
// false when reply names none.
func (e *exchange) attemptOf(reply *Message, earlier []sentIDs) (sentIDs, bool) {
	if current := (sentIDs{e.packet.RequestID, e.packet.MsgID}); e.names(reply, current) {
		return current, true
	}
	for _, ids := range earlier {
		if e.names(reply, ids) {
			return ids, true
		}
	}
	return sentIDs{}, false
}

// names reports whether reply names the attempt that sent the request with
// ids: by the msgID for an SNMPv3 request, else by the request ID.
func (e *exchange) names(reply *Message, ids sentIDs) bool {
	if e.packet.Version == Version3 {
		return reply.MsgID == ids.msgID
	}
	return reply.RequestID == ids.requestID
}

// named reports whether reply names one of the exchange's attempts
// (attemptOf).
func (e *exchange) named(reply *Message, earlier []sentIDs) bool {
	_, ok := e.attemptOf(reply, earlier)
	return ok
}

// decode decodes a message read for the request: the header, which fails a
// message of another SNMP version than the request's and, for an SNMPv3
// request, one whose msgID names none of the exchange's attempts (attemptOf),
// before security processing; for an SNMPv3 request, the security processing
// by the message's own level (RFC 3414 section 3.2: receiveReply, the digest
// exactly when it asks for authentication, decryption exactly when it asks for
// privacy) with the exchange's keys, which no reply changes: no key derives
// for an engine a reply names; then the scoped PDU and the PDU. It reports
// whether the message's digest checked with the request's key. With an error
// it returns the message as far as it read it when it read the ID that names
// the request's attempts (rankOf), else nil.
func (e *exchange) decode(resp []byte, earlier []sentIDs) (_ *Message, verified bool, _ error) {
	reply := &Message{}
	v3 := e.packet.Version == Version3
	cursor, w, err := unmarshalHeader(resp, reply)
	switch {
	case err != nil:
	case reply.Version != e.packet.Version:
		err = errOtherVersion
	case !v3:
	case !e.named(reply, earlier):
		err = errOtherMessage
	default:
		err = receiveReply(reply.SecurityLevel, &reply.SecurityParameters, &e.packet.SecurityParameters, &e.sec.keys)
	}
	// read is reply, as far as it was read, when an error ends the decode: for
	// an SNMPv3 request when the SNMPv3 header's msgID decoded, for another
	// when the PDU's request ID did (atPDU: the decode reached the PDU, which
	// for an SNMPv3 request is after its msgID).
	read := func(atPDU bool) *Message {
		if v3 && w.msgIDRead || atPDU && requestIDRead(resp, cursor) {
			return reply
		}
		return nil
	}
	if err != nil {
		return read(false), false, err
	}
	if v3 {
		if reply.SecurityLevel.authFlag() {
			in := inbound{msg: resp, wire: w, keys: e.sec.keys}
			if err = in.verify(); err != nil {
				return read(false), false, err
			}
			verified = true
		}
		if resp, cursor, err = unmarshalScopedPDU(resp, cursor, reply, reply.SecurityLevel.privFlag(), &e.sec.keys); err != nil {
			return read(false), verified, err
		}
	}
	if err = unmarshalPayload(resp, cursor, reply); err != nil {
		return read(true), verified, err
	}
	return reply, verified, nil
}

// receiveReply applies RFC 3414 section 3.2 steps 4 and 5 to a reply at level
// whose USM parameters are got, to a request whose are want and whose keys are
// keys: the reply's user is the request's (else errUnknownUser), or the empty
// user of discovery, which has no protocols (as net-snmp's), so it names no
// reply that asks for authentication; a reply that asks for authentication
// names the request's engine ID, the only one the request's keys serve (else
// errUnknownUser); the request's keys have the protocols the level asks for.
func receiveReply(level SecurityLevel, got, want *SecurityParameters, keys *usmKeys) error {
	if got.UserName != want.UserName {
		if got.UserName != "" {
			return errUnknownUser
		}
		if level.authFlag() {
			return errNoAuthForMsg
		}
	}
	if level.authFlag() && !bytes.Equal(got.AuthoritativeEngineID, want.AuthoritativeEngineID) {
		return errUnknownUser
	}
	switch needAuth, needPriv := missingProtocol(keys.authProtocol, keys.privProtocol, level); {
	case needAuth:
		return errNoAuthForMsg
	case needPriv:
		return errNoPrivForMsg
	}
	return nil
}

// The reasons a message is discarded for after the header decoded, besides
// security processing's (RFC 3412 section 7.2 steps 3, 10 and 12 b): the
// message does not answer the request, ErrUnmatchedReply.
var (
	errOtherVersion   = unmatched("the reply is of another SNMP version than the request")
	errOtherMessage   = unmatched("the reply's msgID names no attempt of the request")
	errNotAnswer      = unmatched("the reply is neither a Response nor an SNMPv3 Report")
	errOtherRequestID = unmatched("the reply's request ID does not match the request")
	errOtherLevel     = unmatched("the reply's security level is not the request's")
	errOtherUser      = unmatched("the reply's user name is not the request's")
	errOtherEngine    = unmatched("the reply's engine ID is not the request's")
	errOtherContext   = unmatched("the reply's context is not the request's")
)

// unmatched returns the error with text, of ErrUnmatchedReply.
func unmatched(text string) error { return inCategory(ErrUnmatchedReply, errors.New(text)) }

// answers reports whether reply, a message decode read for the request,
// answers it, with the error of a Report that does, or else the reason it does
// not (RFC 3412 section 7.2 steps 11 and 12; net-snmp's snmpv3_verify_msg). An
// SNMPv3 Report answers, whatever its request ID, level and context (security
// processing bound its user, and with authentication its engine ID), with its
// counter's error
// (reportKindOf), none for a resync Report. A Response answers with the
// request ID of the attempt it names (attemptOf: an SNMPv3 one by its msgID,
// so with that attempt's pair of IDs) and, for SNMPv3, the request's security
// level (the auth and priv flags), user name, engine ID, context engine ID and
// context name (step 12 b). Nothing else answers: a request sent back
// unchanged, SNMPv1 and SNMPv2c Reports. A message that does not answer leaves
// the request outstanding, as net-snmp does (step 12 b discards the request
// unless the model or level differs): a forged one cannot end it.
func (e *exchange) answers(reply *Message, earlier []sentIDs) (bool, error) {
	if kind, ok := reportKindOf(reply); ok {
		if kind.resync {
			return true, nil
		}
		return true, kind.err
	}
	if reply.PDUType != Response {
		return false, errNotAnswer
	}
	if ids, ok := e.attemptOf(reply, earlier); !ok || ids.requestID != reply.RequestID {
		return false, errOtherRequestID
	}
	if e.packet.Version != Version3 {
		return true, nil
	}
	p := e.packet
	got, want := &reply.SecurityParameters, &p.SecurityParameters
	switch {
	case reply.SecurityLevel != p.SecurityLevel:
		return false, errOtherLevel
	case got.UserName != want.UserName:
		return false, errOtherUser
	case !bytes.Equal(got.AuthoritativeEngineID, want.AuthoritativeEngineID):
		return false, errOtherEngine
	case !bytes.Equal(reply.ContextEngineID, p.ContextEngineID) || reply.ContextName != p.ContextName:
		return false, errOtherContext
	}
	return true, nil
}

// The names of the counters an SNMPv3 Report can carry, with instance 0: the
// User-based Security Model's (RFC 3414) and message processing's (RFC 3412).
const (
	usmStatsUnsupportedSecLevels = ".1.3.6.1.6.3.15.1.1.1.0"
	usmStatsNotInTimeWindows     = ".1.3.6.1.6.3.15.1.1.2.0"
	usmStatsUnknownUserNames     = ".1.3.6.1.6.3.15.1.1.3.0"
	usmStatsUnknownEngineIDs     = ".1.3.6.1.6.3.15.1.1.4.0"
	usmStatsWrongDigests         = ".1.3.6.1.6.3.15.1.1.5.0"
	usmStatsDecryptionErrors     = ".1.3.6.1.6.3.15.1.1.6.0"
	snmpUnknownSecurityModels    = ".1.3.6.1.6.3.11.2.1.1.0"
	snmpInvalidMsgs              = ".1.3.6.1.6.3.11.2.1.2.0"
	snmpUnknownPDUHandlers       = ".1.3.6.1.6.3.11.2.1.3.0"
)

// reportKind is what the counter an SNMPv3 Report carries means to a request.
type reportKind struct {
	// err is the request's error.
	err error
	// resync marks the Reports that say the request's engine ID or time is
	// out of date: they answer without err. discoverEngine takes the engine
	// parameters of one; send sends the request again with them, or returns
	// err when it may not or when a resync Report answers that too.
	resync bool
	// namesEngine marks the Report that names the engine ID the request
	// should have had (RFC 3414 section 3.2 step 3): a resend takes the
	// Report's engine ID along with its boots and time.
	namesEngine bool
	// timeWindow marks the Report that says the request's engine boots and
	// time are outside the time window (RFC 3414 section 3.2 step 7 b).
	timeWindow bool
}

// reportKinds are the counters of the USM (RFC 3414) and of message processing
// (RFC 3412) a Report can carry, by the counter's OID (reportCounter).
var reportKinds = map[string]reportKind{ //nolint:gochecknoglobals // a read-only table
	reportCounter(usmStatsUnsupportedSecLevels): {err: ErrUnknownSecurityLevel},
	reportCounter(usmStatsNotInTimeWindows):     {err: ErrNotInTimeWindow, resync: true, timeWindow: true},
	reportCounter(usmStatsUnknownUserNames):     {err: ErrUnknownUsername},
	reportCounter(usmStatsUnknownEngineIDs):     {err: ErrUnknownEngineID, resync: true, namesEngine: true},
	reportCounter(usmStatsWrongDigests):         {err: ErrWrongDigest},
	reportCounter(usmStatsDecryptionErrors):     {err: ErrDecryption},
	reportCounter(snmpUnknownSecurityModels):    {err: ErrUnknownSecurityModels},
	reportCounter(snmpInvalidMsgs):              {err: ErrInvalidMsgs},
	reportCounter(snmpUnknownPDUHandlers):       {err: ErrUnknownPDUHandlers},
}

// reportKindOf returns the kind of p as a Report, and false when p is not an
// SNMPv3 Report. The agent puts the counter of the error it detected in the
// Report's varbinds; the Report's request ID is the request's, or 0 when the
// agent could not read it. As in net-snmp's snmpv3_get_report_type, the first
// varbind names the counter, with one instance sub-identifier of any value;
// none, or another name, gives ErrUnknownReportPDU.
func reportKindOf(p *Message) (reportKind, bool) {
	if p.Version != Version3 || p.PDUType != Report {
		return reportKind{}, false
	}
	if len(p.VarBinds) > 0 {
		if kind, ok := reportKinds[reportCounter(p.VarBinds[0].Name)]; ok {
			return kind, true
		}
	}
	return reportKind{err: ErrUnknownReportPDU}, true
}

// reportCounter returns name, an OID, without its last sub-identifier: the
// counter of a Report's varbind name, without the instance.
func reportCounter(name string) string {
	return name[:max(strings.LastIndexByte(name, '.'), 0)]
}
