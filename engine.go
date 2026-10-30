// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
)

// send runs a request: for SNMPv3 it first takes the caller's changes into the
// engine state and discovers the agent's engine when it has none, then sends
// the request, whose answer commits the engine parameters it carries, and
// sends the request once more when the answer is a Report that
// resynchronizes the client with the agent's engine. Every result it returns
// passes through its named results, which the recover below returns when a
// panic, user code's included, ends the request.
func (x *GoSNMP) send(packetOut *SnmpPacket) (result *SnmpPacket, err error) {
	// Known bug: a panic becomes the request's error, with the stacks of all
	// goroutines in its text (8 KB, NUL-padded), and the result the request had
	// when it panicked.
	defer func() {
		if e := recover(); e != nil {
			buf := make([]byte, 8192)
			runtime.Stack(buf, true)

			err = fmt.Errorf("recover: %v Stack:%v", e, string(buf))
		}
	}()

	cfg := x.prepareRequest()
	if _, _, err = x.clientConnection(&cfg); err != nil {
		return nil, err
	}
	if packetOut.Version == Version3 {
		// The engine state is configuration the request reads at its start.
		if err = x.reconcileEngine(); err != nil {
			return &SnmpPacket{}, err
		}
	}
	if x.Logger.enabled() {
		x.Logger.Print("SEND INIT")
	}
	// clock is the engine clock the attempts carry.
	var clock sourcedClock
	if packetOut.Version == Version3 {
		if x.Logger.enabled() {
			x.Logger.Print("SEND INIT NEGOTIATE SECURITY PARAMS")
		}
		if err = x.negotiateInitialSecurityParameters(&cfg, packetOut); err != nil {
			return &SnmpPacket{}, err
		}
		if x.Logger.enabled() {
			x.Logger.Print("SEND END NEGOTIATE SECURITY PARAMS")
		}
		clock = x.engine.clock
	}

	var stored bool
	result, stored, err = x.sendOneRequest(&cfg, packetOut, false, clock)
	if err != nil {
		x.Logger.Printf("SEND Error on the first Request Error: %s", err)
	}
	kind := resyncKindOf(result)
	if !kind.resync {
		return result, err
	}

	// Resynchronize: send the request again, with the engine parameters the
	// client committed from an authenticated Report, or with those of an
	// unauthenticated one in the request only, when mayLend allows it: the
	// answer brings the agent's, which the client commits. A Report that
	// cannot resynchronize the request ends it with its error. The
	// retransmission's result goes into the named result, which a recovered
	// panic returns; a resync Report answering it ends the request with its
	// error.
	if x.Logger.enabled() {
		x.Logger.Print("WARNING detected " + kind.name + " ERROR")
	}
	if stored {
		x.engine.stamp(packetOut)
		clock = x.engine.clock
	} else if !mayLend(packetOut, result, kind) {
		return result, kind.err
	} else if clock, err = x.lendEngineParameters(packetOut, result, kind); err != nil {
		x.Logger.Printf("ERROR lendEngineParameters error: %s", err)
		return result, err
	}
	result, _, err = x.sendOneRequest(&cfg, packetOut, false, clock)
	if err != nil && x.Logger.enabled() {
		x.Logger.Printf("ERROR "+kind.name+" retransmit error: %s", err)
	}
	if kind = resyncKindOf(result); kind.resync {
		return result, kind.err
	}
	return result, err
}

// resyncKindOf returns the kind of result, an answer, when it is a Report;
// its resync field marks one that resynchronizes the client with the agent's
// engine.
func resyncKindOf(result *SnmpPacket) reportKind {
	if result == nil {
		return reportKind{}
	}
	kind, _ := reportKindOf(result)
	return kind
}

// requestConfig is the client's configuration as a request reads it, once, at
// its start: a change a hook or the Logger makes to the client applies from
// the next request. The packet carries the rest (version, security level and
// model, context), and the SNMPv3 engine state takes the caller's changes to
// its fields at the same time (reconcileEngine). Not part of it: the Logger,
// and the connection, which each attempt takes from the client
// (connectionFor).
type requestConfig struct {
	ctx                context.Context
	timeout            time.Duration
	retries            int
	exponentialTimeout bool
	// dial is how a TCP reopen opens a Conn the caller set again.
	dial                                       dialSettings
	preSend, onSent, onRecv, onRetry, onFinish func(*GoSNMP)
}

// prepareRequest reads the request configuration, with a background Context
// when the client has none and no negative retries, and allocates the receive
// buffer the first time: a client given a Conn without Connect works too.
func (x *GoSNMP) prepareRequest() requestConfig {
	if x.rxBuf == nil {
		x.rxBuf = new([rxBufSize]byte)
	}
	ctx := x.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return requestConfig{
		ctx:                ctx,
		timeout:            x.Timeout,
		retries:            max(x.Retries, 0),
		exponentialTimeout: x.ExponentialTimeout,
		dial:               x.dialSettings(cmp.Or(x.Transport, udp)),
		preSend:            x.PreSend,
		onSent:             x.OnSent,
		onRecv:             x.OnRecv,
		onRetry:            x.OnRetry,
		onFinish:           x.OnFinish,
	}
}

// exchange is one request on its way through the attempts sendOneRequest
// makes.
type exchange struct {
	x      *GoSNMP
	packet *SnmpPacket
	// cfg is a copy of the request's configuration: escape analysis is
	// field-insensitive, so a pointer beside packet would move the request's
	// configuration to the heap.
	cfg requestConfig

	// timeout is the current attempt's timeout; ExponentialTimeout doubles it
	// before each retry.
	timeout time.Duration
	// contextDeadline is set when the context's deadline ends the current
	// attempt, at or before its timeout: endErr then reports
	// context.DeadlineExceeded whether or not the Context reports its
	// deadline yet.
	contextDeadline bool
	// discovery marks the engine discovery's exchange, whose answer gives the
	// engine state its engine ID (settle).
	discovery bool
	// clock is the engine clock the attempts of an SNMPv3 request carry
	// (encode): the engine state's, or the one a Report lent to a resend.
	clock sourcedClock

	// discarded is the reason of the discarded message that came closest to
	// answering the request, of rank discardedRank (discard).
	discarded     error
	discardedRank discardRank
	// outOfWindow marks an exchange that discarded an authentic answer
	// outside the time window (settle).
	outOfWindow bool
}

// discardRank orders the messages an exchange discards by how close they came
// to answering it; zero is a message that answers another request, whose
// reason is not recorded.
type discardRank uint8

const (
	// rankUnread: a message whose msgID could not be read, or any message to
	// an SNMPv1 or SNMPv2c request.
	rankUnread discardRank = iota + 1
	// rankNamed: a message with the msgID of one of the exchange's attempts
	// that did not authenticate.
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
	// attemptAgentClosed: the agent closed the TCP connection (io.EOF), which
	// the next attempt opens again.
	attemptAgentClosed
	// attemptClosed: the write or the read failed on a closed connection
	// (net.ErrClosed), or Close closed the client.
	attemptClosed
	// attemptContextDone: the Context was done when the attempt would start.
	attemptContextDone
	// attemptFailed: the client had no connection, or setting the deadline,
	// encoding the request or reopening the TCP connection failed.
	attemptFailed
)

// retryable reports whether another attempt may cure an attempt that ended
// so.
func (k attemptKind) retryable() bool {
	switch k {
	case attemptTimeout, attemptTransportError, attemptAgentClosed:
		return true
	}
	return false
}

// attemptOutcome is how an attempt ended, and with what: the reply and its
// error, or the reason the attempt failed.
type attemptOutcome struct {
	packet *SnmpPacket
	err    error
	kind   attemptKind
	// verified reports that packet's digest checked against the request
	// (exchange.authenticate).
	verified bool
	// committed reports that packet's engine parameters were committed into
	// the engine state (exchange.settle).
	committed bool
}

// ioFailure is the outcome of an attempt whose write or read on c failed with
// err. A TCP connection that fails otherwise than by the attempt's deadline
// or a close (net.ErrClosed), as when the agent closed or reset it, is lost:
// the next attempt opens it again.
func (x *GoSNMP) ioFailure(c *connection, err error) attemptOutcome {
	tcpConn := strings.HasPrefix(c.dial.network, tcp)
	var out attemptOutcome
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return attemptOutcome{kind: attemptTimeout, err: err}
	case errors.Is(err, net.ErrClosed):
		return attemptOutcome{kind: attemptClosed, err: err}
	case tcpConn && errors.Is(err, io.EOF):
		out = attemptOutcome{kind: attemptAgentClosed, err: err}
	default:
		out = attemptOutcome{kind: attemptTransportError, err: err}
	}
	if tcpConn {
		x.Logger.Printf("ERROR: the TCP connection is lost: %v", err)
		x.markLost(c.conn)
	}
	return out
}

// attemptsError is the error of a request whose attempts ran out after a
// timeout or with the agent closing the TCP connection, or that the Context's
// deadline ended after a discard: a text callers know, unwrapping to the last
// attempt's reason (the write's or the read's deadline error, a timeout
// net.Error; io.EOF; context.DeadlineExceeded) and to the reason of the
// discard the exchange recorded, if any, whose text it ends with.
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

// sentIDs are the request ID and the msgID an attempt sent the request with.
type sentIDs struct {
	requestID, msgID uint32
}

// sendOneRequest sends packetOut, the engine discovery's request when
// discovery is set, an SNMPv3 one with the engine boots and time of clock, and
// returns the reply that answers it, and whether the reply's engine parameters
// were committed into the engine state, retrying up to cfg.retries times.
// OnFinish runs when it succeeds. Once Close closed the client, an attempt
// that ends without a reply ends the request with net.ErrClosed, whatever else
// ended it. An exchange that ends without an answer goes through unanswered.
func (x *GoSNMP) sendOneRequest(cfg *requestConfig, packetOut *SnmpPacket, discovery bool, clock sourcedClock) (*SnmpPacket, bool, error) {
	e := exchange{x: x, packet: packetOut, cfg: *cfg, timeout: cfg.timeout, discovery: discovery, clock: clock}
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
			if out.err == nil && cfg.onFinish != nil {
				cfg.onFinish(x)
			}
			return out.packet, out.committed, out.err
		}
		// A retryable attempt has stamped the packet with its IDs.
		earlier = append(earlier, sentIDs{packetOut.RequestID, packetOut.MsgID})
		if err := e.endErr(n, out); err != nil {
			return nil, false, e.unanswered(err)
		}
		e.beforeRetry(n+1, out.err)
	}
}

// endErr decides whether another attempt follows attempt n (counted from 0),
// which ended with out, a failure another attempt may cure: it returns the
// request's error when none follows. A done Context ends the request with its
// error, a timeout at the Context's deadline with context.DeadlineExceeded,
// and the last attempt with its own error, or, after a timeout or the agent
// closing the TCP connection, with an attemptsError.
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
	switch out.kind {
	case attemptTimeout:
		return e.attemptsError(fmt.Sprintf("request timeout (after %d retries)", n), out.err)
	case attemptAgentClosed:
		return e.attemptsError(fmt.Sprintf("max retries (%d) exceeded", e.cfg.retries), out.err)
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
// answer: an error at the Context's deadline that also unwraps to the discard
// the exchange recorded, if any (attemptsError); any other error unchanged.
// After a discarded authentic answer outside the time window it drops the
// engine clock, however the exchange ended (forgetEngineTime).
func (e *exchange) unanswered(err error) error {
	if e.outOfWindow {
		e.x.forgetEngineTime()
	}
	if e.discarded != nil && errors.Is(err, context.DeadlineExceeded) {
		return e.attemptsError(err.Error(), err)
	}
	return err
}

// beforeRetry readies retry n, which follows an attempt that failed with
// lastErr: it runs OnRetry, logs the retry and, with ExponentialTimeout,
// doubles the timeout.
func (e *exchange) beforeRetry(n int, lastErr error) {
	x := e.x
	if e.cfg.onRetry != nil {
		e.cfg.onRetry(x)
	}
	x.Logger.Printf("Retry number %d. Last error was: %v", n, lastErr)
	if e.cfg.exponentialTimeout {
		// https://www.webnms.com/snmp/help/snmpapi/snmpv3/v1/timeout.html
		e.timeout *= 2
	}
}

// attempt sends the request once, on the client's connection, and reads until
// a reply answers it, the attempt's deadline passes or the Context is done. A
// reply to an earlier attempt, one of earlier, answers it too.
func (e *exchange) attempt(earlier []sentIDs) attemptOutcome {
	x := e.x
	if err := e.cfg.ctx.Err(); err != nil {
		return attemptOutcome{kind: attemptContextDone, err: err}
	}
	c, err := x.connectionFor(&e.cfg)
	if err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	var deadline time.Time
	deadline, e.contextDeadline = attemptDeadline(e.cfg.ctx, e.timeout)
	if err = c.conn.SetDeadline(deadline); err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	// Close and the Context interrupt the attempt from here on, after its
	// deadline: an interrupt before it would be undone by it. A Close before
	// that closed the attempt's connection: no hook has replaced Conn yet.
	defer x.interruptible(e.cfg.ctx, c.conn).end()

	e.packet.RequestID = x.nextRequestID()
	// An encoding failure is not retried: another attempt would fail the same
	// way.
	outBuf, err := e.encode()
	if err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}

	if e.cfg.preSend != nil {
		e.cfg.preSend(x)
	}
	if x.Logger.enabled() {
		x.Logger.Printf("SENDING PACKET: %s", e.packet.SafeString())
	}
	if err = c.write(outBuf); err != nil {
		return x.ioFailure(&c, err)
	}
	if e.cfg.onSent != nil {
		e.cfg.onSent(x)
	}
	return e.await(&c, earlier)
}

// attemptDeadline returns when an attempt with timeout ends: after the
// timeout, or at the context's deadline if that comes first or at the same
// time (byContext): the Context's deadline has then passed when the attempt
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
// An authenticated request is signed with the user's key, which must fit its
// protocol (usm.Auth.CheckKey).
func (e *exchange) encode() ([]byte, error) {
	x, p := e.x, e.packet
	if p.Version == Version3 {
		p.MsgID = x.nextMsgID()
		if sp := usmOf(p.SecurityParameters); sp != nil {
			sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = e.clock.timeFor(p, time.Now())
		}
		p.SecurityParameters.Log()
	}
	out, err := p.marshalMsg()
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return out, nil
}

// await reads replies on c until one answers the request. A message that does
// not decode, does not authenticate or that the commit rejects is discarded,
// its reason recorded (discard), and the read goes on until the attempt's
// deadline (RFC 3412 section 7.2 steps 2, 6 and 7); so is one that answers
// another request.
func (e *exchange) await(c *connection, earlier []sentIDs) attemptOutcome {
	x := e.x
	for {
		if x.Logger.enabled() {
			x.Logger.Print("WAITING RESPONSE...")
		}
		resp, err := c.receive(x.rxBuf)
		if err != nil {
			if errors.Is(err, errReplyTooBig) {
				// The connection did not fail: a TCP reply is read whole only
				// when one read takes it (receive's known bug).
				return attemptOutcome{kind: attemptTransportError, err: err}
			}
			return x.ioFailure(c, err)
		}
		if e.cfg.onRecv != nil {
			e.cfg.onRecv(x)
		}
		if x.Logger.enabled() {
			x.Logger.Printf("GET RESPONSE OK: %+v", resp)
		}

		reply, verified, err := e.decode(resp)
		if err != nil {
			e.discard(err, e.rankOf(reply, verified, earlier))
			continue
		}
		if answered, err := e.answers(reply, earlier); answered {
			out, rejected := e.settle(attemptOutcome{kind: attemptReply, packet: reply, err: err, verified: verified})
			if rejected == nil {
				return out
			}
			// The commit rejects only an authentic answer outside the time
			// window.
			e.outOfWindow = true
			e.discard(rejected, rankAuthentic)
			continue
		}
		x.Logger.Print("ERROR out of order")
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

// rankOf returns the rank of a message decode failed on: read is the message
// as far as decode read it when its msgID was, and verified reports that its
// digest checked. A message with the msgID of none of the exchange's attempts
// answers another request: rank zero.
func (e *exchange) rankOf(read *SnmpPacket, verified bool, earlier []sentIDs) discardRank {
	switch {
	case read == nil:
		return rankUnread
	case !e.sentWithMsgID(read.MsgID, earlier):
		return 0
	case verified:
		return rankAuthentic
	}
	return rankNamed
}

// decode decodes a reply to the request: the header, for an SNMPv3 request
// the security processing and the scoped PDU, then the PDU. It reports
// whether the reply's digest checked against the request. The reply's
// security parameters are the request's with the USM fields the reply
// carries, keeping the request's keys only for the request's engine ID: no key
// derives for an engine a reply names. With an error it returns the message
// as far as it read it when it read its msgID (an SNMPv3 message to an SNMPv3
// request), else nil.
func (e *exchange) decode(resp []byte) (_ *SnmpPacket, verified bool, _ error) {
	x := e.x
	reply := &SnmpPacket{Logger: x.Logger}
	var sp *UsmSecurityParameters
	if e.packet.SecurityParameters != nil {
		sp = e.packet.SecurityParameters.Copy().usm()
		reply.SecurityParameters = sp
	}

	cursor, w, err := unmarshalHeader(resp, reply)
	if err == nil && reply.Version == Version3 && sp != nil {
		err = receiveReply(reply.MsgFlags, &w, sp)
	}
	// read is reply, as far as it was read, when an error ends the decode;
	// only an SNMPv3 header has a msgID.
	read := func() *SnmpPacket {
		if e.packet.Version == Version3 && w.has&hasMsgID != 0 {
			return reply
		}
		return nil
	}
	if err != nil {
		x.Logger.Printf("ERROR on unmarshall header: %s", err)
		return read(), false, err
	}
	if e.packet.Version == Version3 {
		in := inbound{msg: resp, wire: w, sp: sp}
		if verified, err = e.authenticate(&in, reply); err != nil {
			if e.unauthenticatedReport(resp, cursor, reply) {
				return reply, false, nil
			}
			x.Logger.Printf("ERROR on Test Authentication on v3: %s", err)
			return read(), false, err
		}
		if resp, cursor, err = unmarshalScopedPDU(resp, cursor, reply, reply.MsgFlags.privFlag()); err != nil {
			x.Logger.Printf("ERROR on the scoped PDU on v3: %s", err)
			return read(), verified, err
		}
	}
	if err = unmarshalPayload(resp, cursor, reply); err != nil {
		x.Logger.Printf("ERROR on UnmarshalPayload: %s", err)
		return read(), verified, err
	}
	return reply, verified, nil
}

// receiveReply makes sp, a copy of a request's parameters, the security
// parameters of a reply with flags whose USM fields are w, after RFC 3414
// section 3.2 steps 4 and 5 by the reply's flags: the reply's user is the
// request's (else errUnknownUser), or the empty user of discovery, which has
// no protocols (as net-snmp's), so it names no reply that asks for
// authentication; a reply that asks for authentication names the request's
// engine ID, the only one the request's keys serve (else errUnknownUser); the
// request's user has the protocols the flags ask for.
func receiveReply(flags SnmpV3MsgFlags, w *v3Wire, sp *UsmSecurityParameters) error {
	if w.userName != sp.UserName {
		if w.userName != "" {
			return errUnknownUser
		}
		if flags.authFlag() {
			return errNoAuthForMsg
		}
	}
	if flags.authFlag() && w.engineID != sp.AuthoritativeEngineID {
		return errUnknownUser
	}
	_, err := sp.receive(flags, w, false)
	return err
}

// authenticate checks in, a reply to an SNMPv3 request in security
// processing, by its own flags (RFC 3414 section 3.2 step 6): a reply that
// asks for authentication must carry a digest that checks with the request's
// key, whatever the request's level; to a request that asks for
// authentication, a reply must ask for it too. It reports whether it checked
// the digest.
func (e *exchange) authenticate(in *inbound, reply *SnmpPacket) (bool, error) {
	if !reply.MsgFlags.authFlag() {
		if e.packet.MsgFlags.authFlag() {
			return false, errNotAuthentic
		}
		return false, nil
	}
	if err := in.verify(); err != nil {
		return false, err
	}
	return true, nil
}

// unauthenticatedReport reports whether resp, a reply that failed the
// authentication its request asked for, is a Report the agent sent without
// authentication, and decodes it into reply. An agent sends most Reports so
// (RFC 3414 section 3.2: it cannot authenticate to an unknown engine ID or
// user), and some agents even notInTimeWindow, which step 7 a sends at
// authNoPriv. Only a plaintext scoped PDU is read, so nothing unauthenticated
// is decrypted, and only a Report at noAuthNoPriv (privacy without
// authentication is invalid, RFC 3412 section 7.2) of the request's security
// model that reportKindOf maps is kept.
func (e *exchange) unauthenticatedReport(resp []byte, cursor int, reply *SnmpPacket) bool {
	if reply.MsgFlags.authFlag() || reply.MsgFlags.privFlag() || reply.SecurityModel != e.packet.SecurityModel ||
		cursor >= len(resp) || PDUType(resp[cursor]) != Sequence {
		return false
	}
	resp, cursor, err := unmarshalScopedPDU(resp, cursor, reply, false)
	if err != nil || unmarshalPayload(resp, cursor, reply) != nil {
		return false
	}
	_, ok := reportKindOf(reply)
	return ok
}

// answers reports whether reply answers the request, and with which error. An
// SNMPv3 request is answered only by an SNMPv3 reply with the msgID of its
// current or an earlier attempt, and an SNMPv3 reply answers no other request
// (RFC 3412 section 7.2 step 10). A Report that reportKindOf maps then answers
// with its kind's error, none for a resync Report; any other reply only as a
// Response (GetResponse), with the request ID of the current or an earlier
// attempt: a request sent back unchanged carries the client's own IDs and
// digest, and other PDUs answer no request. Known bugs: nothing else of the
// reply is compared with the request (the SNMPv1 and SNMPv2c versions, the
// security model, level and context of RFC 3412 section 7.2 step 12 b, nor the
// engine ID of a reply without authentication; decode compares the user); an
// empty Response without an error status answers before its request ID is
// checked; a Response with request ID 0 answers any request.
func (e *exchange) answers(reply *SnmpPacket, earlier []sentIDs) (bool, error) {
	if reply.Version == Version3 || e.packet.Version == Version3 {
		if reply.Version != e.packet.Version || !e.sentWithMsgID(reply.MsgID, earlier) {
			return false, nil
		}
	}
	if kind, ok := reportKindOf(reply); ok {
		if kind.resync {
			return true, nil
		}
		return true, kind.err
	}
	if reply.PDUType != GetResponse {
		return false, nil
	}
	if reply.Error == NoError && len(reply.Variables) < 1 {
		e.x.Logger.Print("Empty result: the reply answers the request")
		return true, nil
	}
	return e.sentWithRequestID(reply.RequestID, earlier) || reply.RequestID == 0, nil
}

// sentWithRequestID reports whether the current or an earlier attempt sent
// the request with id.
func (e *exchange) sentWithRequestID(id uint32, earlier []sentIDs) bool {
	return id == e.packet.RequestID || slices.ContainsFunc(earlier, func(s sentIDs) bool { return s.requestID == id })
}

// sentWithMsgID reports whether the current or an earlier attempt sent the
// request with msgID.
func (e *exchange) sentWithMsgID(msgID uint32, earlier []sentIDs) bool {
	return msgID == e.packet.MsgID || slices.ContainsFunc(earlier, func(s sentIDs) bool { return s.msgID == msgID })
}

// The OIDs of the counters an SNMPv3 Report can carry: the User-based Security
// Model's (RFC 3414) and message processing's (RFC 3412).
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

// The errors of a request answered by a Report: one per Report counter the
// library knows, and ErrUnknownReportPDU for any other counter. The library's
// own rejections of a message unwrap to the counter's error too (see the
// package documentation, Errors).
var (
	ErrDecryption            = errors.New("decryption error")
	ErrInvalidMsgs           = errors.New("invalid messages")
	ErrNotInTimeWindow       = errors.New("not in time window")
	ErrUnknownEngineID       = errors.New("unknown engine id")
	ErrUnknownPDUHandlers    = errors.New("unknown pdu handlers")
	ErrUnknownReportPDU      = errors.New("unknown report pdu")
	ErrUnknownSecurityLevel  = errors.New("unknown security level")
	ErrUnknownSecurityModels = errors.New("unknown security models")
	ErrUnknownUsername       = errors.New("unknown username")
	ErrWrongDigest           = errors.New("wrong digest")
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
	// name names a resync Report in log lines.
	name string
}

// reportKinds are the counters of the USM (RFC 3414) and of message processing
// (RFC 3412) a Report can carry.
var reportKinds = map[string]reportKind{ //nolint:gochecknoglobals // a read-only table
	usmStatsUnsupportedSecLevels: {err: ErrUnknownSecurityLevel},
	usmStatsNotInTimeWindows:     {err: ErrNotInTimeWindow, resync: true, timeWindow: true, name: "out-of-time-window"},
	usmStatsUnknownUserNames:     {err: ErrUnknownUsername},
	usmStatsUnknownEngineIDs:     {err: ErrUnknownEngineID, resync: true, namesEngine: true, name: "unknown engine id"},
	usmStatsWrongDigests:         {err: ErrWrongDigest},
	usmStatsDecryptionErrors:     {err: ErrDecryption},
	snmpUnknownSecurityModels:    {err: ErrUnknownSecurityModels},
	snmpInvalidMsgs:              {err: ErrInvalidMsgs},
	snmpUnknownPDUHandlers:       {err: ErrUnknownPDUHandlers},
}

// reportKindOf returns the kind of p as a Report, and false when p is not one.
// The agent puts the counter of the error it detected in a Report's varbinds;
// the Report's request ID is the request's, or 0 when the agent could not read
// it. An unknown counter gives ErrUnknownReportPDU. Known bug: a Report counts
// only with exactly one varbind, so one with more is treated as a reply and
// matched by its request ID.
func reportKindOf(p *SnmpPacket) (reportKind, bool) {
	if p.Version != Version3 || p.PDUType != Report || len(p.Variables) != 1 {
		return reportKind{}, false
	}
	if kind, ok := reportKinds[p.Variables[0].Name]; ok {
		return kind, true
	}
	return reportKind{err: ErrUnknownReportPDU}, true
}
