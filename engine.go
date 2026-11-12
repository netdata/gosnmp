// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// send runs the request req within ctx and returns its answer, a Response whose
// error-status is NoError, or no message with the error of a request that
// fails: marked with ErrAnswered when an answer ended it (the message request
// returns beside its error), requestPanicked's error for one that panics, and a
// *StatusError for a Response with another error-status. A nil ctx fails the
// request before it starts. The library prevents panics of its own: the recover
// is for the caller's code the request runs on its goroutine (the methods of
// the context it calls) and for bugs, which would otherwise end the process of
// a caller that runs requests on a goroutine without a recover. A flag, not
// recover's value, tells that the request panicked: under GODEBUG=panicnil=1,
// recover returns nil for panic(nil).
//
// req is a request of the Read Class (RFC 3411 section 2.8.1), a Get,
// GetNext or GetBulk, as every request the client sends: the SNMPv3 engine
// clock signs it whatever the clock's source (sourcedClock.timeFor, mayLend),
// which a request that changes the agent must not take.
func (c *Client) send(ctx context.Context, req *Message) (result *Message, err error) {
	if ctx == nil {
		return nil, errNilContext
	}
	completed := false
	defer func() {
		if !completed {
			err = requestPanicked(recover())
		}
	}()
	result, err = c.request(ctx, req)
	completed = true
	if err != nil {
		if result != nil {
			err = answered(err)
		}
		return nil, err
	}
	if result.ErrorStatus != NoError {
		return nil, &StatusError{Status: result.ErrorStatus, Index: result.ErrorIndex}
	}
	return result, nil
}

// request runs a request within ctx: for SNMPv3 it first starts the engine
// state and discovers the agent's engine when it has none, then sends the
// request, whose answer commits the engine parameters it carries, and sends
// the request once more when the answer is a Report that resynchronizes the
// client with the agent's engine. With an error it returns
// the answer that ended the request, a Report or the discovery's answer, and
// no message when none did: send marks the error by it.
func (c *Client) request(ctx context.Context, req *Message) (result *Message, err error) {
	if _, err = c.connection(); err != nil {
		return nil, err
	}
	// sec is the engine clock and the keys the attempts carry.
	var sec attemptSecurity
	if req.Version == Version3 {
		c.startEngine()
		if result, err = c.negotiateInitialSecurityParameters(ctx, req); err != nil {
			return result, err
		}
		sec = attemptSecurity{clock: c.engine.clock, keys: c.engine.keys}
	}

	var stored bool
	result, stored, err = c.sendOneRequest(ctx, req, false, sec)
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
		sec.clock = c.engine.clock
	} else if !mayLend(req, result, kind) {
		return result, kind.err
	} else if sec, err = c.lendEngineParameters(req, result, kind, sec); err != nil {
		return result, err
	}
	result, _, err = c.sendOneRequest(ctx, req, false, sec)
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

// exchange is one request on its way through the attempts sendOneRequest
// makes.
type exchange struct {
	c   *Client
	req *Message
	// ctx is the request's context.
	ctx context.Context

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
	// (net.ErrClosed).
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
	reply *Message
	err   error
	kind  attemptKind
	// verified reports that reply's digest checked against the request
	// (exchange.decode).
	verified bool
	// committed reports that reply's engine parameters were committed into
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

// sendOneRequest sends req, the engine discovery's request when
// discovery is set, an SNMPv3 one with the engine boots and time of sec's clock
// and its keys, and returns the reply that answers it, and whether the reply's
// engine parameters were committed into the engine state, retrying up to
// Retries times. A request that ends without a reply goes through its one
// exit: once Close closed the client, it ends with net.ErrClosed, whatever
// ended it (an attempt's outcome or the decision not to retry), and an
// exchange that ends without an answer goes through unanswered.
func (c *Client) sendOneRequest(ctx context.Context, req *Message, discovery bool, sec attemptSecurity) (*Message, bool, error) {
	e := exchange{c: c, req: req, ctx: ctx, discovery: discovery, sec: sec}
	// The IDs of the attempts before the current one, in a local array, not a
	// field of exchange, so that eight of them stay on the stack: a field
	// would always escape to the heap, and a slice made for Retries+1 of
	// them escapes beyond 32 bytes.
	var sent [8]sentIDs
	earlier := sent[:0]
	for n := 0; ; n++ {
		out := e.attempt(earlier)
		if out.kind == attemptReply {
			return out.reply, out.committed, out.err
		}
		err := out.err
		if out.kind.retryable() {
			// A retryable attempt has stamped req with its IDs.
			earlier = append(earlier, sentIDs{req.RequestID, req.MsgID})
			if err = e.endErr(n, out); err == nil {
				continue
			}
		}
		if c.isClosed() {
			err = errClosed
		}
		return nil, false, e.unanswered(err)
	}
}

// endErr decides whether another attempt follows attempt n (counted from 0),
// which ended with out, a failure another attempt may cure: it returns the
// request's error when none follows. A done context ends the request with its
// error, a timeout at the context's deadline with context.DeadlineExceeded,
// and the last attempt with its own error, or, after a timeout, with an
// attemptsError.
func (e *exchange) endErr(n int, out attemptOutcome) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if out.kind == attemptTimeout && e.contextDeadline {
		return context.DeadlineExceeded
	}
	if n < e.c.config.Retries {
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
		e.c.forgetEngineTime()
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
	c := e.c
	if err := e.ctx.Err(); err != nil {
		return attemptOutcome{kind: attemptContextDone, err: err}
	}
	conn, err := c.connection()
	if err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	var deadline time.Time
	deadline, e.contextDeadline = attemptDeadline(e.ctx, c.config.Timeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	// The context interrupts the attempt from here on, after its deadline: an
	// interrupt before it would be undone by it. Close, at any time, closes
	// the attempt's connection, on which the attempt fails.
	defer c.interruptible(e.ctx, conn).end()

	e.req.RequestID = c.nextRequestID()
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
	c, req := e.c, e.req
	if req.Version == Version3 {
		req.MsgID = c.nextMsgID()
		h := &req.SecurityParameters
		h.AuthoritativeEngineBoots, h.AuthoritativeEngineTime = e.sec.clock.timeFor(time.Now())
	}
	out, err := req.marshalMsg(&e.sec.keys)
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
	c := e.c
	for {
		resp, err := receive(conn, c.rx)
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
		out, rejected := e.settle(attemptOutcome{kind: attemptReply, reply: reply, err: err, verified: verified})
		if rejected == nil {
			return out
		}
		// The commit rejects only an authentic answer outside the time window.
		e.outOfWindow = true
		e.discard(rejected, rankAuthentic)
	}
}
