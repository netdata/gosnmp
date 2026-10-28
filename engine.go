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

// send runs a request: for SNMPv3 it first discovers the agent's engine or
// derives the keys, then sends the request, stores the engine parameters the
// answer carries, and sends the request once more when the answer is a Report
// that resynchronizes the client with the agent's engine. Every result it
// returns passes through its named results, which the recover below returns
// when a panic, user code's included, ends the request.
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
	if x.Logger.enabled() {
		x.Logger.Print("SEND INIT")
	}
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
	}

	var verified bool
	result, verified, err = x.sendOneRequest(&cfg, packetOut)
	if err != nil {
		x.Logger.Printf("SEND Error on the first Request Error: %s", err)
	}
	kind, stored, storeErr := x.settleReply(packetOut, result, verified)
	if storeErr != nil {
		return result, storeErr
	}
	if !kind.resync {
		return result, err
	}

	// Resynchronize: send the request again, with the engine parameters the
	// client stored from an authenticated Report, or with those of an
	// unauthenticated one in the request only, when mayLend allows it: the
	// answer brings the agent's, which the client stores. A Report that cannot
	// resynchronize the request ends it with its error. The retransmission's
	// result goes into the named result, which a recovered panic returns; a
	// resync Report answering it ends the request with its error.
	if x.Logger.enabled() {
		x.Logger.Print("WARNING detected " + kind.name + " ERROR")
	}
	if stored {
		if err = x.updatePktSecurityParameters(packetOut); err != nil {
			x.Logger.Printf("ERROR updatePktSecurityParameters error: %s", err)
			return nil, err
		}
	} else if !mayLend(packetOut, result, kind) {
		return result, kind.err
	} else if err = x.lendEngineParameters(packetOut, result, kind); err != nil {
		x.Logger.Printf("ERROR lendEngineParameters error: %s", err)
		return nil, err
	}
	result, verified, err = x.sendOneRequest(&cfg, packetOut)
	if err != nil && x.Logger.enabled() {
		x.Logger.Printf("ERROR "+kind.name+" retransmit error: %s", err)
	}
	if kind, _, storeErr = x.settleReply(packetOut, result, verified); storeErr != nil {
		return result, storeErr
	}
	if kind.resync {
		return result, kind.err
	}
	return result, err
}

// requestConfig is the client's configuration as a request reads it, once, at
// its start: a change a hook or the Logger makes to the client applies from
// the next request. The packet carries the rest (version, security level and
// model, context). Not part of it: the Logger, the learned SNMPv3 engine
// state, and the connection, which each attempt takes from the client
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
	// attemptInvalidReply: a reply did not decode or authenticate.
	attemptInvalidReply
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
	case attemptTimeout, attemptTransportError, attemptInvalidReply, attemptAgentClosed:
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
// timeout or with the agent closing the TCP connection: a text callers know,
// unwrapping to the last attempt's reason (the write's or the read's deadline
// error, a timeout net.Error; io.EOF).
type attemptsError struct {
	text   string
	reason error
}

func (e *attemptsError) Error() string { return e.text }

func (e *attemptsError) Unwrap() error { return e.reason }

// sentIDs are the request ID and the msgID an attempt sent the request with.
type sentIDs struct {
	requestID, msgID uint32
}

// sendOneRequest sends packetOut and returns the reply that answers it, and
// whether the reply's digest checked against the request, retrying up to
// cfg.retries times. OnFinish runs when it succeeds. Once Close closed the
// client, an attempt that ends without a reply ends the request with
// net.ErrClosed, whatever else ended it.
func (x *GoSNMP) sendOneRequest(cfg *requestConfig, packetOut *SnmpPacket) (*SnmpPacket, bool, error) {
	e := exchange{x: x, packet: packetOut, cfg: *cfg, timeout: cfg.timeout}
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
			if out.err == nil && cfg.onFinish != nil {
				cfg.onFinish(x)
			}
			return out.packet, out.verified, out.err
		}
		// A retryable attempt has stamped the packet with its IDs.
		earlier = append(earlier, sentIDs{packetOut.RequestID, packetOut.MsgID})
		if err := e.endErr(n, out); err != nil {
			return nil, false, err
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
		return &attemptsError{text: fmt.Sprintf("request timeout (after %d retries)", n), reason: out.err}
	case attemptAgentClosed:
		return &attemptsError{text: fmt.Sprintf("max retries (%d) exceeded", e.cfg.retries), reason: out.err}
	}
	return out.err
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

// encode marshals the request, for SNMPv3 with a new message ID (the encoder
// draws the salt of an encrypted message). An authenticated request is signed
// with the user's key, which must fit its protocol (usm.Auth.CheckKey).
func (e *exchange) encode() ([]byte, error) {
	x, p := e.x, e.packet
	if p.Version == Version3 {
		p.MsgID = x.nextMsgID()
		p.SecurityParameters.Log()
	}
	out, err := p.marshalMsg()
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return out, nil
}

// await reads replies on c until one answers the request.
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
			// Known bug: an undecodable reply ends the attempt, and the request
			// is sent again at once, instead of reading on.
			return attemptOutcome{kind: attemptInvalidReply, err: err}
		}
		if answered, err := e.answers(reply, earlier); answered {
			return attemptOutcome{kind: attemptReply, packet: reply, err: err, verified: verified}
		}
		x.Logger.Print("ERROR out of order")
	}
}

// decode decodes a reply to the request: the header, for an SNMPv3 request
// the authentication and the scoped PDU, then the PDU. It reports whether the
// reply's digest checked against the request. The reply's security
// parameters are the request's with the USM fields the reply carries, keeping
// the request's keys only for the request's engine ID: no key derives for an
// engine a reply names.
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
		_, err = sp.receive(reply.MsgFlags, &w, false)
	}
	if err != nil {
		x.Logger.Printf("ERROR on unmarshall header: %s", err)
		return nil, false, err
	}
	if e.packet.Version == Version3 {
		if verified, err = e.authenticate(resp, &w, reply); err != nil {
			if e.unauthenticatedReport(resp, cursor, reply) {
				return reply, false, nil
			}
			x.Logger.Printf("ERROR on Test Authentication on v3: %s", err)
			return nil, false, err
		}
		if resp, cursor, err = unmarshalScopedPDU(resp, cursor, reply); err != nil {
			x.Logger.Printf("ERROR on the scoped PDU on v3: %s", err)
			return nil, false, err
		}
	}
	if err = unmarshalPayload(resp, cursor, reply); err != nil {
		x.Logger.Printf("ERROR on UnmarshalPayload: %s", err)
		return nil, false, err
	}
	return reply, verified, nil
}

// authenticate checks reply, an answer to an SNMPv3 request, against the
// request's security state (RFC 3412 section 7.2, RFC 3414 section 3.2): to a
// request that asks for authentication, it must ask for it too, name the
// request's user and engine ID, and carry a digest that checks with the
// request's key. It reports whether it checked the digest; any reply answers a
// request without authentication unchecked.
func (e *exchange) authenticate(resp []byte, w *v3Wire, reply *SnmpPacket) (bool, error) {
	if !e.packet.MsgFlags.authFlag() {
		return false, nil
	}
	if !reply.MsgFlags.authFlag() {
		return false, errNotAuthentic
	}
	authentic, err := e.packet.SecurityParameters.usm().isAuthenticAnswer(resp, w, reply.SecurityParameters.usm())
	if err != nil {
		return false, err
	}
	if !authentic {
		return false, errNotAuthentic
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
	resp, cursor, err := unmarshalScopedPDU(resp, cursor, reply)
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
// security model, level and context of RFC 3412 section 7.2 step 12 b, nor,
// for a request without authentication, the user and engine ID); an empty
// Response without an error status answers before its request ID is checked;
// a Response with request ID 0 answers any request.
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
// library knows, and ErrUnknownReportPDU for any other counter.
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
	// name names a resync Report in log lines.
	name string
}

// reportKinds are the counters of the USM (RFC 3414) and of message processing
// (RFC 3412) a Report can carry.
var reportKinds = map[string]reportKind{ //nolint:gochecknoglobals // a read-only table
	usmStatsUnsupportedSecLevels: {err: ErrUnknownSecurityLevel},
	usmStatsNotInTimeWindows:     {err: ErrNotInTimeWindow, resync: true, name: "out-of-time-window"},
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
