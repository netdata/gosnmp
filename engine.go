// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"errors"
	"fmt"
	"io"
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

	if x.Conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}
	if x.Retries < 0 {
		x.Retries = 0
	}
	if x.Logger.enabled() {
		x.Logger.Print("SEND INIT")
	}
	if packetOut.Version == Version3 {
		if x.Logger.enabled() {
			x.Logger.Print("SEND INIT NEGOTIATE SECURITY PARAMS")
		}
		if err = x.negotiateInitialSecurityParameters(packetOut); err != nil {
			return &SnmpPacket{}, err
		}
		if x.Logger.enabled() {
			x.Logger.Print("SEND END NEGOTIATE SECURITY PARAMS")
		}
	}

	var verified bool
	result, verified, err = x.sendOneRequest(packetOut)
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
	result, verified, err = x.sendOneRequest(packetOut)
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

// exchange is one request on its way through the attempts sendOneRequest
// makes.
type exchange struct {
	x      *GoSNMP
	packet *SnmpPacket

	// timeout is the current attempt's timeout; ExponentialTimeout doubles it
	// before each retry.
	timeout time.Duration
	// contextDeadline is set when the context's deadline, not the timeout,
	// ends the current attempt.
	contextDeadline bool
}

// attemptOutcome is how an attempt ended: with the request's result, or with
// a failure another attempt may cure.
type attemptOutcome struct {
	packet *SnmpPacket
	err    error
	// verified reports that packet's digest checked against the request
	// (exchange.authenticate).
	verified bool
	// retry asks for another attempt; err is the reason, nil after a TCP
	// reconnect.
	retry bool
}

// sentIDs are the request ID and the msgID an attempt sent the request with.
type sentIDs struct {
	requestID, msgID uint32
}

// sendOneRequest sends packetOut and returns the reply that answers it, and
// whether the reply's digest checked against the request, retrying up to
// x.Retries times. OnFinish runs when it succeeds.
func (x *GoSNMP) sendOneRequest(packetOut *SnmpPacket) (*SnmpPacket, bool, error) {
	e := exchange{x: x, packet: packetOut, timeout: x.Timeout}
	// The IDs of the attempts before the current one, in a local array, not a
	// field of exchange, so that eight of them stay on the stack: a field
	// would always escape to the heap, and a slice made for x.Retries+1 of
	// them escapes beyond 32 bytes.
	var sent [8]sentIDs
	earlier := sent[:0]
	var lastErr error
	for n := 0; ; n++ {
		if n > 0 {
			if err := e.beforeRetry(n, lastErr); err != nil {
				return nil, false, err
			}
		}
		out := e.attempt(earlier)
		if out.retry {
			// An attempt asks for a retry only after it has stamped the
			// packet with its IDs.
			earlier = append(earlier, sentIDs{packetOut.RequestID, packetOut.MsgID})
			lastErr = out.err
			continue
		}
		if out.err == nil && x.OnFinish != nil {
			x.OnFinish(x)
		}
		return out.packet, out.verified, out.err
	}
}

// beforeRetry runs before retry n, after an attempt that failed with lastErr.
// It returns the request's error when no retry follows: the context's
// deadline ended the attempt, or the retries are used up.
func (e *exchange) beforeRetry(n int, lastErr error) error {
	x := e.x
	// Known bug: OnRetry runs even when no retry follows.
	if x.OnRetry != nil {
		x.OnRetry(x)
	}
	x.Logger.Printf("Retry number %d. Last error was: %v", n, lastErr)

	if e.contextDeadline && isTimeout(lastErr) {
		return context.DeadlineExceeded
	}
	if n > x.Retries {
		switch {
		case lastErr == nil:
			return fmt.Errorf("max retries (%d) exceeded", x.Retries)
		case isTimeout(lastErr):
			return fmt.Errorf("request timeout (after %d retries)", n-1)
		}
		return lastErr
	}
	if x.ExponentialTimeout {
		// https://www.webnms.com/snmp/help/snmpapi/snmpv3/v1/timeout.html
		e.timeout *= 2
	}
	return nil
}

// isTimeout reports whether err ended an attempt by timing out. Known bug: it
// looks for the word in the error's text, so any error mentioning a timeout
// counts, and a nil err panics (the one after a TCP reconnect, under a context
// deadline; send recovers it).
func isTimeout(err error) bool {
	return strings.Contains(err.Error(), "timeout")
}

// attempt sends the request once and reads until a reply answers it or the
// attempt's deadline passes. A reply to an earlier attempt, one of earlier,
// answers it too.
func (e *exchange) attempt(earlier []sentIDs) attemptOutcome {
	x := e.x
	// Known bug: a client given a Conn without Connect has no Context, and this
	// panics (send recovers it).
	if err := x.Context.Err(); err != nil {
		return attemptOutcome{err: err}
	}
	var deadline time.Time
	deadline, e.contextDeadline = x.attemptDeadline(e.timeout)
	if err := x.Conn.SetDeadline(deadline); err != nil {
		return attemptOutcome{err: err}
	}

	e.packet.RequestID = x.nextRequestID()
	// An encoding failure is not retried: another attempt would fail the same
	// way.
	outBuf, err := e.encode()
	if err != nil {
		return attemptOutcome{err: err}
	}

	if x.PreSend != nil {
		x.PreSend(x)
	}
	if x.Logger.enabled() {
		x.Logger.Printf("SENDING PACKET: %s", e.packet.SafeString())
	}
	if err := x.write(outBuf); err != nil {
		return attemptOutcome{err: err, retry: true}
	}
	if x.OnSent != nil {
		x.OnSent(x)
	}
	return e.await(earlier)
}

// attemptDeadline returns when an attempt with timeout ends: after the
// timeout, or at the context's deadline if that comes first (byContext).
func (x *GoSNMP) attemptDeadline(timeout time.Duration) (deadline time.Time, byContext bool) {
	deadline = time.Now().Add(timeout)
	if ctxDeadline, ok := x.Context.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline, true
	}
	return deadline, false
}

// encode marshals the request, for SNMPv3 with a new message ID and privacy
// parameters. Known bug: it draws them by the client's version and flags,
// not the packet's, so a change of the client's version during a request (by
// its Logger or a hook) sends an SNMPv3 request with msgID 0.
func (e *exchange) encode() ([]byte, error) {
	x, p := e.x, e.packet
	// An authenticated request is signed with the user's key localized to the
	// agent's engine ID, and its answer checked with it; without one, anyone
	// could sign either. The check follows the packet, as the signature does
	// (SnmpPacket.sign).
	if usp := usmOf(p.SecurityParameters); p.Version == Version3 && p.MsgFlags.authFlag() &&
		(usp == nil || len(usp.SecretKey) == 0) {
		return nil, errAuthKeyRequired
	}
	if x.Version == Version3 {
		p.MsgID = x.nextMsgID()
		if err := x.initPacket(p); err != nil {
			return nil, err
		}
		p.SecurityParameters.Log()
	}
	out, err := p.marshalMsg()
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return out, nil
}

// await reads replies until one answers the request. Known bug: it does not
// watch the context, so a cancellation is noticed only when the attempt's
// deadline passes, and in the last attempt it ends as a request timeout.
func (e *exchange) await(earlier []sentIDs) attemptOutcome {
	x := e.x
	for {
		if x.Logger.enabled() {
			x.Logger.Print("WAITING RESPONSE...")
		}
		resp, err := x.receive()
		if err == io.EOF && strings.HasPrefix(x.Transport, tcp) {
			// The agent closed the connection: reconnect for the next attempt.
			x.Logger.Printf("ERROR: EOF. Performing reconnect")
			if err = x.netConnect(); err != nil {
				return attemptOutcome{err: err}
			}
			return attemptOutcome{retry: true}
		}
		if err != nil {
			return attemptOutcome{err: err, retry: true}
		}
		if x.OnRecv != nil {
			x.OnRecv(x)
		}
		if x.Logger.enabled() {
			x.Logger.Printf("GET RESPONSE OK: %+v", resp)
		}

		reply, verified, err := e.decode(resp)
		if err != nil {
			// Known bug: an undecodable reply ends the attempt, and the request
			// is sent again at once, instead of reading on.
			return attemptOutcome{err: err, retry: true}
		}
		if answered, err := e.answers(reply, earlier); answered {
			return attemptOutcome{packet: reply, err: err, verified: verified}
		}
		x.Logger.Print("ERROR out of order")
	}
}

// decode decodes a reply to the request: the header, for an SNMPv3 request
// the authentication and the scoped PDU, then the PDU. It reports whether the
// reply's digest checked against the request.
func (e *exchange) decode(resp []byte) (_ *SnmpPacket, verified bool, _ error) {
	x := e.x
	// Known bug: a reply with an empty msgFlags keeps the request's flags.
	reply := &SnmpPacket{Logger: x.Logger, MsgFlags: e.packet.MsgFlags}
	if e.packet.SecurityParameters != nil {
		reply.SecurityParameters = e.packet.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(resp, reply)
	if err != nil {
		x.Logger.Printf("ERROR on unmarshall header: %s", err)
		return nil, false, err
	}
	if e.packet.Version == Version3 {
		if verified, err = e.authenticate(resp, reply); err != nil {
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
func (e *exchange) authenticate(resp []byte, reply *SnmpPacket) (bool, error) {
	if !e.packet.MsgFlags.authFlag() {
		return false, nil
	}
	if !reply.MsgFlags.authFlag() {
		return false, errNotAuthentic
	}
	authentic, err := e.packet.SecurityParameters.usm().isAuthenticAnswer(resp, reply.SecurityParameters.usm())
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
