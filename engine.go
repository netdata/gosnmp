// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"time"
)

// send runs a request: for SNMPv3 it first discovers the agent's engine or
// derives the keys, then sends the request, and sends it once more when the
// answer is a Report that resynchronizes the client with the agent's engine.
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

	result, err = x.sendOneRequest(packetOut)
	if err != nil {
		// Known bug: the engine boots and time of an authenticated error Report
		// are not stored.
		x.Logger.Printf("SEND Error on the first Request Error: %s", err)
		return result, err
	}
	if result.Version != Version3 {
		return result, nil
	}

	if x.Logger.enabled() {
		x.Logger.Printf("SEND STORE SECURITY PARAMS from result: %s", result.SecurityParameters.SafeString())
	}
	err = x.storeSecurityParameters(result)
	if kind, ok := reportKindOf(result); ok && kind.resync {
		// Known bug: the store error is dropped, so a Report with another
		// security model is acted on instead of being discarded.
		return x.resync(packetOut, kind)
	}
	// Known bug: a reply with another security model is returned together
	// with the store error.
	return result, err
}

// resync sends packetOut again after a Report of kind, with the engine ID or
// time the client stored from it. Known bugs: a failed retransmission returns
// the first Report's error instead of its own; a resync Report answering the
// retransmission is returned with a nil error; the engine boots and time of
// the answer to the retransmission are not stored.
func (x *GoSNMP) resync(packetOut *SnmpPacket, kind reportKind) (*SnmpPacket, error) {
	if x.Logger.enabled() {
		x.Logger.Print("WARNING detected " + kind.name + " ERROR")
	}
	if err := x.updatePktSecurityParameters(packetOut); err != nil {
		x.Logger.Printf("ERROR updatePktSecurityParameters error: %s", err)
		return nil, err
	}
	result, err := x.sendOneRequest(packetOut)
	if err != nil {
		if x.Logger.enabled() {
			x.Logger.Printf("ERROR "+kind.name+" retransmit error: %s", err)
		}
		return result, kind.err
	}
	return result, nil
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
	// retry asks for another attempt; err is the reason, nil after a TCP
	// reconnect.
	retry bool
}

// sendOneRequest sends packetOut and returns the reply that answers it,
// retrying up to x.Retries times. OnFinish runs when it succeeds.
func (x *GoSNMP) sendOneRequest(packetOut *SnmpPacket) (*SnmpPacket, error) {
	e := exchange{x: x, packet: packetOut, timeout: x.Timeout}
	// The request IDs of the attempts before the current one. A local, not a
	// field of exchange: for small Retries it stays on the stack, where a field
	// would always escape to the heap.
	earlierIDs := make([]uint32, 0, x.Retries+1)
	var lastErr error
	for n := 0; ; n++ {
		if n > 0 {
			if err := e.beforeRetry(n, lastErr); err != nil {
				return nil, err
			}
		}
		out := e.attempt(earlierIDs)
		if out.retry {
			// An attempt asks for a retry only after it has stamped the
			// packet with its request ID.
			earlierIDs = append(earlierIDs, packetOut.RequestID)
			lastErr = out.err
			continue
		}
		if out.err == nil && x.OnFinish != nil {
			x.OnFinish(x)
		}
		return out.packet, out.err
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
// attempt's deadline passes. A reply to an earlier attempt, whose request ID
// is one of earlierIDs, answers it too.
func (e *exchange) attempt(earlierIDs []uint32) attemptOutcome {
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
	return e.await(earlierIDs)
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
// parameters.
func (e *exchange) encode() ([]byte, error) {
	x, p := e.x, e.packet
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
func (e *exchange) await(earlierIDs []uint32) attemptOutcome {
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

		reply, err := e.decode(resp)
		if err != nil {
			// Known bug: an undecodable reply ends the attempt, and the request
			// is sent again at once, instead of reading on.
			return attemptOutcome{err: err, retry: true}
		}
		if answered, err := e.answers(reply, earlierIDs); answered {
			return attemptOutcome{packet: reply, err: err}
		}
		x.Logger.Print("ERROR out of order")
	}
}

// decode decodes a reply to the request: the header, for an SNMPv3 client the
// authentication and the scoped PDU, then the PDU.
func (e *exchange) decode(resp []byte) (*SnmpPacket, error) {
	x := e.x
	// Known bug: a reply with an empty msgFlags keeps the request's flags.
	reply := &SnmpPacket{Logger: x.Logger, MsgFlags: e.packet.MsgFlags}
	if e.packet.SecurityParameters != nil {
		reply.SecurityParameters = e.packet.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(resp, reply)
	if err != nil {
		x.Logger.Printf("ERROR on unmarshall header: %s", err)
		return nil, err
	}
	if x.Version == Version3 {
		// Until discovery has set the authoritative engine ID, the reply is
		// checked with its own flags and the security parameters it carries,
		// afterwards with the client's. Known bug: an unauthenticated Report
		// then fails the digest check and is discarded, and the caller never
		// sees its error.
		usp := usmOf(x.SecurityParameters)
		fromReply := usp != nil && usp.AuthoritativeEngineID == ""
		if err = x.testAuthentication(resp, reply, fromReply); err != nil {
			x.Logger.Printf("ERROR on Test Authentication on v3: %s", err)
			return nil, err
		}
		if resp, cursor, err = unmarshalScopedPDU(resp, cursor, reply); err != nil {
			x.Logger.Printf("ERROR on decryptPacket on v3: %s", err)
			return nil, err
		}
	}
	if err = unmarshalPayload(resp, cursor, reply); err != nil {
		x.Logger.Printf("ERROR on UnmarshalPayload on v3: %s", err)
		return nil, err
	}
	return reply, nil
}

// answers reports whether reply answers the request, and with which error: a
// reply answers with the current attempt's request ID or one of earlierIDs;
// a Report gives its kind's error, none for a resync Report. Known bugs:
// nothing else of the reply is compared with the request (its version, PDU
// type and msgID, nor the security model, level, user, engine ID and context
// of RFC 3412 section 7.2 step 12 b); an empty reply without an error status
// and a Report answer before their request ID is checked; request ID 0 answers
// any request.
func (e *exchange) answers(reply *SnmpPacket, earlierIDs []uint32) (bool, error) {
	if reply.Error == NoError && len(reply.Variables) < 1 {
		e.x.Logger.Printf("ERROR on UnmarshalPayload on v3: Empty result")
		return true, nil
	}
	if kind, ok := reportKindOf(reply); ok {
		if kind.resync {
			return true, nil
		}
		return true, kind.err
	}
	id := reply.RequestID
	return id == e.packet.RequestID || slices.Contains(earlierIDs, id) || id == 0, nil
}

// reportKind is what the counter an SNMPv3 Report carries means to a request.
type reportKind struct {
	// err is the request's error.
	err error
	// resync marks the Reports that say the request's engine ID or time is
	// out of date: they answer without err, the caller takes the engine
	// parameters they carry, and send, when it is the caller, sends the request
	// again and returns err only if that fails.
	resync bool
	// name names a resync Report in log lines.
	name string
}

// reportKinds are the counters of the USM (RFC 3414) and of message processing
// (RFC 3412) a Report can carry.
var reportKinds = map[string]reportKind{ //nolint:gochecknoglobals // a read-only table
	usmStatsUnsupportedSecLevels: {err: ErrUnknownSecurityLevel},
	usmStatsNotInTimeWindows:     {err: ErrNotInTimeWindow, resync: true, name: "out-of-time-window"},
	usmStatsUnknownUserNames:     {err: ErrUnknownUsername},
	usmStatsUnknownEngineIDs:     {err: ErrUnknownEngineID, resync: true, name: "unknown engine id"},
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
