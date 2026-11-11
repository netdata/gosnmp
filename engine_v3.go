// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// negotiateInitialSecurityParameters prepares req's security parameters
// before an SNMPv3 request: it discovers the agent's engine while the engine
// state has no engine ID, and gives req the engine state. A failed
// discovery returns its error with the answer that ended it, if any.
func (c *Client) negotiateInitialSecurityParameters(ctx context.Context, req *Message) (*Message, error) {
	if len(c.engine.engineID) == 0 {
		return c.discoverEngine(ctx, req)
	}
	c.engine.stamp(req)
	return nil, nil
}

// discoverEngine runs engine discovery (RFC 3414 section 4): it sends the
// discovery request, whose answer the attempt commits into the engine state
// (exchange.settle), and gives req the engine state. A discovery whose
// answer was not committed returns its error with the answer, if any.
func (c *Client) discoverEngine(ctx context.Context, req *Message) (*Message, error) {
	discovery := newDiscoveryRequest()
	discovery.ContextName = req.ContextName
	answer, committed, err := c.sendOneRequest(ctx, discovery, true, attemptSecurity{})
	if !committed {
		return answer, err
	}
	c.engine.stamp(req)
	return nil, nil
}

// newDiscoveryRequest returns the request that discovers the authoritative
// engine's ID, boots and time (RFC 3414 section 4): an unauthenticated Get
// without variable bindings and with empty security parameters, which the
// encoder sends reportable as every request.
func newDiscoveryRequest() *Message {
	return &Message{
		Version:       Version3,
		SecurityLevel: NoAuthNoPriv,
		PDUType:       GetRequest,
	}
}

// engineFoundDespiteUnknownUser reports whether a discovery that failed with
// ErrUnknownUsername still found the engine: some devices (e.g. Dell EMC
// switches) answer discovery with usmStatsUnknownUserNames instead of
// usmStatsUnknownEngineIDs, with valid engine parameters.
func engineFoundDespiteUnknownUser(result *Message, err error) bool {
	if !errors.Is(err, ErrUnknownUsername) || result == nil {
		return false
	}
	return len(result.SecurityParameters.AuthoritativeEngineID) != 0
}

// errReplyNotInTime is the error of an authenticated reply outside the time
// window (RFC 3414 section 3.2 step 7 b).
var errReplyNotInTime = inCategory(ErrNotInTimeWindow, errors.New("the reply is not in the time window"))

// settle commits the engine state an SNMPv3 reply that answers the exchange's
// request carries, after the match, and returns out, the attempt's outcome,
// with the commit or its error, or, for an authenticated reply outside the time
// window, the error that discards it. A discovery answer (an unknownEngineIDs
// Report, the unknownUserNames Report some devices send, or a notInTimeWindows
// Report, carrying an engine ID) gives the engine ID, its keys and an
// unauthenticated clock, or ends the request when it names no engine ID or the
// keys do not derive. A reply whose digest checked against the request
// (verified) gives its engine ID (another one takes keys derived for it, and no
// clock) and the clock replyClock gives; maximum boots are rejected before
// either recovery exception. Unverified, a Response, which answers only a
// request without authentication and names its engine ID (exchange.answers: the
// engine state's, a lent one, or none for discovery), gives that engine ID and
// the clock replyClock gives. A reply whose engine ID gives no valid state
// answers without a commit.
func (e *exchange) settle(out attemptOutcome) (attemptOutcome, error) {
	c, reply := e.c, out.reply
	if reply.Version != Version3 {
		return out, nil
	}
	kind, isReport := reportKindOf(reply)
	switch {
	case e.discovery:
		if out.err != nil && !engineFoundDespiteUnknownUser(reply, out.err) {
			return out, nil
		}
	case !out.verified && isReport:
		return out, nil
	}
	from := &reply.SecurityParameters
	boots, engineTime := from.AuthoritativeEngineBoots, from.AuthoritativeEngineTime
	// Recovery relaxes clock ordering, never the terminal maximum-boots rule.
	if out.verified && boots == maxEngineValue {
		return attemptOutcome{}, errReplyNotInTime
	}
	next, err := c.engine.withEngine(&c.config.User, from.AuthoritativeEngineID)
	if err != nil {
		if e.discovery {
			out.err = err
		}
		return out, nil
	}
	clock, ok := e.replyClock(next.clock, out.verified, kind, boots, engineTime, time.Now())
	if !ok {
		return attemptOutcome{}, errReplyNotInTime
	}
	next.clock = clock
	c.commitEngine(next)
	out.committed = true
	return out, nil
}

// replyClock returns the clock the engine state takes from a reply that
// settles (settle), with engine boots and time received at now, given the
// clock the state has for the reply's engine ID (current); false for an
// authenticated reply outside the time window, which is discarded. An
// unverified reply gives an unauthenticated clock, which does not replace an
// authenticated one (net-snmp's set_enginetime). A verified reply's boots and
// time go by RFC 3414 section 3.2 step 7 b against the authenticated clock
// (none: the first authenticated message); an equal time updates the clock as
// a newer one does (net-snmp; a reply answers an outstanding request, so it
// replays nothing), and a reply outside the time window is discarded
// (resetsClock names the exception; an exchange that ends without an answer
// after one drops the clock, forgetEngineTime). An authenticated
// notInTimeWindow Report gives its boots and time whatever their order: the
// agent's own, matched to the request (a deviation from section 3.2 step 7 b,
// for devices whose boots do not go up when they restart).
func (e *exchange) replyClock(current sourcedClock, verified bool, kind reportKind, boots, engineTime uint32, now time.Time) (sourcedClock, bool) {
	switch {
	case !verified:
		if current.source == fromAuthenticated {
			return current, true
		}
		return clockOf(boots, engineTime, now, fromUnauthenticated), true
	case kind.timeWindow:
		return clockOf(boots, engineTime, now, fromAuthenticated), true
	}
	var clock engineClock
	if current.source == fromAuthenticated {
		clock = current.engineClock
	}
	clock, _ = clock.update(boots, engineTime, now, true)
	if !clock.inWindow(boots, engineTime, now) {
		if !e.resetsClock(boots, engineTime, now) {
			return sourcedClock{}, false
		}
		clock = engineClock{boots: boots, latest: engineTime, received: now}
	}
	return sourcedClock{clock, fromAuthenticated}, true
}

// forgetEngineTime drops the engine state's clock after an exchange that
// discarded an authentic answer outside the time window (settle) ended without
// an answer: the agent's answers contradict the clock and no Report corrects
// it, as from a device that does not check the time of requests and whose
// engine time went back without its boots going up, or whose boots went down
// (a failover pair sharing an engine ID). The next request carries boots and
// time zero, which a device that checks the time window answers with an
// authenticated notInTimeWindow Report carrying its own, and the next
// authentic answer of one that does not is its first (the reset of RFC 3414
// section 2.3). A deviation from section 3.2 step 7 b and net-snmp, which
// reject such a device until the client forgets its time by other means.
func (c *Client) forgetEngineTime() {
	next := c.engine
	next.clock = sourcedClock{}
	c.commitEngine(next)
}

// resetsClock reports whether a verified reply with engine boots and time
// received at now, outside the time window of the engine state's clock,
// answers a resend an unauthenticated notInTimeWindow Report lent its clock
// to, with that clock's boots and a time within timeWindow seconds of its
// notion: the agent accepted the lent time and answered authentically, so its
// boots and time become the clock. Devices that do not raise their boots when
// they restart, and report notInTimeWindow without authentication, so recover;
// a forged Report gets no such answer (net-snmp locks such devices out).
// settle has already rejected maximum engine boots.
func (e *exchange) resetsClock(boots, engineTime uint32, now time.Time) bool {
	lent := e.sec.clock
	if lent.source != fromTimeWindowReport || boots != lent.boots {
		return false
	}
	d := int64(engineTime) - lent.local(now)
	return -timeWindow <= d && d <= timeWindow
}

// mayLend reports whether report, a resync Report of kind the client did not
// store, may lend its engine parameters to the resend of req. A request
// without authentication carries no signature to misuse. An authenticated
// request is signed with what the Report names, so it takes only the engine
// boots and time of a Report that names the request's engine ID (RFC 3414
// section 3.2 checks the engine ID before the time window): it is a read
// request (send), whose copy an on-path sender could replay only as that read
// later (step 7 a accepts a time within 150 s of the agent's), the rule of
// every unauthenticated clock (sourcedClock.timeFor). It never takes an engine
// ID: the request would be signed for another engine with the same
// credentials (section 1.5.2).
func mayLend(req, report *Message, kind reportKind) bool {
	if !req.SecurityLevel.authFlag() {
		return true
	}
	if kind.namesEngine {
		return false
	}
	return bytes.Equal(report.SecurityParameters.AuthoritativeEngineID, req.SecurityParameters.AuthoritativeEngineID)
}

// lendEngineParameters lends the engine parameters of report, a resync Report
// the client does not store, to the resend of req only, which the
// request's attempts so far made with sec: it gives req the engine ID of
// a Report that names the engine and its context engine ID, and the resend the
// keys localized to it (by the rule of a commit, withEngine: an error for an
// empty one), and the clock of the Report's boots and time, received now (RFC
// 3414 section 3.2 checks the engine ID before the time window). The client
// takes the agent's from the authenticated answer.
func (c *Client) lendEngineParameters(req, report *Message, kind reportKind, sec attemptSecurity) (attemptSecurity, error) {
	from := &report.SecurityParameters
	if kind.namesEngine {
		lent, err := c.engine.withEngine(&c.config.User, from.AuthoritativeEngineID)
		if err != nil {
			return attemptSecurity{}, err
		}
		lent.stamp(req)
		sec.keys = lent.keys
	}
	source := fromUnauthenticated
	if kind.timeWindow {
		source = fromTimeWindowReport
	}
	sec.clock = clockOf(from.AuthoritativeEngineBoots, from.AuthoritativeEngineTime, time.Now(), source)
	return sec, nil
}
