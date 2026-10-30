// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"time"
)

// negotiateInitialSecurityParameters prepares packetOut's security parameters
// before an SNMPv3 request: it discovers the agent's engine while the engine
// state has no engine ID, and gives packetOut the engine state.
func (x *GoSNMP) negotiateInitialSecurityParameters(cfg *requestConfig, packetOut *SnmpPacket) error {
	if x.engine.engineID == "" {
		return x.discoverEngine(cfg, packetOut)
	}
	x.engine.stamp(packetOut)
	return nil
}

// discoverEngine runs engine discovery (RFC 3414 section 4): it sends the
// discovery request, whose answer the attempt commits into the engine state
// (exchange.settle), and gives packetOut the engine state.
func (x *GoSNMP) discoverEngine(cfg *requestConfig, packetOut *SnmpPacket) error {
	discoveryPacket := newDiscoveryPacket(packetOut.SecurityParameters.usm().Logger)
	discoveryPacket.ContextName = packetOut.ContextName
	_, committed, err := x.sendOneRequest(cfg, discoveryPacket, true, sourcedClock{})
	if !committed {
		return err
	}
	x.engine.stamp(packetOut)
	return nil
}

// engineFoundDespiteUnknownUser reports whether a discovery that failed with
// ErrUnknownUsername still found the engine: some devices (e.g. Dell EMC
// switches) answer discovery with usmStatsUnknownUserNames instead of
// usmStatsUnknownEngineIDs, with valid engine parameters.
func engineFoundDespiteUnknownUser(result *SnmpPacket, err error) bool {
	if !errors.Is(err, ErrUnknownUsername) || result == nil {
		return false
	}
	usp := usmOf(result.SecurityParameters)
	return usp != nil && usp.AuthoritativeEngineID != ""
}

// errReplyNotInTime is the error of an authenticated reply outside the time
// window (RFC 3414 section 3.2 step 7 b).
var errReplyNotInTime = inCategory(ErrNotInTimeWindow, errors.New("the reply is not in the time window"))

// settle commits the engine state an SNMPv3 reply that answers the exchange's
// request carries, after the match, and returns out, the attempt's outcome,
// with the commit or its error, or a failed attempt for an authenticated reply
// outside the time window. A discovery answer (an unknownEngineIDs Report, or
// the unknownUserNames Report some devices send, carrying an engine ID) gives
// the engine ID, its keys and an unauthenticated clock, or ends the request
// when it names no engine ID or the keys do not derive. A reply whose digest
// checked against the request (verified) gives its engine ID (another one takes
// keys derived for it, and no clock) and, by RFC 3414 section 3.2 step 7 b
// against the authenticated clock (none: the first authenticated message), its
// boots and time; an equal time updates the clock as a newer one does
// (net-snmp; a reply answers an outstanding request, so it replays nothing),
// and a reply outside the time window is rejected (resetsClock names the
// exception; a request that ends so drops the clock, forgetEngineTime).
// Maximum boots are rejected before either recovery exception. An
// authenticated notInTimeWindow Report gives its boots and time whatever their
// order: the agent's own, matched to the request (a deviation from section 3.2
// step 7 b, for devices whose boots do not go up when they restart).
// Unverified, a reply to a request without authentication that is not a Report
// gives its engine ID and an unauthenticated clock, which does not replace an
// authenticated one (net-snmp's set_enginetime). A reply whose engine ID gives
// no valid state answers without a commit.
func (e *exchange) settle(out attemptOutcome) attemptOutcome {
	x, reply := e.x, out.packet
	if reply.Version != Version3 {
		return out
	}
	kind, isReport := reportKindOf(reply)
	switch {
	case e.discovery:
		if out.err != nil && !engineFoundDespiteUnknownUser(reply, out.err) {
			return out
		}
	case !out.verified && (isReport || e.packet.MsgFlags.authFlag()):
		return out
	}
	from := reply.SecurityParameters.usm()
	boots, engineTime := from.AuthoritativeEngineBoots, from.AuthoritativeEngineTime
	// Recovery relaxes clock ordering, never the terminal maximum-boots rule.
	if out.verified && boots == maxEngineValue {
		if x.Logger.enabled() {
			x.Logger.Print("ERROR the reply carries exhausted engine boots")
		}
		return attemptOutcome{kind: attemptInvalidReply, err: errReplyNotInTime}
	}
	next, err := x.engine.withEngine(from.AuthoritativeEngineID)
	if err != nil {
		if e.discovery {
			out.err = err
		}
		return out
	}
	now := time.Now()
	switch {
	case !out.verified:
		if next.clock.source != fromAuthenticated {
			next.clock = clockOf(boots, engineTime, now, fromUnauthenticated)
		}
	case kind.timeWindow:
		next.clock = clockOf(boots, engineTime, now, fromAuthenticated)
	default:
		var clock engineClock
		if next.clock.source == fromAuthenticated {
			clock = next.clock.engineClock
		}
		clock, _ = clock.update(boots, engineTime, now, true)
		if !clock.inWindow(boots, engineTime, now) {
			if !e.resetsClock(boots, engineTime, now) {
				if x.Logger.enabled() {
					x.Logger.Printf("ERROR the reply is not in the time window: boots %d, time %d", boots, engineTime)
				}
				return attemptOutcome{kind: attemptInvalidReply, err: errReplyNotInTime}
			}
			clock = engineClock{boots: boots, latest: engineTime, received: now}
		}
		next.clock = sourcedClock{clock, fromAuthenticated}
	}
	x.commitEngine(next)
	out.committed = true
	if x.Logger.enabled() {
		x.Logger.Printf("SEND STORE SECURITY PARAMS from result: %s", reply.SecurityParameters.SafeString())
	}
	return out
}

// forgetEngineTime drops the engine state's clock after a request whose last
// attempt was answered, authentically, outside the time window (settle): the
// agent's answers contradict the clock and no Report corrects it, as from a
// device that does not check the time of requests and whose engine time went
// back without its boots going up, or whose boots went down (a failover pair
// sharing an engine ID). The next request carries boots and time zero, which a
// device that checks the time window answers with an authenticated
// notInTimeWindow Report carrying its own, and the next authentic answer of
// one that does not is its first (the reset of RFC 3414 section 2.3). A
// deviation from section 3.2 step 7 b and net-snmp, which reject such a device
// until the client forgets its time by other means.
func (x *GoSNMP) forgetEngineTime() {
	next := x.engine
	next.clock = sourcedClock{}
	x.commitEngine(next)
	if x.Logger.enabled() {
		x.Logger.Print("WARNING the agent's answers are outside the time window: the engine time is dropped")
	}
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
	lent := e.clock
	if lent.source != fromTimeWindowReport || boots != lent.boots {
		return false
	}
	d := int64(engineTime) - lent.local(now)
	return -timeWindow <= d && d <= timeWindow
}

// mayLend reports whether report, a resync Report of kind the client did not
// store, may lend its engine parameters to the resend of packetOut. A request
// without authentication carries no signature to misuse. An authenticated
// request is signed with what the Report names, so it takes only the engine
// boots and time of a Report that names the request's engine ID (RFC 3414
// section 3.2 checks the engine ID before the time window), and only as a
// read request, whose copy an on-path sender could replay only as that read
// later (step 7 a accepts a time within 150 s of the agent's): the rule of
// every unauthenticated clock (sourcedClock.timeFor). It never takes an engine
// ID: the request would be signed for another engine with the same
// credentials (section 1.5.2).
func mayLend(packetOut, report *SnmpPacket, kind reportKind) bool {
	if !packetOut.MsgFlags.authFlag() {
		return true
	}
	if !packetOut.PDUType.read() || kind.namesEngine {
		return false
	}
	return report.SecurityParameters.usm().AuthoritativeEngineID == packetOut.SecurityParameters.usm().AuthoritativeEngineID
}

// lendEngineParameters lends the engine parameters of report, a resync Report
// the client does not store, to the resend of packetOut only: it gives
// packetOut the engine ID of a Report that names the engine (by the rule of a
// commit, withEngine: keys localized to that engine ID, an error for an empty
// one; the context engine ID follows it unless the caller configured one), and
// returns the clock of the Report's boots and time, received now, which the
// resend's attempts carry (RFC 3414 section 3.2 checks the engine ID before
// the time window). The client takes the agent's from the authenticated
// answer.
func (x *GoSNMP) lendEngineParameters(packetOut, report *SnmpPacket, kind reportKind) (sourcedClock, error) {
	from, sp := report.SecurityParameters.usm(), packetOut.SecurityParameters.usm()
	if kind.namesEngine {
		lent, err := x.engine.withEngine(from.AuthoritativeEngineID)
		if err != nil {
			return sourcedClock{}, err
		}
		sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey = lent.engineID, lent.authKey, lent.privKey
		packetOut.ContextEngineID = lent.contextEngineID()
	}
	source := fromUnauthenticated
	if kind.timeWindow {
		source = fromTimeWindowReport
	}
	return clockOf(from.AuthoritativeEngineBoots, from.AuthoritativeEngineTime, time.Now(), source), nil
}
