// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
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
	_, committed, err := x.sendOneRequest(cfg, discoveryPacket, true)
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

// errOtherSecurityModel is the error of a reply whose security model is not
// its request's.
var errOtherSecurityModel = errors.New("connection security model does not match security model extracted from packet")

// settle commits the engine state an SNMPv3 reply that answers the exchange's
// request carries, after the match, and returns out, the attempt's outcome,
// with the commit or its error. A discovery answer (an unknownEngineIDs Report,
// or the unknownUserNames Report some devices send, carrying an engine ID)
// gives the engine ID, its keys, boots and time, or ends the request when it
// names no engine ID or the keys do not derive. Another reply gives its engine
// boots and time when its digest checked against the request (verified), and
// an unverified one only to a request without authentication and when it is
// not a Report: then also its engine ID, which takes keys derived for it, and
// a reply whose engine ID gives no valid state answers without a commit (RFC
// 3414 section 3.2 step 7 takes the engine boots and time from authenticated
// messages only). A reply of another security model than the request's ends
// the request, unless it is an error Report. Known bug: a reply with another
// security model is not discarded (RFC 3412 section 7.2 step 4).
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
	if e.packet.SecurityModel != reply.SecurityModel {
		if e.discovery || !isReport || kind.resync {
			out.err = errOtherSecurityModel
		}
		return out
	}
	if x.Logger.enabled() {
		x.Logger.Printf("SEND STORE SECURITY PARAMS from result: %s", reply.SecurityParameters.SafeString())
	}
	from := reply.SecurityParameters.usm()
	next, err := x.engine.withEngine(from.AuthoritativeEngineID)
	if err != nil {
		if e.discovery {
			out.err = err
		}
		return out
	}
	next.boots, next.engineTime = from.AuthoritativeEngineBoots, from.AuthoritativeEngineTime
	x.commitEngine(next)
	out.committed = true
	return out
}

// mayLend reports whether report, a resync Report of kind the client did not
// store, may lend its engine parameters to the resend of packetOut. A request
// without authentication carries no signature to misuse. An authenticated
// request is signed with what the Report names, so it takes only the engine
// boots and time of a Report that names the request's engine ID (RFC 3414
// section 3.2 checks the engine ID before the time window), and only as a
// read request, whose copy an on-path sender could replay only as that read
// later (step 7 a accepts a time within 150 s of the agent's). It never takes
// an engine ID: the request would be signed for another engine with the same
// credentials (section 1.5.2).
func mayLend(packetOut, report *SnmpPacket, kind reportKind) bool {
	if !packetOut.MsgFlags.authFlag() {
		return true
	}
	switch packetOut.PDUType {
	case GetRequest, GetNextRequest, GetBulkRequest:
	default:
		return false
	}
	if kind.namesEngine {
		return false
	}
	return report.SecurityParameters.usm().AuthoritativeEngineID == packetOut.SecurityParameters.usm().AuthoritativeEngineID
}

// lendEngineParameters puts the engine parameters of report, a resync Report
// the client does not store, into packetOut only, for one resend: the engine
// ID, boots and time of a Report that names the engine (the packet's keys are
// localized to that engine ID, and the context engine ID follows it unless
// the caller configured one), the boots and time of another (RFC 3414 section
// 3.2 checks the engine ID before the time window). The client takes the
// agent's from the authenticated answer.
func (x *GoSNMP) lendEngineParameters(packetOut, report *SnmpPacket, kind reportKind) error {
	from, sp := report.SecurityParameters.usm(), packetOut.SecurityParameters.usm()
	if kind.namesEngine {
		authKey, privKey, err := sp.keysFor(from.AuthoritativeEngineID)
		if err != nil {
			return err
		}
		sp.AuthoritativeEngineID, sp.SecretKey, sp.PrivacyKey = from.AuthoritativeEngineID, authKey, privKey
		if x.engine.context == "" {
			packetOut.ContextEngineID = from.AuthoritativeEngineID
		}
	}
	sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = from.AuthoritativeEngineBoots, from.AuthoritativeEngineTime
	return nil
}
