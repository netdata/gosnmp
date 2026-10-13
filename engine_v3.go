// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
)

// negotiateInitialSecurityParameters prepares packetOut's security parameters
// before an SNMPv3 request: it discovers the agent's engine while the client
// does not know its engine ID, and derives the keys otherwise. Known bug: the
// key derivation error is ignored when the engine ID is known.
func (x *GoSNMP) negotiateInitialSecurityParameters(packetOut *SnmpPacket) error {
	// mkSnmpPacket copies the client's version and security model into the
	// packet; they differ here only when the client's Logger changed the client
	// during send.
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("negotiateInitialSecurityParameters called with non Version3 connection or packet")
	}
	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model defined in packet")
	}
	if discoveryPacket := packetOut.SecurityParameters.usm().discoveryRequired(); discoveryPacket != nil {
		return x.discoverEngine(discoveryPacket, packetOut)
	}
	_ = packetOut.SecurityParameters.InitSecurityKeys()
	return nil
}

// discoverEngine runs engine discovery (RFC 3414 section 4): it sends
// discoveryPacket and takes the agent's engine parameters from the answer into
// the client and packetOut. Known bugs: a discovery Report with another
// security model fails the request instead of being discarded; an answer
// without an engine ID is accepted, so the request goes out with an empty
// engine ID (at authPriv it fails in the encoder for want of a privacy key).
func (x *GoSNMP) discoverEngine(discoveryPacket, packetOut *SnmpPacket) error {
	discoveryPacket.ContextName = x.ContextName
	result, _, err := x.sendOneRequest(discoveryPacket)
	if err != nil && !engineFoundDespiteUnknownUser(result, err) {
		return err
	}
	if err = x.storeSecurityParameters(result); err != nil {
		return err
	}
	return x.updatePktSecurityParameters(packetOut)
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

// settleReply stores the engine parameters an SNMPv3 reply to packetOut
// carries, and returns the reply's Report kind (zero for another reply),
// whether its parameters were stored, and the error the request ends with
// unless kind asks for a resync: err, or the store's for a reply other than
// an error Report. A reply is stored when its digest checked against the
// request (verified), so it names the request's engine; an unverified one only
// in a noAuthNoPriv session, and never a Report (RFC 3414 section 3.2 step 7
// takes the engine boots and time from authenticated messages only; discovery,
// which takes the engine ID from an unauthenticated Report, section 4, is
// discoverEngine's). Known bug: a reply with another security model is not
// discarded (RFC 3412 section 7.2 step 4).
func (x *GoSNMP) settleReply(packetOut, reply *SnmpPacket, verified bool, err error) (kind reportKind, stored bool, _ error) {
	if reply == nil || reply.Version != Version3 {
		return reportKind{}, false, err
	}
	kind, isReport := reportKindOf(reply)
	if !verified && (isReport || packetOut.MsgFlags.authFlag()) {
		return kind, false, err
	}
	if x.Logger.enabled() {
		x.Logger.Printf("SEND STORE SECURITY PARAMS from result: %s", reply.SecurityParameters.SafeString())
	}
	if storeErr := x.storeSecurityParameters(reply); storeErr != nil {
		if isReport && !kind.resync {
			return kind, false, err
		}
		return reportKind{}, false, storeErr
	}
	return kind, true, err
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
// localized to that engine ID, and the engine ID becomes the context engine
// ID when the packet has none), the boots and time of another (RFC 3414
// section 3.2 checks the engine ID before the time window). The client takes
// the agent's from the authenticated answer.
func (x *GoSNMP) lendEngineParameters(packetOut, report *SnmpPacket, kind reportKind) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("lendEngineParameters called with non Version3 connection or packet")
	}
	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model defined in packet")
	}
	from := report.SecurityParameters.usm()
	if !kind.namesEngine {
		packetOut.SecurityParameters.usm().setEngineTime(from)
		return nil
	}
	if err := packetOut.SecurityParameters.usm().setSecurityParameters(from); err != nil {
		return err
	}
	if packetOut.ContextEngineID == "" {
		packetOut.ContextEngineID = from.AuthoritativeEngineID
	}
	return nil
}

// save the connection security parameters after a request/response
func (x *GoSNMP) storeSecurityParameters(result *SnmpPacket) error {
	if x.Version != Version3 || result.Version != Version3 {
		return fmt.Errorf("storeParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != result.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	// Known bug: the context engine ID is taken only while the client has
	// none, so it stays the old engine's after the client adopts a new engine
	// ID.
	if x.ContextEngineID == "" {
		x.ContextEngineID = result.SecurityParameters.usm().AuthoritativeEngineID
	}

	return x.SecurityParameters.usm().setSecurityParameters(result.SecurityParameters.usm())
}

// update packet security parameters to match connection security parameters
func (x *GoSNMP) updatePktSecurityParameters(packetOut *SnmpPacket) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("updatePktSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	err := packetOut.SecurityParameters.usm().setSecurityParameters(x.SecurityParameters.usm())
	if err != nil {
		return err
	}

	if packetOut.ContextEngineID == "" {
		packetOut.ContextEngineID = x.ContextEngineID
	}

	return nil
}
