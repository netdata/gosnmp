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
	result, err := x.sendOneRequest(discoveryPacket)
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
// unless kind asks for a resync: err, or the store's. A reply that is not
// SNMPv3 is not stored, nor is an unauthenticated Report: RFC 3414 section 3.2
// step 7 takes the engine boots and time from authenticated messages only,
// and discovery, which takes the engine ID from an unauthenticated Report
// (section 4), is discoverEngine's. Known bug: a reply with another security
// model ends the request with the store error instead of being discarded (RFC
// 3412 section 7.2 step 4).
func (x *GoSNMP) settleReply(packetOut, reply *SnmpPacket, err error) (kind reportKind, stored bool, _ error) {
	if reply == nil || reply.Version != Version3 {
		return reportKind{}, false, err
	}
	kind, isReport := reportKindOf(reply)
	if isReport && !authenticated(packetOut, reply) {
		return kind, false, err
	}
	if x.Logger.enabled() {
		x.Logger.Printf("SEND STORE SECURITY PARAMS from result: %s", reply.SecurityParameters.SafeString())
	}
	if storeErr := x.storeSecurityParameters(reply); storeErr != nil {
		return reportKind{}, false, storeErr
	}
	return kind, true, err
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
