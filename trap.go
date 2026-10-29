// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
)

// UnmarshalTrap decodes a received trap or inform, of any version; an SNMPv3
// message needs a client whose Version is Version3. It decodes any PDU type
// and does not compare the community: check PDUType and Community.
//
// An SNMPv3 message is decoded, when TrapSecurityParametersTable is set, with
// the sets the table holds for its user name, until one accepts it; otherwise
// UnmarshalTrap derives the missing keys of SecurityParameters, so parameters
// naming a protocol with neither a key nor a passphrase fail every message,
// and decodes it with a copy of them. trap is not written (see the package
// documentation for the values that alias it).
//
// An SNMPv3 message goes through the security processing of RFC 3414 section
// 3.2, by its own flags, and each rejection unwraps (errors.Is) to the error
// named after the step's counter: it must name an engine ID
// (ErrUnknownEngineID); the user must be known (ErrUnknownUsername): the table
// looks it up by name, the single user must be the message's, and parameters
// with a key given without its passphrase serve only the engine ID it was
// localized to; the user must have the protocols the message asks for
// (ErrUnknownSecurityLevel); a message that asks for authentication must
// carry a digest that checks with the user's key, localized to the message's
// engine ID (ErrWrongDigest); an authenticated message whose reportable flag
// is clear, a trap, not an inform, must be in the time window of its engine
// (ErrNotInTimeWindow, see the package documentation); a message is decrypted
// exactly when it asks for privacy (ErrDecryption). Then the receiver's
// minimum level applies (ErrUnknownSecurityLevel): a table set or the single
// user with an authentication protocol accepts only authenticated messages;
// the single user also requires the level of the client's MsgFlags, unless
// useResponseSecurityParameters is set. A table tries all of a user's sets in
// the order they were added; when none accepts the message, the error is the
// one of the set that got furthest through these steps, the first on ties.
func (x *GoSNMP) UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	version, _, err := readVersion(trap)
	if err != nil {
		return nil, err
	}
	if x.TrapSecurityParametersTable != nil && version == Version3 {
		return x.unmarshalTrapByUser(trap)
	}
	return x.unmarshalTrapBase(trap, useResponseSecurityParameters)
}

// unmarshalTrapByUser decodes an SNMPv3 trap, whose header it reads once,
// with the parameter sets the table holds for its user name, in the order
// they were added, each a private copy with the message's security
// parameters. The first set that accepts it wins; when none does, the error
// wraps the one of the set that got furthest.
func (x *GoSNMP) unmarshalTrapByUser(trap []byte) (*SnmpPacket, error) {
	var header SnmpPacket
	_, w, err := unmarshalHeader(trap, &header)
	if err != nil {
		return nil, err
	}
	if err = x.checkTrapV3(&w); err != nil {
		return nil, err
	}
	secParamsList, err := x.TrapSecurityParametersTable.Get(w.userName)
	if err != nil {
		return nil, inCategory(ErrUnknownUsername, err)
	}
	var furthest error
	var reached trapStep
	for _, secParams := range secParamsList {
		// The attempts share the header's empty variable list: they run one
		// after the other, and only the last one's result is kept.
		result := new(SnmpPacket)
		*result = header
		step, err := decodeTrapV3(trap, w, result, secParams.Copy().usm(), trapRule{})
		if err == nil {
			return result, nil
		}
		if furthest == nil || step > reached {
			furthest, reached = err, step
		}
	}
	return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", furthest)
}

// unmarshalTrapBase decodes trap with a copy of the client's security
// parameters, whose keys it derives first.
func (x *GoSNMP) unmarshalTrapBase(trap []byte, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	result := new(SnmpPacket)
	if x.SecurityParameters != nil {
		if err := x.SecurityParameters.InitSecurityKeys(); err != nil {
			return nil, err
		}
		result.SecurityParameters = x.SecurityParameters.Copy()
	}

	cursor, w, err := unmarshalHeader(trap, result)
	if err != nil {
		return nil, err
	}
	if result.Version != Version3 {
		if err := unmarshalPayload(trap, cursor, result); err != nil {
			return nil, err
		}
		return result, nil
	}
	if err := x.checkTrapV3(&w); err != nil {
		return nil, err
	}

	var sp *UsmSecurityParameters
	if result.SecurityParameters != nil {
		sp = result.SecurityParameters.usm()
	} else {
		sp = &UsmSecurityParameters{Logger: x.Logger}
	}
	rule := trapRule{singleUser: true}
	if !useResponseSecurityParameters {
		rule.minimum = x.MsgFlags & AuthPriv
	}
	if _, err := decodeTrapV3(trap, w, result, sp, rule); err != nil {
		return nil, err
	}
	return result, nil
}

// checkTrapV3 makes the checks of an SNMPv3 trap that come before its user is
// known: the client's version, and an engine ID that is not empty (RFC 3414
// section 3.2 step 3: no receiver's engine has it).
func (x *GoSNMP) checkTrapV3(w *v3Wire) error {
	if x.Version != Version3 {
		return errors.New("UnmarshalTrap: an SNMPv3 message needs a client whose Version is Version3")
	}
	if w.engineID == "" {
		return errNoEngineID
	}
	return nil
}

// trapRule is what a trap path requires of a message beyond the security
// processing.
type trapRule struct {
	// singleUser is set on the single path: the message's user must be the
	// receiver's (the table looks the user up by name).
	singleUser bool
	// minimum is the security level the receiver requires besides its
	// parameters' (the client's MsgFlags on the single path).
	minimum SnmpV3MsgFlags
}

// trapStep is how far an SNMPv3 trap got through decodeTrapV3 with one set:
// the steps of RFC 3414 section 3.2 from step 4 on, the minimum level, the
// PDU. A local failure counts at the step it occurred in.
type trapStep uint8

const (
	stepUser trapStep = iota
	stepLevel
	stepDigest
	stepTimeliness
	stepPrivacy
	stepMinimum
	stepPDU
)

// decodeTrapV3 decodes the SNMPv3 trap whose header is in result and w with
// sp, a private copy of the receiver's parameters, and returns how far it
// got: the security processing from RFC 3414 section 3.2 step 4 on, by the
// message's flags, the minimum level of rule and sp, then the scoped PDU and
// the PDU.
func decodeTrapV3(trap []byte, w v3Wire, result *SnmpPacket, sp *UsmSecurityParameters, rule trapRule) (trapStep, error) {
	if rule.singleUser && w.userName != sp.UserName {
		return stepUser, errUnknownUser
	}
	minimum := rule.minimum | sp.levelFloor()
	in, err := receiveV3(trap, w, result, sp)
	if err != nil {
		if errors.Is(err, ErrUnknownSecurityLevel) {
			return stepLevel, err
		}
		return stepUser, err
	}
	flags := result.MsgFlags
	if flags.authFlag() {
		if err = in.verify(); err != nil {
			return stepDigest, err
		}
		if flags&Reportable == 0 {
			if err = trapEngineTimes.admit(keyOf(sp), sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime); err != nil {
				return stepTimeliness, err
			}
		}
	}
	scoped, cursor, err := in.scopedPDU(result)
	if err != nil {
		return stepPrivacy, err
	}
	if auth, priv := minimum.authFlag() && !flags.authFlag(), minimum.privFlag() && !flags.privFlag(); auth || priv {
		return stepMinimum, errBelowMinimum
	}
	return stepPDU, unmarshalPayload(scoped, cursor, result)
}
