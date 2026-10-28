// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
)

// UnmarshalTrap decodes a received trap or inform, of any version; an SNMPv3
// message needs a client whose Version is Version3. It decodes any PDU type
// and does not compare the community: check PDUType and Community.
//
// An SNMPv3 message is decoded, when TrapSecurityParametersTable is set, with
// the sets the table holds for its user name, until one decodes it;
// useResponseSecurityParameters is then always set. Otherwise UnmarshalTrap
// derives the missing keys of SecurityParameters, so parameters naming a
// protocol with neither a key nor a passphrase fail every message, and decodes
// it with a copy of them. trap is not written (see the package documentation
// for the values that alias it). The message must be of the User-based
// Security Model; when the flags ask for authentication, it must name the user
// and carry a digest that checks with the user's key, localized to the engine
// ID the message names. Parameters with a key given without its passphrase
// decode only messages naming the engine ID it was localized to. The flags and
// the user are the client's, or, with useResponseSecurityParameters, the
// message's own.
//
// Known bugs: these messages are accepted without the security their user
// needs: one with an empty user name and engine ID, as in engine discovery,
// unchecked; with useResponseSecurityParameters, so on the table path, one
// without the authentication flag; and one without privacy, for a client at
// authPriv (the client's flags decide only whether a digest is checked).
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
// parameters. The first set that decodes it wins; when none does, the error
// wraps the last attempt's.
func (x *GoSNMP) unmarshalTrapByUser(trap []byte) (*SnmpPacket, error) {
	var header SnmpPacket
	_, w, err := unmarshalHeader(trap, &header)
	if err != nil {
		return nil, err
	}
	secParamsList, err := x.TrapSecurityParametersTable.Get(w.userName)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, secParams := range secParamsList {
		// The attempts share the header's empty variable list: they run one
		// after the other, and only the last one's result is kept.
		result := new(SnmpPacket)
		*result = header
		if lastErr = x.decodeTrapV3(trap, w, result, secParams.Copy().usm(), true); lastErr == nil {
			return result, nil
		}
	}
	return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", lastErr)
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

	sp := &UsmSecurityParameters{Logger: x.Logger}
	if result.SecurityParameters != nil {
		sp = result.SecurityParameters.usm()
	}
	if err := x.decodeTrapV3(trap, w, result, sp, useResponseSecurityParameters); err != nil {
		return nil, err
	}
	return result, nil
}

// decodeTrapV3 decodes the SNMPv3 trap whose header is in result and w with
// sp, a private copy of the receiver's parameters: the security processing,
// then the scoped PDU and the PDU.
func (x *GoSNMP) decodeTrapV3(trap []byte, w v3Wire, result *SnmpPacket, sp *UsmSecurityParameters, useResponseSecurityParameters bool) error {
	in, err := receiveV3(trap, w, result, sp)
	if err != nil {
		return err
	}
	if err = x.testAuthentication(&in, result, useResponseSecurityParameters); err != nil {
		return err
	}
	scoped, cursor, err := in.scopedPDU(result)
	if err != nil {
		return err
	}
	return unmarshalPayload(scoped, cursor, result)
}
