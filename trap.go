// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
)

// UnmarshalTrap decodes a received trap or inform, of any version; an SNMPv3
// message needs a client whose Version is Version3. It decodes any PDU type
// and does not compare the community: check PDUType and Community.
//
// An SNMPv3 message is decoded, when TrapSecurityParametersTable is set, with
// the sets the table holds for its user name, each on a copy of trap, until
// one decodes it; useResponseSecurityParameters is then always set. Otherwise
// UnmarshalTrap derives the missing keys of SecurityParameters and decodes
// trap in place (see the package documentation) with a copy of them. When the
// flags ask for authentication, a User-based Security Model message must name
// the user and carry a digest that checks with the user's key, localized to
// the engine ID the message names. The flags and the user are the client's,
// or, with useResponseSecurityParameters, the message's own.
//
// Known bugs: these messages are accepted without the security their user
// needs: one of another security model, and one with an empty user name and
// engine ID, as in engine discovery, both unchecked; with
// useResponseSecurityParameters, so on the table path, one without the
// authentication flag; one without privacy, for a client at authPriv (the
// client's flags decide only whether a digest is checked); and, for a user
// configured with keys instead of passphrases, one that names another engine
// ID and is signed with the empty key, which anyone can compute. Some
// malformed messages make it panic (see the package documentation).
func (x *GoSNMP) UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	version, _, err := readVersion(trap)
	if err != nil {
		return nil, err
	}
	if x.TrapSecurityParametersTable != nil && version == Version3 {
		return x.unmarshalTrapByUser(trap)
	}
	return x.unmarshalTrapBase(trap, nil, useResponseSecurityParameters)
}

// unmarshalTrapByUser decodes an SNMPv3 trap with the parameter sets the
// table holds for its user name, in the order they were added, each with the
// message's security parameters and on its own copy of the trap. The first
// set that decodes it wins; when none does, the error wraps the last
// attempt's.
func (x *GoSNMP) unmarshalTrapByUser(trap []byte) (*SnmpPacket, error) {
	identifier, err := x.getTrapIdentifier(trap)
	if err != nil {
		return nil, err
	}
	secParamsList, err := x.TrapSecurityParametersTable.Get(identifier)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, secParams := range secParamsList {
		result, err := x.unmarshalTrapBase(bytes.Clone(trap), secParams.Copy(), true)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", lastErr)
}

// getTrapIdentifier returns the user name of an SNMPv3 message, the table key
// of its parameter sets; a header that fails to decode after the user name
// still gives it. Known bug: a header that fails before the security
// parameters leaves them nil, and reading the user name panics.
func (x *GoSNMP) getTrapIdentifier(trap []byte) (string, error) {
	// Initialize a packet with no auth/priv to unmarshal ID/key for security parameters to use
	packet := new(SnmpPacket)
	_, err := x.unmarshalHeader(trap, packet)
	// Return err if no identifier was able to be parsed after unmarshaling
	userName := packet.SecurityParameters.usm().UserName
	if err != nil && userName == "" {
		return "", err
	}
	return userName, nil
}

// unmarshalTrapBase decodes trap in place with sp, or, when sp is nil, with a
// copy of the client's security parameters, whose keys it derives first.
// Known bug: the digest of an SNMPv3 message is checked only for the
// User-based Security Model; a message of another model is decrypted, when
// its scoped PDU is encrypted, and accepted.
func (x *GoSNMP) unmarshalTrapBase(trap []byte, sp SnmpV3SecurityParameters, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	result := new(SnmpPacket)

	if x.SecurityParameters != nil && sp == nil {
		err := x.SecurityParameters.InitSecurityKeys()
		if err != nil {
			return nil, err
		}
		result.SecurityParameters = x.SecurityParameters.Copy()
	} else {
		result.SecurityParameters = sp
	}

	cursor, err := x.unmarshalHeader(trap, result)
	if err != nil {
		return nil, err
	}

	if result.Version == Version3 {
		if result.SecurityModel == UserSecurityModel {
			err = x.testAuthentication(trap, result, useResponseSecurityParameters)
			if err != nil {
				return nil, err
			}
		}

		trap, cursor, err = unmarshalScopedPDU(trap, cursor, result)
		if err != nil {
			return nil, err
		}
	}
	err = unmarshalPayload(trap, cursor, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
