// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
)

// UnmarshalTrap unpacks the SNMP Trap.
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
