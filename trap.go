// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
)

// UnmarshalTrap unpacks the SNMP Trap.
func (x *GoSNMP) UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (result *SnmpPacket, err error) {
	// Get only the version from the header of the trap
	version, _, err := unmarshalVersionFromHeader(trap, new(SnmpPacket))
	if err != nil {
		x.Logger.Printf("UnmarshalTrap version unmarshal: %s\n", err)
		return nil, err
	}
	// If there are multiple users configured and the SNMP trap is v3, see which user has valid credentials
	// by iterating through the list matching the identifier and seeing which credentials are authentic / can be used to decrypt
	if x.TrapSecurityParametersTable != nil && version == Version3 {
		identifier, err := x.getTrapIdentifier(trap)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap V3 get trap identifier: %s\n", err)
			return nil, err
		}
		secParamsList, err := x.TrapSecurityParametersTable.Get(identifier)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap V3 get security parameters from table: %s\n", err)
			return nil, err
		}
		for _, secParams := range secParamsList {
			// Copy the trap and pass the security parameters to try to unmarshal with
			cpTrap := make([]byte, len(trap))
			copy(cpTrap, trap)
			if result, err = x.unmarshalTrapBase(cpTrap, secParams.Copy(), true); err == nil {
				return result, nil
			}
		}
		return nil, fmt.Errorf("no credentials successfully unmarshaled trap: %w", err)
	}
	return x.unmarshalTrapBase(trap, nil, useResponseSecurityParameters)
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
		x.Logger.Printf("UnmarshalTrap: %s\n", err)
		return nil, err
	}

	if result.Version == Version3 {
		if result.SecurityModel == UserSecurityModel {
			err = x.testAuthentication(trap, result, useResponseSecurityParameters)
			if err != nil {
				x.Logger.Printf("UnmarshalTrap v3 auth: %s\n", err)
				return nil, err
			}
		}

		trap, cursor, err = unmarshalScopedPDU(trap, cursor, result)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap v3 decrypt: %s\n", err)
			return nil, err
		}
	}
	err = unmarshalPayload(trap, cursor, result)
	if err != nil {
		x.Logger.Printf("UnmarshalTrap: %s\n", err)
		return nil, err
	}
	return result, nil
}
