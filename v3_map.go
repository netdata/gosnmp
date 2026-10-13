// Copyright 2023 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"sync"
)

// SnmpV3SecurityParametersTable holds sets of SNMPv3 security parameters by
// key, for GoSNMP.UnmarshalTrap, which looks them up by the message's user
// name. It is safe for concurrent use.
type SnmpV3SecurityParametersTable struct {
	table map[string][]SnmpV3SecurityParameters
	// Logger receives a line for each Add, and goes to the added parameters
	// that have no Logger.
	Logger Logger
	mu     sync.RWMutex
}

// NewSnmpV3SecurityParametersTable returns an empty table that logs to
// logger.
func NewSnmpV3SecurityParametersTable(logger Logger) *SnmpV3SecurityParametersTable {
	return &SnmpV3SecurityParametersTable{
		table:  make(map[string][]SnmpV3SecurityParameters),
		Logger: logger,
	}
}

// Add derives the keys of sp (InitSecurityKeys), while it holds the table's
// lock, and appends sp itself, not a copy, to the sets of key; UnmarshalTrap
// tries a user's sets in the order they were added.
func (spm *SnmpV3SecurityParametersTable) Add(key string, sp SnmpV3SecurityParameters) error {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	if err := sp.InitSecurityKeys(); err != nil {
		return err
	}

	// If no logger is set for the security params (empty struct), use the one from the table
	if usp := sp.usm(); (Logger{}) == usp.Logger {
		usp.Logger = spm.Logger
	}

	spm.table[key] = append(spm.table[key], sp)
	if spm.Logger.enabled() {
		spm.Logger.Printf("Added security parameters %s for key: %s", sp.SafeString(), key)
	}

	return nil
}

// Get returns the sets of key, as the table's own slice, or an error when
// there are none.
func (spm *SnmpV3SecurityParametersTable) Get(key string) ([]SnmpV3SecurityParameters, error) {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	if sp, ok := spm.table[key]; ok {
		return sp, nil
	}
	return nil, fmt.Errorf("no security parameters found for the key %s", key)
}
