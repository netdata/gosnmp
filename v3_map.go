// Copyright 2023 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"sync"
)

// SnmpV3SecurityParametersTable holds SNMPv3 users by name, each with the
// engine ID it is registered for, for Client.UnmarshalTrap, which looks them
// up by the message's user name. It is safe for concurrent use.
type SnmpV3SecurityParametersTable struct {
	table map[string][]*tableUser
	mu    sync.RWMutex
}

// NewSnmpV3SecurityParametersTable returns an empty table.
func NewSnmpV3SecurityParametersTable() *SnmpV3SecurityParametersTable {
	return &SnmpV3SecurityParametersTable{
		table: make(map[string][]*tableUser),
	}
}

// Add derives user's keys localized to engineID, while it holds the table's
// lock, and appends the user to the entries of its name; UnmarshalTrap tries a
// name's entries in the order they were added, and derives the keys again for
// a message naming another engine ID. Keys that do not derive, as for a
// protocol without a passphrase, fail.
func (spm *SnmpV3SecurityParametersTable) Add(user User, engineID []byte) error {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	keys, err := user.localize(engineID)
	if err != nil {
		return err
	}
	entry := &tableUser{user: user, engineID: bytes.Clone(engineID), keys: keys}
	spm.table[user.Name] = append(spm.table[user.Name], entry)
	return nil
}

// get returns the entries of the user name, as the table's own slice, or an
// error when there are none.
func (spm *SnmpV3SecurityParametersTable) get(name string) ([]*tableUser, error) {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	if entries, ok := spm.table[name]; ok {
		return entries, nil
	}
	return nil, fmt.Errorf("no security parameters found for the key %s", name)
}
