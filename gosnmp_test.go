// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewClient pins what NewClient makes of a configuration: the client keeps
// it with the defaults of its zero Port, Timeout and MaxOids filled in, or it
// fails with an error naming the field and returns no client. The SNMPv3 fields
// are checked for SNMPv3 only.
func TestNewClient(t *testing.T) {
	v3User := User{Name: "codec-user", AuthProtocol: SHA, AuthPassphrase: "codec-auth-pass", PrivProtocol: AES, PrivPassphrase: "codec-priv-pass"}
	type result struct {
		config Config // the client's configuration
		err    string
	}
	tests := map[string]struct {
		config Config
		want   result
	}{
		"defaults": {
			want: result{config: Config{Port: 161, Timeout: time.Second, MaxOids: MaxOids}},
		},
		"values kept": {
			config: Config{
				Target: "192.0.2.1", Port: 1161, Version: Version2c, Community: "codec-community",
				Timeout: 5 * time.Second, Retries: 3, MaxOids: 10,
			},
			want: result{config: Config{
				Target: "192.0.2.1", Port: 1161, Version: Version2c, Community: "codec-community",
				Timeout: 5 * time.Second, Retries: 3, MaxOids: 10,
			}},
		},
		"SNMPv3 fields unchecked for SNMPv2c": {
			config: Config{Version: Version2c, SecurityLevel: 2, User: User{AuthProtocol: 99}},
			want: result{config: Config{
				Port: 161, Version: Version2c, Timeout: time.Second, MaxOids: MaxOids,
				SecurityLevel: 2, User: User{AuthProtocol: 99},
			}},
		},
		"SNMPv3": {
			config: Config{Version: Version3, SecurityLevel: AuthPriv, User: v3User, ContextName: "codec-context"},
			want: result{config: Config{
				Port: 161, Version: Version3, Timeout: time.Second, MaxOids: MaxOids,
				SecurityLevel: AuthPriv, User: v3User, ContextName: "codec-context",
			}},
		},
		"unknown version": {
			config: Config{Version: 2},
			want:   result{err: "Config.Version is Version(2), not Version1, Version2c or Version3"},
		},
		"negative timeout": {
			config: Config{Version: Version2c, Timeout: -time.Nanosecond},
			want:   result{err: "Config.Timeout -1ns is negative"},
		},
		"negative retries": {
			config: Config{Version: Version2c, Retries: -1},
			want:   result{err: "Config.Retries -1 is negative"},
		},
		"negative max OIDs": {
			config: Config{Version: Version2c, MaxOids: -1},
			want:   result{err: "Config.MaxOids -1 is negative"},
		},
		"SNMPv3 unknown security level": {
			config: Config{Version: Version3, SecurityLevel: 2, User: User{Name: "codec-user"}},
			want:   result{err: "Config.SecurityLevel SecurityLevel(2) is not NoAuthNoPriv, AuthNoPriv or AuthPriv"},
		},
		"SNMPv3 user without a name": {
			config: Config{Version: Version3, SecurityLevel: NoAuthNoPriv},
			want:   result{err: "Config.User.Name is required"},
		},
		"SNMPv3 unknown authentication protocol": {
			config: Config{Version: Version3, SecurityLevel: NoAuthNoPriv, User: User{Name: "codec-user", AuthProtocol: 99}},
			want:   result{err: "Config.User.AuthProtocol AuthProtocol(99) is not supported"},
		},
		"SNMPv3 level without its protocol": {
			config: Config{Version: Version3, SecurityLevel: AuthNoPriv, User: User{Name: "codec-user"}},
			want:   result{err: "Config.User.AuthProtocol is required"},
		},
		"SNMPv3 protocol without a passphrase": {
			config: Config{Version: Version3, SecurityLevel: AuthPriv, User: User{
				Name: "codec-user", AuthProtocol: SHA, AuthPassphrase: "codec-auth-pass", PrivProtocol: AES,
			}},
			want: result{err: "Config.User.PrivPassphrase is required when a privacy protocol is specified"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x, err := NewClient(tc.config)
			var got result
			if err != nil {
				got.err = err.Error()
				assert.Nil(t, x)
			} else {
				got.config = x.config
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
