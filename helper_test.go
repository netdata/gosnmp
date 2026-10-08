// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"encoding/base64"
	"testing"

	"github.com/netdata/gosnmp/internal/ber"
)

// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/ is useful

var testsInvalidSNMPResponses = []string{
	"MIIHIQIBAQQHcHJpdmF0ZaKCBxECBGwvRyoCAQACAQAwggcBMBgGCCsGAQIBAQIABgwrBgEEAZJRAwE/AQYwEAYIKwYBAgEBAwBDBBU2aN0wDAYIKwYBAgEBBAAEADAMBggrBgECAQEFAAQAMAwGCCsGAQIBAQYABAAwDQYIKwYBAgEBBwACAUgwDQYIKwYBAgECAQACAQAwDwYKKwYBAgECAgEBAQIBATAPBgorBgECAQICAQcBAgEBMA8GCisGAQIBAgIBBwECAQEwDwYKKwYBAgECAgEHAQIBATAPBgorBgECAQICAQcBAgEBMA8GCisGAQIBAgIBBwECAQEwDwYKKwYBAgECAgEHAQIBATAPBgorBgECAQICAQcBAgEBMBAGCCsGAQIBAQMAQwQVNmjdMAwGCCsGAQIBAQQABAAwDAYIKwYBAgEBBQAEADAMBggrBgECAQEGAAQAMA0GCCsGAQIBAQcAAgFIMA0GCCsGAQIBAgEAAgEAMA8GCisGAQIBAgIBAQECAQEwFgYKKwYBAgECAgECAQQIRXRoZXJuZXQwDwYKKwYBAgECAgEIAQIBATAPBgorBgECAQICAQgBAgEBMA8GCisGAQIBAgIBCAECAQEwDwYKKwYBAgECAgEIAQIBATAPBgorBgECAQICAQgBAgEBMA8GCisGAQIBAgIBCAECAQEwDwYKKwYBAgECAgEIAQIBATAMBggrBgECAQEEAAQAMAwGCCsGAQIBAQUABAAwDAYIKwYBAgEBBgAEADANBggrBgECAQEHAAIBSDANBggrBgECAQIBAAIBADAPBgorBgECAQICAQEBAgEBMBYGCisGAQIBAgIBAgEECEV0aGVybmV0MA8GCisGAQIBAgIBAwECAQYwDwYKKwYBAgECAgEJAUMBADAPBgorBgECAQICAQkBQwEAMA8GCisGAQIBAgIBCQFDAQAwDwYKKwYBAgECAgEJAUMBADAPBgorBgECAQICAQkBQwEAMA8GCisGAQIBAgIBCQFDAQAwDwYKKwYBAgECAgEJAUMBADAMBggrBgECAQEFAAQAMAwGCCsGAQIBAQYABAAwDQYIKwYBAgEBBwACAUgwDQYIKwYBAgECAQACAQAwDwYKKwYBAgECAgEBAQIBATAWBgorBgECAQICAQIBBAhFdGhlcm5ldDAPBgorBgECAQICAQMBAgEGMBAGCisGAQIBAgIBBAECAgXqMBIGCisGAQIBAgIBCgFBBQCUMR+2MBIGCisGAQIBAgIBCgFBBQCUMR+2MBIGCisGAQIBAgIBCgFBBQCUMR+2MBIGCisGAQIBAgIBCgFBBQCUMR+2MBIGCisGAQIBAgIBCgFBBQCUMR+2MBIGCisGAQIBAgIBCgFBBQCUMR+2MBIGCisGAQIBAgIBCgFBBQCUMR+2MAwGCCsGAQIBAQYABAAwDQYIKwYBAgEBBwACAUgwDQYIKwYBAgECAQACAQAwDwYKKwYBAgECAgEBAQIBATAWBgorBgECAQICAQIBBAhFdGhlcm5ldDAPBgorBgECAQICAQMBAgEGMBAGCisGAQIBAgIBBAECAgXqMBIGCisGAQIBAgIBBQFCBDuaygAwEQYKKwYBAgECAgELAUEDDQDJMBEGCisGAQIBAgIBCwFBAw0AyTARBgorBgECAQICAQsBQQMNAMkwEQYKKwYBAgECAgELAUEDDQDJMBEGCisGAQIBAgIBCwFBAw0AyTARBgorBgECAQICAQsBQQMNAMkwEQYKKwYBAgECAgELAUEDDQDJMA0GCCsGAQIBAQcAAgFIMA0GCCsGAQIBAgEAAgEAMA8GCisGAQIBAgIBAQECAQEwFgYKKwYBAgECAgECAQQIRXRoZXJuZXQwDwYKKwYBAgECAgEDAQIBBjAQBgorBgECAQICAQQBAgIF6jASBgorBgECAQICAQUBQgQ7msoAMBQGCisGAQIBAgIBBgEEBryxgWZeBTASBgorBgECAQICAQwBQQQAu5coMBIGCisGAQIBAgIBDAFBBAC7lygwEgYKKwYBAgECAgEMAUEEALuXKDASBgorBgECAQICAQwBQQQAu5coMBIGCisGAQIBAgIBDAFBBAC7lygwEgYKKwYBAgECAgEMAUEEALuXKDASBgorBgECAQICAQwBQQQAu5coMA0GCCsGAQIBAgEAAgEAMA8GCisGAQIBAgIBAQECAQEwFgYKKwYBAgECAgECAQQIRXRoZXJuZXQwDwYKKwYBAgECAgEDAQIBBjAQBgorBgECAQICAQQBAgIF6jASBgorBgECAQICAQUBQgQ7msoAMBQGCisGAQIBAgIBBgEEBryxgWZeBTAPBgorBgECAQICAQcBAgEBMBEGCisGAQIBAgIBDQFBAwdNFzARBgorBgECAQICAQ0BQQMHTRcwEQYKKwYBAgECAgE=",
	"MBoCAQEEB3ByaXZhdGWiDAIESESkywIBBQIBAA==",
	"MEo=",
}

func TestInvalidSNMPResponses(t *testing.T) {
	g := newTestGoSNMP()
	g.Target = "127.0.0.1"

	for i, test := range testsInvalidSNMPResponses {
		testBytes, _ := base64.StdEncoding.DecodeString(test)
		result, err := g.SnmpDecodePacket(testBytes)
		if err == nil {
			t.Errorf("#%d, failed to error %v", i, result)
		}
	}
}

// TestIPAddressReadField tests IPAddress parsing via readField.
// Note: readField only supports IPv4, not IPv6 (returns error for length != 4).
func TestIPAddressReadField(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantIP     string
		wantLength int
		wantNull   bool
		wantErr    bool
	}{
		// Standard short-form
		{
			name:       "short-form IPv4",
			data:       []byte{0x40, 0x04, 192, 168, 1, 1},
			wantIP:     "192.168.1.1",
			wantLength: 6,
		},
		{
			name:       "short-form IPv4 loopback",
			data:       []byte{0x40, 0x04, 127, 0, 0, 1},
			wantIP:     "127.0.0.1",
			wantLength: 6,
		},
		// Long-form BER
		{
			name:       "long-form IPv4",
			data:       []byte{0x40, 0x81, 0x04, 10, 0, 0, 1},
			wantIP:     "10.0.0.1",
			wantLength: 7,
		},
		// Edge cases
		{
			name:       "null IPAddress (length 0)",
			data:       []byte{0x40, 0x00},
			wantNull:   true,
			wantLength: 2,
		},
		// Error cases - readField only supports IPv4
		{
			name:    "IPv6 rejected by readField",
			data:    []byte{0x40, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name:    "truncated IPv4",
			data:    []byte{0x40, 0x04, 192, 168},
			wantErr: true,
		},
		{
			name:    "indefinite length rejected",
			data:    []byte{0x40, 0x80, 192, 168, 1, 1, 0x00, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ber.NewReader(tt.data)
			f, err := readField(&r)

			if tt.wantErr {
				if err == nil {
					t.Errorf("readField() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("readField() unexpected error: %v", err)
				return
			}
			if length := len(tt.data) - r.Len(); length != tt.wantLength {
				t.Errorf("readField() length = %v, want %v", length, tt.wantLength)
			}
			if tt.wantNull {
				if f.kind != fieldNone {
					t.Errorf("readField() = %+v, want an empty IpAddress", f)
				}
				return
			}
			if f.kind != fieldString || f.s != tt.wantIP {
				t.Errorf("readField() = %+v, want %v", f, tt.wantIP)
			}
		})
	}
}
