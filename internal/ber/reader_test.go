// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package ber

import (
	"bytes"
	"errors"
	"testing"
)

func TestReaderNext(t *testing.T) {
	type read struct {
		tag     byte
		content []byte
		err     error
	}
	tests := map[string]struct {
		in    []byte
		reads []read
		rest  []byte
	}{
		"empty input": {
			in:    nil,
			reads: []read{{err: ErrEmpty}},
		},
		"two TLVs then empty": {
			in: []byte{0x02, 0x01, 0x05, 0x04, 0x02, 'h', 'i'},
			reads: []read{
				{tag: 0x02, content: []byte{0x05}},
				{tag: 0x04, content: []byte("hi")},
				{err: ErrEmpty},
			},
		},
		"zero-length content": {
			in:    []byte{0x05, 0x00, 0x02, 0x01, 0x01},
			reads: []read{{tag: 0x05, content: []byte{}}},
			rest:  []byte{0x02, 0x01, 0x01},
		},
		"long form length": {
			in:    append([]byte{0x04, 0x81, 0x80}, make([]byte, 0x80)...),
			reads: []read{{tag: 0x04, content: make([]byte, 0x80)}},
		},
		"lone tag octet is an empty TLV": {
			in:    []byte{0x30},
			reads: []read{{tag: 0x30, content: []byte{}}, {err: ErrEmpty}},
		},
		"content runs past the input": {
			in:    []byte{0x04, 0x03, 'h', 'i'},
			reads: []read{{err: ErrTruncated}},
			rest:  []byte{0x04, 0x03, 'h', 'i'},
		},
		"truncated long form length": {
			in:    []byte{0x30, 0x82, 0x01},
			reads: []read{{err: ErrInvalidPacketLength}},
			rest:  []byte{0x30, 0x82, 0x01},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := NewReader(tc.in)
			for i, want := range tc.reads {
				tag, content, err := r.Next()
				if !errors.Is(err, want.err) {
					t.Fatalf("read %d: err = %v, want %v", i, err, want.err)
				}
				if tag != want.tag || !bytes.Equal(content, want.content) {
					t.Fatalf("read %d: got tag %#x content %x, want tag %#x content %x",
						i, tag, content, want.tag, want.content)
				}
			}
			if !bytes.Equal(r.Rest(), tc.rest) || r.Len() != len(tc.rest) {
				t.Fatalf("rest = %x (len %d), want %x", r.Rest(), r.Len(), tc.rest)
			}
		})
	}
}

func TestReaderPeek(t *testing.T) {
	r := NewReader(nil)
	if _, ok := r.Peek(); ok {
		t.Fatal("Peek on empty input reported a tag")
	}
	r = NewReader([]byte{0x30, 0x00})
	if tag, ok := r.Peek(); !ok || tag != 0x30 {
		t.Fatalf("Peek = %#x, %v, want 0x30, true", tag, ok)
	}
	if r.Len() != 2 {
		t.Fatalf("Peek consumed input: Len = %d", r.Len())
	}
}
