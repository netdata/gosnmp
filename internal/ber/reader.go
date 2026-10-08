// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package ber

import "errors"

// Errors returned by Reader.Next besides those of Length.
var (
	ErrEmpty     = errors.New("no TLV left to read")
	ErrTruncated = errors.New("TLV length exceeds the remaining input")
)

// Reader reads consecutive TLVs from a byte slice. A TLV's content is read
// with a new Reader over it, so every read is bounded by its enclosing TLV.
type Reader struct {
	b []byte
}

// NewReader returns a Reader over b. The TLV contents it returns alias b.
func NewReader(b []byte) Reader {
	return Reader{b: b}
}

// Len returns the number of unread bytes.
func (r *Reader) Len() int {
	return len(r.b)
}

// Rest returns the unread bytes.
func (r *Reader) Rest() []byte {
	return r.b
}

// Peek returns the tag of the next TLV; ok is false when no bytes are left.
func (r *Reader) Peek() (tag byte, ok bool) {
	if len(r.b) == 0 {
		return 0, false
	}
	return r.b[0], true
}

// Next reads the next TLV and returns its tag and content. It fails with
// ErrEmpty when no bytes are left, with the errors of Length, and with
// ErrTruncated when the declared length runs past the input.
func (r *Reader) Next() (tag byte, content []byte, err error) {
	if len(r.b) == 0 {
		return 0, nil, ErrEmpty
	}
	length, header, err := Length(r.b)
	if err != nil {
		return 0, nil, err
	}
	if length > len(r.b) {
		return 0, nil, ErrTruncated
	}
	tag, content = r.b[0], r.b[header:length]
	r.b = r.b[length:]
	return tag, content, nil
}

// SkipHeader reads the tag and length octets of the next TLV and leaves the
// reader at its content. Unlike Next, it neither checks the declared length
// against the input nor bounds later reads to it: the SNMPv3 decoders read
// the fields of msgGlobalData and the USM parameters this way, so packets with
// wrong lengths in those headers decode as long as the fields follow.
func (r *Reader) SkipHeader() (tag byte, err error) {
	if len(r.b) == 0 {
		return 0, ErrEmpty
	}
	_, header, err := Length(r.b)
	if err != nil {
		return 0, err
	}
	tag = r.b[0]
	r.b = r.b[header:]
	return tag, nil
}
