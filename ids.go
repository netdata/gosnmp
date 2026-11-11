// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
)

// randomID returns a random start for the request ID or msgID counter (RFC
// 3412 section 6: msgID INTEGER (0..2147483647); request-id is an Integer32,
// RFC 3416), below 2147483647 so that the first ID is not 0, the request ID of
// a Report whose agent could not read the request's. crypto/rand never fails
// (Go 1.24 and later).
func randomID() uint32 {
	var b [4]byte
	_, _ = crand.Read(b[:])
	return binary.BigEndian.Uint32(b[:]) % math.MaxInt32
}

// nextRequestID advances the request ID counter, which NewClient seeds with a
// random value, and returns it without its top bit, so request IDs wrap to 0
// after 2147483647.
func (x *Client) nextRequestID() uint32 {
	x.requestID++
	return x.requestID & math.MaxInt32
}

// nextMsgID advances the msgID counter, which NewClient seeds with a random
// value, and returns it without its top bit.
func (x *Client) nextMsgID() uint32 {
	x.msgID++
	return x.msgID & math.MaxInt32
}
