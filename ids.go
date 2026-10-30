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

// nextRequestID advances the request ID counter, which starts at a random
// value on first use unless SetRequestID set it, and returns it without its
// top bit, so request IDs wrap to 0 after 2147483647.
func (x *GoSNMP) nextRequestID() uint32 {
	if !x.requestIDSet.Load() {
		x.SetRequestID(randomID())
	}
	return x.requestID.Add(1) & math.MaxInt32
}

// nextMsgID advances the msgID counter, which starts at a random value on
// first use unless SetMsgID set it, and returns it without its top bit.
func (x *GoSNMP) nextMsgID() uint32 {
	if !x.msgIDSet.Load() {
		x.SetMsgID(randomID())
	}
	return x.msgID.Add(1) & math.MaxInt32
}

// SetRequestID sets the request ID counter: the next request ID is reqID+1,
// without its top bit. Connect does not change the counter.
func (x *GoSNMP) SetRequestID(reqID uint32) {
	x.requestID.Store(reqID & math.MaxInt32)
	x.requestIDSet.Store(true)
}

// SetMsgID sets the SNMPv3 msgID counter: the next msgID is msgID+1,
// without its top bit. Connect does not change the counter.
func (x *GoSNMP) SetMsgID(msgID uint32) {
	x.msgID.Store(msgID & math.MaxInt32)
	x.msgIDSet.Store(true)
}
