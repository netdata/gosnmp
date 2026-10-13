// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

// seedIDs starts the request and msg ID counters at the client's random
// value, drawn once. Known bug: Connect calls it each time, discarding what
// SetRequestID and SetMsgID set.
func (x *GoSNMP) seedIDs() error {
	if x.random == 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32)) // returns a uniform random value in [0, 2147483647].
		if err != nil {
			return fmt.Errorf("error occurred while generating random: %w", err)
		}
		x.random = uint32(n.Uint64()) //nolint:gosec
	}
	// http://tools.ietf.org/html/rfc3412#section-6 - msgID only uses the first 31 bits
	// msgID INTEGER (0..2147483647)
	x.msgID.Store(x.random)

	// request-id is an Integer32 (RFC 3416); nextRequestID keeps it
	// non-negative.
	x.requestID.Store(x.random)
	return nil
}

// nextRequestID advances the request ID counter and returns it without its
// top bit, so request IDs wrap to 0 after 2147483647.
func (x *GoSNMP) nextRequestID() uint32 {
	return x.requestID.Add(1) & math.MaxInt32
}

// nextMsgID advances the msg ID counter and returns it without its top bit.
func (x *GoSNMP) nextMsgID() uint32 {
	return x.msgID.Add(1) & math.MaxInt32
}

// SetRequestID sets the request ID counter: the next request ID is reqID+1,
// without its top bit. Connect resets the counter.
func (x *GoSNMP) SetRequestID(reqID uint32) {
	x.requestID.Store(reqID & math.MaxInt32)
}

// SetMsgID sets the SNMPv3 msgID counter: the next msgID is msgID+1,
// without its top bit. Connect resets the counter.
func (x *GoSNMP) SetMsgID(msgID uint32) {
	x.msgID.Store(msgID & math.MaxInt32)
}
