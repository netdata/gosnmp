// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"fmt"
)

// Get sends a GET request for oids, at most MaxOids of them, within ctx, and
// returns the answer, a Response whose error-status is NoError; on an error it
// returns no message, also when the agent's answer ended the request (an
// SNMPv3 Report, or a Response with another error-status, whose error is a
// *StatusError), whose error then matches ErrAnswered (see the package
// documentation, Errors). A done ctx ends the request with its error (see
// the package documentation, Attempts and timeouts); a nil ctx fails it
// before it is sent.
func (c *Client) Get(ctx context.Context, oids []string) (result *Message, err error) {
	req, err := c.oidRequest(GetRequest, oids, 0)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, req)
}

// oidRequest builds the request packet of pdutype for oids, each as a Null
// varbind, with maxRepetitions for a GetBulk, after checking their count
// against MaxOids: Get's, and each of a walk's GetNext and GetBulk requests.
func (c *Client) oidRequest(pduType PDUType, oids []string, maxRepetitions uint32) (*Message, error) {
	if len(oids) > c.config.MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MaxOids (%d)", len(oids), c.config.MaxOids)
	}
	varBinds := make([]VarBind, 0, len(oids))
	for _, oid := range oids {
		varBinds = append(varBinds, VarBind{Name: oid, Value: NullValue()})
	}
	return c.NewMessage(pduType, varBinds, 0, maxRepetitions), nil
}
