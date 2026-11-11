// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/netdata/gosnmp/internal/ber"
)

//
// SNMP Walk functions - Analogous to net-snmp's snmpwalk commands
//

// BulkWalkAll walks the subtree under rootOid with GETBULK requests (SNMPv2c
// and SNMPv3: a request on SNMPv1 fails before it is sent) and returns its
// values, in the order the agent returns them, and how the walk ended. An
// empty or "." rootOid walks .1.3.6.1. The subtree is rootOid and the names
// under it. The walk ends as net-snmp's snmpbulkwalk ends its walk: at the
// first name outside the subtree or exception value (NoSuchObject,
// NoSuchInstance, EndOfMibView), and at an answer whose error-status is
// NoSuchName, the end of an SNMPv1 MIB; it also ends at an answer without
// varbinds, which net-snmp sends again. When the walk's first answer ends it
// with NoSuchName or with a first name outside the subtree, rootOid is taken
// for a leaf and fetched with one Get, whose first value is returned when it
// names rootOid and is not an exception value; that Get answered with an
// error-status means rootOid has no value, as in net-snmp. An exception value
// in the subtree ends the walk without that Get, also in the first answer: a
// leaf rootOid that is the agent's last object answers EndOfMibView and is not
// fetched. WalkEnd says which of these ended the walk, with the varbind that
// did. The walk ends at once with an error, which it returns with the values
// before it and a zero WalkEnd: the error of a failed request; a *StatusError
// for an answer with another error-status than NoSuchName, which net-snmp's
// walk fails with too (it also gets rootOid when it printed nothing); and an
// error for a name in the subtree, rootOid included, that is not after the
// requested one (each name of an answer is compared with the requested one).
// ctx bounds the walk, each of its requests and the Get of a leaf root: a done
// ctx ends the walk with its error and the values before it, and a nil ctx
// fails it before its first request is sent. maxRepetitions is the
// max-repetitions of each GETBULK request, the most objects the agent returns
// after the one name the request carries: 0 sends 50, and a value above
// 2147483647, the most RFC 3416 allows, fails the walk before its first
// request is sent. Some devices fail with large values; see
// https://github.com/gosnmp/gosnmp/issues/100.
func (x *Client) BulkWalkAll(ctx context.Context, rootOid string, maxRepetitions uint32) (results []VarBind, end WalkEnd, err error) {
	return x.walk(ctx, GetBulkRequest, rootOid, maxRepetitions)
}

// WalkAll walks the subtree under rootOid with GETNEXT requests, one per
// value, where BulkWalkAll asks for many at a time, and returns its values and
// how the walk ended. It walks SNMPv1 agents too, and otherwise starts, ends
// and fails as BulkWalkAll does; net-snmp's snmpwalk differs only for a name
// before rootOid, which fails its increasing check where WalkAll ends (or, as
// the first answer, gets rootOid).
func (x *Client) WalkAll(ctx context.Context, rootOid string) (results []VarBind, end WalkEnd, err error) {
	return x.walk(ctx, GetNextRequest, rootOid, 0)
}

// WalkEnd is how a walk ended without an error: what ended it, and the
// varbind that did when there is one. A walk that fails returns the zero
// WalkEnd.
type WalkEnd struct {
	// Reason is what ended the walk.
	Reason WalkReason
	// VarBind is the varbind that ended the walk: for WalkOutside, the name
	// outside the subtree; for WalkException, the exception value; for
	// WalkLeaf, the first varbind of the Get's answer when the answer has one
	// and no error-status (rootOid's value, also the walk's last value; an
	// exception value, NoSuchObject when the agent has no such object,
	// NoSuchInstance when it has one but not this instance, RFC 3416 section
	// 4.2.1; or another name). Otherwise the zero VarBind.
	VarBind VarBind
}

// WalkReason is what ended a walk (WalkEnd).
type WalkReason uint8

// The reasons a walk ends without an error.
const (
	// WalkOutside is a name outside the subtree, after the walk's first
	// value.
	WalkOutside WalkReason = iota + 1
	// WalkException is an exception value (RFC 3416 section 4.2:
	// NoSuchObject, NoSuchInstance or EndOfMibView) in the subtree.
	WalkException
	// WalkNoSuchName is an answer whose error-status is NoSuchName, the end
	// of an SNMPv1 MIB, after the walk's first answer.
	WalkNoSuchName
	// WalkEmpty is an answer without varbinds.
	WalkEmpty
	// WalkLeaf is the Get of rootOid, taken for a leaf: the walk's first
	// answer was NoSuchName or its first name was outside the subtree.
	WalkLeaf
)

//go:generate go tool -modfile=tools/go.mod stringer -type=WalkReason -trimprefix=Walk

// walk returns the values of the subtree under rootOid and how the walk
// ended: it asks the agent for the objects after the root, then after the
// last name it received, with requestType (GetNext or GetBulk), and collects
// the objects in the subtree until an answer ends the walk (visit's rule).
// When that answer shows the root to be a leaf, the walk gets it once
// (getRoot). maxRepetitions is the GetBulk's max-repetitions, zero for the
// default; it is checked after the root, before the first request. Each
// request runs within ctx. An error ends the walk with the values collected
// before it.
func (x *Client) walk(ctx context.Context, requestType PDUType, rootOid string, maxRepetitions uint32) (results []VarBind, end WalkEnd, err error) {
	root, err := walkRoot(rootOid)
	if err != nil {
		return nil, WalkEnd{}, err
	}
	// RFC 3416 section 3: max-repetitions INTEGER (0..max-bindings), where
	// max-bindings is 2147483647.
	if maxRepetitions > math.MaxInt32 {
		return nil, WalkEnd{}, fmt.Errorf("max-repetitions %d is more than %d", maxRepetitions, math.MaxInt32)
	}
	w := walker{
		x:           x,
		requestType: requestType,
		root:        root,
		maxReps:     cmp.Or(maxRepetitions, defaultMaxRepetitions),
	}

	oid := w.root
	for firstAnswer := true; ; firstAnswer = false {
		response, err := w.request(ctx, oid)
		var next walkStep
		switch {
		case err == nil:
			if results, end, next, err = w.visit(response, oid, firstAnswer, results); err != nil {
				return results, WalkEnd{}, err
			}
		case isStatus(err, NoSuchName):
			// noSuchName is the end of an SNMPv1 MIB: as the first answer,
			// the root may still be a leaf, the MIB's last object.
			next, end = walkDone, WalkEnd{Reason: WalkNoSuchName}
			if firstAnswer {
				next = walkGetRoot
			}
		default:
			// Any other error, another error-status included, ends the walk
			// with it.
			return results, WalkEnd{}, err
		}
		switch next {
		case walkContinue:
			oid = response.VarBinds[len(response.VarBinds)-1].Name
			continue
		case walkGetRoot:
			return w.getRoot(ctx, results)
		}
		return results, end, nil
	}
}

// walker holds what a walk fixes at its start.
type walker struct {
	x *Client
	// requestType is GetNextRequest or GetBulkRequest.
	requestType PDUType
	root        string
	// maxReps is the GetBulk max-repetitions.
	maxReps uint32
}

// walkStep is what a walk does after an answer.
type walkStep int

const (
	// walkContinue asks for the objects after the answer's last name.
	walkContinue walkStep = iota
	// walkGetRoot gets the root, a leaf, once and ends the walk.
	walkGetRoot
	// walkDone ends the walk.
	walkDone
)

// walkRoot returns rootOid in the canonical dotted form used by decoded
// response names, so subtree, equality and ordering checks share its identity.
// An empty root or "." walks the 'internet' subtree .1.3.6.1 (IANA, under the
// ISO OID structure of X.660; see https://oidref.com/1.3.6.1), which holds
// both the standard (MIB-2) and the vendor branches and encodes as an OID,
// which needs at least two arcs: X.690 section 8.19 encodes the first two as
// one subidentifier, 40 * arc1 + arc2.
func walkRoot(rootOid string) (string, error) {
	if rootOid == "" || rootOid == "." {
		return ".1.3.6.1", nil
	}
	// Use the wire codec's grammar, including leading zeros and empty arcs,
	// rather than comparing the caller's spelling with decoded names.
	content, err := ber.AppendOID(nil, rootOid)
	if err != nil {
		return "", fmt.Errorf("unable to marshal OID %q: %w", rootOid, err)
	}
	return ber.OID(content)
}

// request asks the agent for the objects after oid, within ctx, with the
// walk's max-repetitions for a GetBulk, which SNMPv1 does not have. An answer
// with an error-status fails it with a *StatusError (send).
func (w *walker) request(ctx context.Context, oid string) (*Message, error) {
	var maxReps uint32
	if w.requestType == GetBulkRequest {
		if w.x.config.Version == Version1 {
			return nil, errors.New("GETBULK not supported in SNMPv1")
		}
		maxReps = w.maxReps
	}
	packetOut, err := w.x.oidRequest(w.requestType, []string{oid}, maxReps)
	if err != nil {
		return nil, err
	}
	return w.x.send(ctx, packetOut)
}

// visit applies the walk's end rule, net-snmp's (apps/snmpwalk.c and
// apps/snmpbulkwalk.c at v5.9.4), to response, an answer without an
// error-status (walk reads those): it appends the values of response that lie
// in the subtree to results, in order, and returns them, how the walk ended
// when the answer ends it, and what the walk does next. oid is the name the
// request asked for; firstAnswer marks the walk's first answer: a walk goes on
// only after an answer whose values it all collected, so only the first answer
// can end a walk that found nothing, the case in which net-snmp gets the root.
func (w *walker) visit(response *Message, oid string, firstAnswer bool, results []VarBind) ([]VarBind, WalkEnd, walkStep, error) {
	// An empty answer ends the walk, where net-snmp sends the request again.
	if len(response.VarBinds) == 0 {
		return results, WalkEnd{Reason: WalkEmpty}, walkDone, nil
	}

	for i, pdu := range response.VarBinds {
		// A name outside the subtree ends the walk; as the walk's first value,
		// it shows the root to be a leaf (gosnmp/gosnmp#78).
		if !inSubtree(pdu.Name, w.root) {
			if firstAnswer && i == 0 {
				return results, WalkEnd{}, walkGetRoot, nil
			}
			return results, WalkEnd{Reason: WalkOutside, VarBind: pdu}, walkDone, nil
		}
		// An exception value (RFC 3416 section 4.2) ends the walk, also as its
		// first value, without the leaf Get, as in net-snmp's snmpwalk: a leaf
		// root that is the MIB's last object answers endOfMibView and is not
		// fetched.
		if isException(pdu.Value.Type()) {
			return results, WalkEnd{Reason: WalkException, VarBind: pdu}, walkDone, nil
		}
		// Each name is compared with the request's, as net-snmp's
		// snmpbulkwalk does: a name equal to the root fails too.
		if oidCompare(oid, pdu.Name) >= 0 {
			return results, WalkEnd{}, walkDone, fmt.Errorf("OID not increasing: %s >= %s", oid, pdu.Name)
		}
		results = append(results, pdu)
	}
	return results, WalkEnd{}, walkContinue, nil
}

// getRoot gets the root, which the walk found to be a leaf, within ctx, as
// net-snmp's snmpwalk does after a walk that printed nothing, and returns
// results with the answer's first value appended when it names the root and is
// not an exception value (a Get of one name is answered by its first varbind),
// and the end WalkLeaf with that varbind. An answer with an error-status adds
// nothing and ends the walk without an error, as net-snmp ignores it; a failed
// Get fails the walk.
func (w *walker) getRoot(ctx context.Context, results []VarBind) ([]VarBind, WalkEnd, error) {
	end := WalkEnd{Reason: WalkLeaf}
	response, err := w.x.Get(ctx, []string{w.root})
	switch {
	case err == nil:
	case errors.As(err, new(*StatusError)):
		return results, end, nil
	default:
		return results, WalkEnd{}, err
	}
	if len(response.VarBinds) == 0 {
		return results, end, nil
	}
	end.VarBind = response.VarBinds[0]
	if pdu := end.VarBind; pdu.Name == w.root && !isException(pdu.Value.Type()) {
		results = append(results, pdu)
	}
	return results, end, nil
}

// inSubtree reports whether name is root or one of the names under it: it
// starts with root, followed by nothing or a dot. The dot keeps a sibling arc
// out: walking .1.3.6.1.2.1.4.22.1.2.1 does not return the names under
// .1.3.6.1.2.1.4.22.1.2.115 (gosnmp/gosnmp#78, #93). These are the names
// net-snmp's snmpbulkwalk takes in; its snmpwalk also takes in the names
// before the root, which then fail its increasing check.
func inSubtree(name, root string) bool {
	return strings.HasPrefix(name, root) && (len(name) == len(root) || name[len(root)] == '.')
}

// isStatus reports whether err is a *StatusError of status. Its target is a
// local of its own: one that escapes to errors.As in walk's loop would be
// allocated for every request.
func isStatus(err error, status ErrorStatus) bool {
	var s *StatusError
	return errors.As(err, &s) && s.Status == status
}

// isException reports whether t is an exception value of RFC 3416 section
// 4.2: noSuchObject, noSuchInstance or endOfMibView.
func isException(t ValueType) bool {
	return t == NoSuchObject || t == NoSuchInstance || t == EndOfMibView
}

// oidCompare compares two OID strings lexicographically.
// Returns -1 if oid1 < oid2, 0 if equal, 1 if oid1 > oid2.
// This matches net-snmp's snmp_oid_compare semantics.
//
// OIDs are compared component by component as unsigned integers.
// A shorter OID is considered less than a longer OID when all
// components of the shorter OID match the prefix of the longer OID.
func oidCompare(oid1, oid2 string) int {
	pos1, pos2 := 0, 0
	for {
		comp1, newPos1, ok1 := nextOIDComponent(oid1, pos1)
		comp2, newPos2, ok2 := nextOIDComponent(oid2, pos2)
		pos1, pos2 = newPos1, newPos2

		switch {
		case !ok1 && !ok2:
			return 0
		case !ok1:
			return -1
		case !ok2:
			return 1
		}

		if comp1 != comp2 {
			return cmp.Compare(comp1, comp2)
		}
	}
}

// nextOIDComponent parses the next OID component starting at pos.
// Returns the component value, the new position, and whether a component was found.
func nextOIDComponent(oid string, pos int) (uint32, int, bool) {
	if pos < len(oid) && oid[pos] == '.' {
		pos++
	}
	if pos >= len(oid) {
		return 0, pos, false
	}

	var val uint32
	start := pos
	for pos < len(oid) && oid[pos] >= '0' && oid[pos] <= '9' {
		val = val*10 + uint32(oid[pos]-'0')
		pos++
	}

	if pos == start {
		return 0, pos, false
	}

	return val, pos, true
}
