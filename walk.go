// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"cmp"
	"fmt"
	"strings"
)

//
// SNMP Walk functions - Analogous to net-snmp's snmpwalk commands
//

// WalkFunc is called for each value a walk visits; an error it returns ends
// the walk with that error.
type WalkFunc func(dataUnit SnmpPDU) error

// BulkWalk walks the subtree under rootOid with GETBULK requests (SNMPv2c and
// SNMPv3), calling walkFn for each value in it, in the order the agent
// returns them. An empty or "." rootOid walks .1.3.6.1. The subtree is
// rootOid and the names under it. The walk ends as net-snmp's snmpbulkwalk
// ends its walk: at the first name outside the subtree or exception value
// (NoSuchObject, NoSuchInstance, EndOfMibView), and at an answer whose Error
// is NoSuchName, the end of an SNMPv1 MIB, without an error. When the walk's
// first answer ends it with NoSuchName or with a first name outside the
// subtree, rootOid is taken for a leaf and fetched with one Get, whose first
// value walkFn gets when it names rootOid and is not an exception value. An
// exception value in the subtree ends the walk without that Get, also in the
// first answer: a leaf rootOid that is the agent's last object answers
// EndOfMibView and is not fetched. The walk returns at once the error of a
// failed request or of walkFn, and an error for a name in the subtree,
// rootOid included, that is not after the requested one: each name of an
// answer is compared with the requested one, and AppOpts "c" turns this check
// off. Known bugs: an empty answer, or one whose Error is another of TooBig
// through InconsistentName, ends the walk without an error; another Error is
// ignored.
func (x *GoSNMP) BulkWalk(rootOid string, walkFn WalkFunc) error {
	return x.walk(GetBulkRequest, rootOid, walkFn)
}

// BulkWalkAll is similar to BulkWalk but returns a filled array of all values
// rather than using a callback function to stream results. Caution: when
// AppOpts has "c", BulkWalkAll may loop until memory runs out; use BulkWalk
// instead.
func (x *GoSNMP) BulkWalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walkAll(GetBulkRequest, rootOid)
}

// Walk walks the subtree under rootOid with GETNEXT requests, one per value,
// where BulkWalk asks for many at a time, calling walkFn for each value in it.
// It starts, ends and fails as BulkWalk does; net-snmp's snmpwalk differs only
// for a name before rootOid, which fails its increasing check where Walk ends
// (or, as the first answer, gets rootOid).
func (x *GoSNMP) Walk(rootOid string, walkFn WalkFunc) error {
	return x.walk(GetNextRequest, rootOid, walkFn)
}

// WalkAll is similar to Walk but returns a filled array of all values rather
// than using a callback function to stream results. Caution: when AppOpts
// has "c", WalkAll may loop until memory runs out; use Walk instead.
func (x *GoSNMP) WalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walkAll(GetNextRequest, rootOid)
}

// walk visits the subtree under rootOid: it asks the agent for the objects
// after the root, then after the last name it received, with getRequestType
// (GetNext or GetBulk), and passes each object in the subtree to walkFn until
// an answer ends the walk (visit's rule). When that answer shows the root to
// be a leaf, the walk gets it once (getRoot).
func (x *GoSNMP) walk(getRequestType PDUType, rootOid string, walkFn WalkFunc) error {
	// AppOpt 'c': do not check that returned OIDs increase.
	_, unchecked := x.AppOpts["c"]
	w := walker{
		x:               x,
		root:            walkRoot(rootOid),
		maxReps:         cmp.Or(x.MaxRepetitions, defaultMaxRepetitions),
		checkIncreasing: !unchecked,
	}

	oid := w.root
	for requests := 1; ; requests++ {
		response, err := w.request(getRequestType, oid)
		if err != nil {
			return err
		}
		next, err := w.visit(response, oid, requests == 1, walkFn)
		if err != nil {
			return err
		}
		switch next {
		case walkContinue:
			oid = response.Variables[len(response.Variables)-1].Name
			continue
		case walkGetRoot:
			requests++
			if err := w.getRoot(walkFn); err != nil {
				return err
			}
		}
		if x.Logger.enabled() {
			x.Logger.Printf("Walk completed in %d requests", requests)
		}
		return nil
	}
}

// walker holds what a walk fixes at its start. walkFn is not one of its
// fields: it would escape to the heap with the client, and with it WalkAll's
// closure and results.
type walker struct {
	x    *GoSNMP
	root string
	// maxReps is the GetBulk max-repetitions.
	maxReps         uint32
	checkIncreasing bool
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

// walkRoot is the root of a walk asked for rootOid, with a leading dot. An
// empty root or "." walks the 'internet' subtree .1.3.6.1 (IANA, under the
// ISO OID structure of X.660; see https://oidref.com/1.3.6.1), which holds
// both the standard (MIB-2) and the vendor branches and encodes as an OID,
// which needs at least two arcs: X.690 section 8.19 encodes the first two as
// one subidentifier, 40 * arc1 + arc2.
func walkRoot(rootOid string) string {
	if rootOid == "" || rootOid == "." {
		return ".1.3.6.1"
	}
	if !strings.HasPrefix(rootOid, ".") {
		return "." + rootOid
	}
	return rootOid
}

// request asks the agent for the objects after oid.
func (w *walker) request(requestType PDUType, oid string) (*SnmpPacket, error) {
	switch requestType {
	case GetBulkRequest:
		return w.x.GetBulk([]string{oid}, 0, w.maxReps)
	case GetNextRequest:
		return w.x.GetNext([]string{oid})
	}
	return nil, fmt.Errorf("unsupported request type: %d", requestType)
}

// visit applies the walk's end rule, net-snmp's (apps/snmpwalk.c and
// apps/snmpbulkwalk.c at v5.9.4), to response: it passes the values of
// response that lie in the subtree to walkFn, in order, and returns what the
// walk does next. oid is the name the request asked for; firstAnswer marks the
// walk's first answer: a walk goes on only after an answer whose values all
// went to walkFn, so only the first answer can end a walk that found nothing,
// the case in which net-snmp gets the root.
func (w *walker) visit(response *SnmpPacket, oid string, firstAnswer bool, walkFn WalkFunc) (walkStep, error) {
	x := w.x
	// The error statuses tooBig to inconsistentName (RFC 3416) end the walk.
	// noSuchName is the end of an SNMPv1 MIB: as the first answer, the root may
	// still be a leaf, the MIB's last object. Known bugs: the others end the
	// walk with a nil error and the values so far, where net-snmp fails; a
	// status the RFC does not name is ignored and the answer walked.
	if status := response.Error; rfcError(status) {
		if x.Logger.enabled() {
			x.Logger.Print("Walk terminated with " + status.String())
		}
		if status == NoSuchName && firstAnswer {
			return walkGetRoot, nil
		}
		return walkDone, nil
	}
	// Known bug: an empty answer ends the walk with a nil error.
	if len(response.Variables) == 0 {
		return walkDone, nil
	}

	for i, pdu := range response.Variables {
		// A name outside the subtree ends the walk; as the walk's first value,
		// it shows the root to be a leaf (gosnmp/gosnmp#78).
		if !inSubtree(pdu.Name, w.root) {
			if firstAnswer && i == 0 {
				return walkGetRoot, nil
			}
			return walkDone, nil
		}
		// An exception value (RFC 3416 section 4.2) ends the walk, also as its
		// first value, without the leaf Get, as in net-snmp's snmpwalk: a leaf
		// root that is the MIB's last object answers endOfMibView and is not
		// fetched.
		if isException(pdu.Type) {
			if x.Logger.enabled() {
				x.Logger.Print("Walk terminated with " + pdu.Type.String())
			}
			return walkDone, nil
		}
		// Each name is compared with the request's, as net-snmp's
		// snmpbulkwalk does: a name equal to the root fails too.
		if w.checkIncreasing && oidCompare(oid, pdu.Name) >= 0 {
			return walkDone, fmt.Errorf("OID not increasing: %s >= %s", oid, pdu.Name)
		}
		if err := walkFn(pdu); err != nil {
			return walkDone, err
		}
	}
	return walkContinue, nil
}

// getRoot gets the root, which the walk found to be a leaf, as net-snmp's
// snmpwalk does after a walk that printed nothing, and passes walkFn the
// answer's first value when it names the root and is not an exception value
// (a Get of one name is answered by its first varbind). Statuses read as in
// visit: an error status passes nothing on (known bug: one the RFC does not
// name is ignored).
func (w *walker) getRoot(walkFn WalkFunc) error {
	response, err := w.x.Get([]string{w.root})
	if err != nil {
		return err
	}
	if rfcError(response.Error) || len(response.Variables) == 0 {
		return nil
	}
	if pdu := response.Variables[0]; pdu.Name == w.root && !isException(pdu.Type) {
		return walkFn(pdu)
	}
	return nil
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

// rfcError reports whether status is one of the error statuses RFC 3416
// names, tooBig to inconsistentName.
func rfcError(status SNMPError) bool {
	return status >= TooBig && status <= InconsistentName
}

// isException reports whether t is an exception value of RFC 3416 section
// 4.2: noSuchObject, noSuchInstance or endOfMibView.
func isException(t Asn1BER) bool {
	return t == NoSuchObject || t == NoSuchInstance || t == EndOfMibView
}

func (x *GoSNMP) walkAll(getRequestType PDUType, rootOid string) (results []SnmpPDU, err error) {
	err = x.walk(getRequestType, rootOid, func(dataUnit SnmpPDU) error {
		results = append(results, dataUnit)
		return nil
	})
	return results, err
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
