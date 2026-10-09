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

// WalkFunc is the type of the function called for each data unit visited
// by the Walk function.  If an error is returned processing stops.
type WalkFunc func(dataUnit SnmpPDU) error

// BulkWalk retrieves a subtree of values using GETBULK. As the tree is
// walked walkFn is called for each new value. The function immediately returns
// an error if either there is an underlaying SNMP error (e.g. GetBulk fails),
// or if walkFn returns an error.
func (x *GoSNMP) BulkWalk(rootOid string, walkFn WalkFunc) error {
	return x.walk(GetBulkRequest, rootOid, walkFn)
}

// BulkWalkAll is similar to BulkWalk but returns a filled array of all values
// rather than using a callback function to stream results. Caution: if you
// have set x.AppOpts to 'c', BulkWalkAll may loop indefinitely and cause an
// Out Of Memory - use BulkWalk instead.
func (x *GoSNMP) BulkWalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walkAll(GetBulkRequest, rootOid)
}

// Walk retrieves a subtree of values using GETNEXT - a request is made for each
// value, unlike BulkWalk which does this operation in batches. As the tree is
// walked walkFn is called for each new value. The function immediately returns
// an error if either there is an underlaying SNMP error (e.g. GetNext fails),
// or if walkFn returns an error.
func (x *GoSNMP) Walk(rootOid string, walkFn WalkFunc) error {
	return x.walk(GetNextRequest, rootOid, walkFn)
}

// WalkAll is similar to Walk but returns a filled array of all values rather
// than using a callback function to stream results. Caution: if you have set
// x.AppOpts to 'c', WalkAll may loop indefinitely and cause an Out Of Memory -
// use Walk instead.
func (x *GoSNMP) WalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walkAll(GetNextRequest, rootOid)
}

// walk visits the subtree under rootOid: it asks the agent for the objects
// after the root, then after the last name it received, with getRequestType
// (GetNext or GetBulk), and passes each object in the subtree to walkFn until
// an answer ends the walk. When the walk's first object lies outside the
// subtree, the root is a leaf, and the walk gets it instead.
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
		case walkGetRoot:
			getRequestType = GetRequest
		case walkDone:
			if x.Logger.enabled() {
				x.Logger.Printf("BulkWalk completed in %d requests", requests)
			}
			return nil
		}
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
	// walkGetRoot gets the root, a leaf.
	walkGetRoot
	// walkDone ends the walk.
	walkDone
)

// walkRoot is the root of a walk asked for rootOid, with a leading dot. An
// empty root or "." walks the 'internet' subtree .1.3.6.1 (IANA, under the
// ISO OID structure of X.660; see https://oidref.com/1.3.6.1), which holds
// both the standard (MIB-2) and the vendor branches and encodes as an OID:
// RFC 2578 section 7.1.3 requires at least two sub-identifiers, and X.690
// section 8.19 encodes the first two arcs as 40 * arc1 + arc2.
func walkRoot(rootOid string) string {
	if rootOid == "" || rootOid == "." {
		return ".1.3.6.1"
	}
	if !strings.HasPrefix(rootOid, ".") {
		return "." + rootOid
	}
	return rootOid
}

// request asks the agent for the objects after oid, or, with GetRequest, for
// oid itself.
func (w *walker) request(requestType PDUType, oid string) (*SnmpPacket, error) {
	switch requestType {
	case GetBulkRequest:
		return w.x.GetBulk([]string{oid}, 0, w.maxReps)
	case GetNextRequest:
		return w.x.GetNext([]string{oid})
	case GetRequest:
		return w.x.Get([]string{oid})
	}
	return nil, fmt.Errorf("unsupported request type: %d", requestType)
}

// visit passes the objects of response that lie in the subtree to walkFn, in
// order, and returns what the walk does next. oid is the name the request
// asked for; firstAnswer marks the walk's first answer.
func (w *walker) visit(response *SnmpPacket, oid string, firstAnswer bool, walkFn WalkFunc) (walkStep, error) {
	x := w.x
	// Known bug: an empty answer ends the walk with a nil error.
	if len(response.Variables) == 0 {
		return walkDone, nil
	}
	// Every error status RFC 3416 names ends the walk. Known bugs: it ends the
	// walk with a nil error and the values so far, where net-snmp's snmpwalk
	// fails for every status but noSuchName (the end of an SNMPv1 MIB); a
	// status the RFC does not name is ignored and the answer walked.
	switch status := response.Error; {
	case status == NoError:
		if x.Logger.enabled() {
			x.Logger.Print("Walk completed with NoError")
		}
	case status <= InconsistentName:
		if x.Logger.enabled() {
			x.Logger.Print("Walk terminated with " + status.String())
		}
		return walkDone, nil
	}

	for i, pdu := range response.Variables {
		// An exception value (noSuchObject, noSuchInstance, endOfMibView:
		// RFC 3416 section 4.2) ends the walk.
		if pdu.Type == EndOfMibView || pdu.Type == NoSuchObject || pdu.Type == NoSuchInstance {
			if x.Logger.enabled() {
				x.Logger.Printf("BulkWalk terminated with type 0x%x", pdu.Type)
			}
			return walkDone, nil
		}
		if !inSubtree(pdu.Name, w.root) {
			return w.outside(pdu, firstAnswer && i == 0, walkFn)
		}
		// Known bug: each name is compared with the request's, not with the
		// name before it, so a decrease inside one GetBulk answer passes.
		if w.checkIncreasing && oidCompare(oid, pdu.Name) >= 0 {
			return walkDone, fmt.Errorf("OID not increasing: %s >= %s", oid, pdu.Name)
		}
		if err := walkFn(pdu); err != nil {
			return walkDone, err
		}
	}
	return walkContinue, nil
}

// outside returns what the walk does at pdu, an object outside the subtree.
// When pdu is the walk's first object (firstObject), the root is a leaf, and
// the walk gets it; the answer to that Get names the root and, unless it is an
// exception value, goes to walkFn. Any other object outside the subtree ends
// the walk.
func (w *walker) outside(pdu SnmpPDU, firstObject bool, walkFn WalkFunc) (walkStep, error) {
	// Known bug: only a first object outside the subtree makes the root a
	// leaf, so a leaf root that is the MIB's last object, answered with
	// endOfMibView or SNMPv1's noSuchName, returns nothing (net-snmp's
	// snmpwalk gets it after noSuchName).
	if firstObject {
		return walkGetRoot, nil
	}
	// Known bug: an answer naming the root in a GetNext or GetBulk walk goes
	// to walkFn too, without the increasing check, and ends the walk.
	if pdu.Name == w.root {
		if err := walkFn(pdu); err != nil {
			return walkDone, err
		}
	}
	return walkDone, nil
}

// inSubtree reports whether name starts with root and a dot, as
// strings.HasPrefix(name, root+".") does, without building the prefix. The
// dot keeps a sibling arc out: walking .1.3.6.1.2.1.4.22.1.2.1 does not
// return .1.3.6.1.2.1.4.22.1.2.115 (gosnmp/gosnmp#78, #93).
func inSubtree(name, root string) bool {
	return len(name) > len(root) && name[len(root)] == '.' && strings.HasPrefix(name, root)
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
			if comp1 < comp2 {
				return -1
			}
			return 1
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
