// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"cmp"
	"errors"
	"fmt"
	"strings"

	"github.com/netdata/gosnmp/internal/ber"
)

//
// SNMP Walk functions - Analogous to net-snmp's snmpwalk commands
//

// BulkWalkAll walks the subtree under rootOid with GETBULK requests (SNMPv2c
// and SNMPv3: a request on SNMPv1 fails before it is sent) and returns its
// values, in the order the agent returns them. An empty or "." rootOid walks
// .1.3.6.1. The subtree is rootOid and the names under it. The walk ends as
// net-snmp's snmpbulkwalk ends its walk: at the first name outside the
// subtree or exception value (NoSuchObject, NoSuchInstance, EndOfMibView),
// and at an answer whose Error is NoSuchName, the end of an SNMPv1 MIB,
// without an error. When the walk's first answer ends it with NoSuchName or
// with a first name outside the subtree, rootOid is taken for a leaf and
// fetched with one Get, whose first value is returned when it names rootOid
// and is not an exception value. An exception value in the subtree ends the
// walk without that Get, also in the first answer: a leaf rootOid that is the
// agent's last object answers EndOfMibView and is not fetched. The walk ends
// at once with the error of a failed request, and with an error for a name in
// the subtree, rootOid included, that is not after the requested one (each
// name of an answer is compared with the requested one); it returns the values
// before the error with it. Known bugs: an empty answer, or one whose Error is
// another of TooBig through InconsistentName, ends the walk without an error;
// another Error is ignored.
func (x *GoSNMP) BulkWalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walk(GetBulkRequest, rootOid)
}

// WalkAll walks the subtree under rootOid with GETNEXT requests, one per
// value, where BulkWalkAll asks for many at a time, and returns its values. It
// walks SNMPv1 agents too, and otherwise starts, ends and fails as BulkWalkAll
// does; net-snmp's snmpwalk differs only for a name before rootOid, which fails
// its increasing check where WalkAll ends (or, as the first answer, gets
// rootOid).
func (x *GoSNMP) WalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walk(GetNextRequest, rootOid)
}

// walk returns the values of the subtree under rootOid: it asks the agent for
// the objects after the root, then after the last name it received, with
// requestType (GetNext or GetBulk), and collects the objects in the subtree
// until an answer ends the walk (visit's rule). When that answer shows the
// root to be a leaf, the walk gets it once (getRoot). An error ends the walk
// with the values collected before it.
func (x *GoSNMP) walk(requestType PDUType, rootOid string) (results []SnmpPDU, err error) {
	root, err := walkRoot(rootOid)
	if err != nil {
		return nil, err
	}
	w := walker{
		x:           x,
		requestType: requestType,
		root:        root,
		maxReps:     cmp.Or(x.MaxRepetitions, defaultMaxRepetitions),
	}

	oid := w.root
	for requests := 1; ; requests++ {
		response, err := w.request(oid)
		if err != nil {
			return results, err
		}
		var next walkStep
		results, next, err = w.visit(response, oid, requests == 1, results)
		if err != nil {
			return results, err
		}
		switch next {
		case walkContinue:
			oid = response.Variables[len(response.Variables)-1].Name
			continue
		case walkGetRoot:
			if results, err = w.getRoot(results); err != nil {
				return results, err
			}
		}
		return results, nil
	}
}

// walker holds what a walk fixes at its start.
type walker struct {
	x *GoSNMP
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

// request asks the agent for the objects after oid, with the walk's
// max-repetitions for a GetBulk, which SNMPv1 does not have.
func (w *walker) request(oid string) (*SnmpPacket, error) {
	var maxReps uint32
	if w.requestType == GetBulkRequest {
		if w.x.Version == Version1 {
			return nil, errors.New("GETBULK not supported in SNMPv1")
		}
		maxReps = w.maxReps
	}
	packetOut, err := w.x.oidRequest(w.requestType, []string{oid}, maxReps)
	if err != nil {
		return nil, err
	}
	return w.x.send(packetOut)
}

// visit applies the walk's end rule, net-snmp's (apps/snmpwalk.c and
// apps/snmpbulkwalk.c at v5.9.4), to response: it appends the values of
// response that lie in the subtree to results, in order, and returns them and
// what the walk does next. oid is the name the request asked for; firstAnswer
// marks the walk's first answer: a walk goes on only after an answer whose
// values it all collected, so only the first answer can end a walk that found
// nothing, the case in which net-snmp gets the root.
func (w *walker) visit(response *SnmpPacket, oid string, firstAnswer bool, results []SnmpPDU) ([]SnmpPDU, walkStep, error) {
	// The error statuses tooBig to inconsistentName (RFC 3416) end the walk.
	// noSuchName is the end of an SNMPv1 MIB: as the first answer, the root may
	// still be a leaf, the MIB's last object. Known bugs: the others end the
	// walk with a nil error and the values so far, where net-snmp fails; a
	// status the RFC does not name is ignored and the answer walked.
	if status := response.Error; rfcError(status) {
		if status == NoSuchName && firstAnswer {
			return results, walkGetRoot, nil
		}
		return results, walkDone, nil
	}
	// Known bug: an empty answer ends the walk with a nil error.
	if len(response.Variables) == 0 {
		return results, walkDone, nil
	}

	for i, pdu := range response.Variables {
		// A name outside the subtree ends the walk; as the walk's first value,
		// it shows the root to be a leaf (gosnmp/gosnmp#78).
		if !inSubtree(pdu.Name, w.root) {
			if firstAnswer && i == 0 {
				return results, walkGetRoot, nil
			}
			return results, walkDone, nil
		}
		// An exception value (RFC 3416 section 4.2) ends the walk, also as its
		// first value, without the leaf Get, as in net-snmp's snmpwalk: a leaf
		// root that is the MIB's last object answers endOfMibView and is not
		// fetched.
		if isException(pdu.Type) {
			return results, walkDone, nil
		}
		// Each name is compared with the request's, as net-snmp's
		// snmpbulkwalk does: a name equal to the root fails too.
		if oidCompare(oid, pdu.Name) >= 0 {
			return results, walkDone, fmt.Errorf("OID not increasing: %s >= %s", oid, pdu.Name)
		}
		results = append(results, pdu)
	}
	return results, walkContinue, nil
}

// getRoot gets the root, which the walk found to be a leaf, as net-snmp's
// snmpwalk does after a walk that printed nothing, and appends the answer's
// first value to results when it names the root and is not an exception value
// (a Get of one name is answered by its first varbind). Statuses read as in
// visit: an error status adds nothing (known bug: one the RFC does not name is
// ignored).
func (w *walker) getRoot(results []SnmpPDU) ([]SnmpPDU, error) {
	response, err := w.x.Get([]string{w.root})
	if err != nil {
		return results, err
	}
	if rfcError(response.Error) || len(response.Variables) == 0 {
		return results, nil
	}
	if pdu := response.Variables[0]; pdu.Name == w.root && !isException(pdu.Type) {
		return append(results, pdu), nil
	}
	return results, nil
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
