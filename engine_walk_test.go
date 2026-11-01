// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
)

// mibAgent is an in-memory v1/v2c agent for the walk tests. It answers Get,
// GetNext and GetBulk from a MIB sorted by OID as RFC 3416 section 4.2 and
// RFC 1157 section 4.1 do: SNMPv2c with noSuchObject, noSuchInstance or
// endOfMibView values, SNMPv1 with a noSuchName error, its index and the
// request's varbinds. GetBulk stops after the repetition in which every
// repeater reached endOfMibView, as RFC 3416 section 4.2.3 allows.
type mibAgent struct {
	tr  *engineTranscript
	mib []SnmpPDU

	// script, when set, changes the answer to the n-th request (counted
	// from 1); drop true leaves the request unanswered.
	script func(n int, req, out *SnmpPacket) (drop bool)
}

// walkMIB is the MIB of the walk tests: the system group, an interface table
// column and one object after them.
var walkMIB = []SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.1.0", Type: OctetString, Value: []byte("codec agent")},
	{Name: ".1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: uint32(4200)},
	{Name: ".1.3.6.1.2.1.1.5.0", Type: OctetString, Value: []byte("codec-host")},
	{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: OctetString, Value: []byte("lo")},
	{Name: ".1.3.6.1.2.1.2.2.1.2.2", Type: OctetString, Value: []byte("eth0")},
	{Name: ".1.3.6.1.2.1.2.2.1.2.10", Type: OctetString, Value: []byte("eth1")},
	{Name: ".1.3.6.1.4.1.99.1.0", Type: Integer, Value: 7},
}

const (
	walkSystem  = ".1.3.6.1.2.1.1"
	walkIfDescr = ".1.3.6.1.2.1.2.2.1.2"
)

// handle is the agent as an engineAgent.
func (a *mibAgent) handle(n int, data []byte) []agentReply {
	req, err := decodeMessage(data)
	if err != nil {
		a.tr.addf("agent: #%d not decodable: %v", n, err)
		return nil
	}
	out := a.answer(req)
	if a.script != nil && a.script(n, req, out) {
		a.tr.addf("agent: drops #%d", n)
		return nil
	}
	b, err := out.marshalMsg()
	if err != nil {
		panic(fmt.Sprintf("agent cannot encode its answer: %v", err))
	}
	return []agentReply{{data: b}}
}

// answer is the agent's answer to req.
func (a *mibAgent) answer(req *SnmpPacket) *SnmpPacket {
	out := &SnmpPacket{
		Version:   req.Version,
		Community: req.Community,
		PDUType:   GetResponse,
		RequestID: req.RequestID,
	}
	v1 := req.Version == Version1
	for i, vb := range req.Variables {
		var got []SnmpPDU
		switch req.PDUType {
		case GetRequest:
			got = []SnmpPDU{a.get(vb.Name)}
		case GetNextRequest:
			got = []SnmpPDU{a.next(vb.Name)}
		case GetBulkRequest:
			if i < int(req.NonRepeaters) {
				got = []SnmpPDU{a.next(vb.Name)}
			}
		default:
			panic(fmt.Sprintf("agent cannot answer %v", req.PDUType))
		}
		if v1 && len(got) == 1 && got[0].Type >= NoSuchObject {
			out.Error, out.ErrorIndex = NoSuchName, uint8(i+1) //nolint:gosec // a test request
			out.Variables = req.Variables
			return out
		}
		out.Variables = append(out.Variables, got...)
	}
	if req.PDUType == GetBulkRequest {
		out.Variables = append(out.Variables, a.repeat(req)...)
	}
	return out
}

// repeat is the repeated part of a GetBulk answer.
func (a *mibAgent) repeat(req *SnmpPacket) []SnmpPDU {
	last := make([]string, 0, len(req.Variables))
	for i, vb := range req.Variables {
		if i >= int(req.NonRepeaters) {
			last = append(last, vb.Name)
		}
	}
	var vbs []SnmpPDU
	for range req.MaxRepetitions {
		ended := 0
		for i, name := range last {
			vb := a.next(name)
			if vb.Type == EndOfMibView {
				ended++
			}
			vbs = append(vbs, vb)
			last[i] = vb.Name
		}
		if ended == len(last) {
			break
		}
	}
	return vbs
}

// get is the value of name, or the exception for it.
func (a *mibAgent) get(name string) SnmpPDU {
	for _, vb := range a.mib {
		if vb.Name == name {
			return vb
		}
	}
	parent := name[:max(strings.LastIndexByte(name, '.'), 0)]
	for _, vb := range a.mib {
		if strings.HasPrefix(vb.Name, parent+".") {
			return SnmpPDU{Name: name, Type: NoSuchInstance}
		}
	}
	return SnmpPDU{Name: name, Type: NoSuchObject}
}

// next is the first object after name, or endOfMibView.
func (a *mibAgent) next(name string) SnmpPDU {
	for _, vb := range a.mib {
		if oidCompare(vb.Name, name) > 0 {
			return vb
		}
	}
	return SnmpPDU{Name: name, Type: EndOfMibView}
}

// walkScenario is one walk run against a mibAgent.
type walkScenario struct {
	v1     bool
	bulk   bool   // BulkWalkAll instead of WalkAll
	root   string // the walk's root OID
	setup  func(x *GoSNMP)
	script func(n int, req, out *SnmpPacket) bool
	// onFinish, when set, is the OnFinish hook, run after each of the
	// walk's requests: user code that changes the client during the walk.
	onFinish func(x *GoSNMP, tr *engineTranscript)
	knownBug string
}

// onWalkRequest changes the answer to request n only.
func onWalkRequest(n int, edit func(req, out *SnmpPacket)) func(int, *SnmpPacket, *SnmpPacket) bool {
	return func(k int, req, out *SnmpPacket) bool {
		if k == n {
			edit(req, out)
		}
		return false
	}
}

// errorStatus answers with status and the request's varbinds, as an agent
// reports an error.
func errorStatus(status SNMPError) func(req, out *SnmpPacket) {
	return func(req, out *SnmpPacket) {
		out.Error, out.ErrorIndex, out.Variables = status, 1, req.Variables
	}
}

// varbinds answers with vbs.
func varbinds(vbs ...SnmpPDU) func(req, out *SnmpPacket) {
	return func(_, out *SnmpPacket) { out.Variables = vbs }
}

// walkScenarios are the scenarios of TestEngineWalkCharacterization.
func walkScenarios() map[string]walkScenario {
	ifDescr := func(i int) SnmpPDU { return walkMIB[3+i] }
	scenarios := map[string]walkScenario{
		"subtree":               {root: walkSystem},
		"subtree/bulk":          {root: walkSystem, bulk: true},
		"subtree/v1":            {root: walkSystem, v1: true},
		"table-column":          {root: walkIfDescr},
		"table-column/bulk":     {root: walkIfDescr, bulk: true},
		"default-root":          {root: ""},
		"default-root/dot":      {root: ".", bulk: true},
		"default-root/v1":       {root: "", v1: true},
		"root-without-dot":      {root: "1.3.6.1.2.1.2.2.1.2"},
		"root-without-dot/bulk": {root: "1.3.6.1.2.1.2.2.1.2", bulk: true},
		"root-past-mib":         {root: ".1.3.6.1.4.1.99.2"},
		"root-past-mib/bulk":    {root: ".1.3.6.1.4.1.99.2", bulk: true},
		"root-past-mib/v1":      {root: ".1.3.6.1.4.1.99.2", v1: true},
		"empty-subtree":         {root: ".1.3.6.1.2.1.1.4"},
		"empty-subtree/bulk":    {root: ".1.3.6.1.2.1.1.4", bulk: true},
		"max-repetitions/two":   {root: walkIfDescr, bulk: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 2 }},
		"max-repetitions/one":   {root: walkSystem, bulk: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 1 }},
		"v1-bulk":               {root: walkSystem, bulk: true, v1: true},
		// A root the codec cannot encode fails the walk before any request,
		// naming the root as given.
		"root-invalid": {root: "1.3.6.x"},

		// A leaf as the root: the first answer is outside the subtree, so the
		// walk gets the root.
		"leaf":                  {root: ".1.3.6.1.2.1.1.5.0"},
		"leaf/bulk":             {root: ".1.3.6.1.2.1.1.5.0", bulk: true},
		"leaf/v1":               {root: ".1.3.6.1.2.1.1.5.0", v1: true},
		"leaf/no-such-instance": {root: ".1.3.6.1.2.1.1.5.1"},
		"leaf/no-such-object":   {root: ".1.3.6.1.2.1.1.7.0"},
		"leaf/v1-no-such-name":  {root: ".1.3.6.1.2.1.1.5.1", v1: true},
		// A leaf root that is the MIB's last object: SNMPv2c answers
		// endOfMibView, which ends the walk without the Get, as in net-snmp's
		// snmpwalk; SNMPv1 answers noSuchName, after which the walk gets it.
		"leaf/last-object":    {root: ".1.3.6.1.4.1.99.1.0"},
		"leaf/last-object-v1": {root: ".1.3.6.1.4.1.99.1.0", v1: true},
		// An agent echoing the root as the first answer: the root is in the
		// subtree and not after the requested name.
		"leaf/root-echo": {
			root: walkSystem, script: onWalkRequest(1, varbinds(SnmpPDU{Name: walkSystem, Type: Integer, Value: 1})),
		},
		// The leaf's Get answered with a name under the root: one Get, nothing
		// passed on.
		"leaf/get-answer-in-subtree": {
			root:   ".1.3.6.1.2.1.1.5.0",
			script: onWalkRequest(2, varbinds(SnmpPDU{Name: ".1.3.6.1.2.1.1.5.0.1", Type: OctetString, Value: []byte("inside")})),
		},
		// The leaf's Get unanswered: the walk returns the request's error.
		"leaf/get-error": {
			root:   ".1.3.6.1.2.1.1.5.0",
			script: func(n int, _, _ *SnmpPacket) bool { return n >= 2 },
		},
		// The leaf's Get answered with an error status: nothing passed on.
		"leaf/get-error-status": {
			root:   ".1.3.6.1.2.1.1.5.0",
			script: onWalkRequest(2, errorStatus(GenErr)),
		},
		// The leaf's Get answered with a status no RFC names.
		"leaf/get-unknown-status": {
			root: ".1.3.6.1.2.1.1.5.0",
			script: onWalkRequest(2, func(_, out *SnmpPacket) {
				out.Error = InconsistentName + 1
			}),
			knownBug: "an error status the walk does not name is ignored and the root's value passed on",
		},
		// The leaf's Get answered with another name before the root's value.
		"leaf/get-other-name-first": {
			root:   ".1.3.6.1.2.1.1.5.0",
			script: onWalkRequest(2, varbinds(walkMIB[0], walkMIB[2])),
		},
		// The leaf's Get answered without varbinds: nothing passed on.
		"leaf/get-empty": {
			root:   ".1.3.6.1.2.1.1.5.0",
			script: onWalkRequest(2, varbinds()),
		},

		// Answers a walk does not expect.
		"empty-response": {
			root: walkSystem, script: onWalkRequest(2, varbinds()),
			knownBug: "an empty response ends the walk with a nil error",
		},
		"empty-response/bulk": {
			root: walkSystem, bulk: true, script: onWalkRequest(1, varbinds()),
			knownBug: "an empty response ends the walk with a nil error",
		},
		"not-increasing/equal":      {root: walkSystem, script: onWalkRequest(2, varbinds(walkMIB[0]))},
		"not-increasing/decreasing": {root: walkIfDescr, script: onWalkRequest(3, varbinds(ifDescr(0)))},
		// Each name is compared with the request's, as in net-snmp's
		// snmpbulkwalk: a decrease inside one answer passes.
		"not-increasing/bulk-inside-response": {
			root: walkIfDescr, bulk: true, script: onWalkRequest(1, varbinds(ifDescr(1), ifDescr(0), ifDescr(2))),
		},
		"exception/no-such-object": {
			root: walkSystem, script: onWalkRequest(2, varbinds(SnmpPDU{Name: walkMIB[1].Name, Type: NoSuchObject})),
		},
		"exception/no-such-instance-bulk": {
			root: walkSystem, bulk: true,
			script: onWalkRequest(1, varbinds(walkMIB[0], SnmpPDU{Name: walkMIB[1].Name, Type: NoSuchInstance}, walkMIB[2])),
		},
		// An exception value outside the subtree as the walk's first value:
		// the subtree is checked first, as in net-snmp, so the walk gets the
		// root.
		"exception/outside-first-value": {
			root:   ".1.3.6.1.2.1.1.5.0",
			script: onWalkRequest(1, varbinds(SnmpPDU{Name: ifDescr(0).Name, Type: NoSuchObject})),
		},
		// A name equal to the root lies in the subtree and fails the
		// increasing check.
		"root-in-bulk-response": {
			root: walkSystem, bulk: true,
			script: onWalkRequest(1, varbinds(walkMIB[0], SnmpPDU{Name: walkSystem, Type: Integer, Value: 1}, walkMIB[1])),
		},
		"root-in-response": {
			root:   walkSystem,
			script: onWalkRequest(2, varbinds(SnmpPDU{Name: walkSystem, Type: Integer, Value: 1})),
		},
		// A name before the root lies outside the subtree.
		"below-root/first-value": {root: walkIfDescr, script: onWalkRequest(1, varbinds(walkMIB[0]))},
		"below-root/later":       {root: walkIfDescr, script: onWalkRequest(2, varbinds(walkMIB[0]))},
		"request-error": {
			root:   walkSystem,
			script: func(n int, _, _ *SnmpPacket) bool { return n > 2 },
		},
		"request-error/bulk": {
			root: walkIfDescr, bulk: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 1 },
			script: func(n int, _, _ *SnmpPacket) bool { return n > 2 },
		},
		// A name that extends the root's last arc lies outside the subtree.
		"sibling-arc": {
			root:   walkIfDescr,
			script: onWalkRequest(4, varbinds(SnmpPDU{Name: walkIfDescr + "0.1", Type: OctetString, Value: []byte("sibling")})),
		},

		// User code changing the client during a walk: the walk keeps the
		// max-repetitions it started with.
		"user-code/hook-sets-max-repetitions": {
			root: walkIfDescr, bulk: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 1 },
			onFinish: func(x *GoSNMP, tr *engineTranscript) {
				tr.addf("hook OnFinish sets MaxRepetitions to 2")
				x.MaxRepetitions = 2
			},
		},
		// A change of version applies from the walk's next request: GETBULK
		// on SNMPv1 is refused, and the walk returns the values so far.
		"user-code/hook-sets-version-1": {
			root: walkIfDescr, bulk: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 1 },
			onFinish: func(x *GoSNMP, tr *engineTranscript) {
				tr.addf("hook OnFinish sets Version to 1")
				x.Version = Version1
			},
		},
		// The walk's later GetNext requests are SNMPv1 requests.
		"user-code/hook-sets-version-1/getnext": {
			root: walkIfDescr,
			onFinish: func(x *GoSNMP, tr *engineTranscript) {
				tr.addf("hook OnFinish sets Version to 1")
				x.Version = Version1
			},
		},
		// MaxOids applies to each of the walk's requests: zero refuses the
		// next one, and the walk returns the values so far.
		"user-code/hook-sets-max-oids-0": {
			root: walkIfDescr,
			onFinish: func(x *GoSNMP, tr *engineTranscript) {
				tr.addf("hook OnFinish sets MaxOids to 0")
				x.MaxOids = 0
			},
		},
	}

	// Every error status the walk names, and one it does not. NoSuchName
	// ends a walk without an error in net-snmp's snmpwalk too.
	for status := TooBig; status <= InconsistentName; status++ {
		sc := walkScenario{root: walkSystem, script: onWalkRequest(2, errorStatus(status))}
		if status != NoSuchName {
			sc.knownBug = "an error status ends the walk with a nil error and the values so far"
		}
		scenarios[fmt.Sprintf("error-status/%d-%v", status, status)] = sc
	}
	scenarios["error-status/19-unknown"] = walkScenario{
		root: walkSystem, script: onWalkRequest(2, errorStatus(InconsistentName+1)),
		knownBug: "an error status the walk does not name is ignored and the varbinds walked",
	}
	scenarios["error-status/19-unknown-empty"] = walkScenario{
		root: walkSystem,
		script: onWalkRequest(2, func(_, out *SnmpPacket) {
			out.Error, out.ErrorIndex, out.Variables = InconsistentName+1, 0, nil
		}),
		knownBug: "an empty response ends the walk with a nil error",
	}
	scenarios["error-status/bulk-too-big"] = walkScenario{
		root: walkSystem, bulk: true, script: onWalkRequest(1, errorStatus(TooBig)),
		knownBug: "an error status ends the walk with a nil error and the values so far",
	}
	// NoSuchName as an SNMPv2c walk's first answer, with and without the
	// request's varbinds: the status is read first, and the walk gets the root.
	scenarios["error-status/no-such-name-first"] = walkScenario{
		root: ".1.3.6.1.2.1.1.5.0", script: onWalkRequest(1, errorStatus(NoSuchName)),
	}
	scenarios["error-status/no-such-name-empty-first"] = walkScenario{
		root: ".1.3.6.1.2.1.1.5.0",
		script: onWalkRequest(1, func(_, out *SnmpPacket) {
			out.Error, out.ErrorIndex, out.Variables = NoSuchName, 0, nil
		}),
	}
	return scenarios
}

// TestEngineWalkCharacterization pins what WalkAll and BulkWalkAll request
// and return, known bugs included: the subtree walked, the leaf fallback to a
// Get, the end of the MIB, error statuses, exception values and the
// increasing check.
// testdata/engine/walk.golden holds the transcripts.
func TestEngineWalkCharacterization(t *testing.T) {
	scenarios := walkScenarios()
	var results []goldenCase
	for _, name := range slices.Sorted(maps.Keys(scenarios)) {
		sc := scenarios[name]
		var dump string
		synctest.Test(t, func(t *testing.T) {
			dump = runWalkScenario(t, sc)
		})
		results = append(results, goldenCase{name: "walk/" + name, dump: dump})
	}
	engineGolden.check(t, "walk", results)
}

// TestEngineWalkRootSpellings exercises the public walks through the codec:
// equivalent root spellings must visit the same objects and get a leaf once.
func TestEngineWalkRootSpellings(t *testing.T) {
	spellings := []struct {
		name string
		root func(string) string
	}{
		{"canonical", func(root string) string { return root }},
		{"undotted", func(root string) string { return strings.TrimPrefix(root, ".") }},
		{"leading-zeros", func(root string) string { return strings.ReplaceAll(root, ".", ".0") }},
		{"leading-dots", func(root string) string { return "." + root }},
		{"repeated-dots", func(root string) string { return strings.ReplaceAll(root, ".", "..") }},
		{"trailing-dot", func(root string) string { return root + "." }},
		{"combined", func(root string) string { return strings.ReplaceAll(root, ".", "..0") + ".." }},
	}
	cases := []struct {
		name    string
		root    string
		version SnmpVersion
		want    []SnmpPDU
		gets    int
		equal   bool // answer the first request with the root itself
	}{
		{name: "subtree", root: walkIfDescr, version: Version2c, want: walkMIB[3:6]},
		{name: "subtree-v1", root: walkIfDescr, version: Version1, want: walkMIB[3:6]},
		{name: "leaf", root: walkMIB[2].Name, version: Version2c, want: walkMIB[2:3], gets: 1},
		{name: "last-leaf-v1", root: walkMIB[6].Name, version: Version1, want: walkMIB[6:7], gets: 1},
		{name: "last-leaf-v2", root: walkMIB[6].Name, version: Version2c},
		{name: "equal-root", root: walkIfDescr, version: Version2c, equal: true},
	}
	for _, api := range []string{"WalkAll", "BulkWalkAll"} {
		for _, tc := range cases {
			if tc.version == Version1 && strings.HasPrefix(api, "Bulk") {
				continue // GetBulk is not supported by SNMPv1.
			}
			for _, spelling := range spellings {
				t.Run(api+"/"+tc.name+"/"+spelling.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						gets := 0
						agent := &mibAgent{mib: walkMIB, script: func(n int, req, out *SnmpPacket) bool {
							if n == 1 || req.PDUType == GetRequest {
								if len(req.Variables) != 1 || req.Variables[0].Name != tc.root {
									t.Fatalf("request root = %v, want %q", req.Variables, tc.root)
								}
							}
							if req.PDUType == GetRequest {
								gets++
							}
							if tc.equal && n == 1 {
								out.Variables = []SnmpPDU{{Name: tc.root, Type: Integer, Value: 1}}
							}
							return false
						}}
						x := newEngineClient(t, nil, tc.version, fakePacketTransport{newFakeTransport(nil, agent.handle)})
						root := spelling.root(tc.root)
						walk := x.WalkAll
						if api == "BulkWalkAll" {
							walk = x.BulkWalkAll
						}
						got, err := walk(root)
						if tc.equal {
							if err == nil || !strings.Contains(err.Error(), "OID not increasing") {
								t.Errorf("error = %v, want OID not increasing", err)
							}
						} else if err != nil {
							t.Errorf("walk: %v", err)
						}
						if !reflect.DeepEqual(got, tc.want) {
							t.Errorf("values = %v, want %v", got, tc.want)
						}
						if gets != tc.gets {
							t.Errorf("leaf Gets = %d, want %d", gets, tc.gets)
						}
					})
				})
			}
		}
	}
}

// runWalkScenario runs sc in the calling synctest bubble and returns its
// transcript.
func runWalkScenario(t *testing.T, sc walkScenario) string {
	tr := newEngineTranscript(t)
	agent := &mibAgent{tr: tr, mib: walkMIB, script: sc.script}
	version := Version2c
	if sc.v1 {
		version = Version1
	}
	x := newEngineClient(t, tr, version, fakePacketTransport{newFakeTransport(tr, agent.handle)})
	x.PreSend, x.OnSent, x.OnRecv, x.OnFinish = nil, nil, nil, nil
	if sc.setup != nil {
		sc.setup(x)
	}
	if sc.onFinish != nil {
		x.OnFinish = func(x *GoSNMP) { sc.onFinish(x, tr) }
	}

	tr.addf("client: %v root=%q bulk=%t max-repetitions=%d", x.Version, sc.root, sc.bulk, x.MaxRepetitions)
	walk := x.WalkAll
	if sc.bulk {
		walk = x.BulkWalkAll
	}
	var err error
	run := func() {
		var vbs []SnmpPDU
		vbs, err = walk(sc.root)
		tr.addf("values: %s", describeVarbinds(vbs))
	}
	if v, _ := recoverPanic(run); v != nil {
		tr.addf("panic: %v", v)
	} else if err != nil {
		tr.addf("result: %s", describeEngineError(err))
	} else {
		tr.addf("result: no error")
	}
	if sc.knownBug != "" {
		tr.addf("known bug: %s", sc.knownBug)
	}
	return tr.text()
}

// BenchmarkWalk runs WalkAll and BulkWalkAll, as the Netdata Agent's SNMP
// collector does, over a 100-row table column on the in-memory agent.
func BenchmarkWalk(b *testing.B) {
	const root = ".1.3.6.1.4.1.99999.1.1.1.1.2.3.4"
	mib := make([]SnmpPDU, 0, 101)
	for i := range 100 {
		mib = append(mib, SnmpPDU{Name: fmt.Sprintf("%s.%d", root, i+1), Type: Counter64, Value: uint64(i)})
	}
	mib = append(mib, SnmpPDU{Name: ".1.3.6.1.4.1.99999.1.1.1.1.2.3.5.1", Type: Integer, Value: 1})

	for name, walkAll := range map[string]func(x *GoSNMP) ([]SnmpPDU, error){
		"WalkAll":     func(x *GoSNMP) ([]SnmpPDU, error) { return x.WalkAll(root) },
		"BulkWalkAll": func(x *GoSNMP) ([]SnmpPDU, error) { return x.BulkWalkAll(root) },
	} {
		b.Run(name, func(b *testing.B) {
			agent := &mibAgent{mib: mib}
			x := newEngineClient(b, nil, Version2c, newFakeTransport(nil, agent.handle))
			b.ReportAllocs()
			for b.Loop() {
				vbs, err := walkAll(x)
				if err != nil || len(vbs) != 100 {
					b.Fatalf("%d values, error %v", len(vbs), err)
				}
			}
		})
	}
}
