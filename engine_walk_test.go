// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"maps"
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
	bulk   bool   // BulkWalk instead of Walk
	root   string // the walk's root OID
	setup  func(x *GoSNMP)
	script func(n int, req, out *SnmpPacket) bool
	// stopAfter, when set, makes walkFn return an error on that value.
	stopAfter int
	// all runs WalkAll or BulkWalkAll instead of Walk or BulkWalk.
	all bool
	// onValue, when set, runs in walkFn at the n-th value, as user code
	// that changes the client during the walk.
	onValue  func(x *GoSNMP, n int)
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

var errWalkFn = errors.New("codec walkFn stop")

const lastLeafBug = "a leaf root that is the MIB's last object returns nothing: the Get fallback runs only when the first answer is outside the subtree, not on endOfMibView or noSuchName (net-snmp's snmpwalk makes the Get for noSuchName)"

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
		"walkfn-error":          {root: walkSystem, stopAfter: 2},
		"walkfn-error/bulk":     {root: walkSystem, bulk: true, stopAfter: 2},
		"walk-all":              {root: walkIfDescr, all: true},
		"walk-all/bulk":         {root: walkIfDescr, bulk: true, all: true},

		// A leaf as the root: the first answer is outside the subtree, so the
		// walk gets the root.
		"leaf":                  {root: ".1.3.6.1.2.1.1.5.0"},
		"leaf/bulk":             {root: ".1.3.6.1.2.1.1.5.0", bulk: true},
		"leaf/v1":               {root: ".1.3.6.1.2.1.1.5.0", v1: true},
		"leaf/walkfn-error":     {root: ".1.3.6.1.2.1.1.5.0", stopAfter: 1},
		"leaf/no-such-instance": {root: ".1.3.6.1.2.1.1.5.1"},
		"leaf/no-such-object":   {root: ".1.3.6.1.2.1.1.7.0"},
		"leaf/v1-no-such-name":  {root: ".1.3.6.1.2.1.1.5.1", v1: true},
		"leaf/last-object": {
			root: ".1.3.6.1.4.1.99.1.0", knownBug: lastLeafBug,
		},
		"leaf/last-object-v1": {
			root: ".1.3.6.1.4.1.99.1.0", v1: true, knownBug: lastLeafBug,
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
		"not-increasing/bulk-inside-response": {
			root: walkIfDescr, bulk: true, script: onWalkRequest(1, varbinds(ifDescr(1), ifDescr(0), ifDescr(2))),
			knownBug: "the increasing check compares each OID with the request's, not with the previous OID, so a decrease inside one response passes",
		},
		"not-increasing/app-opts-c": {
			root: walkIfDescr, setup: func(x *GoSNMP) { x.AppOpts = map[string]any{"c": true} },
			script: onWalkRequest(3, varbinds(ifDescr(0))),
		},
		"not-increasing/app-opts-c-bulk": {
			root: walkIfDescr, bulk: true,
			setup: func(x *GoSNMP) {
				x.AppOpts = map[string]any{"c": true}
				x.MaxRepetitions = 1
			},
			script: onWalkRequest(2, varbinds(ifDescr(0))),
		},
		"exception/no-such-object": {
			root: walkSystem, script: onWalkRequest(2, varbinds(SnmpPDU{Name: walkMIB[1].Name, Type: NoSuchObject})),
		},
		"exception/no-such-instance-bulk": {
			root: walkSystem, bulk: true,
			script: onWalkRequest(1, varbinds(walkMIB[0], SnmpPDU{Name: walkMIB[1].Name, Type: NoSuchInstance}, walkMIB[2])),
		},
		"root-in-bulk-response": {
			root: walkSystem, bulk: true,
			script:   onWalkRequest(1, varbinds(walkMIB[0], SnmpPDU{Name: walkSystem, Type: Integer, Value: 1}, walkMIB[1])),
			knownBug: "an answer naming the root itself skips the increasing check, is passed to walkFn and ends the walk",
		},
		"request-error": {
			root: walkSystem, all: true,
			script: func(n int, _, _ *SnmpPacket) bool { return n > 2 },
		},
		"request-error/bulk": {
			root: walkIfDescr, bulk: true, all: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 1 },
			script: func(n int, _, _ *SnmpPacket) bool { return n > 2 },
		},
		// A name that extends the root's last arc lies outside the subtree.
		"sibling-arc": {
			root:   walkIfDescr,
			script: onWalkRequest(4, varbinds(SnmpPDU{Name: walkIfDescr + "0.1", Type: OctetString, Value: []byte("sibling")})),
		},

		// User code changing the client during a walk: the walk keeps the
		// max-repetitions and the AppOpts it started with.
		"user-code/walkfn-sets-max-repetitions": {
			root: walkIfDescr, bulk: true, setup: func(x *GoSNMP) { x.MaxRepetitions = 1 },
			onValue: func(x *GoSNMP, _ int) { x.MaxRepetitions = 2 },
		},
		"user-code/walkfn-sets-app-opts-c": {
			root: walkIfDescr, script: onWalkRequest(3, varbinds(ifDescr(0))),
			onValue: func(x *GoSNMP, _ int) { x.AppOpts = map[string]any{"c": true} },
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
	scenarios["error-status/bulk-too-big"] = walkScenario{
		root: walkSystem, bulk: true, script: onWalkRequest(1, errorStatus(TooBig)),
		knownBug: "an error status ends the walk with a nil error and the values so far",
	}
	return scenarios
}

// TestEngineWalkCharacterization pins what Walk, BulkWalk, WalkAll and
// BulkWalkAll request and return, known bugs included: the subtree walked,
// the leaf fallback to a Get, the end of the MIB, error statuses, exception
// values, the increasing check and walkFn errors.
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

// runWalkScenario runs sc in the calling synctest bubble and returns its
// transcript.
func runWalkScenario(t *testing.T, sc walkScenario) string {
	tr := newEngineTranscript()
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

	tr.addf("client: %v root=%q bulk=%t max-repetitions=%d", x.Version, sc.root, sc.bulk, x.MaxRepetitions)
	var err error
	run := func() {
		switch {
		case sc.all && sc.bulk:
			var vbs []SnmpPDU
			vbs, err = x.BulkWalkAll(sc.root)
			tr.addf("values: %s", describeVarbinds(vbs))
		case sc.all:
			var vbs []SnmpPDU
			vbs, err = x.WalkAll(sc.root)
			tr.addf("values: %s", describeVarbinds(vbs))
		default:
			values := 0
			walkFn := func(vb SnmpPDU) error {
				values++
				tr.addf("walkFn: %s", describeVarbinds([]SnmpPDU{vb}))
				if sc.onValue != nil {
					sc.onValue(x, values)
				}
				if values == sc.stopAfter {
					return errWalkFn
				}
				return nil
			}
			if sc.bulk {
				err = x.BulkWalk(sc.root, walkFn)
			} else {
				err = x.Walk(sc.root, walkFn)
			}
		}
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
	return strings.Join(tr.lines, "\n")
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
