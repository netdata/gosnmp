// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netdata/gosnmp/internal/ber"
)

// fakeV3Agent is an authoritative SNMPv3 engine for the engine tests. It reads
// a request with its own parser (parseV3Message), checks it with the library's
// digests and ciphers in the order of RFC 3414 section 3.2 (engine ID, user,
// security level, digest, time window, decryption) and answers with a
// GetResponse at the request's security level or with a Report: noAuthNoPriv
// for an unknown engine ID or user, an unsupported level, a wrong digest or a
// decryption error, authNoPriv for a message outside the time window. Its
// engine time counts the seconds of the bubble's clock.
type fakeV3Agent struct {
	tr       *engineTranscript
	engineID string
	boots    uint32
	timeBase uint32
	start    time.Time
	creds    map[string]agentUser
	users    map[string]*UsmSecurityParameters // keys localized to engineID
	vbs      []SnmpPDU
	counters map[string]uint32
	salt     uint64

	// script, when set, answers the n-th request (counted from 1) instead of
	// the RFC 3414 checks; ok false leaves the request to them.
	script func(n int, req agentRequest) (ans agentAnswer, ok bool)
}

// agentUser is the credentials of a fake agent user.
type agentUser struct {
	auth     SnmpV3AuthProtocol
	authPass string
	priv     SnmpV3PrivProtocol
	privPass string
}

// agentRequest is a request as the fake agent read it.
type agentRequest struct {
	msgID                        uint32
	flags                        SnmpV3MsgFlags
	engineID, user               string
	boots, engineTime            uint32
	contextEngineID, contextName string
	pdu                          *SnmpPacket // nil when the scoped PDU was not read
}

// agentAnswer is the answer of the fake agent to one request.
type agentAnswer struct {
	report string         // the Report's counter OID, or "" for a GetResponse
	level  SnmpV3MsgFlags // the security level of the answer
	edit   func(*SnmpPacket)
	drop   bool // no answer
	why    string
}

const (
	agentEngineID      = "\x80\x00\x1f\x88\x04codec-agent"
	agentOtherEngineID = "\x80\x00\x1f\x88\x04codec-other"
	agentBoots         = 7
	agentTimeBase      = 1000
	agentTimeWindow    = 150 // seconds, RFC 3414 section 2.2.3
)

func newFakeV3Agent(tr *engineTranscript, creds map[string]agentUser, vbs ...SnmpPDU) *fakeV3Agent {
	a := &fakeV3Agent{
		tr:       tr,
		boots:    agentBoots,
		timeBase: agentTimeBase,
		start:    time.Now(),
		creds:    creds,
		vbs:      vbs,
		counters: map[string]uint32{},
	}
	a.setEngineID(agentEngineID)
	return a
}

// setEngineID gives the agent another engine ID, as a replaced device has,
// and localizes its users' keys to it.
func (a *fakeV3Agent) setEngineID(engineID string) {
	a.engineID = engineID
	a.users = make(map[string]*UsmSecurityParameters, len(a.creds))
	for name, c := range a.creds {
		sp := &UsmSecurityParameters{
			UserName:                 name,
			AuthenticationProtocol:   c.auth,
			AuthenticationPassphrase: c.authPass,
			PrivacyProtocol:          c.priv,
			PrivacyPassphrase:        c.privPass,
			AuthoritativeEngineID:    engineID,
		}
		if err := sp.InitSecurityKeys(); err != nil {
			panic(err)
		}
		a.users[name] = sp
	}
}

// reboot restarts the agent: its boots go up by one and its time restarts
// from zero.
func (a *fakeV3Agent) reboot() {
	a.boots++
	a.timeBase = 0
	a.start = time.Now()
}

func (a *fakeV3Agent) engineTime() uint32 {
	return a.timeBase + uint32(time.Since(a.start)/time.Second) //nolint:gosec // a test clock
}

// handle is the fake agent as an engineAgent.
func (a *fakeV3Agent) handle(n int, data []byte) []agentReply {
	m, err := parseV3Message(data)
	if err != nil {
		a.tr.addf("agent: #%d not an SNMPv3 message: %v", n, err)
		return nil
	}
	req, err := readAgentRequest(m)
	if err != nil {
		a.tr.addf("agent: #%d unreadable: %v", n, err)
		return nil
	}

	ans, scripted := agentAnswer{}, false
	if a.script != nil {
		ans, scripted = a.script(n, req)
	}
	if !scripted {
		ans = a.check(m, &req)
	} else if req.pdu == nil {
		// A scripted answer still carries the request ID when the agent
		// can read it.
		_ = a.readScopedPDU(m, &req)
	}
	if m.scopedTag == byte(OctetString) && req.pdu != nil {
		a.tr.addf("agent: #%d decrypts to context=%q/%q %v id=%d %s", n, req.contextEngineID, req.contextName,
			req.pdu.PDUType, req.pdu.RequestID, describeVarbinds(req.pdu.Variables))
	}
	if ans.drop {
		a.tr.addf("agent: drops #%d (%s)", n, ans.why)
		return nil
	}

	out := a.answer(req, ans)
	a.tr.addf("agent: answers #%d with %s at %s (%s)", n, describeAnswerPDU(out), describeFlags(ans.level), ans.why)
	b, err := out.MarshalMsg()
	if err != nil {
		panic(fmt.Sprintf("agent cannot encode its answer: %v", err))
	}
	return []agentReply{{data: b}}
}

// check runs the RFC 3414 section 3.2 checks on req, reading its scoped PDU
// when the checks reach it.
func (a *fakeV3Agent) check(m v3Message, req *agentRequest) agentAnswer {
	user := a.users[req.user]
	switch {
	case req.engineID != a.engineID:
		return agentAnswer{report: usmStatsUnknownEngineIDs, why: "unknown engine ID"}
	case user == nil:
		return agentAnswer{report: usmStatsUnknownUserNames, why: "unknown user"}
	case req.flags&AuthNoPriv != 0 && user.AuthenticationProtocol <= NoAuth,
		req.flags&AuthPriv == AuthPriv && user.PrivacyProtocol <= NoPriv:
		return agentAnswer{report: usmStatsUnsupportedSecLevels, why: "unsupported security level"}
	}
	if req.flags&AuthNoPriv != 0 {
		if !agentDigestOK(m, user) {
			return agentAnswer{report: usmStatsWrongDigests, why: "wrong digest"}
		}
		if req.boots != a.boots || absDiff(req.engineTime, a.engineTime()) > agentTimeWindow {
			return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}
		}
	}
	if err := a.readScopedPDU(m, req); err != nil {
		return agentAnswer{report: usmStatsDecryptionErrors, why: err.Error()}
	}
	return agentAnswer{level: req.flags & AuthPriv, why: "request accepted"}
}

// readScopedPDU reads the scoped PDU of req, decrypting it with its user's
// key when it is encrypted.
func (a *fakeV3Agent) readScopedPDU(m v3Message, req *agentRequest) error {
	plain := m.scoped
	if m.scopedTag == byte(OctetString) {
		user := a.users[req.user]
		if user == nil || user.PrivacyProtocol <= NoPriv {
			return errors.New("encrypted scoped PDU without a privacy key")
		}
		dec, err := user.PrivacyProtocol.spec().Decrypt(user.PrivacyKey, m.usm[5], req.boots, req.engineTime, m.scoped)
		if err != nil {
			return err
		}
		r := ber.NewReader(dec)
		if _, plain, err = r.Next(); err != nil {
			return fmt.Errorf("decrypted scoped PDU: %w", err)
		}
	}
	r := ber.NewReader(plain)
	var fields [2]string
	for i := range fields {
		_, f, err := r.Next()
		if err != nil {
			return fmt.Errorf("scoped PDU: %w", err)
		}
		fields[i] = string(f)
	}
	pdu := new(SnmpPacket)
	if err := unmarshalPayload(plain, len(plain)-r.Len(), pdu); err != nil {
		return fmt.Errorf("scoped PDU: %w", err)
	}
	req.contextEngineID, req.contextName, req.pdu = fields[0], fields[1], pdu
	return nil
}

// answer builds the agent's answer to req.
func (a *fakeV3Agent) answer(req agentRequest, ans agentAnswer) *SnmpPacket {
	sp := &UsmSecurityParameters{
		AuthoritativeEngineID:    a.engineID,
		AuthoritativeEngineBoots: a.boots,
		AuthoritativeEngineTime:  a.engineTime(),
		UserName:                 req.user,
	}
	if user := a.users[req.user]; user != nil {
		if ans.level&AuthNoPriv != 0 {
			sp.AuthenticationProtocol, sp.SecretKey = user.AuthenticationProtocol, user.SecretKey
		}
		if ans.level&AuthPriv == AuthPriv {
			a.salt++
			sp.PrivacyProtocol, sp.PrivacyKey = user.PrivacyProtocol, user.PrivacyKey
			sp.PrivacyParameters = binary.BigEndian.AppendUint64(nil, a.salt)
			if user.PrivacyProtocol == DES {
				sp.PrivacyParameters = binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, a.boots), uint32(a.salt)) //nolint:gosec // a 32-bit salt
			}
		}
	}
	out := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           ans.level,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		ContextEngineID:    a.engineID,
		ContextName:        req.contextName,
		PDUType:            GetResponse,
		MsgID:              req.msgID,
		Variables:          a.vbs,
	}
	if req.pdu != nil {
		out.RequestID = req.pdu.RequestID
	}
	if ans.report != "" {
		a.counters[ans.report]++
		out.PDUType = Report
		out.Variables = []SnmpPDU{{Name: ans.report, Type: Counter32, Value: a.counters[ans.report]}}
	}
	if ans.edit != nil {
		ans.edit(out)
	}
	return out
}

// readAgentRequest decodes the header and security parameters of m.
func readAgentRequest(m v3Message) (agentRequest, error) {
	var req agentRequest
	hr := ber.NewReader(m.header)
	var header [4][]byte
	for i := range header {
		_, f, err := hr.Next()
		if err != nil {
			return req, fmt.Errorf("header: %w", err)
		}
		header[i] = f
	}
	msgID, err := ber.Int64(header[0])
	if err != nil {
		return req, fmt.Errorf("msgID: %w", err)
	}
	if len(header[2]) != 1 {
		return req, fmt.Errorf("msgFlags of %d octets", len(header[2]))
	}
	boots, err := ber.Int64(m.usm[1])
	if err != nil {
		return req, fmt.Errorf("engine boots: %w", err)
	}
	engineTime, err := ber.Int64(m.usm[2])
	if err != nil {
		return req, fmt.Errorf("engine time: %w", err)
	}
	req.msgID = uint32(msgID) //nolint:gosec // a test message
	req.flags = SnmpV3MsgFlags(header[2][0])
	req.engineID, req.user = string(m.usm[0]), string(m.usm[3])
	req.boots, req.engineTime = uint32(boots), uint32(engineTime) //nolint:gosec // a test message
	if m.scopedTag != byte(OctetString) {
		// A plaintext scoped PDU is read even before the checks, so a
		// Report can carry its request ID.
		var probe fakeV3Agent
		_ = probe.readScopedPDU(m, &req)
	}
	return req, nil
}

// agentDigestOK reports whether m carries the digest of user's key.
func agentDigestOK(m v3Message, user *UsmSecurityParameters) bool {
	spec := user.AuthenticationProtocol.spec()
	if len(m.usm[4]) != spec.MACLen {
		return false
	}
	zeroed := m
	zeroed.usm[4] = make([]byte, len(m.usm[4]))
	ok, err := spec.Verify(user.SecretKey, zeroed.bytes(), m.usm[4])
	return err == nil && ok
}

func absDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

func describeFlags(f SnmpV3MsgFlags) string {
	level := "noAuthNoPriv"
	switch {
	case f&AuthPriv == AuthPriv:
		level = "authPriv"
	case f&AuthNoPriv != 0:
		level = "authNoPriv"
	case f&AuthPriv == usmPrivacyFlag:
		level = "privOnly"
	}
	if f&Reportable != 0 {
		level += "+reportable"
	}
	return level
}

func describeAgentRequest(req agentRequest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "msgID=%d %s user=%q engine=%q boots=%d time=%d", req.msgID, describeFlags(req.flags), req.user,
		req.engineID, req.boots, req.engineTime)
	if req.pdu != nil {
		fmt.Fprintf(&sb, " context=%q/%q %v id=%d %s", req.contextEngineID, req.contextName, req.pdu.PDUType,
			req.pdu.RequestID, describeVarbinds(req.pdu.Variables))
	}
	return sb.String()
}

func describeAnswerPDU(p *SnmpPacket) string {
	return fmt.Sprintf("%v id=%d msgID=%d %s", p.PDUType, p.RequestID, p.MsgID, describeVarbinds(p.Variables))
}
