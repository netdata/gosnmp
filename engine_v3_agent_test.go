// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netdata/gosnmp/internal/ber"
)

// fakeV3Agent is an authoritative SNMPv3 engine for the engine tests. It reads
// a request with its own parser (parseV3Message) and, like net-snmp's snmpd,
// drops what RFC 3412 discards: another version (section 4.2.1), another
// security model, privacy without authentication, a msgID or msgMaxSize out
// of range (section 7.2), a scoped PDU it cannot decode, and a Report to a
// request that is not reportable and whose PDU it cannot read (section 7.1
// step 3 b). It checks the rest with the library's digests and ciphers in the
// order of RFC 3414 section 3.2 (engine ID, user, security level, digest over
// the message as received, time window, decryption when the privacy flag is
// set) and answers with a GetResponse at the request's security level and in
// its context, or with a Report in the default context: noAuthNoPriv for an
// unknown engine ID or user, an unsupported level, a wrong digest or a
// decryption error, authNoPriv for a message outside the time window. Its
// engine time counts the seconds of the bubble's clock. Unlike snmpd it
// serves every context name.
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
	version, msgID               int64
	maxSize, model               int64
	flags                        SnmpV3MsgFlags
	engineID, user               string
	boots, engineTime            uint32
	salt                         []byte // msgPrivacyParameters
	contextEngineID, contextName string
	pdu                          *SnmpPacket // nil when the scoped PDU was not read
}

// agentAnswer is the answer of the fake agent to one request.
type agentAnswer struct {
	report string         // the Report's counter OID, or "" for a GetResponse
	level  SnmpV3MsgFlags // the security level of the answer
	edit   func(*SnmpPacket)
	raw    func(*v3Message) // edits the encoded answer, after edit
	drop   bool             // no answer
	why    string
}

const (
	agentEngineID      = "\x80\x00\x1f\x88\x04codec-agent"
	agentOtherEngineID = "\x80\x00\x1f\x88\x04codec-other"
	agentBoots         = 7
	agentTimeBase      = 1000
	agentTimeWindow    = 150       // seconds, RFC 3414 section 2.2.3
	agentMinMaxSize    = 484       // msgMaxSize range, RFC 3412 section 6
	agentMaxInt        = 1<<31 - 1 // the largest msgID and msgMaxSize
)

// errAgentDecryption is a scoped PDU the agent's cipher rejects, as opposed
// to one that decrypts to something it cannot decode.
var errAgentDecryption = errors.New("decryption error")

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
	if why := req.discarded(); why != "" {
		a.tr.addf("agent: drops #%d (%s)", n, why)
		return nil
	}

	ans, scripted := agentAnswer{}, false
	if a.script != nil {
		ans, scripted = a.script(n, req)
	}
	if !scripted {
		ans = a.check(data, m, &req)
	} else if req.pdu == nil {
		// A scripted answer still carries the request ID when the agent
		// can read it.
		_ = a.readScopedPDU(m, &req)
	}
	if m.scopedTag == byte(OctetString) && req.pdu != nil {
		a.tr.addf("agent: #%d decrypts to context=%q/%q %v id=%d %s", n, req.contextEngineID, req.contextName,
			req.pdu.PDUType, req.pdu.RequestID, describeVarbinds(req.pdu.Variables))
	}
	if ans.report != "" && req.pdu == nil && req.flags&Reportable == 0 {
		ans = agentAnswer{drop: true, why: "no Report: the request is not reportable and its PDU unknown"}
	}
	if ans.drop {
		a.tr.addf("agent: drops #%d (%s)", n, ans.why)
		return nil
	}

	out := a.answer(req, ans)
	a.tr.addf("agent: answers #%d with %s at %s (%s)", n, describeAnswerPDU(out), describeFlags(out.MsgFlags), ans.why)
	b, err := out.MarshalMsg()
	if err != nil {
		panic(fmt.Sprintf("agent cannot encode its answer: %v", err))
	}
	if ans.raw != nil {
		m, err := parseV3Message(b)
		if err != nil {
			panic(fmt.Sprintf("agent cannot read its answer: %v", err))
		}
		ans.raw(&m)
		b = m.bytes()
	}
	return []agentReply{{data: b}}
}

// check runs the RFC 3414 section 3.2 checks on req, read from data as m,
// reading its scoped PDU when the checks reach it.
func (a *fakeV3Agent) check(data []byte, m v3Message, req *agentRequest) agentAnswer {
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
		if !agentDigestOK(data, m, user) {
			return agentAnswer{report: usmStatsWrongDigests, why: "wrong digest"}
		}
		if req.boots != a.boots || absDiff(req.engineTime, a.engineTime()) > agentTimeWindow {
			return agentAnswer{report: usmStatsNotInTimeWindows, level: AuthNoPriv, why: "not in time window"}
		}
	}
	encrypted := m.scopedTag == byte(OctetString)
	switch {
	case req.flags&usmPrivacyFlag != 0 && (!encrypted || len(req.salt) != 8):
		return agentAnswer{report: usmStatsDecryptionErrors, why: "privacy flag without a ciphertext and an 8-octet salt"}
	case req.flags&usmPrivacyFlag == 0 && encrypted:
		return agentAnswer{drop: true, why: "a ciphertext without the privacy flag"}
	}
	if err := a.readScopedPDU(m, req); err != nil {
		if errors.Is(err, errAgentDecryption) {
			return agentAnswer{report: usmStatsDecryptionErrors, why: err.Error()}
		}
		// A scoped PDU that does not decode is dropped, as snmpd does
		// (snmpInASNParseErrs): a wrong privacy passphrase gets no answer.
		return agentAnswer{drop: true, why: err.Error()}
	}
	return agentAnswer{level: req.flags & AuthPriv, why: "request accepted"}
}

// discarded names why RFC 3412 discards req before its security checks
// (sections 4.2.1 and 7.2), or returns "".
func (req agentRequest) discarded() string {
	switch {
	case req.version != int64(Version3):
		return fmt.Sprintf("msgVersion %d", req.version)
	case req.msgID < 0 || req.msgID > agentMaxInt:
		return fmt.Sprintf("msgID %d", req.msgID)
	case req.maxSize < agentMinMaxSize || req.maxSize > agentMaxInt:
		return fmt.Sprintf("msgMaxSize %d", req.maxSize)
	case req.model != int64(UserSecurityModel):
		return fmt.Sprintf("security model %d", req.model)
	case req.flags&AuthPriv == usmPrivacyFlag:
		return "privacy without authentication"
	}
	return ""
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
			return fmt.Errorf("%w: %w", errAgentDecryption, err)
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
		ContextEngineID:    req.contextEngineID,
		ContextName:        req.contextName,
		PDUType:            GetResponse,
		MsgID:              uint32(req.msgID), //nolint:gosec // checked by discarded
		Variables:          a.vbs,
	}
	if out.ContextEngineID == "" {
		// snmpd answers a request without a context engine ID in its own.
		out.ContextEngineID = a.engineID
	}
	if req.pdu != nil {
		out.RequestID = req.pdu.RequestID
	}
	if ans.report != "" {
		// RFC 3412 section 7.1 step 3 d: the agent's engine ID and the
		// default context.
		a.counters[ans.report]++
		out.PDUType = Report
		out.ContextEngineID, out.ContextName = a.engineID, ""
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
	version, err := ber.Int64(m.version)
	if err != nil {
		return req, fmt.Errorf("msgVersion: %w", err)
	}
	msgID, err := ber.Int64(header[0])
	if err != nil {
		return req, fmt.Errorf("msgID: %w", err)
	}
	maxSize, err := ber.Int64(header[1])
	if err != nil {
		return req, fmt.Errorf("msgMaxSize: %w", err)
	}
	if len(header[2]) != 1 {
		return req, fmt.Errorf("msgFlags of %d octets", len(header[2]))
	}
	model, err := ber.Int64(header[3])
	if err != nil {
		return req, fmt.Errorf("msgSecurityModel: %w", err)
	}
	boots, err := ber.Int64(m.usm[1])
	if err != nil {
		return req, fmt.Errorf("engine boots: %w", err)
	}
	engineTime, err := ber.Int64(m.usm[2])
	if err != nil {
		return req, fmt.Errorf("engine time: %w", err)
	}
	req.version, req.msgID, req.maxSize, req.model = version, msgID, maxSize, model
	req.flags = SnmpV3MsgFlags(header[2][0])
	req.engineID, req.user = string(m.usm[0]), string(m.usm[3])
	req.boots, req.engineTime = uint32(boots), uint32(engineTime) //nolint:gosec // a test message
	req.salt = m.usm[5]
	if m.scopedTag != byte(OctetString) {
		// A plaintext scoped PDU is read even before the checks, so a
		// Report can carry its request ID.
		var probe fakeV3Agent
		_ = probe.readScopedPDU(m, &req)
	}
	return req, nil
}

// agentDigestOK reports whether data, read as m, carries the digest of
// user's key, computed over the message as received with the digest field
// zeroed (RFC 3414 section 3.2 step 6).
func agentDigestOK(data []byte, m v3Message, user *UsmSecurityParameters) bool {
	spec := user.AuthenticationProtocol.spec()
	mac := m.usm[4]
	if len(mac) != spec.MACLen {
		return false
	}
	// The fields of m alias data, so their capacities give their offsets.
	off := cap(data) - cap(mac)
	if off < 0 || off+len(mac) > len(data) || !bytes.Equal(data[off:off+len(mac)], mac) {
		panic("agent cannot locate the digest field")
	}
	zeroed := bytes.Clone(data)
	clear(zeroed[off : off+len(mac)])
	ok, err := spec.Verify(user.SecretKey, zeroed, mac)
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

// describeAgentRequest describes req; the security model and msgMaxSize only
// when they are not the library's (3 and rxBufSize).
func describeAgentRequest(req agentRequest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "msgID=%d %s user=%q engine=%q boots=%d time=%d", req.msgID, describeFlags(req.flags), req.user,
		req.engineID, req.boots, req.engineTime)
	if req.model != int64(UserSecurityModel) {
		fmt.Fprintf(&sb, " model=%d", req.model)
	}
	if req.maxSize != rxBufSize {
		fmt.Fprintf(&sb, " msgMaxSize=%d", req.maxSize)
	}
	if len(req.salt) > 0 {
		fmt.Fprintf(&sb, " salt=%x", req.salt)
	}
	if req.pdu != nil {
		fmt.Fprintf(&sb, " context=%q/%q %v id=%d %s", req.contextEngineID, req.contextName, req.pdu.PDUType,
			req.pdu.RequestID, describeVarbinds(req.pdu.Variables))
	}
	return sb.String()
}

func describeAnswerPDU(p *SnmpPacket) string {
	return fmt.Sprintf("%v id=%d msgID=%d %s", p.PDUType, p.RequestID, p.MsgID, describeVarbinds(p.Variables))
}
