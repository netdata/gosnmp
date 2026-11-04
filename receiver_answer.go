// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

// accept returns n, an accepted notification, with the Response to it when
// it is an SNMPv2c or SNMPv3 InformRequest (respond): an SNMPv3 one names the
// local engine, and user accepted it.
func accept(n *Notification, user *tableUser, local *localEngine) (*Notification, []byte, error) {
	if n.Message.PDUType != InformRequest || n.Message.Version == Version1 {
		return n, nil, nil
	}
	response, err := respond(&n.Message, user, local)
	if err != nil {
		return nil, nil, err
	}
	return n, response, nil
}

// respond returns the Response to inform (RFC 3416 section 4.2.7): its
// request ID and varbinds, error status noError; for SNMPv2c with its
// community; for SNMPv3 from the local engine, its ID, boots and time now
// (RFC 3414 section 3.1 step 1 a), with the inform's msgID, level, user name
// and context, signed and encrypted with user's keys, localized to the local
// engine ID, as the level asks (RFC 3412 section 7.1 step 2). A Response
// longer than the msgMaxSize of an SNMPv3 inform carries tooBig instead of
// the varbinds.
func respond(inform *Message, user *tableUser, local *localEngine) ([]byte, error) {
	response := Message{
		Version:   inform.Version,
		Community: inform.Community,
		PDUType:   Response,
		RequestID: inform.RequestID,
		VarBinds:  inform.VarBinds,
	}
	if inform.Version != Version3 {
		return response.marshalMsg(&usmKeys{})
	}
	boots, engineTime := local.bootsAndTime()
	response.SecurityLevel = inform.SecurityLevel
	response.SecurityParameters = SecurityParameters{
		AuthoritativeEngineID:    local.id,
		AuthoritativeEngineBoots: boots,
		AuthoritativeEngineTime:  engineTime,
		UserName:                 inform.SecurityParameters.UserName,
	}
	response.ContextEngineID, response.ContextName = inform.ContextEngineID, inform.ContextName
	response.MsgID = inform.MsgID
	data, err := response.marshalMsg(&user.keys)
	if err != nil || uint64(len(data)) <= uint64(inform.MsgMaxSize) {
		return data, err
	}
	response.ErrorStatus, response.VarBinds = TooBig, nil
	return response.marshalMsg(&user.keys)
}

// report returns the Report (RFC 3412 section 7.1 step 3) of the SNMPv3
// message in datagram, whose header is in m and w and which the receiver
// rejected with the counter oid, at count, or nil for a message that is not
// answered: one without the reportableFlag, or whose msgData is not what its
// flags say (reportedRequestID). The Report goes from the local engine, its
// ID, boots and time now, to the message's user name, with its msgID, the
// local engine ID as contextEngineID and the default context (step 3 d); at
// noAuthNoPriv, or, with keys, at authNoPriv signed with them (a user's keys
// localized to the local engine ID, for notInTimeWindow, RFC 3414 section 3.2
// step 7 a).
func (r *Receiver) report(datagram []byte, w v3Wire, m *Message, oid string, count uint32, keys *usmKeys) []byte {
	if !w.reportable {
		return nil
	}
	requestID, ok := reportedRequestID(datagram, w, m.SecurityLevel)
	if !ok {
		return nil
	}
	boots, engineTime := r.local.bootsAndTime()
	report := Message{
		Version:       Version3,
		SecurityLevel: NoAuthNoPriv,
		SecurityParameters: SecurityParameters{
			AuthoritativeEngineID:    r.local.id,
			AuthoritativeEngineBoots: boots,
			AuthoritativeEngineTime:  engineTime,
			UserName:                 m.SecurityParameters.UserName,
		},
		ContextEngineID: r.local.id,
		PDUType:         Report,
		MsgID:           m.MsgID,
		RequestID:       requestID,
		VarBinds:        []VarBind{{Name: oid, Value: Counter32Value(count)}},
	}
	var signer usmKeys
	if keys != nil {
		report.SecurityLevel, signer = AuthNoPriv, *keys
	}
	data, err := report.marshalMsg(&signer)
	if err != nil {
		// Every field comes from a header that parsed and the local engine,
		// so this does not happen; a Report that does not encode is not sent.
		return nil
	}
	return data
}

// reportedRequestID returns the request ID a Report to the SNMPv3 message in
// datagram, whose header is in w and asks for level, carries, and whether the
// message is answered (RFC 3412 section 7.1 step 3 b): its msgData must be
// what the flags say (section 6.7): an encrypted scoped PDU, an OCTET STRING,
// whose PDU type cannot be determined (request ID 0), or a plaintext one whose
// PDU decodes and is of the Confirmed Class (its request ID). A message whose
// msgData does not parse is not answered, as a probe a scanner forges.
func reportedRequestID(datagram []byte, w v3Wire, level SecurityLevel) (uint32, bool) {
	if level.privFlag() {
		if w.scoped >= len(datagram) || datagram[w.scoped] != byte(OctetString) {
			return 0, false
		}
		_, _, err := tlvAt(datagram, w.scoped, len(datagram))
		return 0, err == nil
	}
	var m Message
	scoped, cursor, err := unmarshalScopedPDU(datagram, w.scoped, &m, false, nil)
	if err != nil || unmarshalPayload(scoped, cursor, &m) != nil || !m.PDUType.confirmed() {
		return 0, false
	}
	return m.RequestID, true
}
