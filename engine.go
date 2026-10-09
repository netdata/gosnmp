// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"
)

// GoSNMP
// send/receive one snmp request
func (x *GoSNMP) sendOneRequest(packetOut *SnmpPacket) (result *SnmpPacket, err error) {
	allReqIDs := make([]uint32, 0, x.Retries+1)
	// allMsgIDs := make([]uint32, 0, x.Retries+1) // unused

	timeout := x.Timeout
	withContextDeadline := false
sendRetry:
	for retries := 0; ; retries++ {
		if retries > 0 {
			if x.OnRetry != nil {
				x.OnRetry(x)
			}

			x.Logger.Printf("Retry number %d. Last error was: %v", retries, err)
			if withContextDeadline && strings.Contains(err.Error(), "timeout") {
				err = context.DeadlineExceeded
				break
			}
			if retries > x.Retries {
				if err == nil {
					err = fmt.Errorf("max retries (%d) exceeded", x.Retries)
				}
				if strings.Contains(err.Error(), "timeout") {
					err = fmt.Errorf("request timeout (after %d retries)", retries-1)
				}
				break
			}
			if x.ExponentialTimeout {
				// https://www.webnms.com/snmp/help/snmpapi/snmpv3/v1/timeout.html
				timeout *= 2
			}
			withContextDeadline = false
		}
		err = nil

		if x.Context.Err() != nil {
			return nil, x.Context.Err()
		}

		reqDeadline := time.Now().Add(timeout)
		if contextDeadline, ok := x.Context.Deadline(); ok {
			if contextDeadline.Before(reqDeadline) {
				reqDeadline = contextDeadline
				withContextDeadline = true
			}
		}

		err = x.Conn.SetDeadline(reqDeadline)
		if err != nil {
			return nil, err
		}

		reqID := x.nextRequestID()
		allReqIDs = append(allReqIDs, reqID)

		packetOut.RequestID = reqID

		if x.Version == Version3 {
			msgID := x.nextMsgID()

			// allMsgIDs = append(allMsgIDs, msgID) // unused

			packetOut.MsgID = msgID

			err = x.initPacket(packetOut)
			if err != nil {
				break
			}
		}
		if x.Version == Version3 {
			packetOut.SecurityParameters.Log()
		}

		var outBuf []byte
		outBuf, err = packetOut.marshalMsg()
		if err != nil {
			// Don't retry - not going to get any better!
			err = fmt.Errorf("marshal: %w", err)
			break
		}

		if x.PreSend != nil {
			x.PreSend(x)
		}
		if x.Logger.enabled() {
			x.Logger.Printf("SENDING PACKET: %s", packetOut.SafeString())
		}
		if err = x.write(outBuf); err != nil {
			continue
		}
		if x.OnSent != nil {
			x.OnSent(x)
		}

	waitingResponse:
		for {
			if x.Logger.enabled() {
				x.Logger.Print("WAITING RESPONSE...")
			}
			// Receive response and try receiving again on any decoding error.
			// Let the deadline abort us if we don't receive a valid response.

			var resp []byte
			resp, err = x.receive()
			if err == io.EOF && strings.HasPrefix(x.Transport, tcp) {
				x.Logger.Printf("ERROR: EOF. Performing reconnect")
				err = x.netConnect()
				if err != nil {
					return nil, err
				}
				continue sendRetry
			} else if err != nil {
				// receive error. retrying won't help. abort
				break
			}
			if x.OnRecv != nil {
				x.OnRecv(x)
			}
			if x.Logger.enabled() {
				x.Logger.Printf("GET RESPONSE OK: %+v", resp)
			}
			result = new(SnmpPacket)
			result.Logger = x.Logger

			result.MsgFlags = packetOut.MsgFlags
			if packetOut.SecurityParameters != nil {
				result.SecurityParameters = packetOut.SecurityParameters.Copy()
			}

			var cursor int
			cursor, err = x.unmarshalHeader(resp, result)
			if err != nil {
				x.Logger.Printf("ERROR on unmarshall header: %s", err)
				break
			}

			if x.Version == Version3 {
				usp := usmOf(x.SecurityParameters)
				useResponseSecurityParameters := usp != nil && usp.AuthoritativeEngineID == ""
				err = x.testAuthentication(resp, result, useResponseSecurityParameters)
				if err != nil {
					x.Logger.Printf("ERROR on Test Authentication on v3: %s", err)
					break
				}
				resp, cursor, err = unmarshalScopedPDU(resp, cursor, result)
				if err != nil {
					x.Logger.Printf("ERROR on decryptPacket on v3: %s", err)
					break
				}
			}

			err = unmarshalPayload(resp, cursor, result)
			if err != nil {
				x.Logger.Printf("ERROR on UnmarshalPayload on v3: %s", err)
				break
			}
			if result.Error == NoError && len(result.Variables) < 1 {
				x.Logger.Printf("ERROR on UnmarshalPayload on v3: Empty result")
				break
			}

			// While Report PDU was defined by RFC 1905 as part of SNMPv2, it was never
			// used until SNMPv3. Report PDU's allow a SNMP engine to tell another SNMP
			// engine that an error was detected while processing an SNMP message.
			//
			// The format for a Report PDU is
			// -----------------------------------
			// | 0xA8 | reqid | 0 | 0 | varbinds |
			// -----------------------------------
			// where:
			// - PDU type 0xA8 indicates a Report PDU.
			// - reqid is either:
			//    The request identifier of the message that triggered the report
			//    or zero if the request identifier cannot be extracted.
			// - The variable bindings will contain a single object identifier and its value
			//
			// usmStatsNotInTimeWindows and usmStatsUnknownEngineIDs are recoverable errors
			// and will be retransmitted, for others we return the result with an error.
			if result.Version == Version3 && result.PDUType == Report && len(result.Variables) == 1 {
				switch result.Variables[0].Name {
				case usmStatsUnsupportedSecLevels:
					return result, ErrUnknownSecurityLevel
				case usmStatsNotInTimeWindows:
					break waitingResponse
				case usmStatsUnknownUserNames:
					return result, ErrUnknownUsername
				case usmStatsUnknownEngineIDs:
					break waitingResponse
				case usmStatsWrongDigests:
					return result, ErrWrongDigest
				case usmStatsDecryptionErrors:
					return result, ErrDecryption
				case snmpUnknownSecurityModels:
					return result, ErrUnknownSecurityModels
				case snmpInvalidMsgs:
					return result, ErrInvalidMsgs
				case snmpUnknownPDUHandlers:
					return result, ErrUnknownPDUHandlers
				default:
					return result, ErrUnknownReportPDU
				}
			}

			validID := false
			for _, id := range allReqIDs {
				if id == result.RequestID {
					validID = true
				}
			}
			if result.RequestID == 0 {
				validID = true
			}
			if !validID {
				x.Logger.Print("ERROR out of order")
				continue
			}

			break
		}
		if err != nil {
			continue
		}

		if x.OnFinish != nil {
			x.OnFinish(x)
		}
		// Success!
		return result, nil
	}

	// Return last error
	return nil, err
}

// generic "sender" that negotiate any version of snmp request
func (x *GoSNMP) send(packetOut *SnmpPacket) (result *SnmpPacket, err error) {
	defer func() {
		if e := recover(); e != nil {
			buf := make([]byte, 8192)
			runtime.Stack(buf, true)

			err = fmt.Errorf("recover: %v Stack:%v", e, string(buf))
		}
	}()

	if x.Conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}

	if x.Retries < 0 {
		x.Retries = 0
	}
	if x.Logger.enabled() {
		x.Logger.Print("SEND INIT")
	}
	if packetOut.Version == Version3 {
		if x.Logger.enabled() {
			x.Logger.Print("SEND INIT NEGOTIATE SECURITY PARAMS")
		}
		if err = x.negotiateInitialSecurityParameters(packetOut); err != nil {
			return &SnmpPacket{}, err
		}
		if x.Logger.enabled() {
			x.Logger.Print("SEND END NEGOTIATE SECURITY PARAMS")
		}
	}

	// perform request
	result, err = x.sendOneRequest(packetOut)
	if err != nil {
		x.Logger.Printf("SEND Error on the first Request Error: %s", err)
		return result, err
	}

	if result.Version == Version3 {
		if x.Logger.enabled() {
			x.Logger.Printf("SEND STORE SECURITY PARAMS from result: %s", result.SecurityParameters.SafeString())
		}
		err = x.storeSecurityParameters(result)

		if result.PDUType == Report && len(result.Variables) == 1 {
			switch result.Variables[0].Name {
			case usmStatsNotInTimeWindows:
				x.Logger.Print("WARNING detected out-of-time-window ERROR")
				if err = x.updatePktSecurityParameters(packetOut); err != nil {
					x.Logger.Printf("ERROR updatePktSecurityParameters error: %s", err)
					return nil, err
				}
				// retransmit with updated auth engine params
				result, err = x.sendOneRequest(packetOut)
				if err != nil {
					x.Logger.Printf("ERROR out-of-time-window retransmit error: %s", err)
					return result, ErrNotInTimeWindow
				}

			case usmStatsUnknownEngineIDs:
				x.Logger.Print("WARNING detected unknown engine id ERROR")
				if err = x.updatePktSecurityParameters(packetOut); err != nil {
					x.Logger.Printf("ERROR updatePktSecurityParameters error: %s", err)
					return nil, err
				}
				// retransmit with updated engine id
				result, err = x.sendOneRequest(packetOut)
				if err != nil {
					x.Logger.Printf("ERROR unknown engine id retransmit error: %s", err)
					return result, ErrUnknownEngineID
				}
			}
		}
	}
	return result, err
}
