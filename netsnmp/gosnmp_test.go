// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package netsnmp

import (
	"encoding/base64"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/netdata/gosnmp"
)

var (
	rec  = flag.Bool("rec", false, "record and use net-snmp expected outputs, else use recorded values [if true requires libsnmp/cgo]. ")
	pcap = flag.String("pcap", "", "dir to put exp and got data as pcap files, no pcaps made if blank.")
)

// pduCases are the varbinds TestPDU sends as a v2c SetRequest with request ID
// 1 and compares with net-snmp's encoding, and the value DecodeMessage
// returns for each recorded net-snmp packet. New cases go at the end: the
// case index is part of the recording file name.
var pduCases = []struct {
	pdu     gosnmp.VarBind
	decoded any
}{
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.7.0", Type: gosnmp.Integer, Value: 104}, 104},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint32(271070065)}, uint(271070065)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.2.2.1.5.1", Type: gosnmp.Gauge32, Value: uint32(math.MaxUint32)}, uint(math.MaxUint32)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.4.0", Type: gosnmp.OctetString, Value: []byte("Administrator")}, []byte("Administrator")},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.4.21.1.1.127.0.0.1", Type: gosnmp.IPAddress, Value: "127.0.0.1"}, "127.0.0.1"},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.6574.4.2.12.1.0", Type: gosnmp.OpaqueFloat, Value: float32(10.0)}, float32(10.0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.6574.4.2.12.1.1", Type: gosnmp.OpaqueFloat, Value: float32(0.0)}, float32(0.0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.6574.4.2.12.2.0", Type: gosnmp.OpaqueDouble, Value: float64(10.0)}, float64(10.0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.6574.4.2.12.2.1", Type: gosnmp.OpaqueDouble, Value: float64(0.0)}, float64(0.0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint32(271070065)}, uint(271070065)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(318870100)}, uint32(318870100)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.3.1", Type: gosnmp.Uinteger32, Value: uint32(math.MaxInt32)}, uint32(math.MaxInt32)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.3.2", Type: gosnmp.Counter64, Value: uint64(math.MaxInt64)}, uint64(math.MaxInt64)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.7.0", Type: gosnmp.Integer, Value: -1}, -1},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.7.0", Type: gosnmp.Integer, Value: math.MinInt32}, math.MinInt32},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.7.0", Type: gosnmp.Integer, Value: math.MaxInt32}, math.MaxInt32},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.2.2.1.10.1", Type: gosnmp.Counter32, Value: uint32(0)}, uint(0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.2.2.1.5.1", Type: gosnmp.Gauge32, Value: uint32(0)}, uint(0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(math.MaxUint32)}, uint32(math.MaxUint32)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.31.1.1.1.6.1", Type: gosnmp.Counter64, Value: uint64(0)}, uint64(0)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.31.1.1.1.6.1", Type: gosnmp.Counter64, Value: uint64(math.MaxUint64)}, uint64(math.MaxUint64)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.4.0", Type: gosnmp.OctetString, Value: []byte{}}, []byte{}},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.4.0", Type: gosnmp.OctetString, Value: []byte(strings.Repeat("a", 200))}, []byte(strings.Repeat("a", 200))},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.4.20.1.1.0.0.0.0", Type: gosnmp.IPAddress, Value: "0.0.0.0"}, "0.0.0.0"},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.4.20.1.1.10.20.30.40", Type: gosnmp.IPAddress, Value: "10.20.30.40"}, "10.20.30.40"},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.4294967295.1", Type: gosnmp.Integer, Value: 1}, 1},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1" + strings.Repeat(".300", 114), Type: gosnmp.Integer, Value: 1}, 1},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.6574.4.2.12.1.2", Type: gosnmp.OpaqueFloat, Value: float32(-1.5)}, float32(-1.5)},
	{gosnmp.VarBind{Name: ".1.3.6.1.4.1.6574.4.2.12.2.2", Type: gosnmp.OpaqueDouble, Value: float64(1e300)}, float64(1e300)},
	{gosnmp.VarBind{Name: ".1.3.6.1.2.1.1.3.1", Type: gosnmp.Uinteger32, Value: uint32(0)}, uint32(0)},
}

// pduCaseName names the subtest and the recording file of pduCases[i].
func pduCaseName(i int, pdu gosnmp.VarBind) string {
	return fmt.Sprintf("test%d_PDU%s", i, pdu.Type.String())
}

func TestPDU(t *testing.T) {
	flag.Parse()

	if isPlayback() {
		t.Log("playback mode enabled")
	}

	recdir := filepath.Join("testdata", t.Name())
	if *rec && !isPlayback() {
		if err := os.MkdirAll(recdir, 0o755); err != nil {
			t.Fatalf("error creating record dir: %s", err)
		}
	} else if *rec {
		t.Fatal("record mode requires `-tags netsnmp` and libsnmpd installed")
	}

	pcapdir := ""
	if *pcap != "" {
		pcapdir = filepath.Join(*pcap, t.Name())
		if err := os.MkdirAll(pcapdir, 0o755); err != nil {
			t.Fatalf("error creating pcap dir: %s", err)
		}
	}

	sess := &gosnmp.Client{Community: "public", Version: gosnmp.Version2c}

	for i, tc := range pduCases {
		tstpdu := tc.pdu
		tname := pduCaseName(i, tstpdu)
		t.Run(tname, func(t *testing.T) {
			fname := filepath.Join(recdir, tname+"_pkt.b64")

			pdus := []gosnmp.VarBind{tstpdu}
			pkt := sess.NewMessage(gosnmp.SetRequest, pdus, 0, 0)
			pkt.RequestID++

			exp, err := netSnmpPduPkt(fname, pdus[0], sess, pkt.RequestID, testing.Verbose())
			if err != nil {
				t.Fatal(err)
			}

			if *rec {
				pktrec := base64.StdEncoding.EncodeToString(exp)
				if err = os.WriteFile(fname, []byte(pktrec), 0o600); err != nil {
					t.Logf("error writing record file: %s", err)
				}
			}

			got, err := pkt.Encode()
			if err != nil {
				t.Fatal(err)
			}

			if *pcap != "" {
				savePcap(t, filepath.Join(pcapdir, tname), exp, got)
			}

			if diff := cmp.Diff(exp, got); diff != "" {
				t.Fatalf("\ngot(%d): %q\nexp(%d): %q\ndiff:\n%s", len(got), got, len(exp), exp, diff)
			}
		})
	}
}

func writePcap(fn string, payload []byte) error {
	fn += ".pcap"

	f, err := os.OpenFile(fn, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	l3 := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.2.1"),
		DstIP:    net.ParseIP("192.168.2.2"),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
	}
	l4 := &layers.UDP{
		SrcPort: 161,
		DstPort: 161,
	}
	err = l4.SetNetworkLayerForChecksum(l3)
	if err != nil {
		return err
	}

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		l3,
		l4,
		gopacket.Payload(payload),
	)
	if err != nil {
		return err
	}

	pkt := gopacket.NewPacket(buf.Bytes(),
		layers.LinkTypeIPv4,
		gopacket.Default)

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(1600, layers.LinkTypeIPv4)
	if err != nil {
		return err
	}

	err = w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(pkt.Data()),
		Length:        len(pkt.Data()),
	}, pkt.Data())
	if err != nil {
		return err
	}

	return nil
}

func savePcap(t *testing.T, fp string, exp, got []byte) {
	err := writePcap(fp+"_exp", exp)
	if err != nil {
		t.Logf("error saving exp pcap: %s", err.Error())
	}
	err = writePcap(fp+"_got", got)
	if err != nil {
		t.Logf("error saving got pcap: %s", err.Error())
	}
}

// TestDecodeRecorded decodes the recorded net-snmp packets and compares the
// decoded header fields and varbinds with the PDU each one was made from.
func TestDecodeRecorded(t *testing.T) {
	type decoded struct {
		Version     gosnmp.Version
		Community   string
		PDUType     gosnmp.PDUType
		RequestID   uint32
		ErrorStatus gosnmp.ErrorStatus
		ErrorIndex  uint8
		VarBinds    []gosnmp.VarBind
	}

	for i, tc := range pduCases {
		tname := pduCaseName(i, tc.pdu)
		t.Run(tname, func(t *testing.T) {
			pkt, err := readRecording(filepath.Join("testdata", "TestPDU", tname+"_pkt.b64"))
			if err != nil {
				t.Fatal(err)
			}

			x := &gosnmp.Client{}
			res, err := x.DecodeMessage(pkt)
			if err != nil {
				t.Fatal(err)
			}

			want := decoded{
				Version:   gosnmp.Version2c,
				Community: "public",
				PDUType:   gosnmp.SetRequest,
				RequestID: 1,
				VarBinds:  []gosnmp.VarBind{{Name: tc.pdu.Name, Type: tc.pdu.Type, Value: tc.decoded}},
			}
			got := decoded{
				Version:     res.Version,
				Community:   res.Community,
				PDUType:     res.PDUType,
				RequestID:   res.RequestID,
				ErrorStatus: res.ErrorStatus,
				ErrorIndex:  res.ErrorIndex,
				VarBinds:    res.VarBinds,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("decoded packet differs (-want +got):\n%s", diff)
			}
		})
	}
}
