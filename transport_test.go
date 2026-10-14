// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectResult is what TestConnect observes of a Connect.
type connectResult struct {
	err       string // "" for no error
	transport string // Transport after the Connect
	network   string // the network of the connection the client opened
	connected bool   // Conn is set
	local     string // the IP of Conn's local address
	controls  []string
}

// TestConnect pins how Connect, ConnectIPv4 and ConnectIPv6 validate the
// client, choose the network and dial, on loopback sockets: Transport keeps
// its value (Connect fills in "udp" when it is empty), the network gets the
// suffix and the narrowing.
func TestConnect(t *testing.T) {
	udpPort := unusedUDPPort(t)
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcp.Close()
	tcpPort := tcp.Addr().(*net.TCPAddr).Port

	recordControl := func(x *GoSNMP, got *connectResult, sleep time.Duration) {
		x.Control = func(network, _ string, _ syscall.RawConn) error {
			got.controls = append(got.controls, network)
			time.Sleep(sleep)
			return nil
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := map[string]struct {
		setup   func(x *GoSNMP, got *connectResult)
		connect func(x *GoSNMP) error
		unix    bool // the dial checks its context after a UDP connect only on Unix
		want    connectResult
	}{
		"udp": {
			want: connectResult{transport: "udp", network: "udp", connected: true, local: "127.0.0.1"},
		},
		"udp with an IPv4 local address": {
			setup: func(x *GoSNMP, _ *connectResult) { x.LocalAddr = "127.0.0.1:0" },
			want:  connectResult{transport: "udp", network: "udp4", connected: true, local: "127.0.0.1"},
		},
		"tcp with an IPv4 local address": {
			setup: func(x *GoSNMP, _ *connectResult) {
				x.Transport, x.LocalAddr, x.Port = "tcp", "127.0.0.1:0", uint16(tcpPort) //nolint:gosec // a loopback port
			},
			want: connectResult{transport: "tcp", network: "tcp4", connected: true, local: "127.0.0.1"},
		},
		"ConnectIPv4": {
			connect: (*GoSNMP).ConnectIPv4,
			want:    connectResult{transport: "udp", network: "udp4", connected: true, local: "127.0.0.1"},
		},
		"ConnectIPv4 twice": {
			connect: func(x *GoSNMP) error {
				if err := x.ConnectIPv4(); err != nil {
					return err
				}
				_ = x.Conn.Close()
				return x.ConnectIPv4()
			},
			want: connectResult{transport: "udp", network: "udp4", connected: true, local: "127.0.0.1"},
		},
		"ConnectIPv6 to an IPv4 target": {
			connect: (*GoSNMP).ConnectIPv6,
			want: connectResult{
				err:       "error establishing connection to host: dial udp6: address 127.0.0.1: no suitable address found",
				transport: "udp",
			},
		},
		"invalid parameters": {
			setup: func(x *GoSNMP, _ *connectResult) { x.MaxOids = -1 },
			want:  connectResult{err: "field MaxOids cannot be less than 0", transport: "udp"},
		},
		"Control": {
			setup: func(x *GoSNMP, got *connectResult) { recordControl(x, got, 0) },
			want:  connectResult{transport: "udp", network: "udp", connected: true, local: "127.0.0.1", controls: []string{"udp4"}},
		},
		"dial timeout": {
			unix: true,
			setup: func(x *GoSNMP, got *connectResult) {
				x.Timeout = 20 * time.Millisecond
				recordControl(x, got, 200*time.Millisecond)
			},
			want: connectResult{
				err:       "error establishing connection to host: dial udp :0->127.0.0.1:" + strconv.Itoa(int(udpPort)) + ": i/o timeout",
				transport: "udp", controls: []string{"udp4"},
			},
		},
		"canceled context": {
			setup: func(x *GoSNMP, _ *connectResult) { x.Context = canceled },
			want: connectResult{
				err:       "error establishing connection to host: dial udp :0->127.0.0.1:" + strconv.Itoa(int(udpPort)) + ": operation was canceled",
				transport: "udp",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.unix && runtime.GOOS == "windows" {
				t.Skip("Windows dials UDP without checking the context after connect")
			}
			x := &GoSNMP{Target: "127.0.0.1", Port: udpPort, Version: Version2c, Community: "public", Timeout: time.Second}
			var got connectResult
			if tc.setup != nil {
				tc.setup(x, &got)
			}
			connect := tc.connect
			if connect == nil {
				connect = (*GoSNMP).Connect
			}
			if err := connect(x); err != nil {
				got.err = err.Error()
			}
			got.transport, got.network = x.Transport, x.opened.dial.network
			if x.Conn != nil {
				got.connected = true
				host, _, err := net.SplitHostPort(x.Conn.LocalAddr().String())
				require.NoError(t, err)
				got.local = host
				_ = x.Conn.Close()
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestConnectUnconnectedUDPListenFailure pins what Connect leaves when the
// unconnected UDP socket cannot be opened: its error, and no connection.
func TestConnectUnconnectedUDPListenFailure(t *testing.T) {
	x := &GoSNMP{
		Target: "127.0.0.1", Port: 161, Version: Version2c, Community: "public", Timeout: time.Second,
		UseUnconnectedUDPSocket: true,
		LocalAddr:               "192.0.2.1:0", // TEST-NET-1: no local interface has it
	}
	err := x.Connect()
	assert.ErrorContains(t, err, "error establishing connection to host: listen udp4 192.0.2.1:0")
	assert.Equal(t, [2]string{"udp", ""}, [2]string{x.Transport, x.opened.dial.network}, "Transport, network")
	assert.Nil(t, x.Conn)
}

// TestConnectTCPLocalAddr pins that a TCP connection is made from the
// configured local address, port included.
func TestConnectTCPLocalAddr(t *testing.T) {
	agent, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer agent.Close()
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	localPort := free.Addr().(*net.TCPAddr).Port
	require.NoError(t, free.Close())

	x := &GoSNMP{
		Target: "127.0.0.1", Port: uint16(agent.Addr().(*net.TCPAddr).Port), //nolint:gosec // a loopback port
		Transport: "tcp", LocalAddr: "127.0.0.1:" + strconv.Itoa(localPort),
		Version: Version2c, Community: "public", Timeout: time.Second,
	}
	require.NoError(t, x.Connect())
	defer x.Conn.Close()
	assert.Equal(t, localPort, x.Conn.LocalAddr().(*net.TCPAddr).Port)
}

// closeErrConn is a connection whose Close fails.
type closeErrConn struct {
	net.Conn
	closes int
}

var errCloseConn = errors.New("codec close failure")

func (c *closeErrConn) Close() error {
	c.closes++
	return errCloseConn
}

// TestCloseOnce pins that Close closes the connection once, returns its error
// and leaves no connection, and that a client without one closes cleanly.
func TestCloseOnce(t *testing.T) {
	c := &closeErrConn{}
	x := &GoSNMP{Conn: c}
	assert.ErrorIs(t, x.Close(), errCloseConn)
	assert.Nil(t, x.Conn)
	assert.NoError(t, x.Close())
	assert.Equal(t, 1, c.closes)
}

// TestHandlerClose pins that the Handler's Close is the client's: on a client
// without a connection it returns nil, and it closes a connection once, leaving
// no connection.
func TestHandlerClose(t *testing.T) {
	type outcome struct {
		panics        bool
		first, second error
		connSet       bool // Conn is still set after the two calls
		closes        int  // the connection's Close calls
	}
	tests := map[string]struct {
		conn bool
		want outcome
	}{
		"without a connection": {want: outcome{}},
		"twice":                {conn: true, want: outcome{first: errCloseConn, closes: 1}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := NewHandler()
			c := &closeErrConn{}
			if tc.conn {
				h.(*snmpHandler).Conn = c
			}
			var got outcome
			if v, _ := recoverPanic(func() { got.first = h.Close() }); v != nil {
				got.panics = true
			} else {
				got.second = h.Close()
			}
			got.connSet, got.closes = h.(*snmpHandler).Conn != nil, c.closes
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestConnectReplacesConnection pins what a second Connect does with the
// client's connection: when it opens a new one, it closes the first; when its
// dial fails, the client keeps the first.
func TestConnectReplacesConnection(t *testing.T) {
	type outcome struct {
		err       bool
		connFirst bool // Conn is the first connection
		connNil   bool
		firstOpen bool // the first connection is still open
	}
	errControl := errors.New("codec control refuses")
	tests := map[string]struct {
		failDial bool
		want     outcome
	}{
		"opens":      {want: outcome{}},
		"dial fails": {failDial: true, want: outcome{err: true, connFirst: true, firstOpen: true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			agent, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer agent.Close()
			x := &GoSNMP{
				Target: "127.0.0.1", Port: uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
				Version: Version2c, Community: "public", Timeout: time.Second,
			}
			require.NoError(t, x.Connect())
			first := x.Conn
			defer first.Close()
			defer x.Close()
			if tc.failDial {
				x.Control = func(string, string, syscall.RawConn) error { return errControl }
			}
			err = x.Connect()
			assert.Equal(t, tc.want, outcome{
				err:       err != nil,
				connFirst: x.Conn == first,
				connNil:   x.Conn == nil,
				firstOpen: first.SetDeadline(time.Time{}) == nil,
			})
		})
	}
}

// TestRequestWithoutConnection pins the result of a request on a client
// without a connection: no packet, and net.ErrClosed after Close, until
// Connect, "Conn is missing" otherwise; an SNMPv3 request does not discover
// the engine first.
func TestRequestWithoutConnection(t *testing.T) {
	tests := map[string]struct {
		v3     bool
		before func(t *testing.T, x *GoSNMP)
		want   error
	}{
		"never connected": {want: errNoConn},
		"after Close": {want: errClosed, before: func(t *testing.T, x *GoSNMP) {
			require.NoError(t, x.Connect())
			require.NoError(t, x.Close())
		}},
		"SNMPv3 after Close": {v3: true, want: errClosed, before: func(t *testing.T, x *GoSNMP) {
			require.NoError(t, x.Connect())
			require.NoError(t, x.Close())
		}},
		"Conn removed after Close and Connect": {want: errNoConn, before: func(t *testing.T, x *GoSNMP) {
			require.NoError(t, x.Connect())
			require.NoError(t, x.Close())
			require.NoError(t, x.Connect())
			require.NoError(t, x.Conn.Close())
			x.Conn = nil
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &GoSNMP{
				Target: "127.0.0.1", Port: unusedUDPPort(t), Version: Version2c, Community: "public",
				Timeout: time.Second, MaxOids: MaxOids,
			}
			if tc.v3 {
				x.Version, x.SecurityModel, x.MsgFlags = Version3, UserSecurityModel, NoAuthNoPriv
				x.SecurityParameters = &UsmSecurityParameters{UserName: "codec"}
			}
			if tc.before != nil {
				tc.before(t, x)
			}
			res, err := x.Get([]string{engineOID})
			assert.Nil(t, res)
			assert.Equal(t, tc.want, err)
		})
	}
}

// TestCloseDuringRequest checks, on a loopback socket, Close as Netdata's SNMP
// topology uses it: two goroutines close the client, through the Handler,
// while a request waits for its answer. The request ends at once with
// net.ErrClosed, the next one fails the same way without being sent, and
// Connect opens the client again.
func TestCloseDuringRequest(t *testing.T) {
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 1 {
			return nil // the agent does not answer the first request
		}
		return replyTo(req, nil, sysDescr)
	})
	h := NewHandler()
	h.SetTarget("127.0.0.1")
	h.SetPort(port)
	h.SetTimeout(time.Minute)
	require.NoError(t, h.Connect())
	defer h.Close()

	closers := closeOnRelease(h, 2, func() { <-reads })
	start := time.Now()
	_, err := h.Get([]string{engineOID})
	require.ErrorIs(t, err, net.ErrClosed)
	assert.Less(t, time.Since(start), 10*time.Second, "the request ends before its timeout")
	closers.Wait()

	_, err = h.Get([]string{engineOID})
	require.ErrorIs(t, err, net.ErrClosed)

	require.NoError(t, h.Connect())
	res, err := h.Get([]string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []SnmpPDU{sysDescr}, res.Variables)
	assert.Len(t, reads, 1, "the agent read the request after Connect, not the one after Close")
}

// TestCloseDuringWalk checks, on a loopback socket, Close as Netdata's SNMP
// topology uses it during a walk: two goroutines close the client, through the
// Handler, while the walk waits for an answer. The walk ends at once with
// net.ErrClosed.
func TestCloseDuringWalk(t *testing.T) {
	const root = ".1.3.6.1.2.1.2.2.1.2"
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 5 {
			return nil // the agent does not answer the fifth request
		}
		p, err := decodeMessage(req)
		if err != nil || len(p.Variables) == 0 {
			return nil
		}
		next := root + ".1"
		if arc, ok := strings.CutPrefix(p.Variables[0].Name, root+"."); ok {
			i, _ := strconv.Atoi(arc)
			next = root + "." + strconv.Itoa(i+1)
		}
		return replyTo(req, nil, SnmpPDU{Name: next, Type: OctetString, Value: []byte("codec")})
	})
	h := NewHandler()
	h.SetTarget("127.0.0.1")
	h.SetPort(port)
	h.SetTimeout(time.Minute)
	require.NoError(t, h.Connect())
	defer h.Close()

	closers := closeOnRelease(h, 2, func() {
		for n := range reads {
			if n == 5 {
				return
			}
		}
	})
	start := time.Now()
	_, err := h.BulkWalkAll(root)
	require.ErrorIs(t, err, net.ErrClosed)
	assert.Less(t, time.Since(start), 10*time.Second, "the walk ends before its request's timeout")
	closers.Wait()
}

// closeOnRelease starts n goroutines that close h once release returns, and
// returns their WaitGroup.
func closeOnRelease(h Handler, n int, release func()) *sync.WaitGroup {
	released := make(chan struct{})
	go func() {
		release()
		close(released)
	}()
	var closers sync.WaitGroup
	for range n {
		closers.Go(func() {
			<-released
			_ = h.Close()
		})
	}
	return &closers
}

// TestCloseDuringConnect checks, under the race detector, a Close from another
// goroutine at the time of a Connect: the client ends either closed, failing
// requests with net.ErrClosed, or connected, without a race.
func TestCloseDuringConnect(t *testing.T) {
	port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
	for range 20 {
		x := &GoSNMP{Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public", Timeout: 10 * time.Second}
		require.NoError(t, x.Connect())
		closed := make(chan error, 1)
		go func() { closed <- x.Close() }()
		require.NoError(t, x.Connect())
		require.NoError(t, <-closed)

		_, err := x.Get([]string{engineOID})
		if x.Conn == nil {
			assert.ErrorIs(t, err, net.ErrClosed)
		} else {
			assert.NoError(t, err)
		}
		_ = x.Close()
	}
}

// TestContextCancelDuringRequest checks, on a loopback socket, that canceling
// the Context ends a request waiting for its answer at once, and that the
// client's next request, with another Context, is answered.
func TestContextCancelDuringRequest(t *testing.T) {
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 1 {
			return nil // the agent does not answer the first request
		}
		return replyTo(req, nil, sysDescr)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x := &GoSNMP{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: time.Minute, Retries: 2, Context: ctx,
	}
	require.NoError(t, x.Connect())
	defer x.Close()

	go func() {
		<-reads
		cancel()
	}()
	start := time.Now()
	_, err := x.Get([]string{engineOID})
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 10*time.Second, "the request ends before its timeout")

	x.Context = context.Background()
	res, err := x.Get([]string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []SnmpPDU{sysDescr}, res.Variables)
}

// udpAgent listens on a loopback UDP port and answers request n (counted from
// 1) with the reply handle returns, if any; reads receives the number of each
// request it reads. The socket closes when the test ends.
func udpAgent(t *testing.T, handle func(n int, req []byte) []byte) (port uint16, reads <-chan int) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	read := make(chan int, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for n := 1; ; n++ {
			m, from, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			select {
			case read <- n:
			default:
			}
			if reply := handle(n, bytes.Clone(buf[:m])); reply != nil {
				_, _ = pc.WriteTo(reply, from)
			}
		}
	}()
	t.Cleanup(func() {
		pc.Close()
		<-done
	})
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port), read //nolint:gosec // a UDP port
}
