// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectResult is what TestConnect observes of a Connect.
type connectResult struct {
	err       string // "" for no error
	transport string
	connected bool   // Conn is set
	local     string // the IP of Conn's local address
	controls  []string
}

// TestConnect pins how Connect, ConnectIPv4 and ConnectIPv6 validate the
// client, choose the network and dial, known bugs included, on loopback
// sockets.
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
			want: connectResult{transport: "udp", connected: true, local: "127.0.0.1"},
		},
		"udp with an IPv4 local address": {
			setup: func(x *GoSNMP, _ *connectResult) { x.LocalAddr = "127.0.0.1:0" },
			want:  connectResult{transport: "udp4", connected: true, local: "127.0.0.1"},
		},
		"tcp with an IPv4 local address": {
			setup: func(x *GoSNMP, _ *connectResult) {
				x.Transport, x.LocalAddr, x.Port = "tcp", "127.0.0.1:0", uint16(tcpPort) //nolint:gosec // a loopback port
			},
			want: connectResult{transport: "tcp4", connected: true, local: "127.0.0.1"},
		},
		"ConnectIPv4": {
			connect: (*GoSNMP).ConnectIPv4,
			want:    connectResult{transport: "udp4", connected: true, local: "127.0.0.1"},
		},
		"ConnectIPv4 twice": {
			connect: func(x *GoSNMP) error {
				if err := x.ConnectIPv4(); err != nil {
					return err
				}
				_ = x.Conn.Close()
				return x.ConnectIPv4()
			},
			want: connectResult{
				err:       "error establishing connection to host: dial udp44: unknown network udp44",
				transport: "udp44", connected: false,
			},
		},
		"ConnectIPv6 to an IPv4 target": {
			connect: (*GoSNMP).ConnectIPv6,
			want: connectResult{
				err:       "error establishing connection to host: dial udp6: address 127.0.0.1: no suitable address found",
				transport: "udp6",
			},
		},
		"invalid parameters": {
			setup: func(x *GoSNMP, _ *connectResult) { x.MaxOids = -1 },
			want:  connectResult{err: "field MaxOids cannot be less than 0", transport: "udp"},
		},
		"Control": {
			setup: func(x *GoSNMP, got *connectResult) { recordControl(x, got, 0) },
			want:  connectResult{transport: "udp", connected: true, local: "127.0.0.1", controls: []string{"udp4"}},
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
			got.transport = x.Transport
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
