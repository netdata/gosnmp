// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

// Connect readies the client and opens its connection to Target and Port
// (see the package documentation); a client connects before its requests.
// Over UDP it sends nothing, so it succeeds whether or not an agent answers.
func (x *GoSNMP) Connect() error {
	return x.connect("")
}

// ConnectIPv4 connects like Connect, over IPv4 only: it appends "4" to
// Transport. Known bug: it appends it on every call, so the next ConnectIPv4
// fails ("udp44").
func (x *GoSNMP) ConnectIPv4() error {
	return x.connect("4")
}

// ConnectIPv6 connects like Connect, over IPv6 only: it appends "6" to
// Transport. Known bug: it appends it on every call, so the next ConnectIPv6
// fails ("udp66").
func (x *GoSNMP) ConnectIPv6() error {
	return x.connect("6")
}

// Close closes the connection. Only the first call after Connect closes it;
// later calls, and calls from other goroutines at the same time, return nil.
// Like the rest of GoSNMP, Close is not safe to call while a request is
// running.
func (x *GoSNMP) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.Conn == nil {
		return nil
	}

	err := x.Conn.Close()
	x.Conn = nil
	return err
}

// connect readies the client, appends networkSuffix ("", "4" or "6") to
// Transport, opens the connection, seeds the IDs and allocates the receive
// buffer.
func (x *GoSNMP) connect(networkSuffix string) error {
	err := x.prepare()
	if err != nil {
		return err
	}

	// Known bug: the suffix is appended on every call.
	x.Transport += networkSuffix
	if err = x.netConnect(); err != nil {
		return fmt.Errorf("error establishing connection to host: %w", err)
	}

	if err = x.seedIDs(); err != nil {
		return err
	}

	x.rxBuf = new([rxBufSize]byte)

	return nil
}

// netConnect opens the connection to the agent, or for an unconnected UDP
// socket a local socket; the TCP transport reconnects with it. A UDP or TCP
// local address in IPv4 narrows the transport to IPv4.
func (x *GoSNMP) netConnect() error {
	addr := net.JoinHostPort(x.Target, strconv.Itoa(int(x.Port)))

	switch x.Transport {
	case "udp", "udp4", "udp6":
		local, err := net.ResolveUDPAddr(x.Transport, x.LocalAddr)
		if err != nil {
			return err
		}
		if local.IP.To4() != nil {
			x.Transport = "udp4"
		}
		if x.UseUnconnectedUDPSocket {
			return x.listenUnconnectedUDP(local, addr)
		}
		return x.dial(local, addr)
	case "tcp", "tcp4", "tcp6":
		local, err := net.ResolveTCPAddr(x.Transport, x.LocalAddr)
		if err != nil {
			return err
		}
		if local.IP.To4() != nil {
			x.Transport = "tcp4"
		}
		return x.dial(local, addr)
	}
	return x.dial(nil, addr)
}

// dial connects to addr from the local address, nil for any.
func (x *GoSNMP) dial(local net.Addr, addr string) error {
	dialer := net.Dialer{Timeout: x.Timeout, LocalAddr: local, Control: x.Control}
	var err error
	x.Conn, err = dialer.DialContext(x.Context, x.Transport, addr)
	return err
}

// listenUnconnectedUDP opens a UDP socket on the local address that writes to
// the agent at addr. Known bug: when the socket cannot be opened, Conn is left
// holding a nil *net.UDPConn, which compares unequal to nil.
func (x *GoSNMP) listenUnconnectedUDP(local *net.UDPAddr, addr string) error {
	var err error
	if x.uaddr, err = net.ResolveUDPAddr(x.Transport, addr); err != nil {
		return err
	}
	x.Conn, err = net.ListenUDP(x.Transport, local)
	return err
}

// write sends b to the agent: to its address when the client uses an
// unconnected UDP socket, on the connection otherwise.
func (x *GoSNMP) write(b []byte) error {
	if uconn, ok := x.Conn.(net.PacketConn); ok && x.uaddr != nil {
		_, err := uconn.WriteTo(b, x.uaddr)
		return err
	}
	_, err := x.Conn.Write(b)
	return err
}

const rxBufSize = 65535 // max size of IPv4 & IPv6 packet

// receive reads one reply from the connection. Known bugs: a client given a
// Conn without Connect has no receive buffer, and this panics (send recovers
// it); a TCP reply is taken from a single Read, so a reply split over several
// reads fails to decode.
func (x *GoSNMP) receive() ([]byte, error) {
	var n int
	var err error
	// On a packet connection (UDP, connected or not), read a datagram; its
	// source address is not checked.
	if uconn, ok := x.Conn.(net.PacketConn); ok {
		n, _, err = uconn.ReadFrom(x.rxBuf[:])
	} else {
		n, err = x.Conn.Read(x.rxBuf[:])
	}
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("error reading from socket: %w", err)
	}

	if n == rxBufSize {
		// A read that fills the buffer may have cut the reply short: a datagram
		// cannot be this large, a TCP stream can.
		return nil, fmt.Errorf("response buffer too small")
	}

	resp := make([]byte, n)
	copy(resp, x.rxBuf[:n])
	return resp, nil
}
