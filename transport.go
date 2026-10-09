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

// Connect creates and opens a socket. Because UDP is a connectionless
// protocol, you won't know if the remote host is responding until you send
// packets. Neither will you know if the host is regularly disappearing and reappearing.
//
// For historical reasons (ie this is part of the public API), the method won't
// be renamed to Dial().
func (x *GoSNMP) Connect() error {
	return x.connect("")
}

// ConnectIPv4 forces an IPv4-only connection
func (x *GoSNMP) ConnectIPv4() error {
	return x.connect("4")
}

// ConnectIPv6 forces an IPv6-only connection
func (x *GoSNMP) ConnectIPv6() error {
	return x.connect("6")
}

// Close closes the underlaying connection.
//
// This method is safe to call multiple times and from concurrent goroutines.
// Only the first call will close the connection; subsequent calls are no-ops.
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

// connect to address addr on the given network
//
// https://golang.org/pkg/net/#Dial gives acceptable network values as:
//
//	"tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), "udp", "udp4" (IPv4-only),"udp6" (IPv6-only), "ip",
//	"ip4" (IPv4-only), "ip6" (IPv6-only), "unix", "unixgram" and "unixpacket"
func (x *GoSNMP) connect(networkSuffix string) error {
	err := x.validateParameters()
	if err != nil {
		return err
	}

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

// Performs the real socket opening network operation. This can be used to do a
// reconnect (needed for TCP)
func (x *GoSNMP) netConnect() error {
	var err error
	var localAddr net.Addr
	addr := net.JoinHostPort(x.Target, strconv.Itoa(int(x.Port)))

	switch x.Transport {
	case "udp", "udp4", "udp6":
		if localAddr, err = net.ResolveUDPAddr(x.Transport, x.LocalAddr); err != nil {
			return err
		}
		if addr4 := localAddr.(*net.UDPAddr).IP.To4(); addr4 != nil {
			x.Transport = "udp4"
		}
		if x.UseUnconnectedUDPSocket {
			x.uaddr, err = net.ResolveUDPAddr(x.Transport, addr)
			if err != nil {
				return err
			}
			x.Conn, err = net.ListenUDP(x.Transport, localAddr.(*net.UDPAddr))
			return err
		}
	case "tcp", "tcp4", "tcp6":
		if localAddr, err = net.ResolveTCPAddr(x.Transport, x.LocalAddr); err != nil {
			return err
		}
		if addr4 := localAddr.(*net.TCPAddr).IP.To4(); addr4 != nil {
			x.Transport = "tcp4"
		}
	}
	dialer := net.Dialer{Timeout: x.Timeout, LocalAddr: localAddr, Control: x.Control}
	x.Conn, err = dialer.DialContext(x.Context, x.Transport, addr)
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

// receive response from network and read into a byte array
func (x *GoSNMP) receive() ([]byte, error) {
	var n int
	var err error
	// If we are using UDP and unconnected socket, read the packet and
	// disregard the source address.
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
		// This should never happen unless we're using something like a unix domain socket.
		return nil, fmt.Errorf("response buffer too small")
	}

	resp := make([]byte, n)
	copy(resp, x.rxBuf[:n])
	return resp, nil
}
