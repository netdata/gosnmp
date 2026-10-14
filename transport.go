// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"
)

// Connect readies the client and opens its connection to Target and Port
// (see the package documentation); a client connects before its requests.
// Over UDP it sends nothing, so it succeeds whether or not an agent answers.
// The new connection replaces the client's, which Connect closes; when
// Connect fails, the client keeps the connection it had.
func (x *GoSNMP) Connect() error {
	return x.connect("")
}

// ConnectIPv4 connects like Connect, over IPv4 only: over Transport with "4"
// appended.
func (x *GoSNMP) ConnectIPv4() error {
	return x.connect("4")
}

// ConnectIPv6 connects like Connect, over IPv6 only: over Transport with "6"
// appended.
func (x *GoSNMP) ConnectIPv6() error {
	return x.connect("6")
}

// Close closes the client's connection. Any goroutine may call it, also while
// a request runs: the request's read or write then fails, with an error
// wrapping net.ErrClosed for the standard library's connections, and later
// requests fail with an error wrapping net.ErrClosed until Connect opens a
// connection or Conn is set. Only the first call closes the connection; later
// calls, and calls on a client without a connection, return nil.
func (x *GoSNMP) Close() error {
	x.mu.Lock()
	conn := x.Conn
	x.Conn, x.opened, x.closed = nil, connection{}, true
	x.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// errNoConn is the error of a request on a client without a connection, and
// errClosed after Close.
var (
	errNoConn = errors.New("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	errClosed = fmt.Errorf("the client was closed: %w", net.ErrClosed)
)

// connect readies the client and opens its connection over Transport with
// networkSuffix ("", "4" or "6") appended.
func (x *GoSNMP) connect(networkSuffix string) error {
	if err := x.prepare(); err != nil {
		return err
	}
	c, err := x.dialSettings(x.Transport+networkSuffix).open(x.Context, x.Timeout)
	if err != nil {
		return fmt.Errorf("error establishing connection to host: %w", err)
	}
	x.mu.Lock()
	old := x.Conn
	x.Conn, x.opened, x.closed = c.conn, c, false
	x.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// connectionFor returns the client's connection for an attempt of the request
// with configuration cfg: the connection the client opened, or a Conn the
// caller set, which a TCP reconnect opens again with the request's settings.
// It fails without a connection, with net.ErrClosed after Close.
func (x *GoSNMP) connectionFor(cfg *requestConfig) (connection, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	switch {
	case x.Conn == nil && x.closed:
		return connection{}, errClosed
	case x.Conn == nil:
		return connection{}, errNoConn
	case x.Conn == x.opened.conn:
		return x.opened, nil
	}
	return connection{conn: x.Conn, dial: cfg.dial}, nil
}

// reconnect opens c, the client's connection the agent closed, again, and
// replaces it with the new one, which it closes instead when c is no longer
// the client's connection: after Close, the attempt ends with net.ErrClosed;
// after a hook replaced Conn, the next attempt uses that. A failed dial leaves
// c in place and ends the attempt with its error.
func (x *GoSNMP) reconnect(ctx context.Context, timeout time.Duration, c *connection) attemptOutcome {
	nc, err := c.dial.open(ctx, timeout)
	if err != nil {
		return attemptOutcome{kind: attemptFailed, err: err}
	}
	x.mu.Lock()
	current, closed := x.Conn == c.conn, x.Conn == nil && x.closed
	if current {
		x.Conn, x.opened = nc.conn, nc
	}
	x.mu.Unlock()
	switch {
	case current:
		_ = c.conn.Close()
	case closed:
		_ = nc.conn.Close()
		return attemptOutcome{kind: attemptClosed, err: errClosed}
	default:
		_ = nc.conn.Close()
	}
	return attemptOutcome{kind: attemptReconnected, err: io.EOF}
}

// dialSettings are how the client opens a connection: what Connect reads from
// the client, and what a TCP reconnect opens again.
type dialSettings struct {
	// network is "udp" or "tcp", either with "4" or "6".
	network   string
	target    string
	port      uint16
	localAddr string
	control   func(network, address string, c syscall.RawConn) error
	// unconnected asks for an unconnected UDP socket.
	unconnected bool
}

// dialSettings returns the client's settings for a connection over network.
func (x *GoSNMP) dialSettings(network string) dialSettings {
	return dialSettings{
		network:     network,
		target:      x.Target,
		port:        x.Port,
		localAddr:   x.LocalAddr,
		control:     x.Control,
		unconnected: x.UseUnconnectedUDPSocket,
	}
}

// connection is a connection to the agent and how it was opened: with dial,
// whose network a local address narrowed; uaddr is the agent's address for an
// unconnected UDP socket.
type connection struct {
	conn  net.Conn
	dial  dialSettings
	uaddr *net.UDPAddr
}

// open opens a connection to the agent, or for an unconnected UDP socket a
// local socket, with ctx and timeout bounding the dial. A UDP or TCP local
// address in IPv4 narrows the network to IPv4.
func (d dialSettings) open(ctx context.Context, timeout time.Duration) (connection, error) {
	addr := net.JoinHostPort(d.target, strconv.Itoa(int(d.port)))

	var local net.Addr
	switch d.network {
	case "udp", "udp4", "udp6":
		udpLocal, err := net.ResolveUDPAddr(d.network, d.localAddr)
		if err != nil {
			return connection{}, err
		}
		if udpLocal.IP.To4() != nil {
			d.network = "udp4"
		}
		if d.unconnected {
			return d.listenUnconnectedUDP(udpLocal, addr)
		}
		local = udpLocal
	case "tcp", "tcp4", "tcp6":
		tcpLocal, err := net.ResolveTCPAddr(d.network, d.localAddr)
		if err != nil {
			return connection{}, err
		}
		if tcpLocal.IP.To4() != nil {
			d.network = "tcp4"
		}
		local = tcpLocal
	}
	dialer := net.Dialer{Timeout: timeout, LocalAddr: local, Control: d.control}
	conn, err := dialer.DialContext(ctx, d.network, addr)
	if err != nil {
		return connection{}, err
	}
	return connection{conn: conn, dial: d}, nil
}

// listenUnconnectedUDP opens a UDP socket on the local address that writes to
// the agent at addr.
func (d dialSettings) listenUnconnectedUDP(local *net.UDPAddr, addr string) (connection, error) {
	uaddr, err := net.ResolveUDPAddr(d.network, addr)
	if err != nil {
		return connection{}, err
	}
	conn, err := net.ListenUDP(d.network, local)
	if err != nil {
		return connection{}, err
	}
	return connection{conn: conn, dial: d, uaddr: uaddr}, nil
}

// write sends b to the agent: to its address on an unconnected UDP socket, on
// the connection otherwise.
func (c *connection) write(b []byte) error {
	if uconn, ok := c.conn.(net.PacketConn); ok && c.uaddr != nil {
		_, err := uconn.WriteTo(b, c.uaddr)
		return err
	}
	_, err := c.conn.Write(b)
	return err
}

const rxBufSize = 65535 // max size of IPv4 & IPv6 packet

// receive reads one reply from the connection into buf. Known bug: a TCP
// reply is taken from a single Read, so a reply split over several reads fails
// to decode.
func (c *connection) receive(buf *[rxBufSize]byte) ([]byte, error) {
	var n int
	var err error
	// On a packet connection (UDP, connected or not), read a datagram; its
	// source address is not checked.
	if uconn, ok := c.conn.(net.PacketConn); ok {
		n, _, err = uconn.ReadFrom(buf[:])
	} else {
		n, err = c.conn.Read(buf[:])
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
	copy(resp, buf[:n])
	return resp, nil
}
