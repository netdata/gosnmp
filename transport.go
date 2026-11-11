// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Connect opens the client's connection, a UDP socket connected to the
// configuration's Target and Port (see the package documentation), the only
// connection a client has; a client connects before its requests. ctx bounds
// Connect only, its lookup of Target and its dial, with Timeout; each request
// takes its own. It sends nothing, so it succeeds whether or not an agent
// answers. The new connection replaces the client's, which Connect closes;
// when Connect fails, the client keeps the connection it had. A nil ctx, and
// then an empty Target, fail Connect before it changes the client.
func (c *Client) Connect(ctx context.Context) error {
	if ctx == nil {
		return errNilContext
	}
	if c.config.Target == "" {
		return errNoTarget
	}
	conn, err := dial(ctx, c.config.Timeout, net.JoinHostPort(c.config.Target, strconv.Itoa(int(c.config.Port))))
	if err != nil {
		return fmt.Errorf("error establishing connection to host: %w", err)
	}
	if c.rx == nil {
		c.rx = new(receiveBuffer)
	}
	c.mu.Lock()
	old := c.conn
	c.conn, c.closed = conn, false
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Close closes the client's connection, which ends the running attempt at
// once. Any goroutine may call it, also while a request runs, which it ends:
// once Close has run, a request whose attempt ends without a reply fails with
// an error wrapping net.ErrClosed, as do later requests until Connect opens a
// connection (see the package documentation). Only the first call closes the
// connection; later calls, and calls on a client never connected, return nil.
func (c *Client) Close() error {
	conn := c.markClosed()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// markClosed marks the client closed and returns its connection, which it
// removes.
func (c *Client) markClosed() transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn := c.conn
	c.conn, c.closed = nil, true
	return conn
}

// runningAttempt is the attempt a request runs, which the request's context
// interrupts: the connection it uses, nil once it ends; its number,
// which keeps a late interrupt from reaching a later attempt; and interrupted,
// which closes once an interrupt that started has set its deadline.
type runningAttempt struct {
	conn        transport
	seq         uint64
	interrupted chan struct{}
}

// interruptible makes the attempt that uses conn the client's running attempt,
// which ctx interrupts once it is done. The attempt calls it after setting its
// deadline, which would otherwise undo an interrupt, and ends it with end.
func (c *Client) interruptible(ctx context.Context, conn transport) attemptInterrupts {
	c.mu.Lock()
	c.attempt.seq++
	c.attempt.conn = conn
	seq := c.attempt.seq
	c.mu.Unlock()
	a := attemptInterrupts{c: c, seq: seq}
	// Until this returns, the caller cannot defer end. Roll back setup if
	// a context's method panics, including while AfterFunc registers it.
	completed := false
	defer func() {
		if !completed {
			a.end()
		}
	}()
	if ctx.Done() != nil {
		a.stopContext = context.AfterFunc(ctx, func() { c.interrupt(seq) })
	}
	completed = true
	return a
}

// attemptInterrupts are the interrupts of attempt seq.
type attemptInterrupts struct {
	c           *Client
	seq         uint64
	stopContext func() bool
}

// end ends the attempt's interrupts: it stops the context's, then ends the
// attempt (clear), also when stopping panics: a context with its own AfterFunc
// method gives the stop function, the caller's code.
func (a attemptInterrupts) end() {
	defer a.clear()
	if a.stopContext != nil {
		a.stopContext()
	}
}

// clear ends the attempt: an interrupt that runs later finds it ended, and one
// that has started is waited for, so that its deadline cannot land after a
// later attempt's.
func (a attemptInterrupts) clear() {
	c := a.c
	c.mu.Lock()
	interrupted := c.attempt.interrupted
	c.attempt.conn, c.attempt.interrupted = nil, nil
	c.mu.Unlock()
	if interrupted != nil {
		<-interrupted
	}
}

// interrupt makes the pending and later reads and writes of attempt seq fail
// at once, with a deadline in the past on its connection, while the attempt
// runs; once one interrupt has started, others do nothing. It sets the
// deadline without mu, which a slow SetDeadline then cannot hold.
func (c *Client) interrupt(seq uint64) {
	c.mu.Lock()
	conn := c.attempt.conn
	if conn == nil || c.attempt.seq != seq || c.attempt.interrupted != nil {
		c.mu.Unlock()
		return
	}
	interrupted := make(chan struct{})
	c.attempt.interrupted = interrupted
	c.mu.Unlock()
	defer close(interrupted)
	_ = conn.SetDeadline(time.Unix(1, 0))
}

// errNoConn is the error of a request on a client Connect never connected
// (and Close never closed), errClosed after Close, errNilContext of a request
// or Connect given a nil context, and errNoTarget of Connect without a Target.
var (
	errNoConn     = errors.New("the client is not connected: call Connect first")
	errNoTarget   = errors.New("Config.Target is empty")
	errClosed     = fmt.Errorf("the client was closed: %w", net.ErrClosed)
	errNilContext = errors.New("nil context")
)

// isClosed reports whether Close closed the client's connection, which no
// Connect has replaced since.
func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn == nil && c.closed
}

// connection returns the client's connection, which an attempt of a request
// uses. It fails without a connection, with net.ErrClosed after Close.
func (c *Client) connection() (transport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.conn == nil && c.closed:
		return nil, errClosed
	case c.conn == nil:
		return nil, errNoConn
	}
	return c.conn, nil
}

// transport is the client's connection as a request uses it: the UDP socket
// Connect opens, or the tests' fake. A request writes each message with Write
// and reads each reply, a datagram, with ReadFrom.
type transport interface {
	Write(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetDeadline(t time.Time) error
	Close() error
}

// dial opens a UDP socket connected to address, "host:port", within ctx and
// timeout, which bound the dial and its lookup of the host's name together.
func dial(ctx context.Context, timeout time.Duration, address string) (*net.UDPConn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	// A UDP dial returns a *net.UDPConn: checked, not asserted, as the library
	// does not panic.
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("dial udp %s: a %T, not a UDP socket", address, conn)
	}
	return udp, nil
}

// rxBufSize is the size of the receive buffer: the largest message the client
// reads, and the msgMaxSize its SNMPv3 requests advertise. It is the largest
// IPv4 and IPv6 packet.
const rxBufSize = 65535

// errReplyTooBig is the error of a datagram that fills the receive buffer.
var errReplyTooBig = errors.New("response buffer too small")

// receiveBuffer is the buffer a client reads replies into.
type receiveBuffer [rxBufSize]byte

// receive reads one reply, a datagram, from conn into rx and returns a copy;
// its source address is not checked.
func receive(conn transport, rx *receiveBuffer) ([]byte, error) {
	n, _, err := conn.ReadFrom(rx[:])
	if err != nil {
		return nil, fmt.Errorf("error reading from socket: %w", err)
	}
	if n == rxBufSize {
		// The datagram may have been cut short.
		return nil, errReplyTooBig
	}
	resp := make([]byte, n)
	copy(resp, rx[:n])
	return resp, nil
}
