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
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/netdata/gosnmp/internal/ber"
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

// Close closes the client's connection, the one Conn holds, and interrupts the
// running attempt, whatever connection it uses (a hook may have replaced
// Conn). Any goroutine may call it, also while a request runs, which it ends:
// once Close has run, a request whose attempt ends without a reply fails with
// an error wrapping net.ErrClosed, as do later requests until Connect opens a
// connection or Conn is set (see the package documentation). Close does not
// cut the dial of a TCP reopen short; the dial's timeout and the Context bound
// it. Only the first call closes the connection; later calls, and calls on a
// client without a connection, return nil.
func (x *GoSNMP) Close() error {
	conn, attempt := x.markClosed()
	x.interrupt(attempt)
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// markClosed marks the client closed and returns the connection Conn held,
// which it removes, and the number of the running attempt, for Close to
// interrupt.
func (x *GoSNMP) markClosed() (net.Conn, uint64) {
	x.mu.Lock()
	defer x.mu.Unlock()
	conn := x.Conn
	x.Conn, x.opened, x.closed = nil, connection{}, true
	return conn, x.attempt.seq
}

// runningAttempt is the attempt a request runs, which Close and the request's
// Context interrupt: the connection it uses, nil once it ends; its number,
// which keeps a late interrupt from reaching a later attempt; and interrupted,
// which closes once an interrupt that started has set its deadline.
type runningAttempt struct {
	conn        net.Conn
	seq         uint64
	interrupted chan struct{}
}

// interruptible makes the attempt that uses conn the client's running attempt,
// which Close interrupts, and which ctx interrupts once it is done. The
// attempt calls it after setting its deadline, which would otherwise undo an
// interrupt, and ends it with end.
func (x *GoSNMP) interruptible(ctx context.Context, conn net.Conn) attemptInterrupts {
	x.mu.Lock()
	x.attempt.seq++
	x.attempt.conn = conn
	seq := x.attempt.seq
	x.mu.Unlock()
	a := attemptInterrupts{x: x, seq: seq}
	if ctx.Done() != nil {
		a.stopContext = context.AfterFunc(ctx, func() { x.interrupt(seq) })
	}
	return a
}

// attemptInterrupts are the interrupts of attempt seq.
type attemptInterrupts struct {
	x           *GoSNMP
	seq         uint64
	stopContext func() bool
}

// end ends the attempt's interrupts: it waits for one that has started, so
// that its deadline cannot land after a later attempt's, and one that runs
// later finds the attempt ended.
func (a attemptInterrupts) end() {
	if a.stopContext != nil {
		a.stopContext()
	}
	x := a.x
	x.mu.Lock()
	interrupted := x.attempt.interrupted
	x.attempt.conn, x.attempt.interrupted = nil, nil
	x.mu.Unlock()
	if interrupted != nil {
		<-interrupted
	}
}

// interrupt makes the pending and later reads and writes of attempt seq fail
// at once, with a deadline in the past on its connection, while the attempt
// runs; once one interrupt has started, others do nothing. It sets the
// deadline without mu, which a slow SetDeadline then cannot hold.
func (x *GoSNMP) interrupt(seq uint64) {
	x.mu.Lock()
	conn := x.attempt.conn
	if conn == nil || x.attempt.seq != seq || x.attempt.interrupted != nil {
		x.mu.Unlock()
		return
	}
	interrupted := make(chan struct{})
	x.attempt.interrupted = interrupted
	x.mu.Unlock()
	defer close(interrupted)
	_ = conn.SetDeadline(time.Unix(1, 0))
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
	x.Conn, x.opened, x.closed, x.unconnectedAddr = c.conn, c, false, c.uaddr
	x.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// isClosed reports whether Close closed the client's connection, which no
// Connect or Conn has replaced since.
func (x *GoSNMP) isClosed() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.Conn == nil && x.closed
}

// connectionFor returns the client's connection for an attempt of the request
// with configuration cfg (clientConnection); a lost TCP connection it opens
// again first (reopen). It fails without a connection, with net.ErrClosed
// after Close, and with the error of a failed reopen.
func (x *GoSNMP) connectionFor(cfg *requestConfig) (connection, error) {
	c, lost, err := x.clientConnection(cfg)
	if err != nil {
		return connection{}, err
	}
	if lost {
		return x.reopen(cfg.ctx, cfg.timeout, c)
	}
	return c, nil
}

// clientConnection returns the client's connection for a request with
// configuration cfg: the record of the one the client opened, or for a Conn
// the caller set one with the request's settings (adopt), and whether it is
// lost: the connection markLost recorded, while Conn holds it. It fails
// without a connection, with net.ErrClosed after Close.
func (x *GoSNMP) clientConnection(cfg *requestConfig) (c connection, lost bool, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	switch {
	case x.Conn == nil && x.closed:
		return connection{}, false, errClosed
	case x.Conn == nil:
		return connection{}, false, errNoConn
	}
	if x.lost != nil && !sameConn(x.Conn, x.lost) {
		x.lost = nil // Connect, a reopen or the caller replaced it
	}
	lost = x.lost != nil
	// opened.conn is nil or a connection open made, of a comparable type, so
	// == cannot panic: values of different types are unequal.
	if x.Conn == x.opened.conn {
		return x.opened, lost, nil
	}
	return cfg.dial.adopt(x.Conn, x.unconnectedAddr), lost, nil
}

// markLost records that conn, the TCP connection an attempt used, is lost:
// while Conn holds it, the next attempt opens it again.
func (x *GoSNMP) markLost(conn net.Conn) {
	x.mu.Lock()
	x.lost = conn
	x.mu.Unlock()
}

// errReopenSuperseded is the error of a reopen whose connection is no longer
// the client's when its dial completes: Close ran meanwhile.
var errReopenSuperseded = errors.New("the client's connection changed while it was reopened")

// reopen opens c, the client's lost TCP connection, again, with the settings
// it was opened with, within ctx and timeout, and makes the new connection the
// client's in its place, closing c; when c is no longer the client's
// connection, it closes the new one instead and fails. A failed dial leaves c
// the client's connection, still lost, for the next attempt.
func (x *GoSNMP) reopen(ctx context.Context, timeout time.Duration, c connection) (connection, error) {
	x.Logger.Print("Reopening the lost TCP connection")
	nc, err := c.dial.open(ctx, timeout)
	if err != nil {
		return connection{}, err
	}
	if !x.replace(c.conn, nc) {
		_ = nc.conn.Close()
		return connection{}, errReopenSuperseded
	}
	_ = c.conn.Close()
	return nc, nil
}

// replace makes nc the client's connection while old is, and reports whether
// it did.
func (x *GoSNMP) replace(old net.Conn, nc connection) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if !sameConn(x.Conn, old) {
		return false
	}
	x.Conn, x.opened = nc.conn, nc
	return true
}

// sameConn reports whether conn, the client's connection, is still old, the
// connection an attempt took. == cannot panic when either value is
// comparable: where the dynamic types match, both values are. Two values that
// are not comparable (== would panic) count as the same: a caller's Conn of
// such a type is more likely than a hook replacing it by another of the same
// type.
func sameConn(conn, old net.Conn) bool {
	v, o := reflect.ValueOf(conn), reflect.ValueOf(old)
	switch {
	case !v.IsValid() || !o.IsValid():
		return conn == nil && old == nil
	case v.Type() != o.Type():
		return false
	case !v.Comparable() && !o.Comparable():
		return true
	}
	return conn == old
}

// dialSettings are how the client opens a connection: what Connect reads from
// the client, and what a TCP reopen opens again.
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

// connection is a connection to the agent and how it is opened: with dial,
// whose network a local address narrowed (for a Conn the caller set: the
// request's settings, see adopt); uaddr is the agent's address for an
// unconnected UDP socket.
type connection struct {
	conn  net.Conn
	dial  dialSettings
	uaddr *net.UDPAddr
}

// open opens a connection to the agent, or for an unconnected UDP socket a
// local socket, with ctx and timeout bounding every step: the lookups of the
// local address and of an unconnected socket's agent, and the dial, which
// looks up the agent. A UDP or TCP local address in IPv4 narrows the network
// to IPv4.
func (d dialSettings) open(ctx context.Context, timeout time.Duration) (connection, error) {
	// One deadline for the whole opening: a Dialer's Timeout would bound the
	// dial only. A zero timeout sets none, as a zero Dialer.Timeout does.
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var local net.Addr
	switch d.network {
	case "udp", "udp4", "udp6":
		ip, port, err := resolveAddr(ctx, net.DefaultResolver, d.network, d.localAddr)
		if err != nil {
			return connection{}, err
		}
		udpLocal := &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}
		if udpLocal.IP.To4() != nil {
			d.network = "udp4"
		}
		if d.unconnected {
			return d.listenUnconnectedUDP(ctx, udpLocal)
		}
		local = udpLocal
	case "tcp", "tcp4", "tcp6":
		ip, port, err := resolveAddr(ctx, net.DefaultResolver, d.network, d.localAddr)
		if err != nil {
			return connection{}, err
		}
		tcpLocal := &net.TCPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}
		if tcpLocal.IP.To4() != nil {
			d.network = "tcp4"
		}
		local = tcpLocal
	}
	dialer := net.Dialer{LocalAddr: local, Control: d.control}
	conn, err := dialer.DialContext(ctx, d.network, d.agentAddr())
	if err != nil {
		return connection{}, err
	}
	return connection{conn: conn, dial: d}, nil
}

// adopt returns the record of conn, a Conn the caller set, with d, the
// request's settings: for an unconnected UDP socket also uaddr, the agent's
// address the last Connect resolved, if any. It resolves no name: a request
// does not.
func (d dialSettings) adopt(conn net.Conn, uaddr *net.UDPAddr) connection {
	c := connection{conn: conn, dial: d}
	if d.unconnected && strings.HasPrefix(d.network, udp) {
		c.uaddr = uaddr
	}
	return c
}

// agentAddr is the agent's address, "host:port".
func (d dialSettings) agentAddr() string {
	return net.JoinHostPort(d.target, strconv.Itoa(int(d.port)))
}

// lookupIPAddrs looks up host's addresses of family ("", "4" or "6") with r,
// with the query the standard library makes for a network of that family,
// zones included: without a family, LookupIPAddr asks for both families and
// keeps the zones; with one, LookupIP asks for that family alone but drops the
// zones, which a scoped IPv6 address among the answers then takes from
// LookupIPAddr.
//
// Intended difference from net.ResolveUDPAddr and net.ResolveTCPAddr, not a
// bug: with a family, a zone a hosts file gives an address that is not scoped
// (an IPv4 or a global IPv6 one) is dropped. A zone qualifies only a scoped
// address, and keeping these would take a second query of every lookup.
func lookupIPAddrs(ctx context.Context, r nameResolver, family, host string) ([]net.IPAddr, error) {
	if family == "" {
		return r.LookupIPAddr(ctx, host)
	}
	ips, err := r.LookupIP(ctx, "ip"+family, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		addrs[i].IP = ip
	}
	if !slices.ContainsFunc(ips, scopedIPv6) {
		return addrs, nil
	}
	zoned, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for i := range addrs {
		if j := slices.IndexFunc(zoned, func(z net.IPAddr) bool { return z.IP.Equal(addrs[i].IP) }); j >= 0 {
			addrs[i].Zone = zoned[j].Zone
		}
	}
	return addrs, nil
}

// scopedIPv6 reports whether ip is an IPv6 address a zone qualifies: a
// link-local or interface-local one.
func scopedIPv6(ip net.IP) bool {
	return ip.To4() == nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast())
}

// listenUnconnectedUDP opens a UDP socket on the local address that writes to
// the agent, whose address it looks up within ctx.
func (d dialSettings) listenUnconnectedUDP(ctx context.Context, local *net.UDPAddr) (connection, error) {
	ip, port, err := resolveAddr(ctx, net.DefaultResolver, d.network, d.agentAddr())
	if err != nil {
		return connection{}, err
	}
	conn, err := net.ListenUDP(d.network, local)
	if err != nil {
		return connection{}, err
	}
	return connection{conn: conn, dial: d, uaddr: &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}}, nil
}

// nameResolver is what resolveAddr asks of a *net.Resolver.
type nameResolver interface {
	LookupPort(ctx context.Context, network, service string) (int, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// resolveAddr resolves address, "host:port", over network ("udp" or "tcp",
// either with "4" or "6") with r within ctx, as net.ResolveUDPAddr and
// net.ResolveTCPAddr resolve it with net.DefaultResolver without one: an
// empty address or host is the unspecified address; of a host's addresses of
// the network's family, zones included but for one intended difference (see
// lookupIPAddrs), it takes the first IPv4 one, the first IPv6 one for a host
// in brackets on a network without a family, or else the first.
func resolveAddr(ctx context.Context, r nameResolver, network, address string) (net.IPAddr, int, error) {
	if address == "" {
		return net.IPAddr{}, 0, nil
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return net.IPAddr{}, 0, err
	}
	port, err := r.LookupPort(ctx, network, service)
	if err != nil {
		return net.IPAddr{}, 0, err
	}
	if host == "" {
		return net.IPAddr{}, port, nil
	}
	family := network[len(udp):] // "", "4" or "6"; udp and tcp have the same length
	var ips []net.IPAddr
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		ips = []net.IPAddr{{IP: ip.AsSlice(), Zone: ip.Zone()}}
	} else if ips, err = lookupIPAddrs(ctx, r, family, host); err != nil {
		return net.IPAddr{}, 0, err
	}
	// As the standard library does (Go issue 18806): the IPv6 unspecified
	// address stands for the IPv4 one too.
	if len(ips) == 1 && ips[0].IP.Equal(net.IPv6unspecified) {
		ips = append(ips, net.IPAddr{IP: net.IPv4zero})
	}
	switch family {
	case "4":
		ips = slices.DeleteFunc(ips, func(ip net.IPAddr) bool { return ip.IP.To4() == nil })
	case "6":
		ips = slices.DeleteFunc(ips, func(ip net.IPAddr) bool { return len(ip.IP) != net.IPv6len || ip.IP.To4() != nil })
	}
	if len(ips) == 0 {
		return net.IPAddr{}, 0, &net.AddrError{Err: "no suitable address found", Addr: host}
	}
	want6 := (network == udp || network == tcp) && strings.Contains(address, "[")
	for _, ip := range ips {
		if (ip.IP.To4() == nil) == want6 {
			return ip, port, nil
		}
	}
	return ips[0], port, nil
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

// rxBufSize is the size of the receive buffer: the largest message the client
// reads, and the msgMaxSize its SNMPv3 requests advertise. It is the largest
// IPv4 and IPv6 packet.
const rxBufSize = 65535

// errReplyTooBig is the error of a datagram that fills the receive buffer, and
// of a message on a TCP stream longer than the buffer.
var errReplyTooBig = errors.New("response buffer too small")

// errLostFraming is the error of octets on a TCP stream that cannot start a
// message: no later message can be found on the stream.
var errLostFraming = errors.New("lost the message framing of the TCP stream")

// receiveBuffer is the buffer a client reads replies into. On a TCP stream it
// also keeps the octets read past the last message receive returned,
// buf[start:end], the start of the next messages on conn.
type receiveBuffer struct {
	buf        [rxBufSize]byte
	conn       net.Conn
	start, end int
}

// stream reports whether c is a TCP connection, by the network it was opened
// with (for a Conn the caller set: the request's Transport): one that receive
// reads as a stream and that is lost when it fails (ioFailure).
func (c *connection) stream() bool {
	return strings.HasPrefix(c.dial.network, tcp)
}

// receive reads one reply from the connection into rx and returns a copy: on a
// TCP stream the next message (readMessage), otherwise a datagram, whose
// source address is not checked.
func (c *connection) receive(rx *receiveBuffer) ([]byte, error) {
	if c.stream() {
		return rx.readMessage(c.conn)
	}
	rx.conn, rx.start, rx.end = nil, 0, 0 // no stream to continue after a datagram
	var n int
	var err error
	if uconn, ok := c.conn.(net.PacketConn); ok {
		n, _, err = uconn.ReadFrom(rx.buf[:])
	} else {
		n, err = c.conn.Read(rx.buf[:])
	}
	if err != nil {
		return nil, readError(err)
	}
	if n == rxBufSize {
		// The datagram may have been cut short.
		return nil, errReplyTooBig
	}
	resp := make([]byte, n)
	copy(resp, rx.buf[:n])
	return resp, nil
}

// readMessage returns the next message on the TCP stream conn (RFC 3430
// section 2.1), reading from conn until the whole message is buffered: one
// SEQUENCE, by the decoder's length rule (frame). The octets after it stay
// buffered for the next call on conn, and so does a message that a read error
// cuts short: a timeout keeps the stream's framing. A call on another
// connection than the last call's starts with an empty buffer. Octets that
// cannot start a message fail with errLostFraming, and a message longer than
// the buffer with errReplyTooBig: the stream cannot be read on.
func (rx *receiveBuffer) readMessage(conn net.Conn) ([]byte, error) {
	if !sameConn(rx.conn, conn) {
		rx.conn, rx.start, rx.end = conn, 0, 0
	}
	var readErr error
	for {
		size, err := frame(rx.buf[rx.start:rx.end])
		if err != nil {
			return nil, err
		}
		if size > rxBufSize {
			return nil, errReplyTooBig
		}
		need := int(size)
		if need != 0 && need <= rx.end-rx.start {
			return rx.take(need), nil
		}
		if readErr != nil {
			return nil, readError(readErr)
		}
		// Make room for the rest of the message, or of its header.
		if rx.end == rxBufSize || rx.start+need > rxBufSize {
			rx.end = copy(rx.buf[:], rx.buf[rx.start:rx.end])
			rx.start = 0
		}
		var n int
		n, readErr = conn.Read(rx.buf[rx.end:])
		rx.end += n
	}
}

// take returns a copy of the n octets buffered at start, which it consumes.
func (rx *receiveBuffer) take(n int) []byte {
	b := make([]byte, n)
	copy(b, rx.buf[rx.start:])
	rx.start += n
	if rx.start == rx.end {
		rx.start, rx.end = 0, 0
	}
	return b
}

// frame returns the size of the message that b, octets read from a TCP
// stream, starts with, or 0 while b does not hold its whole header. A message
// is a SEQUENCE whose length the decoder takes (readVersion, ber.Length);
// octets that cannot start one fail with errLostFraming.
func frame(b []byte) (uint64, error) {
	switch {
	case len(b) == 0:
		return 0, nil
	case PDUType(b[0]) != Sequence:
		return 0, fmt.Errorf("%w: a message starts with 0x%02x, not a SEQUENCE", errLostFraming, b[0])
	case !ber.HeaderComplete(b):
		return 0, nil
	}
	size, _, err := ber.Length(b)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errLostFraming, err)
	}
	return size, nil
}

// readError is the error of a failed read: io.EOF as it is, as the agent
// closing a TCP connection ends a read, and any other wrapped.
func readError(err error) error {
	if err == io.EOF {
		return err
	}
	return fmt.Errorf("error reading from socket: %w", err)
}
