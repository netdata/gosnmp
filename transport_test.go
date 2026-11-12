// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectResult is what TestConnect observes of a Connect.
type connectResult struct {
	err       string // "" for no error
	connected bool   // Conn is set
	local     string // the IP of Conn's local address
	maxOids   int    // MaxOids after Connect: the default once it readied the client
}

// TestConnect pins how Connect validates the client and dials, on a loopback
// socket.
func TestConnect(t *testing.T) {
	udpPort := unusedUDPPort(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := map[string]struct {
		setup func(x *Client)
		ctx   context.Context // background unless set
		nil   bool            // a nil context
		want  connectResult
	}{
		"udp": {
			want: connectResult{connected: true, local: "127.0.0.1", maxOids: MaxOids},
		},
		"invalid parameters": {
			setup: func(x *Client) { x.MaxOids = -1 },
			want:  connectResult{err: "field MaxOids cannot be less than 0", maxOids: -1},
		},
		"negative timeout": {
			setup: func(x *Client) { x.Timeout = -time.Second },
			want: connectResult{
				err:     "error establishing connection to host: dial udp 127.0.0.1:" + strconv.Itoa(int(udpPort)) + ": i/o timeout",
				maxOids: MaxOids,
			},
		},
		"canceled context": {
			ctx: canceled,
			want: connectResult{
				err:     "error establishing connection to host: dial udp 127.0.0.1:" + strconv.Itoa(int(udpPort)) + ": operation was canceled",
				maxOids: MaxOids,
			},
		},
		// A nil context fails Connect before it readies the client or dials.
		"nil context": {
			nil:  true,
			want: connectResult{err: "nil context"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{Target: "127.0.0.1", Port: udpPort, Version: Version2c, Community: "public", Timeout: time.Second}
			if tc.setup != nil {
				tc.setup(x)
			}
			ctx := cmp.Or(tc.ctx, context.Background())
			if tc.nil {
				ctx = nil
			}
			var got connectResult
			if err := x.Connect(ctx); err != nil {
				got.err = err.Error()
			}
			got.maxOids = x.MaxOids
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

// packetConnWrapper wraps a UDP socket, as a caller may to instrument it: a
// net.Conn and a net.PacketConn of another type than the socket's.
type packetConnWrapper struct {
	net.Conn
	pc net.PacketConn
}

func (w packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) { return w.pc.ReadFrom(b) }

func (w packetConnWrapper) WriteTo(b []byte, addr net.Addr) (int, error) {
	return w.pc.WriteTo(b, addr)
}

// TestUDPAgentAddress checks where a request goes after Port changed from
// agent A's to agent B's: to A from the socket Connect dialed and from a
// wrapper of it, whose peer the dial fixed; to its own peer from a connected
// socket the caller set, also after Close; an unconnected socket the caller
// set has no peer, and the request fails.
func TestUDPAgentAddress(t *testing.T) {
	connectedTo := func(t *testing.T, port uint16) net.Conn {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	tests := map[string]struct {
		// conn gives the client its connection; portB is agent B's port.
		conn func(t *testing.T, x *Client, portB uint16)
		want string // the agent that answers; "" when the request fails
	}{
		"the socket Connect opened": {want: "A", conn: func(t *testing.T, x *Client, _ uint16) {
			require.NoError(t, x.Connect(context.Background()))
		}},
		"a wrapper of the socket Connect opened": {want: "A", conn: func(t *testing.T, x *Client, _ uint16) {
			require.NoError(t, x.Connect(context.Background()))
			x.Conn = packetConnWrapper{Conn: x.Conn, pc: x.Conn.(net.PacketConn)}
		}},
		"a connected socket the caller set after Connect": {want: "B", conn: func(t *testing.T, x *Client, portB uint16) {
			require.NoError(t, x.Connect(context.Background()))
			replaced := x.Conn
			t.Cleanup(func() { _ = replaced.Close() })
			x.Conn = connectedTo(t, portB)
		}},
		"a connected socket the caller set after Close": {want: "B", conn: func(t *testing.T, x *Client, portB uint16) {
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Close())
			x.Conn = connectedTo(t, portB)
		}},
		"an unconnected socket the caller set": {conn: func(t *testing.T, x *Client, _ uint16) {
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			t.Cleanup(func() { _ = pc.Close() })
			x.Conn = pc
		}},
	}
	agent := func(name string) uint16 {
		port, _ := udpAgent(t, func(_ int, req []byte) []byte {
			return replyTo(req, nil, VarBind{Name: engineOID, Value: OctetStringValue([]byte(name))})
		})
		return port
	}
	portA, portB := agent("A"), agent("B")
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{
				Target: "127.0.0.1", Port: portA, Version: Version2c, Community: "public",
				Timeout: 500 * time.Millisecond, MaxOids: MaxOids,
			}
			tc.conn(t, x, portB)
			defer x.Close()
			x.Port = portB

			res, err := x.Get(context.Background(), []string{engineOID})
			if tc.want == "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, res.VarBinds, 1)
			got, _ := res.VarBinds[0].Value.Bytes()
			assert.Equal(t, tc.want, string(got))
		})
	}
}

// TestRequestResolvesNoName checks that a request resolves no name: after
// Target changed to a name since Connect, it goes over the socket Connect
// dialed, with no lookup.
func TestRequestResolvesNoName(t *testing.T) {
	var lookups atomic.Int32
	defaultResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("codec: no lookups during a request")
	}}
	defer func() { net.DefaultResolver = defaultResolver }()

	port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
	x := &Client{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 500 * time.Millisecond,
	}
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()
	x.Target = "agent.invalid"

	_, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, int32(0), lookups.Load(), "lookups")
}

// TestRetryUsesConnReplacedDuringRequest checks that each attempt of a request
// uses the connection Conn holds when it starts: as the first attempt writes
// to agent A, which never answers, the Conn's code sets Conn to a socket
// connected to agent B, which answers the retry.
func TestRetryUsesConnReplacedDuringRequest(t *testing.T) {
	portA, _ := udpAgent(t, func(int, []byte) []byte { return nil })
	portB, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
	x := &Client{
		Target: "127.0.0.1", Port: portA, Version: Version2c, Community: "public",
		Timeout: 200 * time.Millisecond, Retries: 1,
	}
	require.NoError(t, x.Connect(context.Background()))
	first := &actingConn{UDPConn: x.Conn.(*net.UDPConn)}
	x.Conn = first
	defer first.Close()
	defer x.Close()
	first.afterWrite = func() {
		first.afterWrite = nil
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(portB)})
		require.NoError(t, err)
		x.Conn = conn
	}

	res, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
}

// TestConnectIPv6Target checks a request to an agent on the IPv6 loopback
// address: Connect dials Target "::1" over IPv6, and the agent answers.
func TestConnectIPv6Target(t *testing.T) {
	agent, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		buf := make([]byte, 2048)
		for {
			n, from, readErr := agent.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = agent.WriteToUDP(replyTo(buf[:n], nil, sysDescr), from)
		}
	}()
	defer func() {
		_ = agent.Close()
		<-served
	}()
	x := &Client{
		Target: "::1", Port: uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Version: Version2c, Community: "public", Timeout: 500 * time.Millisecond,
	}
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()
	assert.True(t, x.Conn.RemoteAddr().(*net.UDPAddr).IP.Equal(net.IPv6loopback), "remote %v", x.Conn.RemoteAddr())

	res, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
}

// TestConnectedSocketOtherSource checks that the socket Connect dials takes
// replies from the agent's address only: replies sent from another socket do
// not reach the request, which times out.
func TestConnectedSocketOtherSource(t *testing.T) {
	srvr, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer srvr.Close()
	x := &Client{
		Target: "127.0.0.1", Port: uint16(srvr.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Version: Version2c, Community: "public", Timeout: 100 * time.Millisecond, Retries: 2,
	}
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()
	go serveResponses(t, srvr, x, sendFromNewSocket)

	_, err = x.Get(context.Background(), []string{".1.2"})
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

// stubDNS is net.DefaultResolver for a test: a Go resolver whose DNS server
// on loopback answers each A query with 127.0.0.1, and each other query with
// no records, while answering is set; otherwise a lookup reaches no server
// and waits until its context ends or release runs, after a send on held.
// The names tests look up end in ".invalid.", so that no hosts file has them.
type stubDNS struct {
	answering atomic.Bool
	held      chan struct{}
	release   func()
}

// newStubDNS makes a stubDNS net.DefaultResolver until the test ends.
func newStubDNS(t *testing.T) *stubDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan struct{})
	go func() {
		defer close(served)
		buf := make([]byte, 512)
		for {
			n, from, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if reply := stubDNSReply(buf[:n]); reply != nil {
				_, _ = pc.WriteTo(reply, from)
			}
		}
	}()
	released := make(chan struct{})
	var once sync.Once
	dns := &stubDNS{held: make(chan struct{}, 16), release: func() { once.Do(func() { close(released) }) }}
	dns.answering.Store(true)
	resolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if dns.answering.Load() {
			var d net.Dialer
			return d.DialContext(ctx, "udp4", pc.LocalAddr().String())
		}
		select {
		case dns.held <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-released:
			return nil, errors.New("codec: the stub DNS released the lookup")
		}
	}}
	t.Cleanup(func() {
		dns.release()
		net.DefaultResolver = resolver
		_ = pc.Close()
		<-served
	})
	return dns
}

// stubDNSReply answers query, a DNS message with one question: an A question
// with 127.0.0.1, any other with no records.
func stubDNSReply(query []byte) []byte {
	const header = 12
	end := header
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	end += 5 // the root label, QTYPE and QCLASS
	if end > len(query) {
		return nil
	}
	reply := bytes.Clone(query[:end])
	binary.BigEndian.PutUint16(reply[2:], 0x8180)    // a response, recursion desired and available, no error
	binary.BigEndian.PutUint16(reply[6:], 0)         // ANCOUNT
	binary.BigEndian.PutUint16(reply[8:], 0)         // NSCOUNT
	binary.BigEndian.PutUint16(reply[10:], 0)        // ARCOUNT
	if binary.BigEndian.Uint16(reply[end-4:]) == 1 { // QTYPE A
		binary.BigEndian.PutUint16(reply[6:], 1)
		// The question's name (a pointer to offset 12), A, IN, TTL 60, 4 octets.
		reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
	}
	return reply
}

// awaitHeld waits until a lookup waits in dns.
func (dns *stubDNS) awaitHeld(t *testing.T) {
	t.Helper()
	select {
	case <-dns.held:
	case <-time.After(5 * time.Second):
		t.Fatal("no lookup reached the stub DNS")
	}
}

// TestConnectLookupWithinBounds checks that Connect looks up the agent's name
// within its context and Timeout: a lookup that does not end fails Connect once
// the context is canceled or the Timeout passes, with an error that matches it.
func TestConnectLookupWithinBounds(t *testing.T) {
	bounds := map[string]struct {
		timeout time.Duration
		cancel  bool
		want    error
	}{
		"canceled context": {timeout: time.Minute, cancel: true, want: context.Canceled},
		"Timeout":          {timeout: 50 * time.Millisecond, want: context.DeadlineExceeded},
	}
	for name, bound := range bounds {
		t.Run(name, func(t *testing.T) {
			dns := newStubDNS(t)
			dns.answering.Store(false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x := &Client{
				Target: "agent.codec.invalid.", Port: 161, Version: Version2c, Community: "public",
				Timeout: bound.timeout,
			}
			result := make(chan error, 1)
			go func() { result <- x.Connect(ctx) }()
			dns.awaitHeld(t)
			if bound.cancel {
				cancel()
			}
			select {
			case err := <-result:
				assert.ErrorIs(t, err, bound.want)
			case <-time.After(2 * time.Second):
				dns.release()
				t.Errorf("Connect waits for the lookup; after its release: %v", <-result)
			}
			assert.Nil(t, x.Conn)
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
// and leaves no connection, and that a client without one closes cleanly:
// one whose connection Close already closed, and one that never had any.
func TestCloseOnce(t *testing.T) {
	assert.NoError(t, (&Client{}).Close(), "a client that never had a connection")
	c := &closeErrConn{}
	x := &Client{Conn: c}
	assert.ErrorIs(t, x.Close(), errCloseConn)
	assert.Nil(t, x.Conn)
	assert.NoError(t, x.Close())
	assert.Equal(t, 1, c.closes)
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
			x := &Client{
				Target: "127.0.0.1", Port: uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
				Version: Version2c, Community: "public", Timeout: time.Second,
			}
			require.NoError(t, x.Connect(context.Background()))
			first := x.Conn
			defer first.Close()
			defer x.Close()
			if tc.failDial {
				x.Timeout = -time.Second
			}
			err = x.Connect(context.Background())
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
		before func(t *testing.T, x *Client)
		want   error
	}{
		"never connected": {want: errNoConn},
		"after Close": {want: errClosed, before: func(t *testing.T, x *Client) {
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Close())
		}},
		"SNMPv3 after Close": {v3: true, want: errClosed, before: func(t *testing.T, x *Client) {
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Close())
		}},
		"Conn removed after Close and Connect": {want: errNoConn, before: func(t *testing.T, x *Client) {
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Close())
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Conn.Close())
			x.Conn = nil
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &Client{
				Target: "127.0.0.1", Port: unusedUDPPort(t), Version: Version2c, Community: "public",
				Timeout: time.Second, MaxOids: MaxOids,
			}
			if tc.v3 {
				x.Version, x.SecurityLevel = Version3, NoAuthNoPriv
				x.User = User{Name: "codec"}
			}
			if tc.before != nil {
				tc.before(t, x)
			}
			res, err := x.Get(context.Background(), []string{engineOID})
			assert.Nil(t, res)
			assert.Equal(t, tc.want, err)
		})
	}
}

// TestCloseDuringRequest checks, on a loopback socket, Close as Netdata's SNMP
// topology uses it: two goroutines close the client while a request waits for
// its answer. The request ends at once with net.ErrClosed, the next one fails
// the same way without being sent, and Connect opens the client again.
func TestCloseDuringRequest(t *testing.T) {
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 1 {
			return nil // the agent does not answer the first request
		}
		return replyTo(req, nil, sysDescr)
	})
	x := &Client{Target: "127.0.0.1", Port: port, Community: "public", Version: Version2c, Timeout: 10 * time.Second}
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()

	closers := closeOnRelease(x, 2, func() { <-reads })
	start := time.Now()
	_, err := x.Get(context.Background(), []string{engineOID})
	require.ErrorIs(t, err, net.ErrClosed)
	assert.Less(t, time.Since(start), 5*time.Second, "the request ends before its timeout")
	closers.Wait()

	_, err = x.Get(context.Background(), []string{engineOID})
	require.ErrorIs(t, err, net.ErrClosed)

	require.NoError(t, x.Connect(context.Background()))
	res, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
	assert.Len(t, reads, 1, "the agent read the request after Connect, not the one after Close")
}

// TestCloseDuringWalk checks, on a loopback socket, Close as Netdata's SNMP
// topology uses it during a walk: two goroutines close the client while the
// walk waits for an answer. The walk ends at once with net.ErrClosed.
func TestCloseDuringWalk(t *testing.T) {
	const root = ".1.3.6.1.2.1.2.2.1.2"
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 5 {
			return nil // the agent does not answer the fifth request
		}
		p, err := decodeMessage(req)
		if err != nil || len(p.VarBinds) == 0 {
			return nil
		}
		next := root + ".1"
		if arc, ok := strings.CutPrefix(p.VarBinds[0].Name, root+"."); ok {
			i, _ := strconv.Atoi(arc)
			next = root + "." + strconv.Itoa(i+1)
		}
		return replyTo(req, nil, VarBind{Name: next, Value: OctetStringValue([]byte("codec"))})
	})
	x := &Client{Target: "127.0.0.1", Port: port, Community: "public", Version: Version2c, Timeout: 10 * time.Second}
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()

	closers := closeOnRelease(x, 2, func() {
		for n := range reads {
			if n == 5 {
				return
			}
		}
	})
	start := time.Now()
	_, err := x.BulkWalkAll(context.Background(), root)
	require.ErrorIs(t, err, net.ErrClosed)
	assert.Less(t, time.Since(start), 5*time.Second, "the walk ends before its request's timeout")
	closers.Wait()
}

// TestCloseDuringRequestConnReplaced checks, on loopback sockets, a Close from
// another goroutine after the Conn's code removed or replaced Conn during the
// attempt, with and without a context that can be canceled: the request ends
// at once with net.ErrClosed. Close closes the connection Conn holds and
// leaves the one that was replaced, the caller's again, open.
func TestCloseDuringRequestConnReplaced(t *testing.T) {
	type outcome struct {
		errClosed       bool // the request failed with net.ErrClosed
		beforeTimeout   bool // the request ended well before its timeout
		replacedOpen    bool // the connection that was replaced is open
		otherConnClosed bool // the connection set in its place is closed
	}
	tests := map[string]struct {
		otherConn bool // the Conn's code sets another connection; it removes Conn otherwise
		context   bool // the request has a context that can be canceled
		want      outcome
	}{
		"Conn removed":                  {want: outcome{errClosed: true, beforeTimeout: true, replacedOpen: true}},
		"Conn removed, with a context":  {context: true, want: outcome{errClosed: true, beforeTimeout: true, replacedOpen: true}},
		"Conn replaced":                 {otherConn: true, want: outcome{true, true, true, true}},
		"Conn replaced, with a context": {otherConn: true, context: true, want: outcome{true, true, true, true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			port, _ := udpAgent(t, func(int, []byte) []byte { return nil }) // the agent never answers
			const timeout = 2 * time.Second
			x := &Client{Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public", Timeout: timeout}
			ctx := context.Background()
			if tc.context {
				ctx = t.Context()
			}
			require.NoError(t, x.Connect(context.Background()))
			replaced := &actingConn{UDPConn: x.Conn.(*net.UDPConn)}
			x.Conn = replaced
			defer replaced.Close()
			defer x.Close()
			var otherConn net.Conn
			if tc.otherConn {
				var err error
				otherConn, err = net.Dial("udp4", replaced.RemoteAddr().String())
				require.NoError(t, err)
				defer otherConn.Close()
			}
			ready, closed := make(chan struct{}), make(chan struct{})
			go func() {
				<-ready
				_ = x.Close()
				close(closed)
			}()
			replaced.afterWrite = func() {
				replaced.afterWrite = nil
				x.Conn = otherConn
				close(ready)
				<-closed // the attempt reads after Close returned
			}

			start := time.Now()
			_, err := x.Get(ctx, []string{engineOID})
			got := outcome{
				errClosed:     errors.Is(err, net.ErrClosed),
				beforeTimeout: time.Since(start) < timeout/2,
				replacedOpen:  replaced.SetDeadline(time.Time{}) == nil,
			}
			if otherConn != nil {
				got.otherConnClosed = errors.Is(otherConn.SetDeadline(time.Time{}), net.ErrClosed)
			}
			assert.Equal(t, tc.want, got, "error %v", err)
		})
	}
}

// actingConn is a UDP socket, as Connect opens it, whose Write runs
// afterWrite once it has written: the Conn's code acting on the client during
// a request.
type actingConn struct {
	*net.UDPConn
	afterWrite func()
}

func (c *actingConn) Write(b []byte) (int, error) {
	n, err := c.UDPConn.Write(b)
	if err == nil && c.afterWrite != nil {
		c.afterWrite()
	}
	return n, err
}

// closeOnRelease starts n goroutines that close x once release returns, and
// returns their WaitGroup.
func closeOnRelease(x *Client, n int, release func()) *sync.WaitGroup {
	released := make(chan struct{})
	go func() {
		release()
		close(released)
	}()
	var closers sync.WaitGroup
	for range n {
		closers.Go(func() {
			<-released
			_ = x.Close()
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
		x := &Client{Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public", Timeout: 10 * time.Second}
		require.NoError(t, x.Connect(context.Background()))
		closed := make(chan error, 1)
		go func() { closed <- x.Close() }()
		require.NoError(t, x.Connect(context.Background()))
		require.NoError(t, <-closed)

		_, err := x.Get(context.Background(), []string{engineOID})
		if x.Conn == nil {
			assert.ErrorIs(t, err, net.ErrClosed)
		} else {
			assert.NoError(t, err)
		}
		_ = x.Close()
	}
}

// TestContextCancelDuringRequest checks, on a loopback socket, that canceling
// a request's context ends the request waiting for its answer at once, and
// that the client's next request, with another context, is answered.
func TestContextCancelDuringRequest(t *testing.T) {
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 1 {
			return nil // the agent does not answer the first request
		}
		return replyTo(req, nil, sysDescr)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x := &Client{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 10 * time.Second,
	}
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()

	go func() {
		<-reads
		cancel()
	}()
	start := time.Now()
	_, err := x.Get(ctx, []string{engineOID})
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 5*time.Second, "the request ends before its timeout")

	res, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
}

// TestConnectContextBoundsConnectOnly checks, on a loopback socket, that
// Connect's context bounds Connect only: a request after it is canceled, with
// its own context, is answered.
func TestConnectContextBoundsConnectOnly(t *testing.T) {
	port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
	ctx, cancel := context.WithCancel(context.Background())
	x := &Client{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 10 * time.Second,
	}
	require.NoError(t, x.Connect(ctx))
	defer x.Close()
	cancel()

	res, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
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

// scriptedConn is a net.Conn whose reads hand out reads in turn: the octets of
// each, as many at a time as the caller's buffer takes, then its error. Past
// the last read, reads fail with io.EOF. Only Read is implemented.
type scriptedConn struct {
	net.Conn
	reads []scriptedRead
}

// scriptedRead is one read of a scriptedConn.
type scriptedRead struct {
	data []byte
	err  error
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	r := &c.reads[0]
	n := copy(b, r.data)
	if r.data = r.data[n:]; len(r.data) > 0 {
		return n, nil
	}
	err := r.err
	c.reads = c.reads[1:]
	return n, err
}
