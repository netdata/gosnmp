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
	connected bool   // the client has a connection
	local     string // the IP of the connection's local address
}

// TestConnect pins how Connect checks the client's Target and dials, on a
// loopback socket.
func TestConnect(t *testing.T) {
	udpPort := unusedUDPPort(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := map[string]struct {
		target *string         // 127.0.0.1 unless set
		ctx    context.Context // background unless set
		nil    bool            // a nil context
		want   connectResult
	}{
		"udp": {
			want: connectResult{connected: true, local: "127.0.0.1"},
		},
		"canceled context": {
			ctx: canceled,
			want: connectResult{
				err: "error establishing connection to host: dial udp 127.0.0.1:" + strconv.Itoa(int(udpPort)) + ": operation was canceled",
			},
		},
		// An empty Target fails Connect before it dials.
		"empty target": {
			target: new(""),
			want:   connectResult{err: "Config.Target is empty"},
		},
		// A nil context fails Connect before it checks the Target or dials.
		"nil context": {
			target: new(""),
			nil:    true,
			want:   connectResult{err: "nil context"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config := Config{Target: "127.0.0.1", Port: udpPort, Version: Version2c, Community: "public", Timeout: time.Second}
			if tc.target != nil {
				config.Target = *tc.target
			}
			x := mustClient(config)
			ctx := cmp.Or(tc.ctx, context.Background())
			if tc.nil {
				ctx = nil
			}
			var got connectResult
			if err := x.Connect(ctx); err != nil {
				got.err = err.Error()
			}
			if x.conn != nil {
				got.connected = true
				host, _, err := net.SplitHostPort(x.conn.(*net.UDPConn).LocalAddr().String())
				require.NoError(t, err)
				got.local = host
				_ = x.Close()
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestConnectDefaultPort checks that Connect dials port 161 when Port is zero:
// NewClient's default.
func TestConnectDefaultPort(t *testing.T) {
	x := mustClient(Config{Target: "127.0.0.1", Version: Version2c, Community: "public"})
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()
	remote, ok := x.conn.(*net.UDPConn).RemoteAddr().(*net.UDPAddr)
	require.True(t, ok)
	assert.Equal(t, 161, remote.Port)
}

// TestRequestResolvesNoName checks that a request resolves no name: Connect
// looks up a Target that is a name, and a request then goes over the socket
// Connect dialed, with no lookup, while the name no longer resolves.
func TestRequestResolvesNoName(t *testing.T) {
	dns := newStubDNS(t)
	port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
	x := mustClient(Config{
		Target: "agent.codec.invalid.", Port: port, Version: Version2c, Community: "public",
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()
	dns.answering.Store(false)

	// A lookup now waits in the stub DNS: the context bounds a request that
	// would make one.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := x.Get(ctx, []string{engineOID})
	require.NoError(t, err)
	assert.Empty(t, dns.held, "lookups during the request")
}

// TestRetryOnConnectedSocket checks, on a loopback socket, a retry over the
// socket Connect opened: the agent does not answer the first attempt, and the
// retry, on the same socket, is answered.
func TestRetryOnConnectedSocket(t *testing.T) {
	port, reads := udpAgent(t, func(n int, req []byte) []byte {
		if n == 1 {
			return nil
		}
		return replyTo(req, nil, sysDescr)
	})
	x := mustClient(Config{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 200 * time.Millisecond, Retries: 1,
	})
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()

	res, err := x.Get(context.Background(), []string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
	assert.Len(t, reads, 2, "the agent read both attempts")
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
	x := mustClient(Config{
		Target: "::1", Port: uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Version: Version2c, Community: "public", Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, x.Connect(context.Background()))
	defer x.Close()
	remote := x.conn.(*net.UDPConn).RemoteAddr()
	assert.True(t, remote.(*net.UDPAddr).IP.Equal(net.IPv6loopback), "remote %v", remote)

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
	x := mustClient(Config{
		Target: "127.0.0.1", Port: uint16(srvr.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Version: Version2c, Community: "public", Timeout: 100 * time.Millisecond, Retries: 2,
	})
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
			x := mustClient(Config{
				Target: "agent.codec.invalid.", Port: 161, Version: Version2c, Community: "public",
				Timeout: bound.timeout,
			})
			result := make(chan error, 1)
			go func() { result <- x.Connect(ctx) }()
			dns.awaitHeld(t)
			if bound.cancel {
				cancel()
			}
			// Well within the 1 s default Timeout, so that the bound is the
			// configured one.
			select {
			case err := <-result:
				assert.ErrorIs(t, err, bound.want)
			case <-time.After(500 * time.Millisecond):
				dns.release()
				t.Errorf("Connect waits for the lookup; after its release: %v", <-result)
			}
			assert.Nil(t, x.conn)
		})
	}
}

// closeErrConn is a connection whose Close fails.
type closeErrConn struct {
	transport
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
	assert.NoError(t, mustClient(Config{}).Close(), "a client that never had a connection")
	c := &closeErrConn{}
	x := &Client{conn: c}
	assert.ErrorIs(t, x.Close(), errCloseConn)
	assert.Nil(t, x.conn)
	assert.NoError(t, x.Close())
	assert.Equal(t, 1, c.closes)
}

// TestConnectReplacesConnection pins what a second Connect does with the
// client's connection: when it opens a new one, it closes the first; when its
// dial fails, the client keeps the first.
func TestConnectReplacesConnection(t *testing.T) {
	type outcome struct {
		err       bool
		connFirst bool // the client's connection is the first
		connNil   bool
		firstOpen bool // the first connection is still open
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := map[string]struct {
		failDial bool // the second Connect's dial fails: its context is canceled
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
			x := mustClient(Config{
				Target: "127.0.0.1", Port: uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
				Version: Version2c, Community: "public", Timeout: time.Second,
			})
			require.NoError(t, x.Connect(context.Background()))
			first := x.conn
			defer first.Close()
			defer x.Close()
			ctx := context.Background()
			if tc.failDial {
				ctx = canceled
			}
			err = x.Connect(ctx)
			assert.Equal(t, tc.want, outcome{
				err:       err != nil,
				connFirst: x.conn == first,
				connNil:   x.conn == nil,
				firstOpen: first.SetDeadline(time.Time{}) == nil,
			})
		})
	}
}

// TestRequestWithoutConnection pins the result of a request on a client
// without a connection: no packet, and errNoConn before the first Connect,
// net.ErrClosed after Close until Connect; an SNMPv3 request fails so before
// its engine starts: before the user's checks and the discovery.
func TestRequestWithoutConnection(t *testing.T) {
	tests := map[string]struct {
		v3     bool
		before func(t *testing.T, x *Client)
		want   error
	}{
		"never connected":        {want: errNoConn},
		"SNMPv3 never connected": {v3: true, want: errNoConn},
		"after Close": {want: errClosed, before: func(t *testing.T, x *Client) {
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Close())
		}},
		"SNMPv3 after Close": {v3: true, want: errClosed, before: func(t *testing.T, x *Client) {
			require.NoError(t, x.Connect(context.Background()))
			require.NoError(t, x.Close())
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config := Config{
				Target: "127.0.0.1", Port: unusedUDPPort(t), Version: Version2c, Community: "public",
				Timeout: time.Second,
			}
			if tc.v3 {
				config.Version, config.SecurityLevel, config.User = Version3, NoAuthNoPriv, User{Name: "codec"}
			}
			x := mustClient(config)
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
// its answer, with a context that is never done and with one that can be
// canceled, whose interrupt the attempt registers. The request ends at once
// with net.ErrClosed, the next one fails the same way without being sent, and
// Connect opens the client again.
func TestCloseDuringRequest(t *testing.T) {
	for name, cancelable := range map[string]bool{"context never done": false, "context that can be canceled": true} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if cancelable {
				ctx = t.Context()
			}
			port, reads := udpAgent(t, func(n int, req []byte) []byte {
				if n == 1 {
					return nil // the agent does not answer the first request
				}
				return replyTo(req, nil, sysDescr)
			})
			x := mustClient(Config{Target: "127.0.0.1", Port: port, Community: "public", Version: Version2c, Timeout: 10 * time.Second})
			require.NoError(t, x.Connect(context.Background()))
			defer x.Close()

			closers := closeOnRelease(x, 2, func() { <-reads })
			start := time.Now()
			_, err := x.Get(ctx, []string{engineOID})
			require.ErrorIs(t, err, net.ErrClosed)
			assert.Less(t, time.Since(start), 5*time.Second, "the request ends before its timeout")
			closers.Wait()

			_, err = x.Get(ctx, []string{engineOID})
			require.ErrorIs(t, err, net.ErrClosed)

			require.NoError(t, x.Connect(context.Background()))
			res, err := x.Get(ctx, []string{engineOID})
			require.NoError(t, err)
			assert.Equal(t, []VarBind{sysDescr}, res.VarBinds)
			assert.Len(t, reads, 1, "the agent read the request after Connect, not the one after Close")
		})
	}
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
	x := mustClient(Config{Target: "127.0.0.1", Port: port, Community: "public", Version: Version2c, Timeout: 10 * time.Second})
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
	_, err := x.BulkWalkAll(context.Background(), root, 0)
	require.ErrorIs(t, err, net.ErrClosed)
	assert.Less(t, time.Since(start), 5*time.Second, "the walk ends before its request's timeout")
	closers.Wait()
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
		x := mustClient(Config{Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public", Timeout: 10 * time.Second})
		require.NoError(t, x.Connect(context.Background()))
		closed := make(chan error, 1)
		go func() { closed <- x.Close() }()
		require.NoError(t, x.Connect(context.Background()))
		require.NoError(t, <-closed)

		_, err := x.Get(context.Background(), []string{engineOID})
		if x.conn == nil {
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
	x := mustClient(Config{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 10 * time.Second,
	})
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
	x := mustClient(Config{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 10 * time.Second,
	})
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
