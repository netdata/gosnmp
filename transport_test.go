// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netdata/gosnmp/internal/ber"
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
		"negative timeout": {
			setup: func(x *GoSNMP, _ *connectResult) { x.Timeout = -time.Second },
			want: connectResult{
				err:       "error establishing connection to host: dial udp :0->127.0.0.1:" + strconv.Itoa(int(udpPort)) + ": i/o timeout",
				transport: "udp",
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

// packetConnWrapper wraps an unconnected UDP socket, as a caller may to
// instrument it: a net.Conn and a net.PacketConn of another type than the
// socket's.
type packetConnWrapper struct {
	net.Conn
	pc net.PacketConn
}

func (w packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) { return w.pc.ReadFrom(b) }

func (w packetConnWrapper) WriteTo(b []byte, addr net.Addr) (int, error) {
	return w.pc.WriteTo(b, addr)
}

// TestUnconnectedUDPAgentAddress checks where a client in unconnected UDP mode
// sends a request after Port changed from agent A's to agent B's: to the
// address the last Connect resolved (A's), from the socket Connect opened and
// from a Conn the caller set, also after Close; a caller's socket without such
// a Connect has no address, and a connected socket the caller set with
// UseUnconnectedUDPSocket off writes to its peer.
func TestUnconnectedUDPAgentAddress(t *testing.T) {
	callerSocket := func(t *testing.T) net.Conn {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		return pc
	}
	// replaceConn sets conn in place of the client's connection, which is the
	// caller's again.
	replaceConn := func(t *testing.T, x *GoSNMP, conn net.Conn) {
		replaced := x.Conn
		t.Cleanup(func() { _ = replaced.Close() })
		x.Conn = conn
	}
	tests := map[string]struct {
		// conn gives the client its connection; portB is agent B's port.
		conn func(t *testing.T, x *GoSNMP, portB uint16)
		want string // the agent that answers; "" when the request fails
	}{
		"the socket Connect opened": {want: "A", conn: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
		}},
		"a wrapper of the socket Connect opened": {want: "A", conn: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
			x.Conn = packetConnWrapper{Conn: x.Conn, pc: x.Conn.(net.PacketConn)}
		}},
		"a socket the caller opened after Connect": {want: "A", conn: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
			replaceConn(t, x, callerSocket(t))
		}},
		"a socket the caller opened after Connect and Close": {want: "A", conn: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
			require.NoError(t, x.Close())
			x.Conn = callerSocket(t)
		}},
		"a socket the caller opened without Connect": {conn: func(t *testing.T, x *GoSNMP, _ uint16) {
			x.Conn = callerSocket(t)
		}},
		"a socket the caller opened after a Connect in connected mode": {conn: func(t *testing.T, x *GoSNMP, _ uint16) {
			require.NoError(t, x.Connect())
			x.UseUnconnectedUDPSocket = false
			require.NoError(t, x.Connect())
			x.UseUnconnectedUDPSocket = true
			replaceConn(t, x, callerSocket(t))
		}},
		"a connected socket the caller set in connected mode": {want: "B", conn: func(t *testing.T, x *GoSNMP, portB uint16) {
			require.NoError(t, x.Connect())
			x.UseUnconnectedUDPSocket = false
			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(portB)})
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			replaceConn(t, x, conn)
		}},
	}
	agent := func(name string) uint16 {
		port, _ := udpAgent(t, func(_ int, req []byte) []byte {
			return replyTo(req, nil, SnmpPDU{Name: engineOID, Type: OctetString, Value: []byte(name)})
		})
		return port
	}
	portA, portB := agent("A"), agent("B")
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			x := &GoSNMP{
				Target: "127.0.0.1", Port: portA, Version: Version2c, Community: "public",
				Timeout: 500 * time.Millisecond, MaxOids: MaxOids, UseUnconnectedUDPSocket: true,
			}
			tc.conn(t, x, portB)
			defer x.Close()
			x.Port = portB

			res, err := x.Get([]string{engineOID})
			if tc.want == "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, res.Variables, 1)
			assert.Equal(t, tc.want, string(res.Variables[0].Value.([]byte)))
		})
	}
}

// TestUnconnectedUDPWrapperIPv6 checks that a wrapper of the unconnected
// socket ConnectIPv6 opened writes to the IPv6 address ConnectIPv6 resolved
// for a Target that has an IPv4 one too.
func TestUnconnectedUDPWrapperIPv6(t *testing.T) {
	if _, err := net.ResolveUDPAddr("udp6", "localhost:161"); err != nil {
		t.Skipf("localhost has no IPv6 address: %v", err)
	}
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
	x := &GoSNMP{
		Target: "localhost", Port: uint16(agent.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port
		Version: Version2c, Community: "public", Timeout: 500 * time.Millisecond, UseUnconnectedUDPSocket: true,
	}
	require.NoError(t, x.ConnectIPv6())
	defer x.Close()
	_, err = x.Get([]string{engineOID})
	require.NoError(t, err, "the socket ConnectIPv6 opened")
	x.Conn = packetConnWrapper{Conn: x.Conn, pc: x.Conn.(net.PacketConn)}
	_, err = x.Get([]string{engineOID})
	require.NoError(t, err, "a wrapper of it")
}

// TestUnconnectedUDPNoLookup checks that a request over a Conn the caller set
// in unconnected UDP mode resolves no name: after Target changed to a name
// since Connect, it writes to the address Connect resolved, with no lookup.
func TestUnconnectedUDPNoLookup(t *testing.T) {
	var lookups atomic.Int32
	defaultResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("codec: no lookups during a request")
	}}
	defer func() { net.DefaultResolver = defaultResolver }()

	port, _ := udpAgent(t, func(_ int, req []byte) []byte { return replyTo(req, nil, sysDescr) })
	x := &GoSNMP{
		Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public",
		Timeout: 500 * time.Millisecond, UseUnconnectedUDPSocket: true,
	}
	require.NoError(t, x.Connect())
	defer x.Close()
	x.Conn = packetConnWrapper{Conn: x.Conn, pc: x.Conn.(net.PacketConn)}
	x.Target = "agent.invalid"

	_, err := x.Get([]string{engineOID})
	require.NoError(t, err)
	assert.Equal(t, int32(0), lookups.Load(), "lookups")
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

// TestConnectLookupWithinBounds checks that Connect looks up every name, the
// local address's, an unconnected socket's agent and the dialed agent, within
// its Context and Timeout: a lookup that does not end fails Connect once the
// Context is canceled or the Timeout passes, with an error that matches it.
func TestConnectLookupWithinBounds(t *testing.T) {
	settings := map[string]func(x *GoSNMP){
		"TCP local address":     func(x *GoSNMP) { x.Transport, x.LocalAddr = "tcp", "bind.codec.invalid.:0" },
		"UDP local address":     func(x *GoSNMP) { x.LocalAddr = "bind.codec.invalid.:0" },
		"unconnected UDP agent": func(x *GoSNMP) { x.Target, x.UseUnconnectedUDPSocket = "agent.codec.invalid.", true },
		"TCP agent":             func(x *GoSNMP) { x.Transport, x.Target = "tcp", "agent.codec.invalid." },
	}
	bounds := map[string]struct {
		timeout time.Duration
		cancel  bool
		want    error
	}{
		"canceled Context": {timeout: time.Minute, cancel: true, want: context.Canceled},
		"Timeout":          {timeout: 50 * time.Millisecond, want: context.DeadlineExceeded},
	}
	for settingsName, set := range settings {
		for boundName, bound := range bounds {
			t.Run(settingsName+", "+boundName, func(t *testing.T) {
				dns := newStubDNS(t)
				dns.answering.Store(false)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				x := &GoSNMP{
					Target: "127.0.0.1", Port: 161, Version: Version2c, Community: "public",
					Timeout: bound.timeout, Context: ctx,
				}
				set(x)
				result := make(chan error, 1)
				go func() { result <- x.Connect() }()
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
}

// TestResolveAddrMatchesStdlib checks resolveAddr against net.ResolveUDPAddr
// and net.ResolveTCPAddr, which it follows within a Context, over a stub DNS
// that has an IPv4 address only: the same address or error for each network
// and address.
func TestResolveAddrMatchesStdlib(t *testing.T) {
	newStubDNS(t)
	addresses := []string{
		"", ":0", ":161", ":snmp", "127.0.0.1:0", "127.0.0.1:161", "0.0.0.0:0", "[::1]:161", "[::]:0",
		"[fe80::1%lo0]:161", "[::ffff:127.0.0.1]:161", "agent.codec.invalid.:161", "[agent.codec.invalid.]:161",
		"127.0.0.1", "127.0.0.1:99999", "127.0.0.1:no-such-service", "[::1:161",
	}
	describe := func(addr net.Addr, err error) string {
		if err != nil {
			return "error: " + err.Error()
		}
		return addr.String()
	}
	for _, network := range []string{"udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"} {
		for _, address := range addresses {
			ip, port, err := resolveAddr(context.Background(), net.DefaultResolver, network, address)
			var got, want string
			if strings.HasPrefix(network, "udp") {
				got = describe(&net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, err)
				want = describe(net.ResolveUDPAddr(network, address))
			} else {
				got = describe(&net.TCPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, err)
				want = describe(net.ResolveTCPAddr(network, address))
			}
			assert.Equal(t, want, got, "%s %q", network, address)
		}
	}
}

// hostsResolver answers lookups from a table, as a hosts file does, zones
// included; its LookupIP, as *net.Resolver's does, keeps the addresses of the
// family asked for, fails when none is left and drops the zones.
type hostsResolver map[string][]net.IPAddr

func (r hostsResolver) LookupPort(_ context.Context, _, service string) (int, error) {
	return strconv.Atoi(service)
}

func (r hostsResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	addrs, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return slices.Clone(addrs), nil
}

func (r hostsResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		if network == "ip" || (network == "ip4") == (a.IP.To4() != nil) {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
	}
	return ips, nil
}

// TestResolveAddrZones checks that resolveAddr keeps the zone a hosts file
// gives a name's scoped IPv6 address, on every network, as
// net.ResolveUDPAddr and net.ResolveTCPAddr do, and picks a name's address
// by their rules; the zones come from the lookup that keeps them.
func TestResolveAddrZones(t *testing.T) {
	linkLocal := net.ParseIP("fe80::1")
	hosts := hostsResolver{
		"scoped.invalid": {{IP: linkLocal, Zone: "lo0"}},
		"mixed.invalid":  {{IP: net.ParseIP("127.0.0.1")}, {IP: linkLocal, Zone: "lo0"}},
		"twice.invalid":  {{IP: linkLocal, Zone: "lo0"}, {IP: linkLocal, Zone: "en0"}},
		"global.invalid": {{IP: net.ParseIP("2001:db8::1"), Zone: "en0"}},
		"mlink.invalid":  {{IP: net.ParseIP("ff02::1"), Zone: "lo0"}},
		"miface.invalid": {{IP: net.ParseIP("ff01::1"), Zone: "lo0"}},
	}
	tests := map[string]struct {
		network, address string
		want             string // the address, or the error's text
	}{
		"udp, a scoped address":            {network: "udp", address: "scoped.invalid:161", want: "[fe80::1%lo0]:161"},
		"udp6, a scoped address":           {network: "udp6", address: "scoped.invalid:161", want: "[fe80::1%lo0]:161"},
		"tcp6, a scoped address":           {network: "tcp6", address: "scoped.invalid:0", want: "[fe80::1%lo0]:0"},
		"udp4, a scoped address":           {network: "udp4", address: "scoped.invalid:161", want: "address scoped.invalid: no suitable address found"},
		"udp, IPv4 first":                  {network: "udp", address: "mixed.invalid:161", want: "127.0.0.1:161"},
		"udp in brackets, IPv6":            {network: "udp", address: "[mixed.invalid]:161", want: "[fe80::1%lo0]:161"},
		"udp6, mixed":                      {network: "udp6", address: "mixed.invalid:161", want: "[fe80::1%lo0]:161"},
		"tcp4, mixed":                      {network: "tcp4", address: "mixed.invalid:161", want: "127.0.0.1:161"},
		"udp6, one address with two zones": {network: "udp6", address: "twice.invalid:161", want: "[fe80::1%lo0]:161"},
		"udp6, link-local multicast":       {network: "udp6", address: "mlink.invalid:161", want: "[ff02::1%lo0]:161"},
		"udp6, interface-local multicast":  {network: "udp6", address: "miface.invalid:161", want: "[ff01::1%lo0]:161"},
		"udp, a zoned global address":      {network: "udp", address: "global.invalid:161", want: "[2001:db8::1%en0]:161"},
		// Dropped, an intended difference from the standard library, not a bug:
		// no zone qualifies a global address (see lookupIPAddrs).
		"udp6, a zoned global address": {network: "udp6", address: "global.invalid:161", want: "[2001:db8::1]:161"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ip, port, err := resolveAddr(context.Background(), hosts, tc.network, tc.address)
			got := (&net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}).String()
			if err != nil {
				got = err.Error()
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestScopedIPv6 pins which addresses take a zone from a second lookup: the
// IPv6 link-local and interface-local ones; an IPv4 link-local address takes
// no second lookup.
func TestScopedIPv6(t *testing.T) {
	tests := map[string]bool{
		"fe80::1":     true,  // link-local unicast
		"ff02::1":     true,  // link-local multicast
		"ff01::1":     true,  // interface-local multicast
		"2001:db8::1": false, // global
		"::1":         false, // loopback
		"169.254.1.1": false, // IPv4 link-local
		"127.0.0.1":   false,
	}
	for address, want := range tests {
		t.Run(address, func(t *testing.T) {
			assert.Equal(t, want, scopedIPv6(net.ParseIP(address)))
		})
	}
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
	h.SetTimeout(10 * time.Second)
	h.SetRetries(0)
	require.NoError(t, h.Connect())
	defer h.Close()

	closers := closeOnRelease(h, 2, func() { <-reads })
	start := time.Now()
	_, err := h.Get([]string{engineOID})
	require.ErrorIs(t, err, net.ErrClosed)
	assert.Less(t, time.Since(start), 5*time.Second, "the request ends before its timeout")
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
	h.SetTimeout(10 * time.Second)
	h.SetRetries(0)
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
	assert.Less(t, time.Since(start), 5*time.Second, "the walk ends before its request's timeout")
	closers.Wait()
}

// TestCloseDuringRequestConnReplaced checks, on loopback sockets, a Close from
// another goroutine after a hook removed or replaced Conn during the attempt,
// with and without a Context that can be canceled: the request ends at once
// with net.ErrClosed. Close closes the connection Conn holds and leaves the
// one the hook replaced, the caller's again, open.
func TestCloseDuringRequestConnReplaced(t *testing.T) {
	type outcome struct {
		errClosed      bool // the request failed with net.ErrClosed
		beforeTimeout  bool // the request ended well before its timeout
		replacedOpen   bool // the connection the hook replaced is open
		hookConnClosed bool // the connection the hook set is closed
	}
	tests := map[string]struct {
		hookConn bool // the hook sets another connection; it removes Conn otherwise
		context  bool // the client has a Context that can be canceled
		want     outcome
	}{
		"Conn removed":                  {want: outcome{errClosed: true, beforeTimeout: true, replacedOpen: true}},
		"Conn removed, with a Context":  {context: true, want: outcome{errClosed: true, beforeTimeout: true, replacedOpen: true}},
		"Conn replaced":                 {hookConn: true, want: outcome{true, true, true, true}},
		"Conn replaced, with a Context": {hookConn: true, context: true, want: outcome{true, true, true, true}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			port, _ := udpAgent(t, func(int, []byte) []byte { return nil }) // the agent never answers
			const timeout = 2 * time.Second
			x := &GoSNMP{Target: "127.0.0.1", Port: port, Version: Version2c, Community: "public", Timeout: timeout}
			if tc.context {
				x.Context = t.Context()
			}
			require.NoError(t, x.Connect())
			replaced := x.Conn
			defer replaced.Close()
			defer x.Close()
			var hookConn net.Conn
			if tc.hookConn {
				var err error
				hookConn, err = net.Dial("udp4", replaced.RemoteAddr().String())
				require.NoError(t, err)
				defer hookConn.Close()
			}
			ready, closed := make(chan struct{}), make(chan struct{})
			go func() {
				<-ready
				_ = x.Close()
				close(closed)
			}()
			x.OnSent = func(x *GoSNMP) {
				x.OnSent = nil
				x.Conn = hookConn
				close(ready)
				<-closed // the attempt reads after Close returned
			}

			start := time.Now()
			_, err := x.Get([]string{engineOID})
			got := outcome{
				errClosed:     errors.Is(err, net.ErrClosed),
				beforeTimeout: time.Since(start) < timeout/2,
				replacedOpen:  replaced.SetDeadline(time.Time{}) == nil,
			}
			if hookConn != nil {
				got.hookConnClosed = errors.Is(hookConn.SetDeadline(time.Time{}), net.ErrClosed)
			}
			assert.Equal(t, tc.want, got, "error %v", err)
		})
	}
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
		Timeout: 10 * time.Second, Context: ctx,
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
	assert.Less(t, time.Since(start), 5*time.Second, "the request ends before its timeout")

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

// TestSameConn pins the rule the client uses to tell whether its connection
// is still the one an attempt took or found lost (a TCP reopen's commit, the
// lost mark): by ==, without panicking, and the same for two values == cannot
// compare.
func TestSameConn(t *testing.T) {
	type wrapped struct{ net.Conn } // comparable, holding any connection
	type otherUncomparable struct {
		net.Conn
		values []int
	}
	a, b := &net.TCPConn{}, &net.TCPConn{}
	u1 := uncomparableConn{Conn: a, onClose: func() {}}
	u2 := uncomparableConn{Conn: b, onClose: func() {}}
	tests := map[string]struct {
		conn, old net.Conn
		want      bool
	}{
		"both nil":                     {want: true},
		"no connection any more":       {old: a},
		"the same pointer":             {conn: a, old: a, want: true},
		"another pointer":              {conn: b, old: a},
		"another type":                 {conn: u1, old: a},
		"two values == cannot compare": {conn: u1, old: u2, want: true},
		"two values == cannot compare, of two types":      {conn: otherUncomparable{Conn: a, values: []int{1}}, old: u1},
		"a wrapper that cannot compare, another that can": {conn: wrapped{u1}, old: wrapped{a}},
		"a wrapper that can, another that cannot":         {conn: wrapped{a}, old: wrapped{u1}},
		"two wrappers of one pointer":                     {conn: wrapped{a}, old: wrapped{a}, want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, sameConn(tc.conn, tc.old))
		})
	}
}

// streamConn is a net.Conn whose reads hand out reads in turn: the octets of
// each, as many at a time as the caller's buffer takes, then its error. Past
// the last read, reads fail with io.EOF. Only Read is implemented.
type streamConn struct {
	net.Conn
	reads []streamRead
}

// streamRead is one read of a streamConn.
type streamRead struct {
	data []byte
	err  error
}

func (c *streamConn) Read(b []byte) (int, error) {
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

// seqMessage is a SEQUENCE of n content octets.
func seqMessage(n int) []byte {
	b := ber.AppendHeader(nil, byte(Sequence), n)
	for i := range n {
		b = append(b, byte(i))
	}
	return b
}

// describeRead describes what readMessage returned, for a comparison.
func describeRead(b []byte, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("% x", b)
}

// TestReadMessage pins how readMessage frames a TCP stream: the messages it
// returns, one per call, and the errors of octets it cannot frame and of
// reads that fail.
func TestReadMessage(t *testing.T) {
	msg := seqMessage(3)
	tests := map[string]struct {
		reads []streamRead
		calls int
		want  []string
	}{
		"two messages in one read": {
			reads: []streamRead{{data: slices.Concat(msg, seqMessage(1))}},
			calls: 3, want: []string{"30 03 00 01 02", "30 01 00", "error: EOF"},
		},
		"a message in reads of one octet": {
			reads: []streamRead{{data: msg[:1]}, {data: msg[1:2]}, {data: msg[2:4]}, {data: msg[4:]}},
			calls: 1, want: []string{"30 03 00 01 02"},
		},
		"a long-form header in parts": {
			reads: []streamRead{{data: []byte{0x30}}, {data: []byte{0x82}}, {data: []byte{0x00}}, {data: []byte{0x03, 7, 8, 9}}},
			calls: 1, want: []string{"30 82 00 03 07 08 09"},
		},
		"a read of nothing": {
			reads: []streamRead{{}, {data: msg}},
			calls: 1, want: []string{"30 03 00 01 02"},
		},
		"a message and an error in one read": {
			reads: []streamRead{{data: msg, err: io.EOF}},
			calls: 2, want: []string{"30 03 00 01 02", "error: EOF"},
		},
		"a timeout inside a message, then the rest": {
			reads: []streamRead{{data: msg[:2], err: os.ErrDeadlineExceeded}, {data: msg[2:]}},
			calls: 2, want: []string{"error: error reading from socket: i/o timeout", "30 03 00 01 02"},
		},
		"the stream's end inside a message": {
			reads: []streamRead{{data: msg[:4]}},
			calls: 1, want: []string{"error: EOF"},
		},
		"not a SEQUENCE": {
			reads: []streamRead{{data: []byte{byte(OctetString), 1, 0}}},
			calls: 1, want: []string{"error: lost the message framing of the TCP stream: a message starts with 0x04, not a SEQUENCE"},
		},
		"not a SEQUENCE, before a length octet arrives": {
			reads: []streamRead{{data: []byte{byte(OctetString)}}, {err: os.ErrDeadlineExceeded}},
			calls: 1, want: []string{"error: lost the message framing of the TCP stream: a message starts with 0x04, not a SEQUENCE"},
		},
		"a message, then octets that do not start one": {
			reads: []streamRead{{data: slices.Concat(msg, []byte{byte(Integer), 1, 0})}},
			calls: 2, want: []string{"30 03 00 01 02", "error: lost the message framing of the TCP stream: a message starts with 0x02, not a SEQUENCE"},
		},
		"the indefinite form": {
			reads: []streamRead{{data: []byte{byte(Sequence), 0x80, byte(Null), 0, 0, 0}}},
			calls: 1, want: []string{"error: lost the message framing of the TCP stream: invalid packet length: indefinite length encoding (0x80) is not permitted in SNMP"},
		},
		"nine length octets, before they arrive": {
			reads: []streamRead{{data: []byte{byte(Sequence), 0x89}}, {err: os.ErrDeadlineExceeded}},
			calls: 1, want: []string{"error: lost the message framing of the TCP stream: invalid packet length: more than 8 length octets"},
		},
		"a length past the largest uint64": {
			reads: []streamRead{{data: []byte{byte(Sequence), 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},
			calls: 1, want: []string{"error: lost the message framing of the TCP stream: invalid packet length: TLV length exceeds the remaining input"},
		},
		"longer than the buffer, before its content arrives": {
			reads: []streamRead{{data: []byte{byte(Sequence), 0x82, 0xff, 0xfc}}, {err: os.ErrDeadlineExceeded}},
			calls: 1, want: []string{"error: response buffer too small"},
		},
		"a header cut at the buffer's end": {
			reads: []streamRead{{data: slices.Concat(seqMessage(rxBufSize-7), []byte{byte(Sequence), 0x82, 0x00})}, {data: []byte{0x03, 7, 8, 9}}},
			calls: 2, want: []string{fmt.Sprintf("% x", seqMessage(rxBufSize-7)), "30 82 00 03 07 08 09"},
		},
		"as long as the buffer, after a message": {
			reads: []streamRead{{data: slices.Concat(msg, seqMessage(rxBufSize-4))}},
			calls: 2, want: []string{"30 03 00 01 02", fmt.Sprintf("% x", seqMessage(rxBufSize-4))},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			conn := &streamConn{reads: tc.reads}
			rx := new(receiveBuffer)
			var got []string
			for range tc.calls {
				got = append(got, describeRead(rx.readMessage(conn)))
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestReadMessageSplits checks that readMessage returns the messages of a TCP
// stream one by one, however the stream is split into reads, and then the
// stream's end.
func TestReadMessageSplits(t *testing.T) {
	msgs := [][]byte{
		seqMessage(0), seqMessage(1), seqMessage(127), seqMessage(128), seqMessage(1000),
		{byte(Sequence), 0x82, 0x00, 0x03, 7, 8, 9}, // a length with a leading zero
		seqMessage(rxBufSize - 4),                   // as long as the buffer
	}
	rng := rand.New(rand.NewPCG(58, 58))
	for round := range 300 {
		var want [][]byte
		var stream []byte
		for range 1 + rng.IntN(6) {
			m := msgs[rng.IntN(len(msgs))]
			want = append(want, m)
			stream = append(stream, m...)
		}
		conn := &streamConn{}
		for len(stream) > 0 {
			n := 1 + rng.IntN(min(len(stream), []int{8, 300, 70000}[rng.IntN(3)]))
			conn.reads = append(conn.reads, streamRead{data: stream[:n]})
			stream = stream[n:]
		}
		rx := new(receiveBuffer)
		for i, m := range want {
			got, err := rx.readMessage(conn)
			require.NoError(t, err, "round %d, message %d", round, i)
			require.Equal(t, m, got, "round %d, message %d", round, i)
		}
		_, err := rx.readMessage(conn)
		require.Equal(t, io.EOF, err, "round %d", round)
	}
}

// TestReceiveStreamState checks what the receive buffer keeps of a TCP
// stream: the octets after a message, for the next read on that connection
// only; a read on another connection, or of a datagram, starts afresh.
func TestReceiveStreamState(t *testing.T) {
	msg := seqMessage(3)
	tcpOn := func(conn net.Conn) *connection { return &connection{conn: conn, dial: dialSettings{network: "tcp"}} }
	udpOn := func(conn net.Conn) *connection { return &connection{conn: conn, dial: dialSettings{network: "udp"}} }
	a := &streamConn{reads: []streamRead{{data: slices.Concat(msg, msg[:2])}, {data: msg[2:]}}}
	b := &streamConn{reads: []streamRead{{data: seqMessage(1)}, {data: slices.Concat(msg, msg[:2])}, {data: msg[2:]}, {data: seqMessage(1)}}}
	rx := new(receiveBuffer)
	var got []string
	for _, c := range []*connection{tcpOn(a), tcpOn(b), tcpOn(a), tcpOn(b), udpOn(b), tcpOn(b)} {
		got = append(got, describeRead(c.receive(rx)))
	}
	assert.Equal(t, []string{
		"30 03 00 01 02", // a: the message; its next one starts
		"30 01 00",       // b: a's octets are not read
		"error: lost the message framing of the TCP stream: a message starts with 0x00, not a SEQUENCE", // a: its start is gone
		"30 03 00 01 02", // b: the message; its next one starts
		"00 01 02",       // b as a datagram: the next read, not the buffered start
		"30 01 00",       // b: the start went with the datagram
	}, got)
}

// TestReadMessageAllocs checks that reading a message from a TCP stream
// allocates only the message's copy: every reply of a TCP request is read so.
func TestReadMessageAllocs(t *testing.T) {
	msg := seqMessage(3)
	reads := make([]streamRead, 1)
	conn := &streamConn{}
	rx := new(receiveBuffer)
	allocs := testing.AllocsPerRun(100, func() {
		reads[0] = streamRead{data: msg}
		conn.reads = reads
		if _, err := rx.readMessage(conn); err != nil {
			t.Fatal(err)
		}
	})
	assert.Equal(t, 1.0, allocs)
}
