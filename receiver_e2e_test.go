// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build end2end

package gosnmp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end tests of the receiver as the authoritative engine of informs,
// with net-snmp's snmpinform as the sender: discovery, every level, a
// restart that raises the engine boots, time synchronization and a stale
// engine ID. They need the end2end environment (GOSNMP_TARGET) and net-snmp's
// command-line tools.

const e2eInformEngineID = "\x80\x00\x1f\x88\x04e2e-inform"

// informServer serves a receiver on a loopback UDP socket as a trap
// receiver would: each datagram goes to the receiver, its answer back to the
// sender, and each notification to got.
type informServer struct {
	conn     *net.UDPConn
	receiver atomic.Pointer[Receiver]
	got      chan *Notification
	mu       sync.Mutex
	errs     []error
}

func newInformServer(t *testing.T, r *Receiver) *informServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	s := &informServer{conn: conn, got: make(chan *Notification, 16)}
	s.receiver.Store(r)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, rxBufSize)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			notification, response, err := s.receiver.Load().Receive(append([]byte(nil), buf[:n]...))
			if response != nil {
				_, _ = conn.WriteToUDP(response, peer)
			}
			if err != nil {
				s.mu.Lock()
				s.errs = append(s.errs, err)
				s.mu.Unlock()
				continue
			}
			s.got <- notification
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return s
}

// rejected returns the errors of the datagrams the receiver rejected.
func (s *informServer) rejected() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.errs...)
}

// e2eInformReceiver returns a receiver whose own engine is e2eInformEngineID
// at boots, with users registered for it.
func e2eInformReceiver(t *testing.T, boots uint32, users ...User) *Receiver {
	t.Helper()
	config := ReceiverConfig{EngineID: []byte(e2eInformEngineID), EngineBoots: boots}
	for _, u := range users {
		config.Users = append(config.Users, EngineUser{EngineID: []byte(e2eInformEngineID), User: u})
	}
	r, err := NewReceiver(config)
	require.NoError(t, err)
	return r
}

// snmpinform runs net-snmp's snmpinform against s with args before the
// address, and returns its combined output and error; its configuration and
// persistent state are of the test only, and it loads no MIB.
func snmpinform(t *testing.T, s *informServer, args ...string) (string, error) {
	t.Helper()
	if os.Getenv("GOSNMP_TARGET") == "" {
		t.Skip("environment variable not set: GOSNMP_TARGET")
	}
	bin, err := exec.LookPath("snmpinform")
	require.NoError(t, err, "the end2end environment has net-snmp's snmpinform")
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args = append([]string{"-v3", "-r", "2", "-t", "1", "-m", "", "-Ob"}, args...)
	args = append(args, s.conn.LocalAddr().String(), "", "1.3.6.1.6.3.1.1.5.1", "1.3.6.1.2.1.1.5.0", "s", "e2e-inform")
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "SNMPCONFPATH="+dir, "SNMP_PERSISTENT_DIR="+dir, "MIBS=", "MIBDIRS="+dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// receivedInform waits for the inform snmpinform sent, its trap OID and
// varbind.
func receivedInform(t *testing.T, s *informServer, level SecurityLevel) {
	t.Helper()
	select {
	case n := <-s.got:
		require.Equal(t, InformRequest, n.Message.PDUType)
		assert.Equal(t, level, n.Message.SecurityLevel)
		require.Len(t, n.Message.VarBinds, 3)
		assert.Equal(t, ".1.3.6.1.6.3.1.1.4.1.0", n.Message.VarBinds[1].Name)
		value, _ := n.Message.VarBinds[2].Value.Bytes()
		assert.Equal(t, "e2e-inform", string(value))
	case <-time.After(5 * time.Second):
		t.Fatal("no inform received")
	}
}

// informUser is a sender of the e2e informs: its receiver user and the
// snmpinform arguments of the same credentials.
type informUser struct {
	user  User
	level SecurityLevel
	args  []string
}

// e2eInformUsers are the senders of every authentication protocol without
// privacy and with each privacy protocol, and one without authentication,
// each with a name of its own.
func e2eInformUsers() map[string]informUser {
	auths := map[AuthProtocol]string{MD5: "MD5", SHA: "SHA", SHA224: "SHA-224", SHA256: "SHA-256", SHA384: "SHA-384", SHA512: "SHA-512"}
	privs := map[PrivProtocol]string{
		NoPriv: "", DES: "DES", AES: "AES", AES192: "AES-192", AES256: "AES-256", AES192C: "AES-192-C", AES256C: "AES-256-C",
	}
	users := map[string]informUser{
		"noAuthNoPriv": {User{Name: "e2e-plain"}, NoAuthNoPriv, []string{"-l", "noAuthNoPriv", "-u", "e2e-plain"}},
	}
	for auth, a := range auths {
		for priv, p := range privs {
			name := strings.ToLower(auth.String() + "-" + priv.String())
			u := User{Name: name, AuthProtocol: auth, AuthPassphrase: "e2e-auth-pass", PrivProtocol: priv, PrivPassphrase: "e2e-priv-pass"}
			args := []string{"-u", name, "-a", a, "-A", "e2e-auth-pass"}
			level := AuthNoPriv
			if priv == NoPriv {
				args = append(args, "-l", "authNoPriv")
			} else {
				level = AuthPriv
				args = append(args, "-l", "authPriv", "-x", p, "-X", "e2e-priv-pass")
			}
			users[name] = informUser{u, level, args}
		}
	}
	return users
}

// TestE2EInformDiscovery pins that snmpinform discovers the receiver's engine
// ID, boots and time (a usmStatsUnknownEngineIDs Report to its probe), and gets
// its inform acknowledged: the Response verified and decrypted by net-snmp,
// at every level and for every protocol pair.
func TestE2EInformDiscovery(t *testing.T) {
	for name, u := range e2eInformUsers() {
		t.Run(name, func(t *testing.T) {
			r := e2eInformReceiver(t, 5, u.user)
			s := newInformServer(t, r)
			out, err := snmpinform(t, s, u.args...)
			require.NoError(t, err, out)
			receivedInform(t, s, u.level)
			assert.Equal(t, uint32(1), r.local.unknownEngineIDs.Load(), "one discovery")
			assert.Zero(t, r.local.notInTimeWindows.Load(), "the time from the discovery Report")
		})
	}
}

// TestE2EInformAcrossRestart pins the answers to a sender that kept the
// receiver's engine boots and time from before a restart, which raised the
// boots: a usmStatsNotInTimeWindows Report, which net-snmp verifies and takes
// the new ones from, and the acknowledgment of its inform sent again; for
// every authentication protocol and privacy protocol. A sender that knows only
// the engine ID synchronizes the same way, with boots and time zero (RFC 3414
// section 4).
func TestE2EInformAcrossRestart(t *testing.T) {
	engineID := hex.EncodeToString([]byte(e2eInformEngineID))
	for userName, u := range e2eInformUsers() {
		if u.level == NoAuthNoPriv {
			continue // no time window
		}
		for name, args := range map[string][]string{
			"the boots and time before the restart": {"-e", engineID, "-Z", "5,100"},
			"the engine ID alone":                   {"-e", engineID},
		} {
			t.Run(userName+"/"+name, func(t *testing.T) {
				s := newInformServer(t, e2eInformReceiver(t, 5, u.user))
				out, err := snmpinform(t, s, u.args...)
				require.NoError(t, err, out)
				receivedInform(t, s, u.level)

				restarted := e2eInformReceiver(t, 6, u.user)
				s.receiver.Store(restarted)
				out, err = snmpinform(t, s, append(append([]string(nil), u.args...), args...)...)
				require.NoError(t, err, out)
				receivedInform(t, s, u.level)
				assert.Equal(t, uint32(1), restarted.local.notInTimeWindows.Load(), "one resynchronization")
				assert.Zero(t, restarted.local.unknownEngineIDs.Load(), "no discovery")
			})
		}
	}
}

// TestE2EInformStaleEngineID pins the answer to a sender that holds another
// engine ID than the receiver's (its state was lost): a usmStatsUnknownEngineIDs
// Report to each attempt. snmpinform, given the engine ID (-e), does not act on
// it and times out, as it does against snmptrapd, whose Report has the same
// fields (noAuthNoPriv, the user name, the local engine ID as contextEngineID,
// request ID 0 for an encrypted inform); a sender that discovers anew gets the
// local engine ID (TestE2EInformDiscovery).
func TestE2EInformStaleEngineID(t *testing.T) {
	u := e2eInformUsers()["sha-aes"]
	r := e2eInformReceiver(t, 5, u.user)
	s := newInformServer(t, r)
	out, err := snmpinform(t, s, append(append([]string(nil), u.args...), "-e", "80001f88046f746865722d656e67696e65", "-Z", "5,100")...)
	require.Error(t, err, out)
	assert.Equal(t, uint32(3), r.local.unknownEngineIDs.Load(), "a Report to each of the three attempts")
	rejected := s.rejected()
	assert.Len(t, rejected, 3)
	for _, e := range rejected {
		assert.True(t, errors.Is(e, ErrUnknownEngineID), fmt.Sprint(e))
	}
}
