// Copyright 2026 Netdata Inc. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/netdata/gosnmp"
)

// A client of an SNMPv2c agent gets two objects. The examples that need an
// agent use the documentation address 192.0.2.1.
func ExampleNewClient() {
	client, err := gosnmp.NewClient(gosnmp.Config{
		Target:    "192.0.2.1",
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   2,
	})
	if err != nil {
		log.Fatal(err) // the error names the field NewClient rejects
	}
	// The context bounds each call it is given: here Connect and the Get.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	result, err := client.Get(ctx, []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}) // sysContact, sysServices
	if err != nil {
		log.Fatal(err)
	}
	for _, vb := range result.VarBinds {
		fmt.Printf("%s = %v: %v\n", vb.Name, vb.Value.Type(), vb.Value)
	}
}

// An SNMPv3 client at authPriv: the configuration holds the user's
// passphrases; the client discovers the agent's engine at its first request
// and localizes the keys to it.
func ExampleNewClient_snmpv3() {
	client, err := gosnmp.NewClient(gosnmp.Config{
		Target:        "192.0.2.1",
		Version:       gosnmp.Version3,
		SecurityLevel: gosnmp.AuthPriv,
		User: gosnmp.User{
			Name:           "monitor",
			AuthProtocol:   gosnmp.SHA256,
			AuthPassphrase: "authentication passphrase",
			PrivProtocol:   gosnmp.AES,
			PrivPassphrase: "privacy passphrase",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if err = client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	result, err := client.Get(ctx, []string{"1.3.6.1.2.1.1.5.0"}) // sysName
	if errors.Is(err, gosnmp.ErrUnknownEngineID) {
		// The agent's engine ID changed: forget the engine and ask again.
		client.ForgetEngine()
		result, err = client.Get(ctx, []string{"1.3.6.1.2.1.1.5.0"})
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.VarBinds[0].Value)
}

// A failed request returns no message: its error tells whether the agent
// answered, and how.
func ExampleClient_Get() {
	client, err := gosnmp.NewClient(gosnmp.Config{Target: "192.0.2.1", Community: "public", Version: gosnmp.Version2c})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if err = client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	result, err := client.Get(ctx, []string{"1.3.6.1.2.1.1.3.0"}) // sysUpTime
	var status *gosnmp.StatusError
	switch {
	case err == nil:
		uptime, _ := result.VarBinds[0].Value.Uint32()
		fmt.Println("uptime:", time.Duration(uptime)*10*time.Millisecond)
	case errors.As(err, &status):
		// A Response with an error-status: the agent answered.
		fmt.Printf("the agent answered %v for varbind %d\n", status.Status, status.Index)
	case errors.Is(err, gosnmp.ErrAnswered):
		// An SNMPv3 Report, whose counter's category the error matches.
		fmt.Println("the agent answered:", err)
	default:
		// No answer: a timeout, the context, a transport error.
		fmt.Println("no answer:", err)
	}
}

// A walk returns the subtree's values and how it ended; a walk that fails
// returns the values before its error.
func ExampleClient_BulkWalkAll() {
	client, err := gosnmp.NewClient(gosnmp.Config{Target: "192.0.2.1", Community: "public", Version: gosnmp.Version2c})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if err = client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// The interfaces table, 10 objects per GETBULK request (0 sends 50).
	values, end, err := client.BulkWalkAll(ctx, "1.3.6.1.2.1.2.2", 10)
	for _, vb := range values {
		fmt.Printf("%s = %v\n", vb.Name, vb.Value)
	}
	if err != nil {
		log.Fatal(err)
	}
	// The end: past the subtree, an exception value such as EndOfMibView, or
	// the Get of a root that is a leaf, whose NoSuchObject or NoSuchInstance
	// tells an object the agent lacks from an instance it lacks.
	fmt.Printf("ended by %v at %s\n", end.Reason, end.VarBind.Name)
}

// Each SMI type has one Go type, read through its accessor.
func ExampleValue() {
	values := []gosnmp.Value{
		gosnmp.Counter32Value(4294967295),
		gosnmp.Counter64Value(18446744073709551615),
		gosnmp.OctetStringValue([]byte{0x00, 0x1b, 0x21}),
		gosnmp.NoSuchInstanceValue(),
	}
	for _, v := range values {
		if n, ok := v.Uint64(); ok {
			fmt.Printf("%v: %d\n", v.Type(), n)
		} else if b, ok := v.Bytes(); ok {
			fmt.Printf("%v: %x\n", v.Type(), b)
		} else {
			fmt.Printf("%v: no value (%v)\n", v.Type(), v)
		}
	}
	// Output:
	// Counter32: 4294967295
	// Counter64: 18446744073709551615
	// OctetString: 001b21
	// NoSuchInstance: no value (<nil>)
}

// A receiver decodes a datagram the caller read: here an SNMPv2c trap that a
// client encodes.
func ExampleReceiver() {
	sender, err := gosnmp.NewClient(gosnmp.Config{Version: gosnmp.Version2c, Community: "public"})
	if err != nil {
		log.Fatal(err)
	}
	datagram, err := sender.EncodeMessage(gosnmp.SNMPv2Trap, []gosnmp.VarBind{
		// sysUpTime.0, then snmpTrapOID.0: linkDown.
		{Name: ".1.3.6.1.2.1.1.3.0", Value: gosnmp.TimeTicksValue(12345)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Value: gosnmp.ObjectIdentifierValue(".1.3.6.1.6.3.1.1.5.3")},
	}, 0, 0)
	if err != nil {
		log.Fatal(err)
	}

	receiver, err := gosnmp.NewReceiver(gosnmp.ReceiverConfig{})
	if err != nil {
		log.Fatal(err)
	}
	notification, response, err := receiver.Receive(datagram)
	if err != nil {
		log.Fatal(err)
	}
	m := notification.Message
	fmt.Println(m.Version, m.PDUType, m.Community)
	for _, vb := range m.VarBinds {
		fmt.Printf("%s = %v: %v\n", vb.Name, vb.Value.Type(), vb.Value)
	}
	fmt.Println("response to send:", response != nil)
	// Output:
	// 2c SNMPv2Trap public
	// .1.3.6.1.2.1.1.3.0 = TimeTicks: 12345
	// .1.3.6.1.6.3.1.1.4.1.0 = ObjectIdentifier: .1.3.6.1.6.3.1.1.5.3
	// response to send: false
}

// A receiver's read loop: the caller owns the socket, checks what the library
// does not (the PDU type and the community) and sends the answers.
func ExampleReceiver_Receive() {
	// The receiver's own engine, the authoritative engine of the informs it
	// receives: the caller keeps the engine ID and the boots across restarts
	// and raises the boots at each.
	localEngineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x04, 't', 'r', 'a', 'p', 's'}
	user := gosnmp.User{
		Name:           "monitor",
		AuthProtocol:   gosnmp.SHA256,
		AuthPassphrase: "authentication passphrase",
		PrivProtocol:   gosnmp.AES,
		PrivPassphrase: "privacy passphrase",
	}
	receiver, err := gosnmp.NewReceiver(gosnmp.ReceiverConfig{
		EngineID:    localEngineID,
		EngineBoots: 1,
		// Informs name the receiver's engine; an agent's traps name its own.
		Users: []gosnmp.EngineUser{
			{EngineID: localEngineID, User: user},
			{EngineID: []byte{0x80, 0x00, 0x1f, 0x88, 0x04, 'a', 'g', 'e', 'n', 't'}, User: user},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 162})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		notification, response, err := receiver.Receive(buf[:n])
		if err != nil {
			// A rejected SNMPv3 message may get a Report that lets its sender
			// discover the engine or its time: the caller decides whether to
			// send it, and how often.
			if response != nil {
				_, _ = conn.WriteToUDP(response, from)
			}
			log.Printf("rejected a datagram from %v: %v", from, err)
			continue
		}
		m := &notification.Message
		switch m.PDUType {
		case gosnmp.Trap, gosnmp.SNMPv2Trap, gosnmp.InformRequest:
		default:
			continue
		}
		if m.Version != gosnmp.Version3 && m.Community != "public" {
			continue
		}
		if response != nil {
			_, _ = conn.WriteToUDP(response, from) // an inform's Response
		}
		// The values alias buf: use or copy them before the next read.
		for _, vb := range m.VarBinds {
			fmt.Printf("%v %s = %v\n", from, vb.Name, vb.Value)
		}
	}
}
