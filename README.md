gosnmp
======

> [!NOTE]
> This is Netdata's fork of [gosnmp/gosnmp](https://github.com/gosnmp/gosnmp). It started from upstream
> `v1.45.0` (commit `d2a3184`) with full history, and is maintained by Netdata for the
> [Netdata Agent](https://github.com/netdata/netdata). It is not affiliated with or endorsed by the upstream
> project. The original code remains under its BSD-style license; see [LICENSE](LICENSE).

[![Build Status](https://github.com/netdata/gosnmp/actions/workflows/ci.yml/badge.svg)](https://github.com/netdata/gosnmp/actions/workflows/ci.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/netdata/gosnmp)](https://pkg.go.dev/github.com/netdata/gosnmp)

GoSNMP is an SNMP client library written in Go. It sends Get requests, walks subtrees with GetNext or GetBulk requests,
and decodes received traps and informs, over __SNMPv1__, __SNMPv2c__ and __SNMPv3__ (the User-based Security Model), on
IPv4 and IPv6, over UDP. Tests run on Linux (amd64 and 386), macOS and Windows, and CI builds for every platform the Netdata
Agent ships its Go plugins on.

# About

**gosnmp** was started by [Andreas Louca](https://github.com/alouca), then
completely rewritten by [Sonia Hamilton](https://github.com/soniah)
(2012-2020), and then transferred to the community at
[gosnmp/gosnmp](https://github.com/gosnmp/gosnmp).

For support and help with this fork, open an [issue](https://github.com/netdata/gosnmp/issues).

# Overview

A client (`NewClient`) talks to one agent:

* **NewClient** - makes a client of a `Config`, which it checks, with defaults for a zero port (161), timeout (1 s) and
  `MaxOids` (60).
* **Connect** and **Close** - open and close the client's UDP socket; Close may end a running request.
* **Get** - one or more OIDs, up to `MaxOids`; an answer with an error-status fails it with a `*StatusError`.
* **WalkAll** - retrieve a subtree of values using GETNEXT, and how the walk ended (`WalkEnd`).
* **BulkWalkAll** - retrieve a subtree of values using GETBULK (SNMPv2c and SNMPv3), with the walk's max-repetitions,
  and how the walk ended.
* **ForgetEngine** - makes an SNMPv3 client discover the agent's engine again, after a request fails with
  `ErrUnknownEngineID`.
* **EncodeMessage** and **DecodeMessage** - encode and decode messages for other transports and for tests.

A receiver (`NewReceiver`) decodes the notifications a manager receives:

* **Receive** - decodes a received trap or inform with the receiver's SNMPv3 users, by engine ID, and returns the answer
  the RFCs give, for the caller to send: the Response to an inform, as its authoritative engine, and the Reports a
  sender discovers its engine ID and time by. The library does not listen for notifications or send answers.

Connect and the requests take a context, which bounds that call. The library writes no log or other output and never
exits the process: every function reports through its results and errors. A call that fails returns no result with
its error, but a walk, which also returns the values it collected before the error. Each error of an incoming message
matches one exported category (`errors.Is`), named after the RFC counter that counts it but for `ErrUnmatchedReply`, a
reply that does not answer the request.

Each varbind holds a `Value` of one Go type per SMI type (an Integer is an `int32`, a Counter32 a `uint32`, an IpAddress
a `netip.Addr`, ...), read through its accessor (`Int32`, `Uint32`, `IP`, ...) and built by its constructor
(`IntegerValue`, `Counter32Value`, ...); `String` prints it as `%v` printed the untyped value.

The [package documentation](https://pkg.go.dev/github.com/netdata/gosnmp) describes the client, walks, values, errors
and the receiver, then the protocol rules: request attempts and timeouts, SNMPv3 engine discovery and Reports, keys,
and how messages are encoded and decoded.

# Installation

```shell
go get github.com/netdata/gosnmp
```

# Documentation

https://pkg.go.dev/github.com/netdata/gosnmp

# Usage

A client of an SNMPv2c agent gets two objects (`ExampleNewClient`):

```go
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
```

A receiver decodes each datagram the caller reads; the caller checks the PDU type and the community and sends the
answer, if any, Reports at a rate it limits (`reportAllowed`; all of it in `ExampleReceiver_Receive`):

```go
notification, response, err := receiver.Receive(buf[:n])
if err != nil {
	// A rejected SNMPv3 message may get a Report that lets its sender
	// discover the engine or its time: the caller decides whether to
	// send it, and how often.
	if response != nil && reportAllowed() {
		_, _ = conn.WriteToUDP(response, from)
	}
	log.Printf("rejected a datagram from %v: %v", from, err)
	continue
}
```

`example_test.go` holds the examples, shown with the API on [pkg.go.dev](https://pkg.go.dev/github.com/netdata/gosnmp):
a Get and the errors of a failed one, an SNMPv3 client, a walk and how it ended, values, and a receiver.

# MIB Parser

GoSNMP does not parse MIBs; https://github.com/sleepinggenius2/gosmi does.

# Contributions

Contributions are welcome, especially ones that have packet captures (see
below).

If you've never contributed to a Go project before, here is an example workflow.

1. [fork this repo on the GitHub webpage](https://github.com/netdata/gosnmp/fork)
1. `git clone https://github.com/netdata/gosnmp.git`
1. `cd gosnmp`
1. `git remote rename origin upstream`
1. `git remote add origin git@github.com:<your-github-username>/gosnmp.git`
1. `git checkout -b development`
1. `git push -u origin development` (setup where you push to, check it works)

Before opening a pull request, run `make test` and `make lint` (which needs
[golangci-lint](https://golangci-lint.run/)). If you change an enum, run
`make generate` and commit the regenerated files.

# Packet Captures

Create your packet captures in the following way:

Expected output, obtained via an **snmp** command. For example:

```shell
% snmpget -On -v2c -c public 192.0.2.17 1.3.6.1.2.1.1.7.0 \
  1.3.6.1.2.1.2.2.1.2.6 1.3.6.1.2.1.2.2.1.5.3
.1.3.6.1.2.1.1.7.0 = INTEGER: 78
.1.3.6.1.2.1.2.2.1.2.6 = STRING: GigabitEthernet0
.1.3.6.1.2.1.2.2.1.5.3 = Gauge32: 4294967295
```

A packet capture, obtained while running the snmpget. For example:

```shell
sudo tcpdump -s 0 -i eth0 -w foo.pcap host 192.0.2.17 and port 161
```

# Bugs

Please create an [issue](https://github.com/netdata/gosnmp/issues) with packet captures (upload them to Google Drive,
Dropbox, or similar) that show the bug, for example a value type GoSNMP does not decode; the package documentation
lists the value types it decodes and encodes. If possible, please include 2 or 3 examples.

Rane's document [SNMP: Simple? Network Management Protocol](https://www.ranecommercial.com/legacy/note161.html) is a
good introduction to the SNMP protocol.

# Running the Tests

`make test` runs the unit tests of both modules.

The end-to-end tests need an SNMP agent. To run them against net-snmp in Docker:
```shell
docker build -t netdata/gosnmp:latest .
docker run -it netdata/gosnmp:latest
```

or, against another agent:

```shell
export GOSNMP_TARGET=192.0.2.1
export GOSNMP_PORT=161
go test -v -tags end2end ./...
```

`go test ./...` runs all unit tests, including the public API consistency tests in
`gosnmp_api_test.go`. The end-to-end tests only build with the `end2end` build tag and run when
`GOSNMP_TARGET` is set: those in `generic_e2e_test.go` against the SNMP agent the environment
variables above name, those in `receiver_e2e_test.go` with net-snmp's `snmpinform` on the `PATH`,
which the Docker image and CI install.

The generic end-to-end integration test `generic_e2e_test.go` should
work against any SNMP MIB-2 compliant host (e.g. a router, NAS box, printer).
Its SNMPv3 test logs in as each user of `testdata/snmp_users.txt`, one per
authentication and privacy protocol pair; `snmp_users.sh` creates them in
net-snmp's `snmpd.conf`, as CI and the Docker image do.

The `netsnmp` module compares gosnmp with net-snmp: message encodings and the SNMPv3
User-based Security Model (localized keys, encryption and authentication for every
protocol pair). By default it replays the recordings in `netsnmp/testdata`. With libsnmp
installed (`libsnmp-dev`), `make -C netsnmp test_netsnmp` compares with the library
directly, and `go test -tags netsnmp -rec ./...` in `netsnmp/` re-records them.

The `*_string.go` files are generated by `go generate ./...`, which runs the `stringer`
version pinned in `tools/go.mod`.

To profile cpu usage:

```shell
go test -cpuprofile cpu.out
go test -c
go tool pprof gosnmp.test cpu.out
```

To profile memory usage:

```shell
go test -memprofile mem.out
go test -c
go tool pprof gosnmp.test mem.out
```

To check test coverage:

```shell
go test -coverprofile cover.out ./...
go tool cover -html cover.out
```

To measure key localization with the password-to-key cache filled:

```shell
go test -run '^$' -bench 'BenchmarkUSMKeys'
```


# License

Parts of the code are taken from the Golang project (specifically some
functions for unmarshaling BER responses), which are under the same terms
and conditions as the Go language. The rest of the code is under a BSD
license.

See the LICENSE file for more details.

The remaining code is Copyright 2012 the GoSNMP Authors - see
AUTHORS.md for a list of authors.
