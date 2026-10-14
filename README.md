gosnmp
======

> [!NOTE]
> This is Netdata's fork of [gosnmp/gosnmp](https://github.com/gosnmp/gosnmp). It started from upstream
> `v1.45.0` (commit `d2a3184`) with full history, and is maintained by Netdata for the
> [Netdata Agent](https://github.com/netdata/netdata). It is not affiliated with or endorsed by the upstream
> project. The original code remains under its BSD-style license; see [LICENSE](LICENSE).

[![Build Status](https://github.com/netdata/gosnmp/actions/workflows/ci.yml/badge.svg)](https://github.com/netdata/gosnmp/actions/workflows/ci.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/netdata/gosnmp)](https://pkg.go.dev/github.com/netdata/gosnmp)

GoSNMP is an SNMP client library written in Go. It sends Get, GetNext, GetBulk and Set requests, walks subtrees, and
decodes received traps and informs, over __SNMPv1__, __SNMPv2c__ and __SNMPv3__ (the User-based Security Model), on IPv4
and IPv6, over UDP or TCP. Tests run on Linux (amd64 and 386), macOS and Windows, and CI builds for every platform the
Netdata Agent ships its Go plugins on.

# About

**gosnmp** was started by [Andreas Louca](https://github.com/alouca), then
completely rewritten by [Sonia Hamilton](https://github.com/soniah)
(2012-2020), and then transferred to the community at
[gosnmp/gosnmp](https://github.com/gosnmp/gosnmp).

For support and help with this fork, open an [issue](https://github.com/netdata/gosnmp/issues).

# Overview

GoSNMP has the following SNMP functions:

* **Get** and **GetNext** - one or more OIDs, up to `MaxOids` (60 by default).
* **GetBulk** (SNMPv2c and SNMPv3 only).
* **Walk** and **WalkAll** - retrieve a subtree of values using GETNEXT.
* **BulkWalk** and **BulkWalkAll** - retrieve a subtree of values using GETBULK (SNMPv2c and SNMPv3 only). The `All`
  variants return the values in a slice rather than passing each to a callback.
* **Set** - Integer, OctetString, Gauge32, IPAddress, ObjectIdentifier, Counter32, Counter64, Null, TimeTicks,
  Uinteger32, OpaqueFloat and OpaqueDouble values.
* **UnmarshalTrap** - decodes received traps and informs; the library does not listen for them.
* **SnmpEncodePacket** and **SnmpDecodePacket** - encode and decode messages for other transports and for tests.

GoSNMP has the following **helper** functions:

* **ToBigInt** - treat returned integer values as `*big.Int`
* **Partition** - facilitates dividing up large slices of OIDs

The [package documentation](https://pkg.go.dev/github.com/netdata/gosnmp) describes request attempts and timeouts,
hooks, SNMPv3 engine discovery and Reports, the Go type of each value type, and how messages are decoded.

## Logging

A client writes debug output only when its `Logger` is set to `gosnmp.NewLogger(l)`, where `l` has the `Print` and
`Printf` methods of the standard `*log.Logger` (`gosnmp.LoggerInterface`):

```go
g := &gosnmp.GoSNMP{
    ...
    Logger: gosnmp.NewLogger(log.New(os.Stdout, "", 0)),
}
```

The encoder and decoder write nothing to the `Logger`, and without a logger the request path does not format log
messages.

# Installation

```shell
go get github.com/netdata/gosnmp
```

# Documentation

https://pkg.go.dev/github.com/netdata/gosnmp

# Usage

Here is the body of `examples/example/main.go`, which imports the package as `g`:

```go
// Default is a pointer to a GoSNMP struct that contains sensible defaults
// eg port 161, community public, etc
g.Default.Target = "192.168.1.10"
err := g.Default.Connect()
if err != nil {
    log.Fatalf("Connect() err: %v", err)
}
defer g.Default.Close()

oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
result, err2 := g.Default.Get(oids) // Get accepts up to MaxOids OIDs (60 by default)
if err2 != nil {
    log.Fatalf("Get() err: %v", err2)
}

for i, variable := range result.Variables {
    fmt.Printf("%d: oid: %s ", i, variable.Name)

    // The Go type of a Value depends on its Type (see the package
    // documentation). You could do a type switch...
    switch variable.Type {
    case g.OctetString:
        fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
    default:
        // ... or often you're just interested in numeric values.
        // ToBigInt() will return the Value as a BigInt, for plugging
        // into your calculations.
        fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
    }
}
```

Run against an agent, it prints, for example:

```shell
% go run ./examples/example
0: oid: .1.3.6.1.2.1.1.4.0 string: Administrator
1: oid: .1.3.6.1.2.1.1.7.0 number: 104
```

More examples, each a program under `examples/`:

* `example2` - a client built as a `GoSNMP` literal rather than `g.Default`, with verbose logging and hooks that time
  each request
* `example3` - SNMPv3 at authPriv
* `example4` - Set
* `walkexample` and `walktcpexample` - BulkWalk over UDP and TCP, where the agent may close the connection between
  walks
* `Hex-String` - OctetString values that are not text, printed octet by octet in decimal
* `linux_vrf` - a socket bound to a Linux VRF device with `Control`
* `logger` - logging turned on and off

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
[golangci-lint](https://golangci-lint.run/)). If you change an enum or
`interface.go`, run `make generate` and commit the regenerated files.

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
export GOSNMP_TARGET_IPV6='2001:db8::1'
export GOSNMP_PORT_IPV6=161
go test -v -tags end2end ./...
```

`go test ./...` runs all unit tests, including the public API consistency tests in
`gosnmp_api_test.go`. The end-to-end integration tests in `generic_e2e_test.go` need a
running SNMP agent and the environment variables above, so they only build with the
`end2end` build tag.

The generic end-to-end integration test `generic_e2e_test.go` should
work against any SNMP MIB-2 compliant host (e.g. a router, NAS box, printer).
Its SNMPv3 test logs in as each user of `testdata/snmp_users.txt`, one per
authentication and privacy protocol pair; `snmp_users.sh` creates them in
net-snmp's `snmpd.conf`, as CI and the Docker image do.

The `netsnmp` module compares gosnmp with net-snmp: packet encodings and the SNMPv3
User-based Security Model (localized keys, encryption and authentication for every
protocol pair). By default it replays the recordings in `netsnmp/testdata`. With libsnmp
installed (`libsnmp-dev`), `make -C netsnmp test_netsnmp` compares with the library
directly, and `go test -tags netsnmp -rec ./...` in `netsnmp/` re-records them.

The `*_string.go` files and the `go.uber.org/mock` mocks in `mocks/` are generated by
`go generate ./...`, which runs the `stringer` and `mockgen` versions pinned in `tools/go.mod`.

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

To measure the password-to-key cache, compare the cached and uncached key derivation benchmarks:

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
