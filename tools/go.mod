// Code generators used by go:generate, kept out of the library module so
// their dependencies do not reach modules that import gosnmp.
module github.com/netdata/gosnmp/tools

go 1.27.0

tool (
	go.uber.org/mock/mockgen
	golang.org/x/tools/cmd/stringer
)

require (
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
)
