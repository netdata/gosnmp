GO_TOOL := go tool -modfile=$(CURDIR)/tools/go.mod

all: test lint

.PHONY: test
test:
	go test ./...
	cd netsnmp && go test ./...

# Needs a running SNMP agent; see "Running the Tests" in README.md.
.PHONY: test-e2e
test-e2e:
	go test -v -tags end2end ./...

.PHONY: generate
generate:
	go generate ./...

.PHONY: vulncheck
vulncheck:
	$(GO_TOOL) govulncheck ./...
	cd netsnmp && $(GO_TOOL) govulncheck ./...

.PHONY: lint
lint: check_license
	golangci-lint run --build-tags=end2end ./...
	cd netsnmp && golangci-lint run ./...

.PHONY: check_license
check_license:
	@echo ">> checking license header"
	@licRes=$$(for file in $$(find . -type f -iname '*.go' ! -path './vendor/*') ; do \
               awk 'NR<=3' $$file | grep -Eq "(Copyright [0-9]+ (The GoSNMP Authors|Netdata Inc\.)|generated|GENERATED)" || echo $$file; \
       done); \
       if [ -n "$${licRes}" ]; then \
               echo "license header checking failed:"; echo "$${licRes}"; \
               exit 1; \
       fi
