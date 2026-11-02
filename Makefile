BIN     := ambitd
BIN2    := mcp-interpose
BIN3    := ambit-replay
BIN4    := agentdojo-convert
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

EXE := $(if $(filter Windows_NT,$(OS)),.exe,)

.PHONY: all build test race vet fmt check clean cross smoke smoke-windows fixtures replay fuzz lint vuln

all: check build

build:
	go build $(LDFLAGS) -o bin/$(BIN)$(EXE) ./cmd/ambitd
	go build $(LDFLAGS) -o bin/$(BIN2)$(EXE) ./cmd/mcp-interpose
	go build $(LDFLAGS) -o bin/$(BIN3)$(EXE) ./cmd/ambit-replay
	go build $(LDFLAGS) -o bin/$(BIN4)$(EXE) ./cmd/agentdojo-convert

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# staticcheck, pinned so a new release cannot fail CI on code nobody changed. `go run pkg@version`
# builds it with whatever go is first on PATH, which can be older than go.mod's floor and then cannot
# load the module; GOTOOLCHAIN makes it build with the toolchain this module selects.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@2025.1.1
TOOLCHAIN   := $(shell go env GOVERSION)

lint:
	GOTOOLCHAIN=$(TOOLCHAIN) go run $(STATICCHECK) ./...

# govulncheck reports known vulnerabilities in the code paths ambit actually calls, in its modules
# and in the Go standard library. It needs vuln.go.dev, so it fails offline rather than passing.
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.1.4

vuln:
	GOTOOLCHAIN=$(TOOLCHAIN) go run $(GOVULNCHECK) ./...

check: vet race
	@gofmt -l . | grep . && { echo "gofmt needed (see above)"; exit 1; } || echo "gofmt clean"

cross:
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN)-darwin-arm64 ./cmd/ambitd
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN)-darwin-amd64 ./cmd/ambitd
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN)-linux-arm64  ./cmd/ambitd
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN)-linux-amd64  ./cmd/ambitd
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN2)-darwin-arm64 ./cmd/mcp-interpose
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN2)-darwin-amd64 ./cmd/mcp-interpose
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN2)-linux-arm64  ./cmd/mcp-interpose
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN2)-linux-amd64  ./cmd/mcp-interpose
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN)-windows-amd64.exe  ./cmd/ambitd
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN)-windows-arm64.exe  ./cmd/ambitd
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN2)-windows-amd64.exe ./cmd/mcp-interpose
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN2)-windows-arm64.exe ./cmd/mcp-interpose

smoke: build
	./scripts/smoke.sh
	./scripts/interpose-smoke.sh

smoke-windows: build
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/smoke.ps1 -Bin bin/$(BIN)$(EXE)

fixtures: build
	./scripts/gen-fixtures.sh

clean:
	rm -rf bin

replay: build
	./bin/$(BIN3)$(EXE) $(ARGS) testdata/replay

# FUZZTIME is a count of inputs per target ("100000x"), not a duration. With a duration, go test fails
# the target with "context deadline exceeded" when the time runs out while a worker is still on a slow
# input, as the targets that write files can be; that is a failure with no failing input. A count has no
# deadline. A duration ("30s") still works, with that risk.
FUZZTIME ?= 100000x
FUZZ_TARGETS := \
	./internal/redact:FuzzRedactIsAFixedPoint \
	./internal/redact:FuzzRedactStripsADelimitedSecret \
	./internal/redact:FuzzPrefilterChangesNothing \
	./internal/features:FuzzPerWordExtractionChangesNothing \
	./internal/features:FuzzDestinationsAreExtractedDomains \
	./internal/classify:FuzzBashWrappingNeverLowersTheClass \
	./internal/classify:FuzzTokenScannerSplitsAsTokenizeDid \
	./internal/mcp:FuzzRelayIsByteExact \
	./internal/mcp:FuzzCanonicalJSONIsAFixedPoint \
	./internal/mcp:FuzzParseNeverPanics \
	./internal/sse:FuzzReaderNeverPanics \
	./internal/collector:FuzzSandboxDenialsStayClean \
	./internal/collector:FuzzNoContentCrossesToTheSIEMInCleartext \
	./internal/collector:FuzzHandleArbitraryHookJSON \
	./internal/collector:FuzzDeniedHostIsAHostOrNothing \
	./internal/egress:FuzzLoadAnyFile \
	./internal/otlp:FuzzDecodeNeverPanics \
	./internal/toolscan:FuzzScanFieldsNeverPanics \
	./internal/labelsuggest:FuzzSuggestionsNeverRelaxWithoutTheHintAndANameThatReads \
	./internal/baseline:FuzzFileNameStaysInTheDirectory \
	./internal/baseline:FuzzObserveWithAnyRecordOnDisk \
	./internal/config:FuzzLoadAnyFile \
	./internal/doctor:FuzzLoadMCPAnyFile \
	./internal/doctor:FuzzMCPFindingsNeverRepeatASecret \
	./internal/m0report:FuzzBuildFromAnySpool

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		echo "== $$name ($(FUZZTIME))"; \
		go test $$pkg -run '^$$' -fuzz "^$$name\$$" -fuzztime $(FUZZTIME) -fuzzminimizetime 10s || exit 1; \
	done
