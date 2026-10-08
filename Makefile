BIN     := ambitd
BIN2    := mcp-interpose
BIN3    := ambit-replay
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

# Go does not add .exe when -o names a file, and Windows will not run an executable
# without one, so do it here when building on Windows (GNU make sets OS=Windows_NT).
EXE := $(if $(filter Windows_NT,$(OS)),.exe,)

.PHONY: all build test race vet fmt check clean cross smoke smoke-windows fixtures replay

all: check build

build:
	go build $(LDFLAGS) -o bin/$(BIN)$(EXE) ./cmd/ambitd
	go build $(LDFLAGS) -o bin/$(BIN2)$(EXE) ./cmd/mcp-interpose
	go build $(LDFLAGS) -o bin/$(BIN3)$(EXE) ./cmd/ambit-replay

test:
	go test ./...

# The race detector matters here: the hook path and the sink drain goroutine share
# state by design, and a data race in the collector would corrupt the audit trail.
race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet race
	@gofmt -l . | grep . && { echo "gofmt needed (see above)"; exit 1; } || echo "gofmt clean"

# ambitd ships to developer endpoints on macOS, Linux, WSL2 and native Windows. Static
# binaries mean no runtime to install and nothing to keep in sync with a system Python.
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

# The Windows form of smoke.sh. The interposer's end-to-end checks are Go tests
# (cmd/mcp-interpose/e2e_test.go), so `go test ./...` covers them on every platform.
smoke-windows: build
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/smoke.ps1 -Bin bin/$(BIN)$(EXE)

# Wazuh rule fixtures are generated from the real pipeline, never hand-edited: a
# fixture that has drifted from the schema tests nothing while looking like it tests
# everything. Depends on build so it can never be generated from stale binaries.
fixtures: build
	./scripts/gen-fixtures.sh

clean:
	rm -rf bin

# Replay the trajectory corpus through the real collector and print precision, recall, the
# confidence-floor sweep and Rule-of-Two saturation. Exits non-zero if any scenario's
# assertions fail. In-process against in-memory sinks: it never touches a running ambitd,
# the spool or the Wazuh sink. `go test ./...` runs the same corpus as a regression test.
# Pass extra flags with ARGS, e.g. `make replay ARGS="-v -min-confidence 0.9"`.
replay: build
	./bin/$(BIN3)$(EXE) $(ARGS) testdata/replay
