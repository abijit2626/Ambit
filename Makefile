BIN     := ambitd
BIN2    := mcp-interpose
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build test race vet fmt check clean cross smoke

all: check build

build:
	go build $(LDFLAGS) -o bin/$(BIN) ./cmd/ambitd
	go build $(LDFLAGS) -o bin/$(BIN2) ./cmd/mcp-interpose

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

# ambitd ships to developer endpoints on macOS, Linux and WSL2. Static binaries
# mean no runtime to install and nothing to keep in sync with a system Python.
cross:
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN)-darwin-arm64 ./cmd/ambitd
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN)-darwin-amd64 ./cmd/ambitd
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN)-linux-arm64  ./cmd/ambitd
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN)-linux-amd64  ./cmd/ambitd
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN2)-darwin-arm64 ./cmd/mcp-interpose
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN2)-darwin-amd64 ./cmd/mcp-interpose
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BIN2)-linux-arm64  ./cmd/mcp-interpose
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BIN2)-linux-amd64  ./cmd/mcp-interpose

smoke: build
	./scripts/smoke.sh
	./scripts/interpose-smoke.sh

clean:
	rm -rf bin
