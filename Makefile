BIN     := ambitd
BIN2    := mcp-interpose
BIN3    := ambit-replay
BIN4    := agentdojo-convert
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

EXE := $(if $(filter Windows_NT,$(OS)),.exe,)

.PHONY: all build test race vet fmt check clean cross smoke smoke-windows fixtures replay

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
