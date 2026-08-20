BINARY  := fastrecon
PKG     := github.com/JoshuaMart/FastRecon
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build test lint fmt vet cover docker clean

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/fastrecon

test:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(BINARY):$(VERSION) .

clean:
	rm -rf bin coverage.out
