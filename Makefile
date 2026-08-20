BINARY  := fastrecon
PKG     := github.com/JoshuaMart/FastRecon
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build test lint fmt vet cover static docker clean

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

# The distroless runtime image has no dynamic loader, so a dependency that
# dlopens libc would produce a binary that cannot start in it.
static:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/$(BINARY)-static ./cmd/fastrecon
	@file /tmp/$(BINARY)-static | grep -q "statically linked" \
		&& echo "static: ok" \
		|| { file /tmp/$(BINARY)-static; echo "static: FAILED"; exit 1; }

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(BINARY):$(VERSION) .

clean:
	rm -rf bin coverage.out
