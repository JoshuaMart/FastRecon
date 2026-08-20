# syntax=docker/dockerfile:1

# Build stage. Nothing here may take a credential: build args are recorded in
# the image history, and this image is built by CI and published.
# The builder runs natively on the build machine and cross-compiles, which is
# far faster than emulating the target platform.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=""
ARG DATE=""

# Provided by buildx. The runtime stage below resolves to the same platform,
# so the image manifest and the binary inside it can never disagree.
ARG TARGETOS
ARG TARGETARCH

# Static build: no libc at runtime, so the final image can be distroless.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w \
      -X github.com/JoshuaMart/FastRecon/internal/version.Version=${VERSION} \
      -X github.com/JoshuaMart/FastRecon/internal/version.Commit=${COMMIT} \
      -X github.com/JoshuaMart/FastRecon/internal/version.Date=${DATE}" \
    -o /out/fastrecon ./cmd/fastrecon

# Runtime stage: static distroless, non-root, no shell, no package manager.
# The binary needs CA certificates to reach the enumeration sources; the
# static image ships them.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/fastrecon /usr/local/bin/fastrecon

USER nonroot:nonroot

# Configuration arrives as environment variables and arguments, so the same
# image serves a local `docker run` and a serverless job definition.
ENTRYPOINT ["/usr/local/bin/fastrecon"]
