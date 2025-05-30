# Build stage
FROM golang:alpine3.21 as builder

RUN apk add make gcc g++ zlib zlib-dev git wget

WORKDIR /app
COPY main.go .
RUN go build main.go

RUN git clone https://github.com/blechschmidt/massdns && \
    cd massdns && \
    make

RUN wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt && \
    wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/d3mondev/puredns/v2@latest

# Run stage
FROM alpine:latest

# Create app directory
WORKDIR /app
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/puredns /usr/local/bin/puredns
COPY --from=builder /app/massdns/bin/massdns /usr/local/bin/massdns
COPY --from=builder /app/resolvers.txt /app/resolvers.txt
COPY --from=builder /app/resolvers-trusted.txt /app/resolvers-trusted.txt
COPY --from=builder /app/main /app/main
COPY subfinder.yaml .

# Run the binary
CMD ["sh", "-c", "./main"]
