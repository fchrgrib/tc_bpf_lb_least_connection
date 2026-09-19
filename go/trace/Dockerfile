# active-conn image: counts active TCP connections per pod IP via
# tracepoint/sock/inet_sock_set_state. This is the signal source that feeds
# fentry -> map_sync -> hash_map -> the least-connection selector.
#
# Built from the REPO ROOT:
#   docker build -f go/trace/Dockerfile -t <registry>/active-conn:latest .
#
# Needs clang + libbpf headers at build time for bpf2go (go generate).
# Runtime is static Go: no shell tooling, no iproute2, no bpffs mount required.
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libelf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# libbpf helper/core headers (tracepoint.bpf.c includes <bpf/bpf_tracing.h> etc.)
COPY libbpf/src/*.h /usr/include/bpf/
# BPF source + headers referenced by go:generate (../../ from go/trace)
COPY bpf/trace/ /src/bpf/trace/
COPY vmlinux/ /src/vmlinux/
COPY libbpf/include/ /src/libbpf/include/
# Go module root
WORKDIR /src/go
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/trace/ ./trace/
RUN cd trace && go generate && cd .. && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /active-conn ./trace

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /active-conn .
ENTRYPOINT ["/app/active-conn"]
