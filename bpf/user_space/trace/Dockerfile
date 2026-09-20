# active-conn image: counts active TCP connections per pod IP via
# tracepoint/sock/inet_sock_set_state. This is the signal source that feeds
# map_sync -> remote_counts -> the least-connection selector.
#
# Built from the REPO ROOT:
#   docker build -f bpf/user_space/trace/Dockerfile -t <registry>/active-conn:latest .
#
# Needs clang + libbpf headers at build time for bpf2go (go generate).
# Runtime is static Go: no shell tooling, no iproute2, no bpffs mount required.
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libelf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# libbpf helper/core headers (tracepoint.bpf.c includes <bpf/bpf_tracing.h> etc.)
COPY lib/libbpf/src/*.h /usr/include/bpf/
# BPF source + headers referenced by go:generate (../../data_plane from bpf/user_space/trace)
COPY bpf/data_plane/trace/ /src/bpf/data_plane/trace/
COPY lib/vmlinux.h/include/x86/ /src/lib/vmlinux.h/include/x86/
COPY lib/libbpf/include/ /src/lib/libbpf/include/
# Go module root
WORKDIR /src/bpf/user_space
COPY bpf/user_space/go.mod bpf/user_space/go.sum ./
RUN go mod download
COPY bpf/user_space/trace/ ./trace/
RUN cd trace && go generate && cd .. && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /active-conn ./trace

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /active-conn .
ENTRYPOINT ["/app/active-conn"]
