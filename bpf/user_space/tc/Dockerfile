# tc-loader image: attaches the TC eBPF least-connection program on each node.
# Built from the REPO ROOT:
#   docker build -f bpf/user_space/tc/Dockerfile -t <registry>/tc-lb-loader:latest .
#
# Needs clang + libbpf headers at build time for bpf2go (go generate).
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libelf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# libbpf helper/core headers (tc.bpf.c includes <bpf/bpf_helpers.h> etc.)
COPY lib/libbpf/src/*.h /usr/include/bpf/
# BPF source + headers referenced by go:generate (../../data_plane from bpf/user_space/tc)
COPY bpf/data_plane/tc/ /src/bpf/data_plane/tc/
COPY lib/vmlinux.h/include/x86/ /src/lib/vmlinux.h/include/x86/
COPY lib/libbpf/include/ /src/lib/libbpf/include/
# Go module root
WORKDIR /src/bpf/user_space
COPY bpf/user_space/go.mod bpf/user_space/go.sum ./
RUN go mod download
COPY bpf/user_space/tc/ ./tc/
RUN cd tc && go generate && cd .. && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /tc-loader ./tc

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /tc-loader /app/tc-loader
RUN chmod +x /app/tc-loader
# Iface detection (LB_IFACE, default route, else first non-lo) lives in tc.go.
# iproute2 stays for the DaemonSet preStop hook (tc qdisc del).
ENTRYPOINT ["/app/tc-loader"]
