# tc-loader image: attaches the TC eBPF least-connection program on each node.
# Built from the REPO ROOT: docker build -f go/tc/Dockerfile -t <registry>/tc-lb-loader:latest .
#
# Needs clang + libbpf headers at build time for bpf2go (go generate).
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libelf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# libbpf helper/core headers (tc.bpf.c includes <bpf/bpf_helpers.h> etc.)
COPY libbpf/src/*.h /usr/include/bpf/
# BPF source + headers referenced by go:generate (../../ from go/tc)
COPY bpf/tc/ /src/bpf/tc/
COPY vmlinux/ /src/vmlinux/
COPY libbpf/include/ /src/libbpf/include/
# Go module root
WORKDIR /src/go
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/tc/ ./tc/
RUN cd tc && go generate && cd .. && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /tc-loader ./tc

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /tc-loader /app/tc-loader
COPY go/tc/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/tc-loader /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
