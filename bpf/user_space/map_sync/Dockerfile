# map_sync image: cross-node hash_map sync over mTLS gRPC.
# Built from the REPO ROOT:
#   docker build -f bpf/user_space/map_sync/Dockerfile -t <registry>/map-sync:latest .
#
# Needs clang + libbpf headers at build time because the fentry BPF program is
# compiled via bpf2go (go generate). Runtime needs no compiler/shell tooling.
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libelf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# libbpf helper/core headers (fentry.c includes <bpf/bpf_core_read.h> etc.)
COPY lib/libbpf/src/*.h /usr/include/bpf/
# fentry BPF source, referenced by go:generate as ../../data_plane/fentry
COPY bpf/data_plane/fentry/ /src/bpf/data_plane/fentry/
# vmlinux BTF header for the -I path in go:generate
COPY lib/vmlinux.h/include/x86/ /src/lib/vmlinux.h/include/x86/
# Go module root
WORKDIR /src/bpf/user_space
COPY bpf/user_space/go.mod bpf/user_space/go.sum ./
RUN go mod download
COPY bpf/user_space/map_sync/ ./map_sync/
RUN cd map_sync && go generate && cd .. && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /map-sync ./map_sync

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /map-sync .
ENTRYPOINT ["/app/map-sync"]
