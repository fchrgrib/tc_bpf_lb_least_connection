# map_sync image: cross-node connection-count sync over mTLS gRPC.
# It only reads the pinned local hash_map and writes the pinned remote_counts
# map, so no BPF program is compiled or attached here -- the builder doesn't
# need clang/libbpf.
#
# Built from the REPO ROOT:
#   docker build -f bpf/user_space/map_sync/Dockerfile -t <registry>/map-sync:latest .
FROM golang:1.25 AS builder
WORKDIR /src/bpf/user_space
COPY bpf/user_space/go.mod bpf/user_space/go.sum ./
RUN go mod download
COPY bpf/user_space/map_sync/ ./map_sync/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /map-sync ./map_sync

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /map-sync .
ENTRYPOINT ["/app/map-sync"]
