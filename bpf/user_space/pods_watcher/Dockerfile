# Small + fast-push tracker image (~15MB instead of ~120MB on ubuntu).
# Static build (no CGO needed: cilium/ebpf + client-go are pure Go), stripped.
# Built from the bpf/user_space module root:
#   docker build -f bpf/user_space/pods_watcher/Dockerfile -t <registry>/pod-ip-tracker:latest bpf/user_space
FROM golang:1.25 AS builder
WORKDIR /app
# Copy module files + this package only
COPY go.mod go.sum ./
RUN go mod download
COPY pods_watcher/ ./pods_watcher/
# Build from subdirectory
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o pod-ip-tracker ./pods_watcher

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/pod-ip-tracker .
CMD ["/app/pod-ip-tracker"]
