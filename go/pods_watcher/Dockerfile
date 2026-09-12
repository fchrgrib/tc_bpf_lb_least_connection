# Small + fast-push tracker image (~15MB instead of ~120MB on ubuntu).
# Static build (no CGO needed: cilium/ebpf + client-go are pure Go), stripped.
FROM golang:1.24.3 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o pod-ip-tracker .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/pod-ip-tracker .
CMD ["/app/pod-ip-tracker"]
