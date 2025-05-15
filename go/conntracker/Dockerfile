FROM golang:1.24.3 as builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o conntracker

FROM ubuntu:22.04
WORKDIR /app
COPY --from=builder /app/conntracker .
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
CMD ["/app/conntracker"]