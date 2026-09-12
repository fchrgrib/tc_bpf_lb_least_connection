# tc-loader image: attaches the TC eBPF least-connection program on each node.
# Built from repo root: docker build -f bpf/tc/Dockerfile -t <registry>/tc-lb-loader:latest .
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm make gcc libelf-dev zlib1g-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Leverage vendored libbpf/bpftool submodules already in the repo.
COPY libbpf/ libbpf/
COPY bpftool/ bpftool/
COPY blazesym/ blazesym/
COPY vmlinux/ vmlinux/
COPY vmlinux.h/ vmlinux.h/
COPY bpf/tc/ bpf/tc/
WORKDIR /src/bpf/tc
RUN make -j"$(nproc)"

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /src/bpf/tc/tc /app/tc
COPY bpf/tc/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/tc /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
