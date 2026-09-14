.PHONY: all build clean bpf go help

# Unified build system for TC eBPF Load Balancer
# All build artifacts go to ./build/

help:
	@echo "TC eBPF Load Balancer - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build      - Build everything (BPF + Go)"
	@echo "  make bpf        - Build BPF programs only"
	@echo "  make go         - Build Go userspace only"
	@echo "  make clean      - Clean all build artifacts"
	@echo "  make help       - Show this help"
	@echo ""
	@echo "Build outputs go to ./build/"

all: build

build: bpf go
	@echo ""
	@echo "✓ Build complete. Artifacts in ./build/"

bpf:
	@echo "==> Building BPF programs..."
	@$(MAKE) -C bpf/tc
	@echo "✓ BPF build complete"

go:
	@echo "==> Building Go userspace..."
	@$(MAKE) -C go
	@echo "✓ Go build complete"

clean:
	@echo "==> Cleaning build artifacts..."
	@$(MAKE) -C bpf/tc clean
	@$(MAKE) -C go clean
	@rm -rf build/
	@echo "✓ Clean complete"

# Install to Kubernetes (convenience wrapper)
install:
	@./kube/build-and-install.sh

# Install with custom service
install-custom:
	@echo "Usage: SERVICE_NAME=<name> NAMESPACE=<ns> NODEPORT=<port> make install-custom"
	@echo "Example: SERVICE_NAME=my-api NAMESPACE=prod NODEPORT=31001 make install-custom"
