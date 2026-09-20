.PHONY: all build clean go help install install-all uninstall stop

# Unified build system for TC eBPF Load Balancer
# All build artifacts go to ./build/

help:
	@echo "TC eBPF Load Balancer - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build      - Build all Go components (includes BPF compilation)"
	@echo "  make go         - Build Go userspace only"
	@echo "  make install    - Install base LB to Kubernetes"
	@echo "  make uninstall  - Stop + remove base LB from Kubernetes (stop)"
	@echo "  make clean      - Clean all build artifacts"
	@echo "  make help       - Show this help"
	@echo ""
	@echo "Build outputs go to ./build/"

all: build

build: go
	@echo ""
	@echo "✓ Build complete. Artifacts in ./build/"

go:
	@echo "==> Building Go userspace..."
	@$(MAKE) -C bpf/user_space
	@echo "✓ Go build complete"

clean:
	@echo "==> Cleaning build artifacts..."
	@$(MAKE) -C bpf/user_space clean
	@rm -rf build/
	@echo "✓ Clean complete"

# Install to Kubernetes (convenience wrapper)
install:
	@./kube/build-and-install.sh

install-all:
	@./kube/build-and-install.sh --all

# Stop + remove from Kubernetes (convenience wrappers)
uninstall:
	@./kube/uninstall.sh

stop: uninstall

uninstall-all:
	@./kube/uninstall.sh --all

# Install with custom service
install-custom:
	@echo "Usage: SERVICE_NAME=<name> NAMESPACE=<ns> NODEPORT=<port> make install-custom"
	@echo "Example: SERVICE_NAME=my-api NAMESPACE=prod NODEPORT=31001 make install-custom"
