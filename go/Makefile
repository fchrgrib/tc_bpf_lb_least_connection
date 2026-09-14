.PHONY: all build clean pods-watcher map-sync

# Centralized build output
BUILD_ROOT := $(abspath ../build)
GO_BUILD := $(BUILD_ROOT)/go

all: build

build: pods-watcher map-sync

pods-watcher:
	@echo "Building pods-watcher..."
	@mkdir -p $(GO_BUILD)
	@go build -o $(GO_BUILD)/pods-watcher ./pods_watcher
	@echo "✓ Built: $(GO_BUILD)/pods-watcher"

map-sync:
	@echo "Building map-sync..."
	@mkdir -p $(GO_BUILD)
	@go build -o $(GO_BUILD)/map-sync ./map_sync
	@echo "✓ Built: $(GO_BUILD)/map-sync"

clean:
	@rm -rf $(GO_BUILD)
	@echo "✓ Cleaned Go binaries"

# Generate BPF code for map-sync
generate:
	@echo "Generating BPF code..."
	@cd map_sync && go generate
	@echo "✓ Generated BPF code"

# Run go mod tidy
tidy:
	@echo "Running go mod tidy..."
	@go mod tidy
	@echo "✓ Dependencies updated"

# Verify all packages build
verify:
	@echo "Verifying builds..."
	@go build ./pods_watcher
	@go build ./map_sync
	@echo "✓ All packages build successfully"
