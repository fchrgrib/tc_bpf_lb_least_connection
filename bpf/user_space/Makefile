.PHONY: all build clean pods-watcher map-sync tc-loader active-conn test

# Centralized build output (repo root ./build)
BUILD_ROOT := $(abspath ../../build)
GO_BUILD := $(BUILD_ROOT)/go

all: build

build: pods-watcher map-sync tc-loader active-conn

test:
	@echo "Running Go tests..."
	@go test ./...
	@echo "✓ Tests passed"

pods-watcher:
	@echo "Building pods-watcher..."
	@mkdir -p $(GO_BUILD)
	@go build -o $(GO_BUILD)/pods-watcher ./pods_watcher
	@echo "✓ Built: $(GO_BUILD)/pods-watcher"

map-sync:
	@echo "Building map-sync..."
	@mkdir -p $(GO_BUILD)
	@cd map_sync && go generate
	@go build -o $(GO_BUILD)/map-sync ./map_sync
	@echo "✓ Built: $(GO_BUILD)/map-sync"

tc-loader:
	@echo "Building tc-loader..."
	@mkdir -p $(GO_BUILD)
	@cd tc && go generate
	@go build -o $(GO_BUILD)/tc-loader ./tc
	@echo "✓ Built: $(GO_BUILD)/tc-loader"

active-conn:
	@echo "Building active-conn..."
	@mkdir -p $(GO_BUILD)
	@cd trace && go generate
	@go build -o $(GO_BUILD)/active-conn ./trace
	@echo "✓ Built: $(GO_BUILD)/active-conn"

clean:
	@rm -rf $(GO_BUILD)
	@rm -f tc/tc_x86_bpfel.go tc/tc_x86_bpfel.o
	@rm -f trace/tracepoint_x86_bpfel.go trace/tracepoint_x86_bpfel.o
	@echo "✓ Cleaned Go binaries and generated BPF files"

# Generate BPF code for all packages
generate:
	@echo "Generating BPF code..."
	@cd map_sync && go generate
	@cd tc && go generate
	@cd trace && go generate
	@echo "✓ Generated BPF code"

# Run go mod tidy
tidy:
	@echo "Running go mod tidy..."
	@go mod tidy
	@echo "✓ Dependencies updated"

# Verify all packages build
verify:
	@echo "Verifying builds..."
	@go build -o /tmp/pods_watcher_test ./pods_watcher
	@go build -o /tmp/map_sync_test ./map_sync
	@cd tc && go generate && cd .. && go build -o /tmp/tc-loader_test ./tc
	@cd trace && go generate && cd .. && go build -o /tmp/active-conn_test ./trace
	@echo "✓ All packages build successfully"
