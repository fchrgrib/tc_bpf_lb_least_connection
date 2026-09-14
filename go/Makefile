.PHONY: all build clean pods-watcher map-sync

all: build

build: pods-watcher map-sync

pods-watcher:
	@echo "Building pods-watcher..."
	@go build -o ../bin/pods-watcher ./pods_watcher
	@echo "✓ Built: ../bin/pods-watcher"

map-sync:
	@echo "Building map-sync..."
	@go build -o ../bin/map-sync ./map_sync
	@echo "✓ Built: ../bin/map-sync"

clean:
	@rm -rf ../bin/pods-watcher ../bin/map-sync
	@echo "✓ Cleaned binaries"

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
