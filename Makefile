.PHONY: build test lint integration-test clean all

all: build test

# Build the gravelpit binary.
build:
	go build -o bin/gravelpit ./cmd/gravelpit

install:
	go install ./cmd/gravelpit

# Run unit tests.
test:
	go test ./...

# Run integration tests (requires Linux x86_64, seccomp user notify support).
integration-test: build
	go test -v -tags integration ./internal/integration/

# Run golangci-lint.
lint:
	golangci-lint run ./...

# Run benchmarks.
bench:
	go test -bench=. -benchmem -run=^$$ ./internal/policy/

# Remove build artifacts.
clean:
	rm -rf bin/

# Verify all tool profiles against their policies.
profile-verify: build
	go run profiles/verify.go

# Re-generate discovered policies for all tool profiles.
profile-record: build
	go run profiles/verify.go --record
