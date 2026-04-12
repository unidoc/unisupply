# unisupply — Go Supply Chain Risk Assessment CLI
# https://github.com/unidoc/unisupply

set dotenv-load := false

# Default: show available recipes
default:
    @just --list

# Build the binary
build:
    go build -o bin/unisupply ./cmd/unisupply/

# Build for all platforms
build-all:
    GOOS=linux   GOARCH=amd64 go build -o bin/unisupply-linux-amd64   ./cmd/unisupply/
    GOOS=linux   GOARCH=arm64 go build -o bin/unisupply-linux-arm64   ./cmd/unisupply/
    GOOS=darwin  GOARCH=amd64 go build -o bin/unisupply-darwin-amd64  ./cmd/unisupply/
    GOOS=darwin  GOARCH=arm64 go build -o bin/unisupply-darwin-arm64  ./cmd/unisupply/
    GOOS=windows GOARCH=amd64 go build -o bin/unisupply-windows-amd64.exe ./cmd/unisupply/

# Install locally
install:
    go install ./cmd/unisupply/

# Run on current directory
run *ARGS:
    go run ./cmd/unisupply/ {{ARGS}}

# Run with verbose output
run-verbose *ARGS:
    go run ./cmd/unisupply/ -v {{ARGS}}

# Generate JSON report
json *ARGS:
    go run ./cmd/unisupply/ -f json {{ARGS}}

# Generate PDF report
pdf *ARGS:
    go run ./cmd/unisupply/ -f pdf {{ARGS}}

# Run with CI/CD scanning enabled
scan-ci *ARGS:
    go run ./cmd/unisupply/ --scan-ci --scan-workflows {{ARGS}}

# Run full scan (all features enabled)
scan-full *ARGS:
    go run ./cmd/unisupply/ -v --scan-ci --scan-workflows {{ARGS}}

# Run tests
test:
    go test ./... -v

# Run tests with race detection
test-race:
    go test ./... -v -race

# Run tests with coverage
test-cover:
    go test ./... -coverprofile=coverage.out
    go tool cover -func=coverage.out
    @echo "HTML report: go tool cover -html=coverage.out"

# Lint (requires golangci-lint)
lint:
    golangci-lint run ./...

# Format code
fmt:
    gofmt -w -s .
    goimports -w .

# Vet
vet:
    go vet ./...

# Tidy dependencies
tidy:
    go mod tidy

# Check — run fmt, vet, and test
check: fmt vet test

# Clean build artifacts
clean:
    rm -rf bin/
    rm -f coverage.out
    rm -f unisupply-report.pdf

# Show dependency tree
deps:
    go mod graph

# Self-scan — run unisupply on itself
self-scan:
    go run ./cmd/unisupply/ -v .

# Self-scan with CI
self-scan-full:
    go run ./cmd/unisupply/ -v --scan-ci --scan-workflows .

# Generate CycloneDX SBOM
sbom-cyclonedx *ARGS:
    go run ./cmd/unisupply/ -f sbom-cyclonedx {{ARGS}}

# Generate SPDX SBOM
sbom-spdx *ARGS:
    go run ./cmd/unisupply/ -f sbom-spdx {{ARGS}}

# Check against strict policy
policy-strict *ARGS:
    go run ./cmd/unisupply/ --policy-preset strict {{ARGS}}

# Check against moderate policy
policy-moderate *ARGS:
    go run ./cmd/unisupply/ --policy-preset moderate {{ARGS}}

# Check against custom policy file
policy FILE *ARGS:
    go run ./cmd/unisupply/ --policy {{FILE}} {{ARGS}}

# Show version
version:
    @go run ./cmd/unisupply/ --version
