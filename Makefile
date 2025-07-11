# Makefile

.PHONY: all build test clean proto docker test-all test-unit test-deadcode test-static test-security test-integration test-ci

# Variables
BINARY_NAME=btsigner
CLIENT_NAME=btclient
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}"

all: clean build

build:
	go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/${BINARY_NAME}
	go build ${LDFLAGS} -o bin/${CLIENT_NAME} ./cmd/${CLIENT_NAME}

build-static:
	CGO_ENABLED=0 go build -a -tags osusergo,netgo ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/${BINARY_NAME}
	CGO_ENABLED=0 go build -a -tags osusergo,netgo ${LDFLAGS} -o bin/${CLIENT_NAME} ./cmd/${CLIENT_NAME}

# Test targets
test: test-unit

# Run all tests and static analysis tools
test-all: test-unit test-integration test-deadcode test-static test-security

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	go test -v ./...

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	go test -v ./tests/integration

# Check for unreachable/dead code
test-deadcode:
	@echo "Running dead code analysis..."
	@go install golang.org/x/tools/cmd/deadcode@latest
	@$(shell go env GOPATH)/bin/deadcode -test ./...

# Run static code analysis
test-static:
	@echo "Running static code analysis..."
	@go vet ./...
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@$(shell go env GOPATH)/bin/staticcheck ./...

# Run security checks
test-security:
	@echo "Running security checks..."
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@$(shell go env GOPATH)/bin/gosec -fmt=json -out=gosec-results.json ./...
	@echo "Security check results saved to gosec-results.json"

# Generate coverage report
test-coverage:
	@echo "Generating test coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

# CI test suite - runs all tests with reports
test-ci:
	@echo "Running CI test suite..."
	@mkdir -p reports

	@echo "Running unit tests with coverage..."
	go test -coverprofile=reports/coverage.out ./...
	go tool cover -html=reports/coverage.out -o reports/coverage.html
	go tool cover -func=reports/coverage.out > reports/coverage_summary.txt

	@echo "Running dead code analysis..."
	go install golang.org/x/tools/cmd/deadcode@latest
	$(shell go env GOPATH)/bin/deadcode -test ./... > reports/deadcode.txt || true

	@echo "Running static analysis..."
	go vet ./... 2> reports/govet.txt || true
	go install honnef.co/go/tools/cmd/staticcheck@latest
	$(shell go env GOPATH)/bin/staticcheck ./... > reports/staticcheck.txt || true

	@echo "Running security checks..."
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	$(shell go env GOPATH)/bin/gosec -fmt=json -out=reports/gosec.json ./... || true
	$(shell go env GOPATH)/bin/gosec -fmt=text -out=reports/gosec.txt ./... || true

	@echo "CI tests completed - reports available in ./reports directory"
	@ls -la reports/

clean:
	go clean
	rm -f bin/${BINARY_NAME} bin/${CLIENT_NAME}
	rm -f coverage.out coverage.html gosec-results.json
	rm -rf reports

proto:
	mkdir -p proto/signer/v1
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/signer.proto

docker:
	docker build -t bittensor-lab/btsigner:${VERSION} -f deploy/docker/Dockerfile .

run:
	./bin/${BINARY_NAME} --config config.yaml

genkey:
	./bin/${BINARY_NAME} --genkey --key ./key.json
