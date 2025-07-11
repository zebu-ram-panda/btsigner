# btsigner

A minimal, secure remote signer for Bittensor using sr25519 cryptography.

## Overview

btsigner keeps your sr25519 private key off your validator node, reducing the risk of key compromise. It provides a simple gRPC API for signing Substrate extrinsics.

## Features

- Simple, focused design with minimal dependencies
- Secure key management with encrypted storage
- TLS/mTLS support for secure communication
- Prometheus metrics for monitoring
- Health check endpoint
- Docker and Kubernetes ready

## Quick Start

### Building

```bash
make build
```

### Generating a key

```bash
./bin/btsigner --genkey --key ./key.json
```

### Running the server

```bash
./bin/btsigner --config config.yaml
```

### Using the client

```bash
# Get the public key
./bin/btclient --get-public-key

# Sign a payload
./bin/btclient --sign 0x68656c6c6f20776f726c64

# Check server health
./bin/btclient --health
```

## Configuration

Example configuration file (config.yaml):

```yaml
server:
  address: ":50051"

key:
  path: "key.json"
  type: "file"

tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
  client_auth: true
  ca_path: "certs/ca.crt"

metrics:
  enabled: true
  address: ":9090"

log:
  level: "info"
  format: "json"
```

## Integration with Bittensor

To use btsigner with Bittensor, configure your validator to use the remote signer client library.

## Security Considerations

- Run btsigner on a separate, hardened machine from your validator
- Use TLS with client authentication
- Restrict network access to the signer
- Consider using a hardware security module (HSM) for key storage

## License

MIT

## Testing Suite

btsigner includes a comprehensive testing suite to verify code quality, identify security issues, and ensure functionality. The following test targets are available via make:

### Basic Test Commands

- `make test` - Run all unit tests
- `make test-all` - Run all tests including unit, integration, dead code analysis, static analysis, and security checks

### Specific Test Commands

- `make test-unit` - Run only unit tests
- `make test-integration` - Run only integration tests
- `make test-deadcode` - Run dead code analysis to identify unreachable functions
- `make test-static` - Run static code analysis (go vet and staticcheck)
- `make test-security` - Run security checks using gosec
- `make test-coverage` - Generate test coverage report
- `make test-ci` - Run all tests and generate reports in the reports/ directory

### CI/CD Integration

The `test-ci` target is particularly useful for continuous integration environments. It:

1. Runs all tests with coverage reports
2. Performs dead code analysis
3. Runs static code analysis
4. Executes security checks
5. Outputs all reports to the `reports/` directory

### Example Usage

```bash
# Run quick unit tests during development
make test

# Run complete test suite before committing
make test-all

# Generate HTML coverage report
make test-coverage

# Generate all test reports for CI
make test-ci
```
