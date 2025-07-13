# btsigner

[![Known Vulnerabilities](https://snyk.io/test/github/zebu-ram-panda/btsigner/badge.svg)](https://app.snyk.io/org/zebu-ram-panda/dashboard)

A minimal, secure remote signer for Bittensor using sr25519 cryptography.

## Overview

btsigner keeps your sr25519 private key off your validator node, reducing the risk of key compromise. It provides a simple gRPC API for signing Substrate extrinsics.

## Features

- **Simple, focused design** with minimal dependencies
- **Secure key management**
  - Encrypted storage with strong password-based encryption
  - Multiple key management options (single key or keystore with multiple keys)
  - Import keys from Bittensor wallet files
  - Key zeroing in memory when no longer needed
- **Multi-key support**
  - Support for managing up to 256 keys in a keystore
  - Ability to select keys by ID for signing operations
  - Default key selection for simplified operations
- **TLS/mTLS support** for secure communication
  - Configurable cipher suites and TLS versions
  - Optional client certificate authentication
- **gRPC API** for efficient remote signing
  - Get public keys and addresses
  - Sign extrinsics with specific keys
  - Check server health

- **Configurable logging** with JSON or console formats
- **CLI client** for testing and manual operations
- **Comprehensive test suite** with integration tests
- **Docker and Kubernetes ready**

## Quick Start

### Building

```bash
make build
```

### Generating a key

#### Single key mode
```bash
./bin/btsigner --genkey --key ./key.json
```

#### Keystore mode (multiple keys)
```bash
./bin/btsigner --genkey --keystore ./keystore --key-id mykey1
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

# Sign with a specific key ID
./bin/btclient --sign 0x68656c6c6f20776f726c64 --key-id mykey1

# Check server health
./bin/btclient --health

# Use TLS
./bin/btclient --tls --ca ./certs/ca.crt --get-public-key
```

## Configuration

Example configuration file (config.yaml):

```yaml
server:
  address: ":50051"  # gRPC server address

# Single key mode
key:
  path: "key.json"
  type: "file"

# OR keystore mode for multiple keys
keystore:
  path: "keystore"

tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
  client_auth: true  # Enable client certificate authentication
  ca_path: "certs/ca.crt"
  min_version: "1.2"
  cipher_suites:
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

metrics:
  enabled: true
  address: ":9090"

log:
  level: "info"  # debug, info, warn, error
  format: "json"  # json, console
```

## Advanced Usage

### Importing Keys from Bittensor Wallet

You can import existing keys from a Bittensor wallet:

```bash
./bin/btsigner --import --coldkey /path/to/coldkey --coldkeypub /path/to/coldkeypub.txt --keystore ./keystore --key-id imported_key
```

### Working with Multiple Keys

List available keys in a keystore:

```bash
./bin/btsigner --keystore ./keystore
```

Load a specific key:

```bash
./bin/btsigner --keystore ./keystore --key-id mykey1
```

### Checking Keys

Verify a key without starting the server:

```bash
./bin/btsigner --check-key --key ./key.json
```

### Securing Communications

For production use, always enable TLS:

```bash
./bin/btsigner --config config.yaml  # with TLS enabled in config
```

## Integration with Bittensor

To use btsigner with Bittensor, configure your validator to use the remote signer client library.

## Security Considerations

- Run btsigner on a separate, hardened machine from your validator
- Use TLS with client authentication
- Restrict network access to the signer
- Consider using a hardware security module (HSM) for key storage
- Regularly rotate keys and certificates
- Monitor logs and metrics for suspicious activity

## Docker Usage

btsigner provides Docker support for both the server and client components.

### Setup Environment Variables

Copy the example environment file and customize it:

```bash
cp .env.example .env
# Edit .env with your preferred text editor
```

Important variables to set:
- `BTSIGNER_PASSWORD`: Password for your key file (required for non-interactive use)
- `KEY_PATH`: Path to your key file inside the container

### Running with Docker Compose

#### Starting the Server

```bash
docker-compose up -d btsigner
```

#### Checking Server Health

```bash
docker-compose run --rm btclient --address=btsigner:50051 --health
```

#### Getting the Public Key

```bash
docker-compose run --rm btclient --address=btsigner:50051 --get-public-key
```

#### Signing a Message

```bash
docker-compose run --rm btclient --address=btsigner:50051 --sign 0x68656c6c6f20776f726c64
```

#### Building Custom Images

```bash
docker-compose build
```

#### Generating a Key in Docker

```bash
# Create a keystore directory first
mkdir -p keystore

# Generate a key
docker-compose run --rm -e BTSIGNER_PASSWORD=your-password btsigner --genkey --key /app/keystore/key.json
```

### Running with Docker Directly

#### Server

```bash
docker build -t bittensor/btsigner:latest --target server .
docker run -d -p 50051:50051 -p 9090:9090 -v ./keystore:/app/keystore -v ./config.yaml:/app/config.yaml:ro -e BTSIGNER_PASSWORD=your-password bittensor/btsigner:latest
```

#### Client

```bash
docker build -t bittensor/btclient:latest --target client .
docker run --rm bittensor/btclient:latest --address=host.docker.internal:50051 --health
```

## Testing Suite

btsigner includes a comprehensive testing suite to verify code quality, identify security issues, and ensure functionality. The following test targets are available via make:

### Basic Test Commands

- `make test` - Run all unit tests
- `make test-keygen` - Run key generation and signing test script
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

## License

MIT
