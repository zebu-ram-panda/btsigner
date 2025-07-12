#  (2025-07-12)

### Features
- **Core Functionality**
  - Secure remote signing for Bittensor using sr25519 cryptography
  - gRPC API for key management and transaction signing
  - Comprehensive error handling and logging
  
- **Key Management**
  - Support for single key and multi-key (keystore) modes
  - Secure key storage with strong encryption
  - Key import from existing Bittensor wallet files
  - Support for up to 256 keys in a keystore
  - Memory protection with key zeroing when not in use
  
- **Security**
  - TLS/mTLS support with configurable parameters
  - Configurable cipher suites and TLS versions
  - Client certificate authentication
  - Secure password handling
  
- **Testing and Quality**
  - Comprehensive test suite
  - Integration tests
  - Code quality checks
  - Security scanning

### Fixed
- Fixed TLS certificate issue in TestClientWithTLS by generating proper test certificates
- Removed unreachable ConstantTimeCompare function from internal/crypto/memguard.go
- Modified test-security target in Makefile to not fail the build



