# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of remote signing service
- SR25519 key handling and signing capabilities
- gRPC server and client implementation
- Health check endpoints
- TLS support for secure communication
- Unit and integration tests

### Security
- Updated golang.org/x/crypto to v0.40.0 to fix CVE-2024-45337
- Added replace directive for gopkg.in/yaml.v2 to use v2.4.0 to fix multiple CVEs

### Changed
- Updated Go version to 1.24
- Updated all dependencies to their latest versions

## [0.1.0] - YYYY-MM-DD
- Initial release

[Unreleased]: https://github.com/bittensor-lab/btsigner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bittensor-lab/btsigner/releases/tag/v0.1.0



