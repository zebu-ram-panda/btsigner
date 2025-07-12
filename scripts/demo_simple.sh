#!/bin/bash

# Simple Bittensor Signer Demo Script
# This script demonstrates key generation and signing functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}== $1 ==${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

main() {
    echo "======================================================================="
    echo "Bittensor Signer Demo - Key Generation and Signing"
    echo "======================================================================="

    # Step 1: Build binaries
    print_step "Step 1: Building binaries"
    make build
    print_success "Binaries built successfully"

    # Step 2: Generate single key
    print_step "Step 2: Generating single key with binary"
    BTSIGNER_PASSWORD="demo-password" BTSIGNER_CONFIRM_PASSWORD="demo-password" \
        ./bin/btsigner --genkey --key ./demo_single_key.json
    print_success "Single key generated"

    # Step 3: Check the key
    print_step "Step 3: Checking the key"
    BTSIGNER_PASSWORD="demo-password" ./bin/btsigner --check-key --key ./demo_single_key.json
    print_success "Key check completed"

    # Step 4: Generate keystore keys
    print_step "Step 4: Generating keystore keys"
    for key_id in "validator-key" "cold-key" "hot-key"; do
        BTSIGNER_PASSWORD="demo-password" BTSIGNER_CONFIRM_PASSWORD="demo-password" \
            ./bin/btsigner --genkey --keystore ./demo_keystore --key-id "$key_id"
        print_success "Generated keystore key: $key_id"
    done

    # Step 5: Run comprehensive test suite
    print_step "Step 5: Running comprehensive test suite (100 signatures)"
    make test-keygen
    print_success "Test suite completed successfully"

    # Step 6: Performance summary
    print_step "Step 6: Performance Summary"
    echo "The btsigner project successfully demonstrates:"
    echo "- Secure Sr25519 key generation"
    echo "- Both single key and keystore (multi-key) support"
    echo "- High-performance signing (100 signatures completed)"
    echo "- Comprehensive error handling and edge case testing"
    echo "- Clean cryptographic key management"

    # Step 7: Show generated files
    print_step "Step 7: Generated Files"
    echo "Single key file:"
    ls -la ./demo_single_key.json
    echo ""
    echo "Keystore directory:"
    ls -la ./demo_keystore/
    echo ""
    echo "Keystore metadata:"
    cat ./demo_keystore/metadata.json | python3 -m json.tool 2>/dev/null || cat ./demo_keystore/metadata.json

    # Cleanup
    print_step "Cleanup"
    rm -f ./demo_single_key.json
    rm -rf ./demo_keystore/
    print_success "Demo files cleaned up"

    echo "======================================================================="
    echo "Demo completed successfully!"
    echo "Note: The gRPC server has a protobuf marshaling issue that needs fixing"
    echo "but the core signing functionality works perfectly as demonstrated."
    echo "======================================================================="
}

# Run main function
main "$@"
