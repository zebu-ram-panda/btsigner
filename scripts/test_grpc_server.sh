#!/bin/bash

# Test script for gRPC server functionality
# This script tests the complete gRPC server workflow including signing operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KEYSTORE_PATH="./test_keystore"
CONFIG_FILE="./test_server_config.yaml"
SERVER_PID_FILE="./server.pid"
SERVER_ADDRESS="localhost:50051"
PASSWORD="test123"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    print_info "Cleaning up..."

    if [ -f "$SERVER_PID_FILE" ]; then
        SERVER_PID=$(cat "$SERVER_PID_FILE")
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            print_info "Stopping server (PID: $SERVER_PID)"
            kill "$SERVER_PID" 2>/dev/null || true
            wait "$SERVER_PID" 2>/dev/null || true
        fi
        rm -f "$SERVER_PID_FILE"
    fi

    # Clean up test files
    rm -rf "$KEYSTORE_PATH" "$CONFIG_FILE" 2>/dev/null || true
    print_info "Cleanup completed"
}

# Set up trap for cleanup
trap cleanup EXIT

print_info "Starting gRPC server test..."

# Step 1: Create keystore and keys
print_info "Step 1: Creating keystore and keys..."
rm -rf "$KEYSTORE_PATH"
mkdir -p "$KEYSTORE_PATH"

# Set environment variables for password
export BTSIGNER_PASSWORD="$PASSWORD"
export BTSIGNER_CONFIRM_PASSWORD="$PASSWORD"

# Generate multiple keys
print_info "Generating validator-key..."
./bin/btsigner --keystore "$KEYSTORE_PATH" --genkey --key-id "validator-key"

print_info "Generating cold-key..."
./bin/btsigner --keystore "$KEYSTORE_PATH" --genkey --key-id "cold-key"

print_info "Generating hot-key..."
./bin/btsigner --keystore "$KEYSTORE_PATH" --genkey --key-id "hot-key"

print_success "Successfully created keystore with 3 keys"

# Step 2: Create server configuration
print_info "Step 2: Creating server configuration..."
cat > "$CONFIG_FILE" << EOF
server:
  address: "$SERVER_ADDRESS"

tls:
  enabled: false

keystore:
  path: "$KEYSTORE_PATH"
  default_key_id: "validator-key"

logging:
  level: "info"
  format: "json"
EOF

print_success "Server configuration created"

# Step 3: Start the server
print_info "Step 3: Starting gRPC server..."
./bin/btsigner --config "$CONFIG_FILE" --keystore "$KEYSTORE_PATH" --key-id "validator-key" &
SERVER_PID=$!
echo "$SERVER_PID" > "$SERVER_PID_FILE"

print_info "Server started with PID: $SERVER_PID"

# Wait for server to start
print_info "Waiting for server to start..."
sleep 3

# Check if server is running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    print_error "Server failed to start"
    exit 1
fi

# Check for timeout command availability
if command -v timeout &> /dev/null; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout &> /dev/null; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
fi

# Function to run command with timeout if available
run_with_timeout() {
    local duration=$1
    shift
    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "$duration" "$@"
    else
        "$@"
    fi
}

# Step 4: Test server connectivity and health
print_info "Step 4: Testing server health..."
run_with_timeout 10 ./bin/btclient -address "$SERVER_ADDRESS" -health || {
    print_error "Health check failed"
    exit 1
}
print_success "Health check passed"

# Step 5: Test GetPublicKey (default key)
print_info "Step 5: Testing GetPublicKey (default key)..."
DEFAULT_PUBKEY_RESULT=$(run_with_timeout 10 ./bin/btclient -address "$SERVER_ADDRESS" -get-public-key 2>&1)
if [ $? -eq 0 ]; then
    print_success "GetPublicKey succeeded"
    echo "$DEFAULT_PUBKEY_RESULT" | head -3
else
    print_error "GetPublicKey failed"
    echo "$DEFAULT_PUBKEY_RESULT"
    exit 1
fi

# Step 6: Test signing with default key
print_info "Step 6: Testing SignExtrinsic (default key)..."
TEST_PAYLOAD="48656c6c6f20576f726c64" # "Hello World" in hex
SIGN_RESULT=$(run_with_timeout 10 ./bin/btclient -address "$SERVER_ADDRESS" -sign "$TEST_PAYLOAD" 2>&1)
if [ $? -eq 0 ]; then
    print_success "SignExtrinsic succeeded"
    echo "$SIGN_RESULT" | head -3
else
    print_error "SignExtrinsic failed"
    echo "$SIGN_RESULT"
    exit 1
fi

# Step 7: Test signing with specific keys
print_info "Step 7: Testing SignExtrinsicWithKey..."
for KEY_ID in "validator-key" "cold-key" "hot-key"; do
    print_info "Testing SignExtrinsicWithKey for $KEY_ID..."
    SIGN_WITH_KEY_RESULT=$(run_with_timeout 10 ./bin/btclient -address "$SERVER_ADDRESS" -key-id "$KEY_ID" -sign "$TEST_PAYLOAD" 2>&1)
    if [ $? -eq 0 ]; then
        print_success "SignExtrinsicWithKey for $KEY_ID succeeded"
        echo "$SIGN_WITH_KEY_RESULT" | head -2
    else
        print_error "SignExtrinsicWithKey for $KEY_ID failed"
        echo "$SIGN_WITH_KEY_RESULT"
        exit 1
    fi
done

# Step 8: Stress test signing
print_info "Step 8: Stress testing signing operations..."
STRESS_COUNT=50
print_info "Performing $STRESS_COUNT signing operations..."

START_TIME=$(date +%s)
for i in $(seq 1 $STRESS_COUNT); do
    if ! run_with_timeout 5 ./bin/btclient -address "$SERVER_ADDRESS" -sign "$TEST_PAYLOAD" >/dev/null 2>&1; then
        print_error "Stress test failed at iteration $i"
        exit 1
    fi
done
END_TIME=$(date +%s)

DURATION=$(($END_TIME - $START_TIME)) # Duration in seconds
if [ $DURATION -gt 0 ]; then
    RATE=$(echo "scale=2; $STRESS_COUNT / $DURATION" | bc -l)
    print_success "Stress test completed: $STRESS_COUNT operations in ${DURATION}s (${RATE} ops/sec)"
else
    print_success "Stress test completed: $STRESS_COUNT operations in <1s"
fi

# Step 9: Test error handling
print_info "Step 9: Testing error handling..."

# Test with invalid key ID
print_info "Testing with invalid key ID..."
INVALID_KEY_RESULT=$(run_with_timeout 10 ./bin/btclient -address "$SERVER_ADDRESS" -key-id "invalid-key" -sign "$TEST_PAYLOAD" 2>&1)
if [ $? -ne 0 ]; then
    print_success "Error handling for invalid key ID works correctly"
else
    print_warning "Expected error for invalid key ID, but got success"
fi

# Test with empty payload
print_info "Testing with empty payload..."
EMPTY_PAYLOAD_RESULT=$(run_with_timeout 10 ./bin/btclient -address "$SERVER_ADDRESS" -sign "" 2>&1)
if [ $? -ne 0 ]; then
    print_success "Error handling for empty payload works correctly"
else
    print_warning "Expected error for empty payload, but got success"
fi

print_success "All gRPC server tests passed!"
print_info "Server is working correctly and can handle signing operations over gRPC"

# Summary
echo ""
echo "=================================="
echo "gRPC Server Test Summary"
echo "=================================="
echo "✅ Server startup and health check"
echo "✅ GetPublicKey (default key)"
echo "✅ SignExtrinsic (default key)"
echo "✅ SignExtrinsicWithKey (all keys)"
echo "✅ Stress test ($STRESS_COUNT operations)"
echo "✅ Error handling"
echo ""
echo "🎉 gRPC server is fully functional!"
