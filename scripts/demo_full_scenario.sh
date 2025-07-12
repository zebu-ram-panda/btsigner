#!/bin/bash

# Bittensor Signer Full Scenario Demo Script
# This script demonstrates the complete workflow of btsigner

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEMO_KEY_FILE="demo_key.json"
DEMO_CONFIG_FILE="demo_config.yaml"
DEMO_KEYSTORE_DIR="demo_keystore"
DEMO_PASSWORD="demo-password-123"
SERVER_LOG_FILE="server.log"
SERVER_PID_FILE="server.pid"
SERVER_PORT="50051"

# Function to print colored messages
print_step() {
    echo -e "${BLUE}== $1 ==${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to cleanup
cleanup() {
    print_step "Cleanup"
    
    # Kill server if running
    if [ -f "$SERVER_PID_FILE" ]; then
        local pid=$(cat "$SERVER_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_step "Stopping server (PID: $pid)"
            kill "$pid" 2>/dev/null || true
            sleep 2
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$SERVER_PID_FILE"
    fi
    
    # Kill any remaining btsigner processes
    pkill -f "btsigner.*$DEMO_CONFIG_FILE" 2>/dev/null || true
    
    # Clean up files
    rm -f "$DEMO_KEY_FILE" "$DEMO_CONFIG_FILE" "$SERVER_LOG_FILE"
    rm -rf "$DEMO_KEYSTORE_DIR"
    
    print_success "Cleanup completed"
}

# Function to wait for server to start
wait_for_server() {
    local max_attempts=30
    local attempt=1
    
    print_step "Waiting for server to start on port $SERVER_PORT"
    
    while [ $attempt -le $max_attempts ]; do
        if nc -z localhost "$SERVER_PORT" 2>/dev/null; then
            print_success "Server is ready on port $SERVER_PORT"
            return 0
        fi
        
        # Check if server process is still running
        if [ -f "$SERVER_PID_FILE" ]; then
            local pid=$(cat "$SERVER_PID_FILE")
            if ! kill -0 "$pid" 2>/dev/null; then
                print_error "Server process died. Check $SERVER_LOG_FILE for details"
                if [ -f "$SERVER_LOG_FILE" ]; then
                    echo "Server log:"
                    cat "$SERVER_LOG_FILE"
                fi
                return 1
            fi
        fi
        
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done
    
    print_error "Server failed to start within $max_attempts seconds"
    return 1
}

# Function to create demo config
create_demo_config() {
    print_step "Creating demo configuration file"
    
    cat > "$DEMO_CONFIG_FILE" << EOF
server:
  address: ":$SERVER_PORT"

key:
  path: "$DEMO_KEY_FILE"
  type: "file"

tls:
  enabled: false

metrics:
  enabled: false

log:
  level: "info"
  format: "json"
EOF
    
    print_success "Created $DEMO_CONFIG_FILE"
}

# Function to test single key workflow
test_single_key_workflow() {
    print_step "Testing Single Key Workflow"
    
    # Step 1: Build binaries
    print_step "Step 1: Building binaries"
    make build
    print_success "Binaries built successfully"
    
    # Step 2: Generate key
    print_step "Step 2: Generating key"
    BTSIGNER_PASSWORD="$DEMO_PASSWORD" BTSIGNER_CONFIRM_PASSWORD="$DEMO_PASSWORD" \
        ../bin/btsigner --genkey --key "$DEMO_KEY_FILE"
    print_success "Key generated: $DEMO_KEY_FILE"
    
    # Step 3: Verify key
    print_step "Step 3: Verifying key"
    BTSIGNER_PASSWORD="$DEMO_PASSWORD" ../bin/btsigner --check-key --key "$DEMO_KEY_FILE"
    print_success "Key verification completed"
    
    # Step 4: Create config
    create_demo_config
    
    # Step 5: Start server
    print_step "Step 5: Starting server"
    BTSIGNER_PASSWORD="$DEMO_PASSWORD" ../bin/btsigner --config "$DEMO_CONFIG_FILE" > "$SERVER_LOG_FILE" 2>&1 &
    local server_pid=$!
    echo "$server_pid" > "$SERVER_PID_FILE"
    print_success "Server started with PID: $server_pid"
    
    # Step 6: Wait for server
    if ! wait_for_server; then
        print_error "Server failed to start"
        return 1
    fi
    
    # Step 7: Test client operations
    print_step "Step 7: Testing client operations"
    
    # Get public key
    print_step "Step 7a: Getting public key"
    ../bin/btclient --get-public-key
    print_success "Public key retrieved successfully"
    
    # Test health check
    print_step "Step 7b: Testing health check"
    ../bin/btclient --health
    print_success "Health check passed"
    
    # Test signing
    print_step "Step 7c: Testing signing"
    ../bin/btclient --sign 68656c6c6f20776f726c64  # "hello world" in hex
    print_success "Signing test passed"
    
    # Test multiple signatures for performance
    print_step "Step 7d: Testing multiple signatures (performance test)"
    local start_time=$(date +%s.%N)
    for i in {1..10}; do
        ../bin/btclient --sign $(printf "%064x" $i) > /dev/null
    done
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    print_success "10 signatures completed in ${duration}s (avg: $(echo "scale=4; $duration / 10" | bc)s per signature)"
    
    print_success "Single key workflow completed successfully!"
}

# Function to test keystore workflow
test_keystore_workflow() {
    print_step "Testing Keystore Workflow"
    
    # Step 1: Create keystore and generate keys
    print_step "Step 1: Creating keystore and generating keys"
    
    # Generate multiple keys
    local key_ids=("validator-key" "cold-key" "hot-key")
    for key_id in "${key_ids[@]}"; do
        print_step "Generating key: $key_id"
        BTSIGNER_PASSWORD="$DEMO_PASSWORD" BTSIGNER_CONFIRM_PASSWORD="$DEMO_PASSWORD" \
            ../bin/btsigner --genkey --keystore "$DEMO_KEYSTORE_DIR" --key-id "$key_id"
        print_success "Generated key: $key_id"
    done
    
    # Step 2: Stop single key server
    print_step "Step 2: Stopping single key server"
    cleanup
    
    # Step 3: Create keystore config
    print_step "Step 3: Creating keystore configuration"
    cat > "$DEMO_CONFIG_FILE" << EOF
server:
  address: ":$SERVER_PORT"

key:
  path: ""
  type: "keystore"

tls:
  enabled: false

metrics:
  enabled: false

log:
  level: "info"
  format: "json"
EOF
    
    # Step 4: Start keystore server
    print_step "Step 4: Starting keystore server"
    BTSIGNER_PASSWORD="$DEMO_PASSWORD" ../bin/btsigner --config "$DEMO_CONFIG_FILE" \
        --keystore "$DEMO_KEYSTORE_DIR" --key-id "validator-key" > "$SERVER_LOG_FILE" 2>&1 &
    local server_pid=$!
    echo "$server_pid" > "$SERVER_PID_FILE"
    print_success "Keystore server started with PID: $server_pid"
    
    # Step 5: Wait for server
    if ! wait_for_server; then
        print_error "Keystore server failed to start"
        return 1
    fi
    
    # Step 6: Test keystore operations
    print_step "Step 6: Testing keystore operations"
    
    # Get public key
    print_step "Step 6a: Getting public key from keystore"
    ../bin/btclient --get-public-key
    print_success "Public key retrieved from keystore"
    
    # Test signing with keystore
    print_step "Step 6b: Testing signing with keystore"
    ../bin/btclient --sign 68656c6c6f20776f726c64  # "hello world" in hex
    print_success "Keystore signing test passed"
    
    print_success "Keystore workflow completed successfully!"
}

# Function to run stress test
run_stress_test() {
    print_step "Running Stress Test"
    
    print_step "Running 5000 signature stress test"
    ../bin/btclient --get-public-key > /dev/null  # Warmup
    
    local start_time=$(date +%s.%N)
    local success_count=0
    local error_count=0
    
    for i in {1..5000}; do
        local payload=$(printf "%064x" $i)
        if ../bin/btclient --sign "$payload" > /dev/null 2>&1; then
            success_count=$((success_count + 1))
        else
            error_count=$((error_count + 1))
        fi
        
        if [ $((i % 500)) -eq 0 ]; then
            echo "Completed $i/5000 signatures..."
        fi
    done
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    local avg_time=$(echo "scale=6; $duration / 5000" | bc)
    
    print_success "Stress test completed!"
    echo "Total signatures: 5000"
    echo "Successful: $success_count"
    echo "Failed: $error_count"
    echo "Total time: ${duration}s"
    echo "Average time per signature: ${avg_time}s"
    echo "Signatures per second: $(echo "scale=2; 5000 / $duration" | bc)"
}

# Main execution
main() {
    echo "======================================================================="
    echo "Bittensor Signer Full Scenario Demo"
    echo "======================================================================="
    
    # Check dependencies
    if ! command -v nc &> /dev/null; then
        print_error "netcat (nc) is required but not installed"
        exit 1
    fi
    
    if ! command -v bc &> /dev/null; then
        print_error "bc is required but not installed"
        exit 1
    fi
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Clean up any previous runs
    cleanup
    
    # Test single key workflow
    if ! test_single_key_workflow; then
        print_error "Single key workflow failed"
        exit 1
    fi
    
    # Test keystore workflow
    if ! test_keystore_workflow; then
        print_error "Keystore workflow failed"
        exit 1
    fi
    
    # Run stress test
    if ! run_stress_test; then
        print_error "Stress test failed"
        exit 1
    fi
    
    print_success "All tests completed successfully!"
    
    # Show server logs
    print_step "Server logs"
    if [ -f "$SERVER_LOG_FILE" ]; then
        cat "$SERVER_LOG_FILE"
    fi
    
    echo "======================================================================="
    echo "Demo completed successfully!"
    echo "======================================================================="
}

# Run main function
main "$@" 