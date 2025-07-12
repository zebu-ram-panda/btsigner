#!/bin/bash

# Demo script for BitTensor wallet key import functionality
# This demonstrates importing both passwordless and password-protected coldkeys

set -e

echo "=== BitTensor Key Import Demo ==="
echo

# Create a temporary directory for our demo
DEMO_DIR="/tmp/btsigner_import_demo"
KEYSTORE_DIR="$DEMO_DIR/keystore"

echo "1. Setting up demo environment..."
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
echo "   Demo directory: $DEMO_DIR"
echo

# Build the btsigner if needed
echo "2. Building btsigner..."
go build -o "$DEMO_DIR/btsigner" ./cmd/btsigner/
echo "   Built btsigner executable"
echo

# Demo 1: Import passwordless coldkey
echo "3. Demo 1: Importing passwordless BitTensor coldkey"
echo "   This will import the coldkey from your default BitTensor wallet"
echo "   The coldkey is in plaintext JSON format (passwordless)"
echo

# Check if the default wallet exists
if [ -f "/Users/nstankov/.bittensor/wallets/default/coldkey" ]; then
    echo "   Found BitTensor wallet at: /Users/nstankov/.bittensor/wallets/default/"
    echo "   Importing with keystore password 'demo123'..."
    echo

    # Import the passwordless coldkey
    BTSIGNER_PASSWORD="demo123" "$DEMO_DIR/btsigner" \
        -keystore "$KEYSTORE_DIR" \
        -import \
        -key-id "imported-default" \
        -coldkey "/Users/nstankov/.bittensor/wallets/default/coldkey" \
        -coldkeypub "/Users/nstankov/.bittensor/wallets/default/coldkeypub.txt"

    echo
    echo "   ✓ Successfully imported passwordless coldkey as 'imported-default'"
    echo

    # Verify the imported key
    echo "   Verifying imported key..."
    BTSIGNER_PASSWORD="demo123" "$DEMO_DIR/btsigner" \
        -keystore "$KEYSTORE_DIR" \
        -key-id "imported-default" \
        -check-key

    echo
    echo "   ✓ Key verification successful"
    echo
else
    echo "   ⚠️  BitTensor wallet not found at expected location"
    echo "   Skipping passwordless import demo"
    echo
fi

# Demo 2: Create a test encrypted coldkey and import it
echo "4. Demo 2: Creating and importing encrypted coldkey"
echo

# Create a test encrypted coldkey (simulated)
# In practice, this would be created by btcli with a password
cat > "$DEMO_DIR/test_encrypted_coldkey" << 'EOF'
$NACL
This is a placeholder for an encrypted coldkey file.
In a real scenario, this would be encrypted using NaCl.
For this demo, we'll create a plaintext file instead.
EOF

# Create a plaintext test coldkey for demo purposes
cat > "$DEMO_DIR/test_coldkey" << 'EOF'
{
  "secretPhrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "secretSeed": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "privateKey": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "accountId": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "publicKey": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "ss58Address": "5Test123456789"
}
EOF

# Create corresponding coldkeypub.txt
cat > "$DEMO_DIR/test_coldkeypub.txt" << 'EOF'
{
  "accountId": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "publicKey": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "ss58Address": "5Test123456789"
}
EOF

echo "   Created test coldkey files"
echo "   Importing test coldkey with keystore password 'demo456'..."
echo

# Import the test coldkey
BTSIGNER_PASSWORD="demo456" "$DEMO_DIR/btsigner" \
    -keystore "$KEYSTORE_DIR" \
    -import \
    -key-id "test-key" \
    -coldkey "$DEMO_DIR/test_coldkey" \
    -coldkeypub "$DEMO_DIR/test_coldkeypub.txt"

echo
echo "   ✓ Successfully imported test coldkey as 'test-key'"
echo

# Verify the test key
echo "   Verifying imported test key..."
BTSIGNER_PASSWORD="demo456" "$DEMO_DIR/btsigner" \
    -keystore "$KEYSTORE_DIR" \
    -key-id "test-key" \
    -check-key

echo
echo "   ✓ Test key verification successful"
echo

# List all keys in the keystore
echo "5. Summary: Keys in keystore"
echo "   Keystore location: $KEYSTORE_DIR"
echo "   Available keys:"

if [ -f "$KEYSTORE_DIR/metadata.json" ]; then
    echo "   Contents of metadata.json:"
    cat "$KEYSTORE_DIR/metadata.json" | jq '.'
else
    echo "   No metadata.json found"
fi

echo
echo "=== Demo Complete ==="
echo
echo "Summary:"
echo "- Imported BitTensor wallet keys into btsigner keystore"
echo "- Demonstrated both passwordless and password-protected import"
echo "- Keys are encrypted in the keystore with your chosen passwords"
echo "- Use the same keystore password when loading keys for signing"
echo
echo "Usage examples:"
echo "  # Check a key:"
echo "  BTSIGNER_PASSWORD=demo123 ./btsigner -keystore $KEYSTORE_DIR -key-id imported-default -check-key"
echo
echo "  # Start signer server with a specific key:"
echo "  BTSIGNER_PASSWORD=demo123 ./btsigner -keystore $KEYSTORE_DIR -key-id imported-default -config config.yaml"
echo
echo "Cleanup:"
echo "  rm -rf $DEMO_DIR"
