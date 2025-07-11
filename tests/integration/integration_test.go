package integration

import (
	"context"
	"os"
	"testing"

	"github.com/bittensor-lab/btsigner/internal/crypto"
	"github.com/bittensor-lab/btsigner/pkg/signer"
)

const (
	testPassword = "test-password"
	testKeyPath  = "test_key.json"
)

// TestSr25519SignerIntegration tests the Sr25519Signer component
func TestSr25519SignerIntegration(t *testing.T) {
	// Skip this test in CI environments
	if os.Getenv("CI") != "" {
		t.Skip("Skipping integration test in CI environment")
	}

	// Generate a key
	keyPair, err := crypto.GenerateKeyFile(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Create signer
	signerImpl, err := signer.NewSr25519Signer(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	defer signerImpl.Close()

	// Get public key
	pubKey, ss58Addr, err := signerImpl.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	// Check public key matches the one from the key pair
	keyPairPubKey := keyPair.PublicKey()
	if len(pubKey) != len(keyPairPubKey) {
		t.Errorf("Public key length mismatch: %d vs %d", len(pubKey), len(keyPairPubKey))
	}

	for i := range pubKey {
		if pubKey[i] != keyPairPubKey[i] {
			t.Errorf("Public key mismatch at index %d: %d vs %d", i, pubKey[i], keyPairPubKey[i])
		}
	}

	if ss58Addr == "" {
		t.Error("SS58 address is empty")
	}

	// Test signing
	payload := []byte("test message to sign")
	ctx := context.Background()

	signature, err := signerImpl.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	t.Logf("Integration test passed: pubKey=%x, ss58=%s, signature=%x", pubKey, ss58Addr, signature)
}
