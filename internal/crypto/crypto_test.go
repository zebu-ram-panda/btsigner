package crypto

import (
	"os"
	"testing"
)

const (
	testPassword = "test-password"
	testKeyPath  = "test_key.json"
)

func TestKeyGeneration(t *testing.T) {
	// Generate a key
	keyPair, err := GenerateKeyFile(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Check that the key was created
	if _, err := os.Stat(testKeyPath); os.IsNotExist(err) {
		t.Fatalf("Key file was not created: %v", err)
	}

	// Check that the public key is valid
	pubKey := keyPair.PublicKey()
	if len(pubKey) == 0 {
		t.Error("Public key is empty")
	}

	// Test SS58 address generation
	ss58Addr, err := PublicKeyToSS58(pubKey)
	if err != nil {
		t.Fatalf("Failed to convert public key to SS58: %v", err)
	}

	if ss58Addr == "" {
		t.Error("SS58 address is empty")
	}
}

func TestKeyLoadingAndSigning(t *testing.T) {
	// Generate a key
	originalKeyPair, err := GenerateKeyFile(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Load the key
	loadedKeyPair, err := LoadSr25519KeyPair(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Check that the public keys match
	originalPubKey := originalKeyPair.PublicKey()
	loadedPubKey := loadedKeyPair.PublicKey()

	if len(originalPubKey) != len(loadedPubKey) {
		t.Errorf("Public key length mismatch: %d vs %d", len(originalPubKey), len(loadedPubKey))
	}

	for i := range originalPubKey {
		if originalPubKey[i] != loadedPubKey[i] {
			t.Errorf("Public key mismatch at index %d: %d vs %d", i, originalPubKey[i], loadedPubKey[i])
		}
	}

	// Test signing
	message := []byte("test message to sign")

	sig1, err := originalKeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with original key: %v", err)
	}

	sig2, err := loadedKeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with loaded key: %v", err)
	}

	// Signatures will be different each time due to the random nonce in sr25519
	// So we just check that they're non-empty
	if len(sig1) == 0 {
		t.Error("Signature from original key is empty")
	}

	if len(sig2) == 0 {
		t.Error("Signature from loaded key is empty")
	}
}

func TestInvalidPassword(t *testing.T) {
	// Generate a key
	_, err := GenerateKeyFile(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Try to load with wrong password
	_, err = LoadSr25519KeyPair(testKeyPath, []byte("wrong-password"))
	if err == nil {
		t.Error("Expected error when loading with wrong password, got nil")
	}
}

func TestKeyZeroing(t *testing.T) {
	// Generate a key
	keyPair, err := GenerateKeyFile(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Test that we can sign before zeroing
	message := []byte("test message to sign")
	sig, err := keyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with key before zeroing: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Signature is empty")
	}

	// Zero the key
	err = keyPair.Zero()
	if err != nil {
		t.Fatalf("Failed to zero key: %v", err)
	}

	// In Go, we can't reliably test that the key is actually zeroed
	// due to garbage collection, so we'll just check that Zero() doesn't error
	t.Log("Key zeroed successfully")
}
