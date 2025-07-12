package signer

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
)

func TestKeyStoreSigner(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "keystore-signer-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create keystore signer
	signer, err := NewKeyStoreSigner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}
	defer signer.Close()

	// Check initial state
	t.Run("InitialState", func(t *testing.T) {
		if signer.defaultKeyID != "" {
			t.Errorf("Expected empty default key ID, got %s", signer.defaultKeyID)
		}

		// DefaultKeyID should return empty string initially
		if id := signer.DefaultKeyID(); id != "" {
			t.Errorf("Expected empty default key ID from getter, got %s", id)
		}

		// ListKeyIDs should return empty slice initially
		ids := signer.ListKeyIDs()
		if len(ids) != 0 {
			t.Errorf("Expected no key IDs initially, got %d", len(ids))
		}
	})

	// Generate keys for testing
	var key1ID = "test_key_1"
	var key2ID = "test_key_2"
	var password = []byte("test_password")

	t.Run("GenerateKey", func(t *testing.T) {
		// Generate first key
		err := signer.GenerateKey(key1ID, password)
		if err != nil {
			t.Fatalf("Failed to generate first key: %v", err)
		}

		// First key should become the default
		if signer.DefaultKeyID() != key1ID {
			t.Errorf("Expected default key ID %s, got %s", key1ID, signer.DefaultKeyID())
		}

		// Generate second key
		err = signer.GenerateKey(key2ID, password)
		if err != nil {
			t.Fatalf("Failed to generate second key: %v", err)
		}

		// Default key should still be the first one
		if signer.DefaultKeyID() != key1ID {
			t.Errorf("Expected default key ID to remain %s, got %s", key1ID, signer.DefaultKeyID())
		}

		// ListKeyIDs should return both keys
		ids := signer.ListKeyIDs()
		if len(ids) != 2 {
			t.Errorf("Expected 2 key IDs, got %d", len(ids))
		}
	})

	t.Run("SetDefaultKeyID", func(t *testing.T) {
		// Change default key
		signer.SetDefaultKeyID(key2ID)

		if signer.DefaultKeyID() != key2ID {
			t.Errorf("Expected default key ID %s after setting, got %s", key2ID, signer.DefaultKeyID())
		}
	})

	t.Run("GetPublicKeyByID", func(t *testing.T) {
		// Get public key for specific ID
		pubKey1, ss58_1, err := signer.GetPublicKeyByID(key1ID)
		if err != nil {
			t.Fatalf("Failed to get key1 info: %v", err)
		}

		if len(pubKey1) != 32 {
			t.Errorf("Expected 32-byte public key, got %d bytes", len(pubKey1))
		}
		if ss58_1 == "" {
			t.Error("Expected non-empty SS58 address")
		}

		// Get public key for default key
		pubKey2, ss58_2, err := signer.GetPublicKey()
		if err != nil {
			t.Fatalf("Failed to get default key info: %v", err)
		}

		// Should match key2 since it's now the default
		pubKeyByID, ss58ByID, err := signer.GetPublicKeyByID(key2ID)
		if err != nil {
			t.Fatalf("Failed to get key2 info: %v", err)
		}

		if string(pubKey2) != string(pubKeyByID) {
			t.Error("Public key from GetPublicKey doesn't match GetPublicKeyByID")
		}
		if ss58_2 != ss58ByID {
			t.Error("SS58 address from GetPublicKey doesn't match GetPublicKeyByID")
		}

		// Try with no default key set
		signer.defaultKeyID = ""
		_, _, err = signer.GetPublicKey()
		if err != ErrNoDefaultKeyID {
			t.Errorf("Expected ErrNoDefaultKeyID with no default, got %v", err)
		}
		signer.SetDefaultKeyID(key2ID) // Restore for next tests
	})

	t.Run("LoadKey", func(t *testing.T) {
		// Unload all keys to test loading
		for _, id := range signer.ListKeyIDs() {
			signer.UnloadKey(id)
		}

		// Load a key
		err := signer.LoadKey(key1ID, password)
		if err != nil {
			t.Fatalf("Failed to load key: %v", err)
		}

		// Also load the default key for later signing tests
		err = signer.LoadKey(key2ID, password)
		if err != nil {
			t.Fatalf("Failed to load default key: %v", err)
		}

		// Try with wrong password - first unload the key so password validation is triggered
		if err := signer.UnloadKey(key2ID); err != nil {
			t.Fatalf("Failed to unload key before testing wrong password: %v", err)
		}
		err = signer.LoadKey(key2ID, []byte("wrong_password"))
		if err == nil {
			t.Error("Expected error when loading key with wrong password, got nil")
		}
		// We only expect this to not succeed, but the specific error might vary
		// depending on the crypto implementation
	})

	t.Run("Sign", func(t *testing.T) {
		ctx := context.Background()
		payload := []byte("test message to sign")

		// Make sure keys are loaded
		// We load them in the previous test but let's make sure they're available
		err := signer.LoadKey(key2ID, password) // Load default key again just to be safe
		if err != nil {
			t.Fatalf("Failed to load default key before signing: %v", err)
		}

		err = signer.LoadKey(key1ID, password) // Also load the other key
		if err != nil {
			t.Fatalf("Failed to load key1 before signing: %v", err)
		}

		// Sign with default key
		sig1, err := signer.Sign(ctx, payload)
		if err != nil {
			t.Fatalf("Failed to sign with default key: %v", err)
		}
		if len(sig1) == 0 {
			t.Error("Expected non-empty signature")
		}

		// Sign with specific key
		sig2, err := signer.SignWithKey(ctx, key1ID, payload)
		if err != nil {
			t.Fatalf("Failed to sign with specific key: %v", err)
		}
		if len(sig2) == 0 {
			t.Error("Expected non-empty signature")
		}

		// Signatures should be different for different keys
		if string(sig1) == string(sig2) {
			t.Error("Expected different signatures for different keys")
		}

		// Test with empty payload
		_, err = signer.Sign(ctx, []byte{})
		if err != ErrInvalidPayload {
			t.Errorf("Expected ErrInvalidPayload, got %v", err)
		}

		// Test with specific key and empty payload
		_, err = signer.SignWithKey(ctx, key1ID, []byte{})
		if err != ErrInvalidPayload {
			t.Errorf("Expected ErrInvalidPayload, got %v", err)
		}

		// Test with no default key
		signer.defaultKeyID = ""
		_, err = signer.Sign(ctx, payload)
		if err != ErrNoDefaultKeyID {
			t.Errorf("Expected ErrNoDefaultKeyID, got %v", err)
		}
		signer.SetDefaultKeyID(key2ID) // Restore for next tests

		// Test with non-existent key
		_, err = signer.SignWithKey(ctx, "nonexistent", payload)
		if err == nil {
			t.Error("Expected error signing with non-existent key, got nil")
		}
	})

	t.Run("DeleteKey", func(t *testing.T) {
		// Delete a key
		err := signer.DeleteKey(key1ID)
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}

		// Should only have one key left
		ids := signer.ListKeyIDs()
		if len(ids) != 1 {
			t.Errorf("Expected 1 key ID after deletion, got %d", len(ids))
		}
		if ids[0] != key2ID {
			t.Errorf("Expected remaining key to be %s, got %s", key2ID, ids[0])
		}

		// Try to get deleted key info
		_, _, err = signer.GetPublicKeyByID(key1ID)
		if err == nil {
			t.Error("Expected error getting deleted key info, got nil")
		}
	})

	t.Run("Close", func(t *testing.T) {
		// Close signer
		err := signer.Close()
		if err != nil {
			t.Fatalf("Failed to close signer: %v", err)
		}
	})
}

// TestKeyStoreSignerConcurrentAccess tests concurrent access to KeyStoreSigner
func TestKeyStoreSignerConcurrentAccess(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "keystore-concurrent-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create keystore signer
	signer, err := NewKeyStoreSigner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}
	defer signer.Close()

	// Generate multiple keys for testing
	numKeys := 5
	keyIDs := make([]string, numKeys)
	password := []byte("test_password")

	for i := 0; i < numKeys; i++ {
		keyID := fmt.Sprintf("test_key_%d", i)
		keyIDs[i] = keyID
		
		err := signer.GenerateKey(keyID, password)
		if err != nil {
			t.Fatalf("Failed to generate key %s: %v", keyID, err)
		}
	}

	// Load all keys
	for _, keyID := range keyIDs {
		err := signer.LoadKey(keyID, password)
		if err != nil {
			t.Fatalf("Failed to load key %s: %v", keyID, err)
		}
	}

	// Test concurrent access to defaultKeyID
	const numGoroutines = 20
	const numOperations = 100

	// Test concurrent SetDefaultKeyID and DefaultKeyID
	t.Run("ConcurrentDefaultKeyAccess", func(t *testing.T) {
		var wg sync.WaitGroup
		
		// Start multiple goroutines that set default key
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numOperations; j++ {
					keyID := keyIDs[j%len(keyIDs)]
					signer.SetDefaultKeyID(keyID)
					
					// Read the default key ID
					defaultKeyID := signer.DefaultKeyID()
					if defaultKeyID == "" {
						t.Errorf("Default key ID should not be empty")
					}
					
					// Verify it's one of our keys
					found := false
					for _, validKeyID := range keyIDs {
						if defaultKeyID == validKeyID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Default key ID %s is not one of our keys", defaultKeyID)
					}
				}
			}(i)
		}
		
		wg.Wait()
	})

	// Test concurrent signing operations
	t.Run("ConcurrentSigning", func(t *testing.T) {
		var wg sync.WaitGroup
		ctx := context.Background()
		payload := []byte("test message for concurrent signing")
		
		// Start multiple goroutines that sign concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numOperations; j++ {
					keyID := keyIDs[j%len(keyIDs)]
					
					// Sign with specific key
					signature, err := signer.SignWithKey(ctx, keyID, payload)
					if err != nil {
						t.Errorf("Failed to sign with key %s: %v", keyID, err)
						return
					}
					
					if len(signature) == 0 {
						t.Errorf("Signature should not be empty for key %s", keyID)
					}
				}
			}(i)
		}
		
		wg.Wait()
	})

	// Test concurrent sign with default key
	t.Run("ConcurrentSignWithDefault", func(t *testing.T) {
		var wg sync.WaitGroup
		ctx := context.Background()
		payload := []byte("test message for concurrent default signing")
		
		// Set a default key
		signer.SetDefaultKeyID(keyIDs[0])
		
		// Start multiple goroutines that sign with default key
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numOperations; j++ {
					signature, err := signer.Sign(ctx, payload)
					if err != nil {
						t.Errorf("Failed to sign with default key: %v", err)
						return
					}
					
					if len(signature) == 0 {
						t.Errorf("Signature should not be empty")
					}
				}
			}(i)
		}
		
		wg.Wait()
	})

	// Test mixed concurrent operations
	t.Run("MixedConcurrentOperations", func(t *testing.T) {
		var wg sync.WaitGroup
		ctx := context.Background()
		payload := []byte("test message for mixed operations")
		
		// Start goroutines that do different operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numOperations; j++ {
					keyID := keyIDs[j%len(keyIDs)]
					
					switch j % 4 {
					case 0:
						// Set default key
						signer.SetDefaultKeyID(keyID)
					case 1:
						// Get default key
						defaultKeyID := signer.DefaultKeyID()
						if defaultKeyID == "" {
							t.Errorf("Default key ID should not be empty")
						}
					case 2:
						// Sign with specific key
						_, err := signer.SignWithKey(ctx, keyID, payload)
						if err != nil {
							t.Errorf("Failed to sign with key %s: %v", keyID, err)
						}
					case 3:
						// Sign with default key
						_, err := signer.Sign(ctx, payload)
						if err != nil {
							t.Errorf("Failed to sign with default key: %v", err)
						}
					}
				}
			}(i)
		}
		
		wg.Wait()
	})
}
