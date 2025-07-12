package crypto

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testPassword = "test-password"
	testKeyPath  = "test_key.json"
)

func TestKeyGeneration(t *testing.T) {
	// Generate a key
	keyPair, err := GenerateKeyFile(testKeyPath, func() (*SecureBytes, error) {
		return NewSecureBytes([]byte(testPassword)), nil
	})
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

func TestPublicKeyToSS58Error(t *testing.T) {
	// Test SS58 address generation with invalid public key length
	_, err := PublicKeyToSS58([]byte{1, 2, 3}) // Invalid length
	if err == nil {
		t.Error("Expected error for invalid public key length, got nil")
	}
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("Expected error to be or wrap ErrInvalidPublicKey, got %v", err)
	}
}

func TestKeyLoadingAndSigning(t *testing.T) {
	// Generate a key
	originalKeyPair, err := GenerateKeyFile(testKeyPath, func() (*SecureBytes, error) {
		return NewSecureBytes([]byte(testPassword)), nil
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Load the key
	loadedKeyPair, err := LoadSr25519KeyPair(testKeyPath, func() (*SecureBytes, error) {
		return NewSecureBytes([]byte(testPassword)), nil
	})
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
	_, err := GenerateKeyFile(testKeyPath, func() (*SecureBytes, error) {
		return NewSecureBytes([]byte(testPassword)), nil
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Try to load with wrong password
	_, err = LoadSr25519KeyPair(testKeyPath, func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("wrong-password")), nil
	})
	if err == nil {
		t.Error("Expected error when loading with wrong password, got nil")
	}
}

func TestKeyZeroing(t *testing.T) {
	// Generate a key
	keyPair, err := GenerateKeyFile(testKeyPath, func() (*SecureBytes, error) {
		return NewSecureBytes([]byte(testPassword)), nil
	})
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

func TestLoadSr25519KeyPairErrorCases(t *testing.T) {
	// Test loading a non-existent key file
	t.Run("NonExistentFile", func(t *testing.T) {
		_, err := LoadSr25519KeyPair("/nonexistent/path/key.json", func() (*SecureBytes, error) {
			return NewSecureBytes([]byte(testPassword)), nil
		})
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "failed to read key file") {
			t.Errorf("Expected 'failed to read key file' or 'os.ErrNotExist' error, got: %v", err)
		}
	})

	// Test loading a key file with invalid JSON
	t.Run("InvalidJSON", func(t *testing.T) {
		invalidJsonPath := "invalid_key.json"
		if err := os.WriteFile(invalidJsonPath, []byte("invalid json"), 0600); err != nil {
			t.Fatalf("Failed to write invalid JSON file: %v", err)
		}
		defer os.Remove(invalidJsonPath)

		_, err := LoadSr25519KeyPair(invalidJsonPath, func() (*SecureBytes, error) {
			return NewSecureBytes([]byte(testPassword)), nil
		})
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
		if !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("Expected ErrInvalidKeyFile, got: %v", err)
		}
	})

	// Test loading a key file with corrupted ciphertext (simulating decryption failure)
	t.Run("CorruptedCiphertext", func(t *testing.T) {
		// Generate a valid key file first
		_, err := GenerateKeyFile(testKeyPath, func() (*SecureBytes, error) {
			return NewSecureBytes([]byte(testPassword)), nil
		})
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		defer os.Remove(testKeyPath)

		// Read the key file, corrupt the ciphertext, and write it back
		data, err := os.ReadFile(testKeyPath)
		if err != nil {
			t.Fatalf("Failed to read key file: %v", err)
		}
		var keyFile KeyFile
		if err := json.Unmarshal(data, &keyFile); err != nil {
			t.Fatalf("Failed to unmarshal key file: %v", err)
		}
		keyFile.Ciphertext[0] = ^keyFile.Ciphertext[0] // Corrupt first byte
		corruptedData, _ := json.Marshal(keyFile)
		os.WriteFile(testKeyPath, corruptedData, 0600)

		_, err = LoadSr25519KeyPair(testKeyPath, func() (*SecureBytes, error) {
			return NewSecureBytes([]byte(testPassword)), nil
		})
		if err == nil {
			t.Error("Expected error for corrupted ciphertext, got nil")
		}
		if !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("Expected ErrDecryptFailed, got: %v", err)
		}
	})
}

func TestSr25519KeyPairSignErrorCases(t *testing.T) {
	// Test Sign method with a nil secretKey
	t.Run("SignWithNilSecretKey", func(t *testing.T) {
		kp := &Sr25519KeyPair{
			secretKey: nil, // Simulate a nil secret key
			publicKey: []byte{1, 2, 3},
		}
		message := []byte("test message")
		_, err := kp.Sign(message)
		if err == nil {
			t.Error("Expected error when signing with nil secret key, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "nil secret key") { // Assuming schnorrkel returns an error containing "nil secret key"
			t.Errorf("Expected 'nil secret key' error, got: %v", err)
		}
	})
}

func TestGenerateKeyFileErrorCases(t *testing.T) {
	// Test GenerateKeyFile with invalid path (e.g., read-only directory)
	t.Run("InvalidPath", func(t *testing.T) {
		// Attempt to write to a directory that likely doesn't exist or is read-only
		invalidPath := "/nonexistent_dir/test_key.json"
		_, err := GenerateKeyFile(invalidPath, func() (*SecureBytes, error) {
			return NewSecureBytes([]byte(testPassword)), nil
		})
		if err == nil {
			t.Error("Expected error for invalid path, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("Expected 'no such file or directory' or 'permission denied' error, got: %v", err)
		}
	})
	// Test GenerateKeyFile with a path that causes os.WriteFile to fail (e.g., directory not writable)
	t.Run("WriteFileFailure", func(t *testing.T) {
		// Create a read-only directory
		readOnlyDir := t.TempDir()
		if err := os.Chmod(readOnlyDir, 0500); err != nil {
			t.Fatalf("Failed to chmod directory: %v", err)
		} // Make it read-only
		defer os.Chmod(readOnlyDir, 0700) // Change back to writable for cleanup

		filePath := filepath.Join(readOnlyDir, "test_key.json")
		_, err := GenerateKeyFile(filePath, func() (*SecureBytes, error) {
			return NewSecureBytes([]byte(testPassword)), nil
		})
		if err == nil {
			t.Error("Expected error for write file failure, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("Expected 'permission denied' error, got: %v", err)
		}
	})
}
