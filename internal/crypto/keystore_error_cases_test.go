package crypto

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyStoreErrorCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keystore-test-errors")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	password := []byte("password")

	passwordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes(password), nil
	}

	t.Run("GenerateKeyEmptyID", func(t *testing.T) {
		_, err := ks.GenerateKey("", passwordProvider)
		if err != ErrInvalidKeyID {
			t.Errorf("Expected ErrInvalidKeyID, got %v", err)
		}
	})

	t.Run("LoadKeyEmptyID", func(t *testing.T) {
		_, err := ks.LoadKey("", passwordProvider)
		if err != ErrInvalidKeyID {
			t.Errorf("Expected ErrInvalidKeyID, got %v", err)
		}
	})

	t.Run("GenerateKeyMaxKeys", func(t *testing.T) {
		// Fill up the keystore
		for i := 0; i < 256; i++ {
			ks.metadata.KeyEntries[fmt.Sprintf("key-%d", i)] = "dummy.json"
		}
		ks.metadata.KeyCount = 256

		_, err := ks.GenerateKey("one-too-many", passwordProvider)
		if err != ErrMaxKeysReached {
			t.Errorf("Expected ErrMaxKeysReached, got %v", err)
		}

		// Reset for other tests
		ks.metadata.KeyEntries = make(map[string]string)
		ks.metadata.KeyCount = 0
	})

	t.Run("DeleteKeyRemoveFails", func(t *testing.T) {
		keyID := "test-key-for-delete"
		_, err := ks.GenerateKey(keyID, passwordProvider)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Load the key into memory
		_, err = ks.LoadKey(keyID, passwordProvider)
		if err != nil {
			t.Fatalf("Failed to load key: %v", err)
		}

		// Make the directory read-only to cause os.Remove to fail
		if err := os.Chmod(tmpDir, 0500); err != nil {
			t.Fatalf("Failed to make directory read-only: %v", err)
		}
		defer os.Chmod(tmpDir, 0700) // Cleanup

		err = ks.DeleteKey(keyID)
		if err == nil {
			t.Error("Expected error when deleting from read-only directory, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "operation not permitted") {
			t.Errorf("Expected 'permission denied' or 'operation not permitted' error, got: %v", err)
		}

		// The key should NOT have been unloaded from memory if deletion failed
		if _, loaded := ks.keys[keyID]; !loaded {
			t.Error("Key should not be unloaded from memory if file deletion fails")
		}

		// Cleanup: make writable and delete
		os.Chmod(tmpDir, 0700)
		err = ks.DeleteKey(keyID)
		if err != nil {
			t.Fatalf("Failed to cleanup key: %v", err)
		}
	})

	t.Run("GetKeyInfoInvalidPublicKey", func(t *testing.T) {
		keyID := "key-invalid-pubkey"
		_, err := ks.GenerateKey(keyID, passwordProvider)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Corrupt the public key in the loaded keypair struct
		ks.keys[keyID].publicKey = []byte{1, 2, 3}

		_, _, err = ks.GetKeyInfo(keyID)
		if !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
		}
		// cleanup
		err = ks.DeleteKey(keyID)
		if err != nil {
			t.Fatalf("Failed to cleanup key: %v", err)
		}
	})

	t.Run("GenerateKeySaveMetadataFails", func(t *testing.T) {
		metadataPath := filepath.Join(tmpDir, "metadata.json")
		if err := os.Chmod(metadataPath, 0400); err != nil {
			t.Fatalf("Failed to make metadata file read-only: %v", err)
		}

		_, err := ks.GenerateKey("another-key", passwordProvider)
		if err == nil {
			t.Error("Expected error when saving metadata, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "operation not permitted") {
			t.Errorf("Expected 'permission denied' or 'operation not permitted' error, got: %v", err)
		}

		// cleanup
		if err := os.Chmod(metadataPath, 0600); err != nil {
			t.Fatalf("Failed to make metadata file writable: %v", err)
		}
		// we need to remove the key file that was created before the metadata save failed
		keyFilename := fmt.Sprintf("key_%s.json", "another-key")
		keyPath := filepath.Join(tmpDir, keyFilename)
		os.Remove(keyPath)
		// also remove from metadata in memory
		delete(ks.metadata.KeyEntries, "another-key")
	})

	t.Run("LoadKeyCorruptedFile", func(t *testing.T) {
		keyID := "corrupted-key"
		keyFilename := fmt.Sprintf("key_%s.json", keyID)
		keyPath := filepath.Join(tmpDir, keyFilename)

		// Create a corrupted key file
		if err := os.WriteFile(keyPath, []byte("corrupted"), 0600); err != nil {
			t.Fatalf("Failed to write corrupted key file: %v", err)
		}

		// Add to metadata so LoadKey can find it
		ks.metadata.KeyEntries[keyID] = keyFilename
		ks.metadata.KeyCount++

		_, err := ks.LoadKey(keyID, passwordProvider)
		if err == nil {
			t.Error("Expected error when loading corrupted key, got nil")
		}
		if !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("Expected ErrInvalidKeyFile, got %v", err)
		}

		// cleanup
		delete(ks.metadata.KeyEntries, keyID)
		ks.metadata.KeyCount--
		os.Remove(keyPath)
	})

	t.Run("GenerateKeyGenerateKeyFileFails", func(t *testing.T) {
		// Make the base directory read-only
		if err := os.Chmod(tmpDir, 0500); err != nil {
			t.Fatalf("Failed to make temp dir read-only: %v", err)
		}

		_, err := ks.GenerateKey("key-in-readonly-dir", passwordProvider)
		if err == nil {
			t.Error("Expected error when generating key in read-only dir, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "operation not permitted") {
			t.Errorf("Expected 'permission denied' or 'operation not permitted' error, got: %v", err)
		}

		// cleanup
		if err := os.Chmod(tmpDir, 0700); err != nil {
			t.Fatalf("Failed to make temp dir writable: %v", err)
		}
	})
}
