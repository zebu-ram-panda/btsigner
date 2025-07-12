package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestImportKey_Plaintext(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create test coldkey (plaintext JSON format)
	coldkeyData := map[string]interface{}{
		"secretPhrase": "test mnemonic phrase for testing purposes only",
		"secretSeed":   "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		"privateKey":   "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		"accountId":    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"publicKey":    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"ss58Address":  "5Test123456789",
	}

	coldkeyPath := filepath.Join(tempDir, "coldkey")
	coldkeyJSON, err := json.Marshal(coldkeyData)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(coldkeyPath, coldkeyJSON, 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Create test coldkeypub.txt
	coldkeyPubData := BitTensorPublicKey{
		AccountID:   "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		PublicKey:   "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		SS58Address: "5Test123456789",
	}

	coldkeyPubPath := filepath.Join(tempDir, "coldkeypub.txt")
	coldkeyPubJSON, err := json.Marshal(coldkeyPubData)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(coldkeyPubPath, coldkeyPubJSON, 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Create keystore
	keystorePath := filepath.Join(tempDir, "keystore")
	keystore, err := NewKeyStore(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	defer keystore.Close()

	// Test importing the key
	keyID := "test-key"
	coldkeyPasswordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("")), nil // Empty password for plaintext coldkey
	}
	keystorePasswordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("test-password")), nil
	}

	importedKey, err := keystore.ImportKey(keyID, coldkeyPath, coldkeyPubPath, coldkeyPasswordProvider, keystorePasswordProvider)
	if err != nil {
		t.Fatal(err)
	}

	if importedKey == nil {
		t.Fatal("imported key is nil")
	}

	// Verify the key was imported correctly
	publicKey := importedKey.PublicKey()
	if len(publicKey) == 0 {
		t.Fatal("public key is empty")
	}

	// Verify the key is in the keystore
	keyIDs := keystore.ListKeyIDs()
	found := false
	for _, id := range keyIDs {
		if id == keyID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("imported key not found in keystore")
	}

	// Test loading the imported key
	loadedKey, err := keystore.LoadKey(keyID, keystorePasswordProvider)
	if err != nil {
		t.Fatal(err)
	}

	if loadedKey == nil {
		t.Fatal("loaded key is nil")
	}

	// Verify public keys match
	if string(loadedKey.PublicKey()) != string(importedKey.PublicKey()) {
		t.Fatal("public keys don't match")
	}
}

func TestImportKey_DuplicateID(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create keystore
	keystorePath := filepath.Join(tempDir, "keystore")
	keystore, err := NewKeyStore(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	defer keystore.Close()

	// Generate a key first
	keyID := "test-key"
	passwordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("test-password")), nil
	}

	_, err = keystore.GenerateKey(keyID, passwordProvider)
	if err != nil {
		t.Fatal(err)
	}

	// Create dummy coldkey files
	coldkeyPath := filepath.Join(tempDir, "coldkey")
	coldkeyPubPath := filepath.Join(tempDir, "coldkeypub.txt")

	err = os.WriteFile(coldkeyPath, []byte(`{"privateKey":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(coldkeyPubPath, []byte(`{"publicKey":"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Try to import with the same ID - should fail
	coldkeyPasswordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("")), nil
	}
	keystorePasswordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("test-password")), nil
	}
	_, err = keystore.ImportKey(keyID, coldkeyPath, coldkeyPubPath, coldkeyPasswordProvider, keystorePasswordProvider)
	if err == nil {
		t.Fatal("expected error for duplicate key ID")
	}

	if err != ErrKeyIDExists {
		t.Fatalf("expected ErrKeyIDExists, got %v", err)
	}
}

func TestImportKey_InvalidFiles(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create keystore
	keystorePath := filepath.Join(tempDir, "keystore")
	keystore, err := NewKeyStore(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	defer keystore.Close()

	keyID := "test-key"
	coldkeyPasswordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("")), nil
	}
	keystorePasswordProvider := func() (*SecureBytes, error) {
		return NewSecureBytes([]byte("test-password")), nil
	}

	// Test with non-existent files
	_, err = keystore.ImportKey(keyID, "non-existent-coldkey", "non-existent-coldkeypub", coldkeyPasswordProvider, keystorePasswordProvider)
	if err == nil {
		t.Fatal("expected error for non-existent files")
	}

	// Test with invalid JSON
	invalidColdkeyPath := filepath.Join(tempDir, "invalid-coldkey")
	invalidColdkeyPubPath := filepath.Join(tempDir, "invalid-coldkeypub.txt")

	err = os.WriteFile(invalidColdkeyPath, []byte("invalid json"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(invalidColdkeyPubPath, []byte("invalid json"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = keystore.ImportKey(keyID, invalidColdkeyPath, invalidColdkeyPubPath, coldkeyPasswordProvider, keystorePasswordProvider)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestIsBitTensorColdkeyEncrypted(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create keystore
	keystorePath := filepath.Join(tempDir, "keystore")
	keystore, err := NewKeyStore(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	defer keystore.Close()

	// Test with NaCl encrypted data
	naclData := []byte("$NACL" + "encrypted data here")
	if !keystore.isBitTensorColdkeyEncrypted(naclData) {
		t.Fatal("should detect NaCl encrypted data")
	}

	// Test with plain JSON data
	jsonData := []byte(`{"privateKey": "0x1234567890abcdef"}`)
	if keystore.isBitTensorColdkeyEncrypted(jsonData) {
		t.Fatal("should not detect plain JSON as encrypted")
	}

	// Test with empty data
	emptyData := []byte("")
	if keystore.isBitTensorColdkeyEncrypted(emptyData) {
		t.Fatal("should not detect empty data as encrypted")
	}
}
