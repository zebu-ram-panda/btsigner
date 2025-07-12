package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ChainSafe/go-schnorrkel"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

var (
	ErrKeyIDNotFound  = errors.New("key ID not found")
	ErrKeyIDExists    = errors.New("key ID already exists")
	ErrMaxKeysReached = errors.New("maximum number of keys reached (256)")
	ErrInvalidKeyID   = errors.New("invalid key ID")
)

// KeyStoreMetadata holds metadata about the keys in the store
type KeyStoreMetadata struct {
	Version    int               `json:"version"`
	KeyCount   int               `json:"key_count"`
	KeyEntries map[string]string `json:"key_entries"` // Maps key ID to filename
}

// KeyStore manages multiple Sr25519KeyPair instances
type KeyStore struct {
	basePath string
	metadata KeyStoreMetadata
	keys     map[string]*Sr25519KeyPair
	mu       sync.RWMutex
}

// NewKeyStore creates a new key store at the specified directory
func NewKeyStore(basePath string) (*KeyStore, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	metadataPath := filepath.Join(basePath, "metadata.json")
	metadata := KeyStoreMetadata{
		Version:    1,
		KeyCount:   0,
		KeyEntries: make(map[string]string),
	}

	// Try to load existing metadata
	if _, err := os.Stat(metadataPath); err == nil {
		metadataPath = filepath.Clean(metadataPath)
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read metadata: %w", err)
		}

		if err := json.Unmarshal(data, &metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	} else {
		// Create new metadata file
		data, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}

		if err := os.WriteFile(metadataPath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed to write metadata: %w", err)
		}
	}

	return &KeyStore{
		basePath: basePath,
		metadata: metadata,
		keys:     make(map[string]*Sr25519KeyPair),
	}, nil
}

// saveMetadata saves the key store metadata to disk
func (ks *KeyStore) saveMetadata() error {
	metadataPath := filepath.Join(ks.basePath, "metadata.json")
	data, err := json.MarshalIndent(ks.metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return os.WriteFile(metadataPath, data, 0600)
}

// GenerateKey generates a new key with the given ID and password
func (ks *KeyStore) GenerateKey(id string, passwordProvider func() (*SecureBytes, error)) (*Sr25519KeyPair, error) {
	if id == "" {
		return nil, ErrInvalidKeyID
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if ID already exists
	if _, exists := ks.metadata.KeyEntries[id]; exists {
		return nil, ErrKeyIDExists
	}

	// Check if we've reached the maximum number of keys (256)
	if len(ks.metadata.KeyEntries) >= 256 {
		return nil, ErrMaxKeysReached
	}

	// Generate key filename
	keyFilename := fmt.Sprintf("key_%s.json", id)
	keyPath := filepath.Join(ks.basePath, keyFilename)

	// Generate the key
	keyPair, err := GenerateKeyFile(keyPath, passwordProvider)
	if err != nil {
		return nil, err
	}

	// Update metadata
	ks.metadata.KeyEntries[id] = keyFilename
	ks.metadata.KeyCount = len(ks.metadata.KeyEntries)

	// Save metadata
	if err := ks.saveMetadata(); err != nil {
		return nil, err
	}

	// Store in memory
	ks.keys[id] = keyPair

	return keyPair, nil
}

// LoadKey loads a key with the given ID and password
func (ks *KeyStore) LoadKey(id string, passwordProvider func() (*SecureBytes, error)) (*Sr25519KeyPair, error) {
	if id == "" {
		return nil, ErrInvalidKeyID
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if already loaded
	if keyPair, exists := ks.keys[id]; exists {
		return keyPair, nil
	}

	// Check if ID exists in metadata
	keyFilename, exists := ks.metadata.KeyEntries[id]
	if !exists {
		return nil, ErrKeyIDNotFound
	}

	// Load the key
	keyPath := filepath.Join(ks.basePath, keyFilename)
	keyPair, err := LoadSr25519KeyPair(keyPath, passwordProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Store in memory
	ks.keys[id] = keyPair

	return keyPair, nil
}

// UnloadKey removes a key from memory
func (ks *KeyStore) UnloadKey(id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keyPair, exists := ks.keys[id]
	if !exists {
		return nil // Already unloaded
	}

	// Zero the key
	if err := keyPair.Zero(); err != nil {
		return err
	}

	// Remove from memory
	delete(ks.keys, id)

	return nil
}

// DeleteKey permanently deletes a key from disk
func (ks *KeyStore) DeleteKey(id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if ID exists in metadata
	keyFilename, exists := ks.metadata.KeyEntries[id]
	if !exists {
		return ErrKeyIDNotFound
	}

	// Delete the key file
	keyPath := filepath.Join(ks.basePath, keyFilename)
	if err := os.Remove(keyPath); err != nil {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	// Unload from memory if loaded
	if keyPair, loaded := ks.keys[id]; loaded {
		if err := keyPair.Zero(); err != nil {
			return err
		}
		delete(ks.keys, id)
	}

	// Update metadata
	delete(ks.metadata.KeyEntries, id)
	ks.metadata.KeyCount = len(ks.metadata.KeyEntries)

	// Save metadata
	return ks.saveMetadata()
}

// ListKeyIDs returns a list of all key IDs in the store
func (ks *KeyStore) ListKeyIDs() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	ids := make([]string, 0, len(ks.metadata.KeyEntries))
	for id := range ks.metadata.KeyEntries {
		ids = append(ids, id)
	}

	return ids
}

// GetKeyInfo returns information about a key
func (ks *KeyStore) GetKeyInfo(id string) ([]byte, string, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keyPair, exists := ks.keys[id]
	if !exists {
		return nil, "", ErrKeyIDNotFound
	}

	pubKey := keyPair.PublicKey()
	ss58Addr, err := PublicKeyToSS58(pubKey)
	if err != nil {
		return pubKey, "", err
	}

	return pubKey, ss58Addr, nil
}

// Close unloads all keys from memory
func (ks *KeyStore) Close() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var lastErr error
	for id, keyPair := range ks.keys {
		if err := keyPair.Zero(); err != nil {
			lastErr = err
		}
		delete(ks.keys, id)
	}

	return lastErr
}

// BitTensorPublicKey represents the structure of coldkeypub.txt
type BitTensorPublicKey struct {
	AccountID   string `json:"accountId"`
	PublicKey   string `json:"publicKey"`
	SS58Address string `json:"ss58Address"`
}

// ImportKey imports a private key from bittensor wallet files
func (ks *KeyStore) ImportKey(id string, coldkeyPath string, coldkeyPubPath string, coldkeyPasswordProvider func() (*SecureBytes, error), keystorePasswordProvider func() (*SecureBytes, error)) (*Sr25519KeyPair, error) {
	if id == "" {
		return nil, ErrInvalidKeyID
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if ID already exists
	if _, exists := ks.metadata.KeyEntries[id]; exists {
		return nil, ErrKeyIDExists
	}

	// Check if we've reached the maximum number of keys (256)
	if len(ks.metadata.KeyEntries) >= 256 {
		return nil, ErrMaxKeysReached
	}

	// Read the coldkey file
	coldkeyData, err := os.ReadFile(coldkeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read coldkey file: %w", err)
	}

	// Read the coldkeypub.txt file
	coldkeyPubData, err := os.ReadFile(coldkeyPubPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read coldkeypub file: %w", err)
	}

	// Parse the public key file
	var pubKeyData BitTensorPublicKey
	if err := json.Unmarshal(coldkeyPubData, &pubKeyData); err != nil {
		return nil, fmt.Errorf("failed to parse coldkeypub.txt: %w", err)
	}

	// Process the coldkey file based on its format
	var keypairData []byte
	if ks.isBitTensorColdkeyEncrypted(coldkeyData) {
		// Decrypt the encrypted coldkey file
		keypairData, err = ks.decryptBitTensorColdkey(coldkeyData, coldkeyPasswordProvider)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt coldkey: %w", err)
		}
	} else {
		// Use the plaintext coldkey file directly
		keypairData = coldkeyData
	}

	// Parse the keypair data
	var keypairJSON map[string]interface{}
	if err := json.Unmarshal(keypairData, &keypairJSON); err != nil {
		return nil, fmt.Errorf("failed to parse keypair data: %w", err)
	}

	// Extract the private key
	privateKeyHex, ok := keypairJSON["privateKey"].(string)
	if !ok {
		return nil, fmt.Errorf("privateKey not found in keypair data")
	}

	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Decode the private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Convert to Sr25519 format
	// BitTensor uses 64-byte Ed25519 private keys, but schnorrkel expects 32-byte mini secret keys
	// Take the first 32 bytes as the mini secret key
	if len(privateKeyBytes) == 64 {
		privateKeyBytes = privateKeyBytes[:32]
	} else if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32 or 64 bytes, got %d", len(privateKeyBytes))
	}

	// Create Sr25519 keypair
	keyPair, err := ks.createSr25519KeyPairFromBytes(privateKeyBytes, pubKeyData.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Sr25519 keypair: %w", err)
	}

	// Save the imported key to the keystore
	keyFilename := fmt.Sprintf("key_%s.json", id)
	keyPath := filepath.Join(ks.basePath, keyFilename)

	// Encrypt and save the key
	if err := ks.saveImportedKey(keyPath, keyPair, keystorePasswordProvider); err != nil {
		return nil, fmt.Errorf("failed to save imported key: %w", err)
	}

	// Update metadata
	ks.metadata.KeyEntries[id] = keyFilename
	ks.metadata.KeyCount = len(ks.metadata.KeyEntries)

	// Save metadata
	if err := ks.saveMetadata(); err != nil {
		return nil, err
	}

	// Store in memory
	ks.keys[id] = keyPair

	return keyPair, nil
}

// isBitTensorColdkeyEncrypted checks if a coldkey file is encrypted
func (ks *KeyStore) isBitTensorColdkeyEncrypted(data []byte) bool {
	// Check for NaCl encryption prefix
	return strings.HasPrefix(string(data), "$NACL")
}

// decryptBitTensorColdkey decrypts a BitTensor coldkey file using NaCl
func (ks *KeyStore) decryptBitTensorColdkey(data []byte, passwordProvider func() (*SecureBytes, error)) ([]byte, error) {
	// BitTensor uses NaCl encryption with a fixed salt
	const naclSalt = "\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1"

	// Check if it's a NaCl encrypted file
	if !strings.HasPrefix(string(data), "$NACL") {
		return nil, fmt.Errorf("not a NaCl encrypted file")
	}

	// Remove the $NACL prefix
	encryptedData := data[5:]

	// Get the password
	password, err := passwordProvider()
	if err != nil {
		return nil, err
	}
	defer password.Zero()

	// Derive the key using scrypt (similar to BitTensor's approach)
	key, err := scrypt.Key(password.Bytes(), []byte(naclSalt), 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// The first 24 bytes are the nonce
	if len(encryptedData) < 24 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	var nonce [24]byte
	copy(nonce[:], encryptedData[:24])

	var secretKey [32]byte
	copy(secretKey[:], key)

	// Decrypt the data
	decrypted, ok := secretbox.Open(nil, encryptedData[24:], &nonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt data: invalid password or corrupted data")
	}

	return decrypted, nil
}

// createSr25519KeyPairFromBytes creates an Sr25519KeyPair from raw bytes
func (ks *KeyStore) createSr25519KeyPairFromBytes(privateKeyBytes []byte, publicKeyHex string) (*Sr25519KeyPair, error) {
	// Remove 0x prefix if present
	publicKeyHex = strings.TrimPrefix(publicKeyHex, "0x")

	// Decode the public key
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Create schnorrkel secret key from the raw bytes
	var miniSecretKey [32]byte
	copy(miniSecretKey[:], privateKeyBytes)
	secretKey, err := schnorrkel.NewMiniSecretKeyFromRaw(miniSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Create the keypair
	keyPair := &Sr25519KeyPair{
		secretKey:       secretKey,
		publicKey:       publicKeyBytes,
		privateKeyBytes: privateKeyBytes,
	}

	return keyPair, nil
}

// saveImportedKey saves an imported key to the keystore format
func (ks *KeyStore) saveImportedKey(path string, keyPair *Sr25519KeyPair, passwordProvider func() (*SecureBytes, error)) error {
	// Generate salt for key derivation
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	password, err := passwordProvider()
	if err != nil {
		return err
	}
	defer password.Zero()

	// Derive encryption key from password
	key := argon2.IDKey(password.Bytes(), salt, 1, 64*1024, 4, 32)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Encrypt the private key
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nil, nonce, keyPair.privateKeyBytes, nil)

	// Create key file
	keyFile := KeyFile{
		PublicKey:  keyPair.publicKey,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
		Version:    1,
	}

	// Write to file
	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}
