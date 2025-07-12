package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
