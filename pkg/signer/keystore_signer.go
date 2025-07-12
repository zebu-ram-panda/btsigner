package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/bittensor-lab/btsigner/internal/crypto"
)

var (
	ErrNoDefaultKeyID = errors.New("no default key ID specified")
)

// KeyStoreSigner implements the Signer interface using a KeyStore
type KeyStoreSigner struct {
	keyStore     *crypto.KeyStore
	defaultKeyID string
}

// NewKeyStoreSigner creates a new signer that uses a KeyStore
func NewKeyStoreSigner(keyStorePath string) (*KeyStoreSigner, error) {
	keyStore, err := crypto.NewKeyStore(keyStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	return &KeyStoreSigner{
		keyStore: keyStore,
	}, nil
}

// SetDefaultKeyID sets the default key ID to use for signing
func (s *KeyStoreSigner) SetDefaultKeyID(id string) {
	s.defaultKeyID = id
}

// DefaultKeyID returns the current default key ID
func (s *KeyStoreSigner) DefaultKeyID() string {
	return s.defaultKeyID
}


// LoadKey loads a key with the given ID and password
func (s *KeyStoreSigner) LoadKey(id string, password []byte) error {
	_, err := s.keyStore.LoadKey(id, func() (*crypto.SecureBytes, error) {
		return crypto.NewSecureBytes(password), nil
	})
	if err != nil {
		return err
	}

	// If this is the first key loaded, set it as default
	if s.defaultKeyID == "" {
		s.defaultKeyID = id
	}

	return nil
}

// GenerateKey generates a new key with the given ID and password
func (s *KeyStoreSigner) GenerateKey(id string, password []byte) error {
	_, err := s.keyStore.GenerateKey(id, func() (*crypto.SecureBytes, error) {
		return crypto.NewSecureBytes(password), nil
	})
	if err != nil {
		return err
	}

	// If this is the first key generated, set it as default
	if s.defaultKeyID == "" {
		s.defaultKeyID = id
	}

	return nil
}

// UnloadKey unloads a key from memory
func (s *KeyStoreSigner) UnloadKey(id string) error {
	return s.keyStore.UnloadKey(id)
}

// DeleteKey permanently deletes a key
func (s *KeyStoreSigner) DeleteKey(id string) error {
	return s.keyStore.DeleteKey(id)
}

// ListKeyIDs returns a list of all key IDs in the store
func (s *KeyStoreSigner) ListKeyIDs() []string {
	return s.keyStore.ListKeyIDs()
}

// GetPublicKey implements Signer.GetPublicKey using the default key
func (s *KeyStoreSigner) GetPublicKey() ([]byte, string, error) {
	if s.defaultKeyID == "" {
		return nil, "", ErrNoDefaultKeyID
	}

	return s.GetPublicKeyByID(s.defaultKeyID)
}

// GetPublicKeyByID returns the public key for a specific key ID
func (s *KeyStoreSigner) GetPublicKeyByID(id string) ([]byte, string, error) {
	return s.keyStore.GetKeyInfo(id)
}

// Sign implements Signer.Sign using the default key
func (s *KeyStoreSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if s.defaultKeyID == "" {
		return nil, ErrNoDefaultKeyID
	}

	return s.SignWithKey(ctx, s.defaultKeyID, payload)
}

// SignWithKey signs a payload with a specific key
func (s *KeyStoreSigner) SignWithKey(ctx context.Context, id string, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, ErrInvalidPayload
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Get the key
	keyPair, err := s.keyStore.LoadKey(id, nil) // Password not needed as key is already loaded
	if err != nil {
		return nil, err
	}

	// Sign the payload
	signature, err := keyPair.Sign(payload)
	if err != nil {
		return nil, ErrSigningFailed
	}

	return signature, nil
}

// Close implements Signer.Close
func (s *KeyStoreSigner) Close() error {
	return s.keyStore.Close()
}
