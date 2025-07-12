package signer

import (
	"context"
	"errors"

	"github.com/bittensor-lab/btsigner/internal/crypto"
)

var (
	ErrInvalidPayload = errors.New("invalid payload")
	ErrSigningFailed  = errors.New("signing failed")
	ErrKeyNotLoaded   = errors.New("key not loaded")
)

// Signer defines the interface for signing operations
type Signer interface {
	// GetPublicKey returns the public key as bytes and SS58 address
	GetPublicKey() ([]byte, string, error)

	// Sign signs a payload with the private key
	Sign(ctx context.Context, payload []byte) ([]byte, error)

	// Close releases any resources held by the signer
	Close() error
}

// Sr25519Signer implements the Signer interface using sr25519
type Sr25519Signer struct {
	keyPair *crypto.Sr25519KeyPair
}


// NewSr25519Signer creates a new sr25519 signer
func NewSr25519Signer(keyPath string, password []byte) (*Sr25519Signer, error) {
	keyPair, err := crypto.LoadSr25519KeyPair(keyPath, func() (*crypto.SecureBytes, error) {
		return crypto.NewSecureBytes(password), nil
	})
	if err != nil {
		return nil, err
	}

	return &Sr25519Signer{
		keyPair: keyPair,
	}, nil
}

// GetPublicKey implements Signer.GetPublicKey
func (s *Sr25519Signer) GetPublicKey() ([]byte, string, error) {
	if s.keyPair == nil {
		return nil, "", ErrKeyNotLoaded
	}

	pubKey := s.keyPair.PublicKey()
	ss58Addr, err := crypto.PublicKeyToSS58(pubKey)
	if err != nil {
		return pubKey, "", err
	}

	return pubKey, ss58Addr, nil
}

// Sign implements Signer.Sign
func (s *Sr25519Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if s.keyPair == nil {
		return nil, ErrKeyNotLoaded
	}

	if len(payload) == 0 {
		return nil, ErrInvalidPayload
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	signature, err := s.keyPair.Sign(payload)
	if err != nil {
		return nil, ErrSigningFailed
	}

	return signature, nil
}

// Close implements Signer.Close
func (s *Sr25519Signer) Close() error {
	if s.keyPair != nil {
		return s.keyPair.Zero()
	}
	return nil
}
