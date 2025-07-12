package signer

import (
	"context"
	"os"
	"testing"

	"github.com/bittensor-lab/btsigner/internal/crypto"
)

const (
	testPassword = "test-password"
	testKeyPath  = "test_key.json"
)

func TestSr25519Signer(t *testing.T) {
	// Setup: create a test key
	_, err := crypto.GenerateKeyFile(testKeyPath, func() (*crypto.SecureBytes, error) {
		return crypto.NewSecureBytes([]byte(testPassword)), nil
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer os.Remove(testKeyPath)

	// Create signer
	s, err := NewSr25519Signer(testKeyPath, []byte(testPassword))
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	defer s.Close()

	// Test GetPublicKey
	pubKey, ss58Addr, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	if len(pubKey) == 0 {
		t.Error("Public key is empty")
	}

	if ss58Addr == "" {
		t.Error("SS58 address is empty")
	}

	// Test Sign
	payload := []byte("test message to sign")
	ctx := context.Background()

	signature, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Test with empty payload
	_, err = s.Sign(ctx, []byte{})
	if err != ErrInvalidPayload {
		t.Errorf("Expected ErrInvalidPayload, got: %v", err)
	}

	// Test with canceled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Sign(cancelCtx, payload)
	if err == nil {
		t.Error("Expected error with canceled context, got nil")
	}

	t.Run("Close with nil keyPair", func(t *testing.T) {
		// Create a signer with a nil keyPair to test the Close method's nil check
		nilSigner := &Sr25519Signer{keyPair: nil}
		err := nilSigner.Close()
		if err != nil {
			t.Errorf("Expected nil error when closing with nil keyPair, got %v", err)
		}
	})
}
