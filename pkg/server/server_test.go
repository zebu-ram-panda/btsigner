package server

import (
	"context"
	"os"
	"testing"
	"errors"

	"github.com/bittensor-lab/btsigner/internal/config"
	"github.com/bittensor-lab/btsigner/pkg/signer"
	pb "github.com/bittensor-lab/btsigner/proto/signer/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// MockSigner implements the signer.Signer interface for testing
type MockSigner struct {
	pubKey    []byte
	ss58Addr  string
	signature []byte
	err       error
}

func (m *MockSigner) GetPublicKey() ([]byte, string, error) {
	return m.pubKey, m.ss58Addr, m.err
}

func (m *MockSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	return m.signature, m.err
}

func (m *MockSigner) Close() error {
	return nil
}

// MockKeyStoreSigner implements the signer.Signer and KeyStoreSigner interfaces for testing
type MockKeyStoreSigner struct {
	*MockSigner
	mockListKeyIDs     func() []string
	mockDefaultKeyID   func() string
	mockGetPublicKeyByID func(id string) ([]byte, string, error)
	mockSignWithKey    func(ctx context.Context, id string, payload []byte) ([]byte, error)
}

func (m *MockKeyStoreSigner) ListKeyIDs() []string {
	if m.mockListKeyIDs != nil {
		return m.mockListKeyIDs()
	}
	return []string{}
}

func (m *MockKeyStoreSigner) DefaultKeyID() string {
	if m.mockDefaultKeyID != nil {
		return m.mockDefaultKeyID()
	}
	return ""
}

func (m *MockKeyStoreSigner) GetPublicKeyByID(id string) ([]byte, string, error) {
	if m.mockGetPublicKeyByID != nil {
		return m.mockGetPublicKeyByID(id)
	}
	return nil, "", nil
}

func (m *MockKeyStoreSigner) SignWithKey(ctx context.Context, id string, payload []byte) ([]byte, error) {
	if m.mockSignWithKey != nil {
		return m.mockSignWithKey(ctx, id, payload)
	}
	return nil, nil
}

func TestServerGetPublicKey(t *testing.T) {
	// Create logger
	logger, _ := zap.NewDevelopment()

	// Test with a regular signer
	t.Run("RegularSigner", func(t *testing.T) {
		// Create a mock signer
		mockSigner := &MockSigner{
			pubKey:   []byte("mock-public-key"),
			ss58Addr: "5mock-ss58-address",
			err:      nil,
		}

		// Create server
		srv := NewServer(mockSigner, config.DefaultConfig(), logger)

		// Test GetPublicKey
		resp, err := srv.GetPublicKey(context.Background(), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("GetPublicKey failed: %v", err)
		}

		if string(resp.PublicKey) != "mock-public-key" {
			t.Errorf("Expected public key 'mock-public-key', got '%s'", string(resp.PublicKey))
		}

		if resp.Ss58Address != "5mock-ss58-address" {
			t.Errorf("Expected SS58 address '5mock-ss58-address', got '%s'", resp.Ss58Address)
		}
		if resp.KeyId != "" {
			t.Errorf("Expected empty KeyId, got %s", resp.KeyId)
		}
	})

	// Test with a KeyStoreSigner
	t.Run("KeyStoreSigner", func(t *testing.T) {
		// Create a mock KeyStoreSigner
		mockKeyStoreSigner := &MockKeyStoreSigner{
			MockSigner: &MockSigner{
				pubKey:   []byte("mock-keystore-public-key"),
				ss58Addr: "5mock-keystore-ss58-address",
				err:      nil,
			},
			mockDefaultKeyID: func() string { return "default-key-id" },
		}

		// Create server
		srv := NewServer(mockKeyStoreSigner, config.DefaultConfig(), logger)

		// Test GetPublicKey
		resp, err := srv.GetPublicKey(context.Background(), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("GetPublicKey failed: %v", err)
		}

		if string(resp.PublicKey) != "mock-keystore-public-key" {
			t.Errorf("Expected public key 'mock-keystore-public-key', got '%s'", string(resp.PublicKey))
		}

		if resp.Ss58Address != "5mock-keystore-ss58-address" {
			t.Errorf("Expected SS58 address '5mock-keystore-ss58-address', got '%s'", resp.Ss58Address)
		}
		if resp.KeyId != "default-key-id" {
			t.Errorf("Expected KeyId 'default-key-id', got %s", resp.KeyId)
		}
	})

	// Test error from signer
	t.Run("SignerError", func(t *testing.T) {
		// Create a mock signer that returns an error
		mockSigner := &MockSigner{
			err: errors.New("signer error"),
		}

		// Create server
		srv := NewServer(mockSigner, config.DefaultConfig(), logger)

		// Test GetPublicKey
		_, err := srv.GetPublicKey(context.Background(), &emptypb.Empty{})
		if err == nil {
			t.Error("Expected error from GetPublicKey, got nil")
		}
		if err != nil && err.Error() != "signer error" {
			t.Errorf("Expected 'signer error', got %v", err)
		}
	})
}

func TestServerSignExtrinsic(t *testing.T) {
	// Create logger
	logger, _ := zap.NewDevelopment()

	// Test with a regular signer
	t.Run("RegularSigner", func(t *testing.T) {
		// Create a mock signer
		mockSigner := &MockSigner{
			signature: []byte("mock-signature"),
			err:       nil,
		}

		// Create server
		srv := NewServer(mockSigner, config.DefaultConfig(), logger)

		// Test SignExtrinsic
		req := &pb.SignExtrinsicRequest{
			Payload: []byte("test-payload"),
		}

		resp, err := srv.SignExtrinsic(context.Background(), req)
		if err != nil {
			t.Fatalf("SignExtrinsic failed: %v", err)
		}

		if string(resp.Signature) != "mock-signature" {
			t.Errorf("Expected signature 'mock-signature', got '%s'", string(resp.Signature))
		}
		if resp.KeyId != "" {
			t.Errorf("Expected empty KeyId, got %s", resp.KeyId)
		}
	})

	// Test with a KeyStoreSigner
	t.Run("KeyStoreSigner", func(t *testing.T) {
		// Create a mock KeyStoreSigner
		mockKeyStoreSigner := &MockKeyStoreSigner{
			MockSigner: &MockSigner{
				signature: []byte("mock-keystore-signature"),
				err:       nil,
			},
			mockDefaultKeyID: func() string { return "default-key-id" },
		}

		// Create server
		srv := NewServer(mockKeyStoreSigner, config.DefaultConfig(), logger)

		// Test SignExtrinsic
		req := &pb.SignExtrinsicRequest{
			Payload: []byte("test-payload"),
		}

		resp, err := srv.SignExtrinsic(context.Background(), req)
		if err != nil {
			t.Fatalf("SignExtrinsic failed: %v", err)
		}

		if string(resp.Signature) != "mock-keystore-signature" {
			t.Errorf("Expected signature 'mock-keystore-signature', got '%s'", string(resp.Signature))
		}
		if resp.KeyId != "default-key-id" {
			t.Errorf("Expected KeyId 'default-key-id', got %s", resp.KeyId)
		}
	})

	// Test error from signer
	t.Run("SignerError", func(t *testing.T) {
		// Create a mock signer that returns an error
		mockSigner := &MockSigner{
			err: errors.New("signer error"),
		}

		// Create server
		srv := NewServer(mockSigner, config.DefaultConfig(), logger)

		// Test SignExtrinsic
		req := &pb.SignExtrinsicRequest{
			Payload: []byte("test-payload"),
		}

		_, err := srv.SignExtrinsic(context.Background(), req)
		if err == nil {
			t.Error("Expected error from SignExtrinsic, got nil")
		}
		if err != nil && err.Error() != "signer error" {
			t.Errorf("Expected 'signer error', got %v", err)
		}
	})
}

func TestServerHealth(t *testing.T) {
	// Create a mock signer
	mockSigner := &MockSigner{}

	// Create logger
	logger, _ := zap.NewDevelopment()

	// Create server
	srv := NewServer(mockSigner, config.DefaultConfig(), logger)

	// Test Health
	_, err := srv.Health(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
}

func TestServerEmptyPayload(t *testing.T) {
	// Create a mock signer
	mockSigner := &MockSigner{}

	// Create logger
	logger, _ := zap.NewDevelopment()

	// Create server
	srv := NewServer(mockSigner, config.DefaultConfig(), logger)

	// Test with empty payload
	req := &pb.SignExtrinsicRequest{
		Payload: []byte{},
	}

	_, err := srv.SignExtrinsic(context.Background(), req)
	if err == nil {
		t.Error("Expected error with empty payload, got nil")
	}
	if err != nil && err.Error() != "payload cannot be empty" {
		t.Errorf("Expected 'payload cannot be empty' error, got %v", err)
	}
}

func TestServerGetPublicKeyByID(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "keystore-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a real KeyStoreSigner
	ksSigner, err := signer.NewKeyStoreSigner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}
	defer ksSigner.Close()

	// Generate a key for testing
	keyID := "test_key_id"
	password := []byte("test_password")
	err = ksSigner.GenerateKey(keyID, password)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create logger
	logger, _ := zap.NewDevelopment()

	// Create server with the real KeyStoreSigner
	srv := NewServer(ksSigner, config.DefaultConfig(), logger)

	// Test GetPublicKeyByID with valid key ID
	resp, err := srv.GetPublicKeyByID(context.Background(), &pb.GetPublicKeyByIDRequest{KeyId: keyID})
	if err != nil {
		t.Fatalf("GetPublicKeyByID failed: %v", err)
	}

	if len(resp.PublicKey) == 0 {
		t.Errorf("Expected non-empty public key, got empty")
	}

	if resp.Ss58Address == "" {
		t.Errorf("Expected non-empty SS58 address, got empty")
	}

	if resp.KeyId != keyID {
		t.Errorf("Expected key ID %s, got %s", keyID, resp.KeyId)
	}

	// Test GetPublicKeyByID with empty key ID
	_, err = srv.GetPublicKeyByID(context.Background(), &pb.GetPublicKeyByIDRequest{KeyId: ""})
	if err == nil {
		t.Error("Expected error with empty key ID, got nil")
	}

	// Test GetPublicKeyByID with non-keystore signer
	srv = NewServer(&MockSigner{}, config.DefaultConfig(), logger) // Use a non-keystore signer
	_, err = srv.GetPublicKeyByID(context.Background(), &pb.GetPublicKeyByIDRequest{KeyId: keyID})
	if err == nil {
		t.Error("Expected error with non-keystore signer, got nil")
	}
}

func TestServerSignExtrinsicWithKey(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "keystore-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a real KeyStoreSigner
	ksSigner, err := signer.NewKeyStoreSigner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}
	defer ksSigner.Close()

	// Generate a key for testing
	keyID := "test_key_id"
	password := []byte("test_password")
	err = ksSigner.GenerateKey(keyID, password)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create logger
	logger, _ := zap.NewDevelopment()

	// Create server with the real KeyStoreSigner
	srv := NewServer(ksSigner, config.DefaultConfig(), logger)

	// Test SignExtrinsicWithKey with valid key ID and payload
	payload := []byte("test-payload")
	resp, err := srv.SignExtrinsicWithKey(context.Background(), &pb.SignExtrinsicWithKeyRequest{KeyId: keyID, Payload: payload})
	if err != nil {
		t.Fatalf("SignExtrinsicWithKey failed: %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Errorf("Expected non-empty signature, got empty")
	}

	// Test SignExtrinsicWithKey with empty payload
    _, err = srv.SignExtrinsicWithKey(context.Background(), &pb.SignExtrinsicWithKeyRequest{KeyId: keyID, Payload: []byte{}})
    if err == nil {
        t.Error("Expected error with empty payload, got nil")
    }
    if err != nil && err.Error() != "payload cannot be empty" {
        t.Errorf("Expected 'payload cannot be empty' error, got %v", err)
    }

    // Test SignExtrinsicWithKey with empty key ID
    _, err = srv.SignExtrinsicWithKey(context.Background(), &pb.SignExtrinsicWithKeyRequest{KeyId: "", Payload: payload})
    if err == nil {
        t.Error("Expected error with empty key ID, got nil")
    }
    if err != nil && err.Error() != "key_id cannot be empty" {
        t.Errorf("Expected 'key_id cannot be empty' error, got %v", err)
    }

	// Test SignExtrinsicWithKey with non-keystore signer
	srv = NewServer(&MockSigner{}, config.DefaultConfig(), logger) // Use a non-keystore signer
	_, err = srv.SignExtrinsicWithKey(context.Background(), &pb.SignExtrinsicWithKeyRequest{KeyId: keyID, Payload: payload})
	if err == nil {
		t.Error("Expected error with non-keystore signer, got nil")
	}
}

func TestServerListKeys(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "keystore-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a real KeyStoreSigner
	ksSigner, err := signer.NewKeyStoreSigner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}
	defer ksSigner.Close()

	// Generate some keys for testing
	key1ID := "key1"
	key2ID := "key2"
	password := []byte("test_password")
	err = ksSigner.GenerateKey(key1ID, password)
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}
	err = ksSigner.GenerateKey(key2ID, password)
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	// Create logger
	logger, _ := zap.NewDevelopment()

	// Create server with the real KeyStoreSigner
	srv := NewServer(ksSigner, config.DefaultConfig(), logger)

	// Test ListKeys with keystore signer
	resp, err := srv.ListKeys(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp.KeyIds) != 2 {
		t.Errorf("Expected 2 key IDs, got %d", len(resp.KeyIds))
	}

	if !contains(resp.KeyIds, key1ID) || !contains(resp.KeyIds, key2ID) {
		t.Errorf("Expected key IDs to contain %s and %s, got %v", key1ID, key2ID, resp.KeyIds)
	}

	if resp.DefaultKeyId != key1ID {
		t.Errorf("Expected default key ID %s, got %s", key1ID, resp.DefaultKeyId)
	}

	// Test ListKeys with non-keystore signer
	srv = NewServer(&MockSigner{}, config.DefaultConfig(), logger) // Use a non-keystore signer
	resp, err = srv.ListKeys(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp.KeyIds) != 0 || resp.DefaultKeyId != "" {
		t.Errorf("Expected empty key IDs and default key ID for non-keystore signer, got %v, %s", resp.KeyIds, resp.DefaultKeyId)
	}
}

// Helper function to check if a slice contains a string
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func TestHealthServer(t *testing.T) {
	healthServer := NewHealthServer()

	// Test initial state
	req := &grpc_health_v1.HealthCheckRequest{}
	resp, err := healthServer.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("Expected status SERVING, got %v", resp.Status)
	}

	// Test setting status
	healthServer.SetServingStatus(grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	resp, err = healthServer.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if resp.Status != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Errorf("Expected status NOT_SERVING, got %v", resp.Status)
	}
}