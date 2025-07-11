package server

import (
	"context"
	"testing"

	"github.com/bittensor-lab/btsigner/internal/config"
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

func TestServerGetPublicKey(t *testing.T) {
	// Create a mock signer
	mockSigner := &MockSigner{
		pubKey:   []byte("mock-public-key"),
		ss58Addr: "5mock-ss58-address",
		err:      nil,
	}

	// Create logger
	logger, _ := zap.NewDevelopment()

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
}

func TestServerSignExtrinsic(t *testing.T) {
	// Create a mock signer
	mockSigner := &MockSigner{
		signature: []byte("mock-signature"),
		err:       nil,
	}

	// Create logger
	logger, _ := zap.NewDevelopment()

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
