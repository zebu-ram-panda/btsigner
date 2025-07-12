package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/tls"
	pb "github.com/bittensor-lab/btsigner/proto/signer/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestClientOptions(t *testing.T) {
	opts := DefaultClientOptions()

	if opts.Address != "localhost:50051" {
		t.Errorf("Expected default address localhost:50051, got %s", opts.Address)
	}
	if opts.TLSEnabled {
		t.Error("Expected TLS disabled by default")
	}
	if opts.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", opts.Timeout)
	}
}

// MockRemoteSignerServer implements the pb.RemoteSignerServer interface for testing
type MockRemoteSignerServer struct {
	pb.UnimplementedRemoteSignerServer
	getPublicKeyFunc         func(context.Context, *emptypb.Empty) (*pb.GetPublicKeyResponse, error)
	signExtrinsicFunc        func(context.Context, *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error)
	signExtrinsicWithKeyFunc func(context.Context, *pb.SignExtrinsicWithKeyRequest) (*pb.SignExtrinsicResponse, error)
	healthFunc               func(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}

func (m *MockRemoteSignerServer) GetPublicKey(ctx context.Context, in *emptypb.Empty) (*pb.GetPublicKeyResponse, error) {
	if m.getPublicKeyFunc != nil {
		return m.getPublicKeyFunc(ctx, in)
	}
	return &pb.GetPublicKeyResponse{}, nil
}

func (m *MockRemoteSignerServer) SignExtrinsic(ctx context.Context, in *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error) {
	if m.signExtrinsicFunc != nil {
		return m.signExtrinsicFunc(ctx, in)
	}
	return &pb.SignExtrinsicResponse{}, nil
}

func (m *MockRemoteSignerServer) SignExtrinsicWithKey(ctx context.Context, in *pb.SignExtrinsicWithKeyRequest) (*pb.SignExtrinsicResponse, error) {
	if m.signExtrinsicWithKeyFunc != nil {
		return m.signExtrinsicWithKeyFunc(ctx, in)
	}
	return &pb.SignExtrinsicResponse{}, nil
}

func (m *MockRemoteSignerServer) Health(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx, in)
	}
	return &emptypb.Empty{}, nil
}

// startMockServer starts a gRPC server with the given mock service and returns its address
func startMockServer(t *testing.T, mockService pb.RemoteSignerServer, serverOpts ...grpc.ServerOption) (string, func()) {
	lis, err := net.Listen("tcp", "localhost:0") // Listen on a random available port
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(serverOpts...)
	pb.RegisterRemoteSignerServer(s, mockService)
	grpc_health_v1.RegisterHealthServer(s, &MockHealthServer{})

	go func() {
		if err := s.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("Mock server failed: %v", err)
		}
	}()

	return lis.Addr().String(), func() {
		s.Stop()
		lis.Close()
	}
}

// MockHealthServer implements the grpc_health_v1.HealthServer interface
type MockHealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (m *MockHealthServer) Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (m *MockHealthServer) Watch(in *grpc_health_v1.HealthCheckRequest, s grpc_health_v1.Health_WatchServer) error {
	return nil
}

func TestClientCreation(t *testing.T) {
	// Create a mock server
	mockServer := &MockRemoteSignerServer{}
	addr, cleanup := startMockServer(t, mockServer)
	defer cleanup()

	// Test with default options pointing to the mock server
	opts := DefaultClientOptions()
	opts.Address = addr
	client, err := NewSignerClient(opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Verify client was created correctly
	if client.opts != opts {
		t.Error("Client options not set correctly")
	}
}

// Test client creation with TLS enabled
func TestClientWithTLS(t *testing.T) {
	// Create temporary directory for test certs
	tmpDir := "/tmp/btsigner_test_certs"

	// Load server TLS credentials
	serverCert, err := tls.LoadX509KeyPair(filepath.Join(tmpDir, "server.crt"), filepath.Join(tmpDir, "server.key"))
	if err != nil {
		t.Fatalf("Failed to load server key pair: %v", err)
	}
	serverCreds := credentials.NewServerTLSFromCert(&serverCert)

	// Start a mock gRPC server with TLS
	mockServer := &MockRemoteSignerServer{}
	serverAddr, cleanup := startMockServer(t, mockServer, grpc.Creds(serverCreds))
	defer cleanup()

	// Create client options with TLS
	opts := DefaultClientOptions()
	opts.TLSEnabled = true
	opts.CAPath = filepath.Join(tmpDir, "ca.crt")
	opts.CertPath = filepath.Join(tmpDir, "client.crt")
	opts.KeyPath = filepath.Join(tmpDir, "client.key")
	opts.ServerNameOverride = "localhost"
	opts.Address = serverAddr

	// Attempt to create a client and connect to the TLS server
	client, err := NewSignerClient(opts)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}
	defer client.Close()

	// Perform a simple call to ensure connection is established
	_, _, err = client.GetPublicKey(context.Background())
	if err != nil {
		t.Errorf("GetPublicKey failed over TLS: %v", err)
	}
}

// Test different client methods for coverage
func TestClientMethodCoverage(t *testing.T) {
	// Create a mock server
	mockServer := &MockRemoteSignerServer{
		getPublicKeyFunc: func(ctx context.Context, empty *emptypb.Empty) (*pb.GetPublicKeyResponse, error) {
			return &pb.GetPublicKeyResponse{PublicKey: []byte("mock-pub-key"), Ss58Address: "mock-ss58"}, nil
		},
		signExtrinsicFunc: func(ctx context.Context, request *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error) {
			// Check if keyID is passed in context for SignExtrinsicWithKey workaround
			if len(request.Context) > 0 {
				return &pb.SignExtrinsicResponse{Signature: []byte("mock-signature-with-key")}, nil
			}
			return &pb.SignExtrinsicResponse{Signature: []byte("mock-signature")}, nil
		},
		signExtrinsicWithKeyFunc: func(ctx context.Context, request *pb.SignExtrinsicWithKeyRequest) (*pb.SignExtrinsicResponse, error) {
			return &pb.SignExtrinsicResponse{Signature: []byte("mock-signature-with-key")}, nil
		},
		healthFunc: func(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
			return &emptypb.Empty{}, nil
		},
	}
	addr, cleanup := startMockServer(t, mockServer)
	defer cleanup()

	// Create client
	opts := DefaultClientOptions()
	opts.Address = addr
	client, err := NewSignerClient(opts)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Test GetPublicKey
	pubKey, ss58, err := client.GetPublicKey(context.Background())
	if err != nil {
		t.Errorf("GetPublicKey failed: %v", err)
	}
	if string(pubKey) != "mock-pub-key" || ss58 != "mock-ss58" {
		t.Errorf("Unexpected public key or ss58 address: %s, %s", string(pubKey), ss58)
	}

	// Test SignExtrinsic
	signature, err := client.SignExtrinsic(context.Background(), []byte("test-payload"))
	if err != nil {
		t.Errorf("SignExtrinsic failed: %v", err)
	}
	if string(signature) != "mock-signature" {
		t.Errorf("Unexpected signature: %s", string(signature))
	}

	// Test SignExtrinsicWithKey
	signature, err = client.SignExtrinsicWithKey(context.Background(), "test-key-id", []byte("test-payload"))
	if err != nil {
		t.Errorf("SignExtrinsicWithKey failed: %v", err)
	}
	if string(signature) != "mock-signature-with-key" {
		t.Errorf("Unexpected signature: %s", string(signature))
	}

	// Test CheckHealth
	err = client.CheckHealth(context.Background())
	if err != nil {
		t.Errorf("CheckHealth failed: %v", err)
	}

	// Test Close
	err = client.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// Additional test cases
func TestClientErrorCases(t *testing.T) {
	// Test with invalid address format
	t.Run("InvalidAddress", func(t *testing.T) {
		opts := DefaultClientOptions()
		opts.Address = "invalid:::address:::" // Invalid address format
		opts.Timeout = 100 * time.Millisecond // Short timeout to fail quickly

		client, err := NewSignerClient(opts)
		if err != nil {
			// If NewSignerClient already fails, that's fine
			if !strings.Contains(err.Error(), "failed to dial server") {
				t.Errorf("Expected 'failed to dial server' error, got: %v", err)
			}
			return
		}
		defer client.Close()

		// Force the connection to be used
		err = client.CheckHealth(context.Background())
		if err == nil {
			t.Error("Expected error with invalid address format")
		}
	})

	// Test NewSignerClient with CA path error
	t.Run("NewSignerClient_CAPathError", func(t *testing.T) {
		opts := DefaultClientOptions()
		opts.TLSEnabled = true
		opts.CAPath = "/nonexistent/path/ca.crt" // Non-existent path

		_, err := NewSignerClient(opts)
		if err == nil {
			t.Error("Expected error when CA path is invalid")
		}
		if err != nil && !strings.Contains(err.Error(), "failed to read CA cert") {
			t.Errorf("Expected 'failed to read CA cert' error, got: %v", err)
		}
	})

	// Test NewSignerClient with invalid CA cert content
	t.Run("NewSignerClient_InvalidCACertContent", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidCACertPath := filepath.Join(tmpDir, "invalid_ca.crt")
		err := os.WriteFile(invalidCACertPath, []byte("invalid cert content"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid CA cert: %v", err)
		}

		opts := DefaultClientOptions()
		opts.TLSEnabled = true
		opts.CAPath = invalidCACertPath

		_, err = NewSignerClient(opts)
		if err == nil {
			t.Error("Expected error when CA cert content is invalid")
		}
		if err != nil && !strings.Contains(err.Error(), "failed to add CA cert to pool") {
			t.Errorf("Expected 'failed to add CA cert to pool' error, got: %v", err)
		}
	})

	// Test NewSignerClient with client cert/key loading error
	t.Run("NewSignerClient_ClientCertKeyError", func(t *testing.T) {
		tmpDir := t.TempDir()
				// Create dummy files that are not valid key pairs
		invalidCertPath := filepath.Join(tmpDir, "invalid_client.crt")
		invalidKeyPath := filepath.Join(tmpDir, "invalid_client.key")
		if err := os.WriteFile(invalidCertPath, []byte("cert"), 0644); err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}
		if err := os.WriteFile(invalidKeyPath, []byte("key"), 0644); err != nil {
			t.Fatalf("Failed to write key file: %v", err)
		}

		opts := DefaultClientOptions()
		opts.TLSEnabled = true
		opts.CertPath = invalidCertPath
		opts.KeyPath = invalidKeyPath

		_, err := NewSignerClient(opts)
		if err == nil {
			t.Error("Expected error when client cert/key loading fails")
		}
		if err != nil && !strings.Contains(err.Error(), "failed to load client cert") {
			t.Errorf("Expected 'failed to load client cert' error, got: %v", err)
		}
	})

	// Test GetPublicKey error
	t.Run("GetPublicKeyError", func(t *testing.T) {
		mockServer := &MockRemoteSignerServer{
			getPublicKeyFunc: func(ctx context.Context, empty *emptypb.Empty) (*pb.GetPublicKeyResponse, error) {
				return nil, fmt.Errorf("mock GetPublicKey error")
			},
		}
		addr, cleanup := startMockServer(t, mockServer)
		defer cleanup()

		opts := DefaultClientOptions()
		opts.Address = addr
		client, err := NewSignerClient(opts)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		_, _, err = client.GetPublicKey(context.Background())
		if err == nil {
			t.Error("Expected GetPublicKey error, got nil")
		}
	})

	// Test SignExtrinsic error
	t.Run("SignExtrinsicError", func(t *testing.T) {
		mockServer := &MockRemoteSignerServer{
			signExtrinsicFunc: func(ctx context.Context, request *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error) {
				return nil, fmt.Errorf("mock SignExtrinsic error")
			},
		}
		addr, cleanup := startMockServer(t, mockServer)
		defer cleanup()

		opts := DefaultClientOptions()
		opts.Address = addr
		client, err := NewSignerClient(opts)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		_, err = client.SignExtrinsic(context.Background(), []byte("test"))
		if err == nil {
			t.Error("Expected SignExtrinsic error, got nil")
		}
	})

	// Test SignExtrinsicWithKey error
	t.Run("SignExtrinsicWithKeyError", func(t *testing.T) {
		mockServer := &MockRemoteSignerServer{
			signExtrinsicFunc: func(ctx context.Context, request *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error) {
				// This mock is specifically for the SignExtrinsicWithKey error case
				return nil, fmt.Errorf("mock SignExtrinsicWithKey error")
			},
		}
		addr, cleanup := startMockServer(t, mockServer)
		defer cleanup()

		opts := DefaultClientOptions()
		opts.Address = addr
		client, err := NewSignerClient(opts)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		_, err = client.SignExtrinsicWithKey(context.Background(), "test-key", []byte("test"))
		if err == nil {
			t.Error("Expected SignExtrinsicWithKey error, got nil")
		}
	})

	// Test CheckHealth error
	t.Run("CheckHealthError", func(t *testing.T) {
		mockServer := &MockRemoteSignerServer{
			healthFunc: func(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
				return nil, fmt.Errorf("mock CheckHealth error")
			},
		}
		addr, cleanup := startMockServer(t, mockServer)
		defer cleanup()

		opts := DefaultClientOptions()
		opts.Address = addr
		client, err := NewSignerClient(opts)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		err = client.CheckHealth(context.Background())
		if err == nil {
			t.Error("Expected CheckHealth error, got nil")
		}
	})

	// Test Close error (when conn is nil)
	t.Run("CloseNilConn", func(t *testing.T) {
		client := &SignerClient{conn: nil} // Simulate nil connection
		err := client.Close()
		if err != nil {
			t.Errorf("Expected nil error on Close with nil conn, got %v", err)
		}
	})
}
