package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bittensor-lab/btsigner/internal/config"
	"github.com/bittensor-lab/btsigner/pkg/signer"
	pb "github.com/bittensor-lab/btsigner/proto/signer/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Server implements the RemoteSigner gRPC service
type Server struct {
	pb.UnimplementedRemoteSignerServer
	signer signer.Signer
	config *config.Config
	logger *zap.Logger
}

// NewServer creates a new server instance
func NewServer(signerImpl signer.Signer, cfg *config.Config, logger *zap.Logger) *Server {
	return &Server{
		signer: signerImpl,
		config: cfg,
		logger: logger,
	}
}

// Run starts the gRPC server
func (s *Server) Run() error {
	// Create listener
	lis, err := net.Listen("tcp", s.config.Server.Address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Configure server options
	var opts []grpc.ServerOption
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionIdle: 5 * time.Minute,
		Time:              1 * time.Minute,
		Timeout:           20 * time.Second,
	}))

	// Configure TLS if enabled
	if s.config.TLS.Enabled {
		creds, err := credentials.NewServerTLSFromFile(
			s.config.TLS.CertPath,
			s.config.TLS.KeyPath,
		)
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Create gRPC server
	grpcServer := grpc.NewServer(opts...)

	// Register services
	pb.RegisterRemoteSignerServer(grpcServer, s)
	healthServer := NewHealthServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	reflection.Register(grpcServer)

	// Start server
	s.logger.Info("Starting gRPC server", zap.String("address", s.config.Server.Address))
	return grpcServer.Serve(lis)
}

// GetPublicKey returns the public key of the signer
func (s *Server) GetPublicKey(ctx context.Context, _ *emptypb.Empty) (*pb.GetPublicKeyResponse, error) {
	pubKey, ss58Addr, err := s.signer.GetPublicKey()
	if err != nil {
		s.logger.Error("Failed to get public key", zap.Error(err))
		return nil, err
	}

	// Get key ID if available
	keyID := ""
	if ksSigner, ok := s.signer.(*signer.KeyStoreSigner); ok {
		keyID = ksSigner.DefaultKeyID()
		s.logger.Info("Using key",
			zap.String("key_id", keyID),
			zap.String("ss58_address", ss58Addr))
	}

	return &pb.GetPublicKeyResponse{
		PublicKey:   pubKey,
		Ss58Address: ss58Addr,
		KeyId:       keyID,
	}, nil
}

// GetPublicKeyByID returns the public key of a specific signer by ID
func (s *Server) GetPublicKeyByID(ctx context.Context, req *pb.GetPublicKeyByIDRequest) (*pb.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, fmt.Errorf("key_id cannot be empty")
	}

	// Check if we have a KeyStoreSigner
	ksSigner, ok := s.signer.(*signer.KeyStoreSigner)
	if !ok {
		return nil, fmt.Errorf("keystore signer not available")
	}

	pubKey, ss58Addr, err := ksSigner.GetPublicKeyByID(req.KeyId)
	if err != nil {
		s.logger.Error("Failed to get public key by ID",
			zap.String("key_id", req.KeyId),
			zap.Error(err))
		return nil, err
	}

	s.logger.Info("Retrieved public key",
		zap.String("key_id", req.KeyId),
		zap.String("ss58_address", ss58Addr))

	return &pb.GetPublicKeyResponse{
		PublicKey:   pubKey,
		Ss58Address: ss58Addr,
		KeyId:       req.KeyId,
	}, nil
}

// SignExtrinsic signs a payload with the signer's private key
func (s *Server) SignExtrinsic(ctx context.Context, req *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error) {
	if len(req.Payload) == 0 {
		s.logger.Error("Empty payload received")
		return nil, fmt.Errorf("payload cannot be empty")
	}

	// Check if we have a KeyStoreSigner
	keyID := ""
	if ksSigner, ok := s.signer.(*signer.KeyStoreSigner); ok {
		keyID = ksSigner.DefaultKeyID()
		s.logger.Info("Signing with default key", zap.String("key_id", keyID))
	}

	// Default signing with default key
	signature, err := s.signer.Sign(ctx, req.Payload)
	if err != nil {
		s.logger.Error("Failed to sign payload", zap.Error(err))
		return nil, err
	}

	return &pb.SignExtrinsicResponse{
		Signature: signature,
		KeyId:     keyID,
	}, nil
}

// SignExtrinsicWithKey signs a payload with a specific signer's private key
func (s *Server) SignExtrinsicWithKey(ctx context.Context, req *pb.SignExtrinsicWithKeyRequest) (*pb.SignExtrinsicResponse, error) {
	if len(req.Payload) == 0 {
		s.logger.Error("Empty payload received")
		return nil, fmt.Errorf("payload cannot be empty")
	}

	if req.KeyId == "" {
		s.logger.Error("Empty key ID received")
		return nil, fmt.Errorf("key_id cannot be empty")
	}

	// Check if we have a KeyStoreSigner
	ksSigner, ok := s.signer.(*signer.KeyStoreSigner)
	if !ok {
		return nil, fmt.Errorf("keystore signer not available")
	}

	s.logger.Info("Signing with specific key", zap.String("key_id", req.KeyId))
	signature, err := ksSigner.SignWithKey(ctx, req.KeyId, req.Payload)
	if err != nil {
		s.logger.Error("Failed to sign with key",
			zap.String("key_id", req.KeyId),
			zap.Error(err))
		return nil, err
	}

	return &pb.SignExtrinsicResponse{
		Signature: signature,
		KeyId:     req.KeyId,
	}, nil
}

// ListKeys returns a list of all available key IDs
func (s *Server) ListKeys(ctx context.Context, _ *emptypb.Empty) (*pb.ListKeysResponse, error) {
	// Check if we have a KeyStoreSigner
	ksSigner, ok := s.signer.(*signer.KeyStoreSigner)
	if !ok {
		// For single key signers, return empty list
		return &pb.ListKeysResponse{
			KeyIds:       []string{},
			DefaultKeyId: "",
		}, nil
	}

	keyIDs := ksSigner.ListKeyIDs()
	defaultKeyID := ksSigner.DefaultKeyID()

	s.logger.Info("Listed keys",
		zap.Strings("key_ids", keyIDs),
		zap.String("default_key_id", defaultKeyID))

	return &pb.ListKeysResponse{
		KeyIds:       keyIDs,
		DefaultKeyId: defaultKeyID,
	}, nil
}

// Health implements the health check endpoint
func (s *Server) Health(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
