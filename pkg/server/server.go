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

	// Log key info
	if ksSigner, ok := s.signer.(*signer.KeyStoreSigner); ok {
		s.logger.Info("Using key",
			zap.String("key_id", ksSigner.DefaultKeyID()),
			zap.String("ss58_address", ss58Addr))
	}

	return &pb.GetPublicKeyResponse{
		PublicKey:   pubKey,
		Ss58Address: ss58Addr,
	}, nil
}

// SignExtrinsic signs a payload with the signer's private key
func (s *Server) SignExtrinsic(ctx context.Context, req *pb.SignExtrinsicRequest) (*pb.SignExtrinsicResponse, error) {
	if len(req.Payload) == 0 {
		s.logger.Error("Empty payload received")
		return nil, fmt.Errorf("payload cannot be empty")
	}

	// Check if we have a KeyStoreSigner
	if ksSigner, ok := s.signer.(*signer.KeyStoreSigner); ok {
		// Extract key ID from context if provided
		keyID := ""
		if len(req.Context) > 0 {
			// Try to parse context as key ID
			keyID = string(req.Context)
		}

		// If key ID is provided, use it
		if keyID != "" {
			s.logger.Info("Signing with specific key", zap.String("key_id", keyID))
			signature, err := ksSigner.SignWithKey(ctx, keyID, req.Payload)
			if err != nil {
				s.logger.Error("Failed to sign with key",
					zap.String("key_id", keyID),
					zap.Error(err))
				return nil, err
			}
			return &pb.SignExtrinsicResponse{
				Signature: signature,
			}, nil
		}
	}

	// Default signing with default key
	signature, err := s.signer.Sign(ctx, req.Payload)
	if err != nil {
		s.logger.Error("Failed to sign payload", zap.Error(err))
		return nil, err
	}

	return &pb.SignExtrinsicResponse{
		Signature: signature,
	}, nil
}

// Health implements the health check endpoint
func (s *Server) Health(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
