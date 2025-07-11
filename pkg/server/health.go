package server

import (
	"context"
	"sync"

	"google.golang.org/grpc/health/grpc_health_v1"
)

// HealthServer implements the gRPC Health Checking Protocol
type HealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	mu     sync.RWMutex
	status grpc_health_v1.HealthCheckResponse_ServingStatus
}

// NewHealthServer creates a new health server
func NewHealthServer() *HealthServer {
	return &HealthServer{
		status: grpc_health_v1.HealthCheckResponse_SERVING,
	}
}

// Check implements the Check method from the gRPC Health Checking Protocol
func (s *HealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &grpc_health_v1.HealthCheckResponse{
		Status: s.status,
	}, nil
}

// SetServingStatus sets the serving status of the health server
func (s *HealthServer) SetServingStatus(status grpc_health_v1.HealthCheckResponse_ServingStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.status = status
}
