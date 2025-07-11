package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	pb "github.com/bittensor-lab/btsigner/proto/signer/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ClientOptions holds configuration options for the signer client
type ClientOptions struct {
	Address            string
	TLSEnabled         bool
	CAPath             string
	CertPath           string
	ServerNameOverride string
	Timeout            time.Duration
}

// DefaultClientOptions returns default client options
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		Address:    "localhost:50051",
		TLSEnabled: false,
		Timeout:    5 * time.Second,
	}
}

// SignerClient is a client for the remote signer
type SignerClient struct {
	conn   *grpc.ClientConn
	client pb.RemoteSignerClient
	opts   *ClientOptions
}

// NewSignerClient creates a new signer client
func NewSignerClient(opts *ClientOptions) (*SignerClient, error) {
	var dialOpts []grpc.DialOption

	if opts.TLSEnabled {
		var tlsConfig tls.Config

		if opts.CAPath != "" {
			caCert, err := os.ReadFile(opts.CAPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert: %w", err)
			}

			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to add CA cert to pool")
			}

			tlsConfig.RootCAs = certPool
		}

		if opts.CertPath != "" {
			cert, err := tls.LoadX509KeyPair(opts.CertPath, opts.CertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		if opts.ServerNameOverride != "" {
			tlsConfig.ServerName = opts.ServerNameOverride
		}

		creds := credentials.NewTLS(&tlsConfig)
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(opts.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial server: %w", err)
	}

	client := pb.NewRemoteSignerClient(conn)

	return &SignerClient{
		conn:   conn,
		client: client,
		opts:   opts,
	}, nil
}

// GetPublicKey gets the public key from the remote signer
func (c *SignerClient) GetPublicKey(ctx context.Context) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	resp, err := c.client.GetPublicKey(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get public key: %w", err)
	}

	return resp.PublicKey, resp.Ss58Address, nil
}

// SignExtrinsic signs a payload using the remote signer
func (c *SignerClient) SignExtrinsic(ctx context.Context, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	resp, err := c.client.SignExtrinsic(ctx, &pb.SignExtrinsicRequest{
		Payload: payload,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	return resp.Signature, nil
}

// SignExtrinsicWithKey signs a payload using a specific key on the remote signer
func (c *SignerClient) SignExtrinsicWithKey(ctx context.Context, keyID string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	// Since we don't have the SignExtrinsicWithKey RPC yet, we'll use the context field to pass the key ID
	resp, err := c.client.SignExtrinsic(ctx, &pb.SignExtrinsicRequest{
		Payload: payload,
		Context: []byte(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload with key %s: %w", keyID, err)
	}

	return resp.Signature, nil
}

// CheckHealth checks the health of the remote signer
func (c *SignerClient) CheckHealth(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	_, err := c.client.Health(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	return nil
}

// Close closes the client connection
func (c *SignerClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
