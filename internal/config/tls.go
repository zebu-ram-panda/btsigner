package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig holds the TLS configuration

type TLSConfig struct {
	Cert       tls.Certificate
	CACertPool *x509.CertPool
	MinVersion uint16
}

// LoadTLSConfig loads the TLS configuration from the main config file
func (c *Config) LoadTLSConfig() (*TLSConfig, error) {
	if !c.TLS.Enabled {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.TLS.CertPath, c.TLS.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	var caCertPool *x509.CertPool
	if c.TLS.ClientAuth {
		caCert, err := os.ReadFile(c.TLS.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}

		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to add CA cert to pool")
		}
	}

	minVersion, err := parseTLSVersion(c.TLS.MinVersion)
	if err != nil {
		return nil, err
	}

	return &TLSConfig{
		Cert:       cert,
		CACertPool: caCertPool,
		MinVersion: minVersion,
	}, nil
}

func parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return tls.VersionTLS12, nil // Default to TLS 1.2
	}
}
