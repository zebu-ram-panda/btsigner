package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig holds the TLS configuration

type TLSConfig struct {
	Cert             tls.Certificate
	CACertPool       *x509.CertPool
	MinVersion       uint16
	CipherSuites     []uint16
	CurvePreferences []tls.CurveID
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

	cipherSuites, err := parseCipherSuites(c.TLS.CipherSuites)
	if err != nil {
		return nil, err
	}

	return &TLSConfig{
		Cert:             cert,
		CACertPool:       caCertPool,
		MinVersion:       minVersion,
		CipherSuites:     cipherSuites,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
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

func parseCipherSuites(suites []string) ([]uint16, error) {
	if len(suites) == 0 {
		return nil, nil
	}

	suiteIDs := make([]uint16, 0, len(suites))
	for _, suite := range suites {
		id, ok := approvedCipherSuites[suite]
		if !ok {
			return nil, fmt.Errorf("unsupported cipher suite: %s", suite)
		}
		suiteIDs = append(suiteIDs, id)
	}
	return suiteIDs, nil
}

// Note: This list should be updated based on security best practices
var approvedCipherSuites = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
}
