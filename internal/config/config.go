package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	Server struct {
		Address string `yaml:"address" json:"address"`
	} `yaml:"server" json:"server"`

	Key struct {
		Path     string `yaml:"path" json:"path"`
		Type     string `yaml:"type" json:"type"` // file, vault, kms
		VaultURL string `yaml:"vault_url" json:"vault_url,omitempty"`
		VaultKey string `yaml:"vault_key" json:"vault_key,omitempty"`
	} `yaml:"key" json:"key"`

	TLS struct {
		Enabled      bool     `yaml:"enabled" json:"enabled"`
		CertPath     string   `yaml:"cert_path" json:"cert_path"`
		KeyPath      string   `yaml:"key_path" json:"key_path"`
		ClientAuth   bool     `yaml:"client_auth" json:"client_auth"`
		CAPath       string   `yaml:"ca_path" json:"ca_path"`
		MinVersion   string   `yaml:"min_version" json:"min_version"`
		CipherSuites []string `yaml:"cipher_suites" json:"cipher_suites"`
	} `yaml:"tls" json:"tls"`

	Metrics struct {
		Enabled bool   `yaml:"enabled" json:"enabled"`
		Address string `yaml:"address" json:"address"`
	} `yaml:"metrics" json:"metrics"`

	Log struct {
		Level  string `yaml:"level" json:"level"`
		Format string `yaml:"format" json:"format"` // json, console
	} `yaml:"log" json:"log"`
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config

	// Determine file format based on extension
	switch filepath.Ext(path) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", filepath.Ext(path))
	}

	// Apply defaults
	if cfg.Server.Address == "" {
		cfg.Server.Address = ":50051"
	}

	if cfg.Metrics.Enabled && cfg.Metrics.Address == "" {
		cfg.Metrics.Address = ":9090"
	}

	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}

	return &cfg, nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	cfg := &Config{}

	cfg.Server.Address = ":50051"
	cfg.Key.Type = "file"
	cfg.Key.Path = "key.json"
	cfg.TLS.Enabled = false
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = ":9090"
	cfg.Log.Level = "info"
	cfg.Log.Format = "json"

	return cfg
}
