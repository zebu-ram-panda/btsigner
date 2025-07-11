package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create temporary test files
	tmpDir, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test YAML config
	yamlPath := filepath.Join(tmpDir, "config.yaml")
	yamlContent := `server:
  address: ":9000"
key:
  path: "test_key.json"
  type: "file"
tls:
  enabled: true
  cert_path: "test_cert.pem"
  key_path: "test_key.pem"
  client_auth: true
  ca_path: "test_ca.pem"
metrics:
  enabled: true
  address: ":8080"
log:
  level: "debug"
  format: "json"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write yaml config: %v", err)
	}

	// Test JSON config
	jsonPath := filepath.Join(tmpDir, "config.json")
	jsonContent := `{
  "server": {
    "address": ":9001"
  },
  "key": {
    "path": "test_key_json.json",
    "type": "file"
  },
  "tls": {
    "enabled": false
  },
  "metrics": {
    "enabled": true,
    "address": ":8081"
  },
  "log": {
    "level": "info",
    "format": "console"
  }
}`
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("Failed to write json config: %v", err)
	}

	// Invalid format config
	invalidPath := filepath.Join(tmpDir, "config.txt")
	if err := os.WriteFile(invalidPath, []byte("invalid content"), 0644); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}

	// Test loading YAML config
	t.Run("LoadYAMLConfig", func(t *testing.T) {
		cfg, err := LoadConfig(yamlPath)
		if err != nil {
			t.Fatalf("Failed to load YAML config: %v", err)
		}

		// Verify loaded values
		if cfg.Server.Address != ":9000" {
			t.Errorf("Expected server address :9000, got %s", cfg.Server.Address)
		}
		if cfg.Key.Path != "test_key.json" {
			t.Errorf("Expected key path test_key.json, got %s", cfg.Key.Path)
		}
		if !cfg.TLS.Enabled {
			t.Error("Expected TLS enabled")
		}
		if cfg.TLS.CertPath != "test_cert.pem" {
			t.Errorf("Expected cert path test_cert.pem, got %s", cfg.TLS.CertPath)
		}
		if cfg.Metrics.Address != ":8080" {
			t.Errorf("Expected metrics address :8080, got %s", cfg.Metrics.Address)
		}
		if cfg.Log.Level != "debug" {
			t.Errorf("Expected log level debug, got %s", cfg.Log.Level)
		}
	})

	// Test loading JSON config
	t.Run("LoadJSONConfig", func(t *testing.T) {
		cfg, err := LoadConfig(jsonPath)
		if err != nil {
			t.Fatalf("Failed to load JSON config: %v", err)
		}

		// Verify loaded values
		if cfg.Server.Address != ":9001" {
			t.Errorf("Expected server address :9001, got %s", cfg.Server.Address)
		}
		if cfg.Key.Path != "test_key_json.json" {
			t.Errorf("Expected key path test_key_json.json, got %s", cfg.Key.Path)
		}
		if cfg.TLS.Enabled {
			t.Error("Expected TLS disabled")
		}
		if cfg.Log.Format != "console" {
			t.Errorf("Expected log format console, got %s", cfg.Log.Format)
		}
	})

	// Test loading invalid config
	t.Run("LoadInvalidFormat", func(t *testing.T) {
		_, err := LoadConfig(invalidPath)
		if err == nil {
			t.Fatal("Expected error when loading invalid config format, got nil")
		}
	})

	// Test loading non-existent file
	t.Run("LoadNonExistentFile", func(t *testing.T) {
		_, err := LoadConfig(filepath.Join(tmpDir, "nonexistent.yaml"))
		if err == nil {
			t.Fatal("Expected error when loading non-existent file, got nil")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Verify default values
	if cfg.Server.Address != ":50051" {
		t.Errorf("Expected default server address :50051, got %s", cfg.Server.Address)
	}
	if cfg.Key.Type != "file" {
		t.Errorf("Expected default key type file, got %s", cfg.Key.Type)
	}
	if cfg.Key.Path != "key.json" {
		t.Errorf("Expected default key path key.json, got %s", cfg.Key.Path)
	}
	if cfg.TLS.Enabled {
		t.Error("Expected default TLS disabled")
	}
	if cfg.Metrics.Enabled != true {
		t.Error("Expected default metrics enabled")
	}
	if cfg.Metrics.Address != ":9090" {
		t.Errorf("Expected default metrics address :9090, got %s", cfg.Metrics.Address)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Expected default log level info, got %s", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Expected default log format json, got %s", cfg.Log.Format)
	}
}
