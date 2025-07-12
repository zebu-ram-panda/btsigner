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

	// Test loading config with Vault details
	t.Run("LoadConfigWithVault", func(t *testing.T) {
		vaultContent := `key:
  type: "vault"
  vault_url: "http://localhost:8200"
  vault_key: "my-secret-key"
`
		vaultPath := filepath.Join(tmpDir, "config_vault.yaml")
		if err := os.WriteFile(vaultPath, []byte(vaultContent), 0644); err != nil {
			t.Fatalf("Failed to write vault config: %v", err)
		}

		cfg, err := LoadConfig(vaultPath)
		if err != nil {
			t.Fatalf("Failed to load vault config: %v", err)
		}

		if cfg.Key.Type != "vault" {
			t.Errorf("Expected key type vault, got %s", cfg.Key.Type)
		}
		if cfg.Key.VaultURL != "http://localhost:8200" {
			t.Errorf("Expected vault URL http://localhost:8200, got %s", cfg.Key.VaultURL)
		}
		if cfg.Key.VaultKey != "my-secret-key" {
			t.Errorf("Expected vault key my-secret-key, got %s", cfg.Key.VaultKey)
		}
	})

	// Test loading YAML config with missing fields to trigger defaults
	t.Run("LoadYAMLConfigWithDefaults", func(t *testing.T) {
		yamlContent := `key:
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
log:
  level: "debug"
`
		defaultYamlPath := filepath.Join(tmpDir, "config_defaults.yaml")
		if err := os.WriteFile(defaultYamlPath, []byte(yamlContent), 0644); err != nil {
			t.Fatalf("Failed to write yaml config with defaults: %v", err)
		}

		cfg, err := LoadConfig(defaultYamlPath)
		if err != nil {
			t.Fatalf("Failed to load YAML config with defaults: %v", err)
		}

		// Verify default values are applied
		if cfg.Server.Address != ":50051" {
			t.Errorf("Expected default server address :50051, got %s", cfg.Server.Address)
		}
		if cfg.Metrics.Address != ":9090" {
			t.Errorf("Expected default metrics address :9090, got %s", cfg.Metrics.Address)
		}
		if cfg.Log.Format != "json" {
			t.Errorf("Expected default log format json, got %s", cfg.Log.Format)
		}
		if cfg.Log.Level != "debug" { // Should retain specified level
			t.Errorf("Expected log level debug, got %s", cfg.Log.Level)
		}
	})

	// Test loading JSON config with missing fields to trigger defaults
	t.Run("LoadJSONConfigWithDefaults", func(t *testing.T) {
		jsonContent := `{
  "key": {
    "path": "test_key_json.json",
    "type": "file"
  },
  "tls": {
    "enabled": false
  },
  "metrics": {
    "enabled": true
  },
  "log": {
    "format": "console"
  }
}`
		defaultJsonPath := filepath.Join(tmpDir, "config_defaults.json")
		if err := os.WriteFile(defaultJsonPath, []byte(jsonContent), 0644); err != nil {
			t.Fatalf("Failed to write json config with defaults: %v", err)
		}

		cfg, err := LoadConfig(defaultJsonPath)
		if err != nil {
			t.Fatalf("Failed to load JSON config with defaults: %v", err)
		}

		// Verify default values are applied
		if cfg.Server.Address != ":50051" {
			t.Errorf("Expected default server address :50051, got %s", cfg.Server.Address)
		}
		if cfg.Metrics.Address != ":9090" {
			t.Errorf("Expected default metrics address :9090, got %s", cfg.Metrics.Address)
		}
		if cfg.Log.Level != "info" { // Should retain default level
			t.Errorf("Expected default log level info, got %s", cfg.Log.Level)
		}
		if cfg.Log.Format != "console" { // Should retain specified format
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

	// Test loading invalid YAML content
	t.Run("LoadInvalidYAML", func(t *testing.T) {
		invalidYamlPath := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(invalidYamlPath, []byte("server: \n  address: [\n"), 0644); err != nil {
			t.Fatalf("Failed to write invalid YAML: %v", err)
		}
		_, err := LoadConfig(invalidYamlPath)
		if err == nil {
			t.Fatal("Expected error when loading invalid YAML, got nil")
		}
	})

	// Test loading invalid JSON content
	t.Run("LoadInvalidJSON", func(t *testing.T) {
		invalidJsonPath := filepath.Join(tmpDir, "invalid.json")
		if err := os.WriteFile(invalidJsonPath, []byte("{\"server\":{\"address\":"), 0644); err != nil {
			t.Fatalf("Failed to write invalid JSON: %v", err)
		}
		_, err := LoadConfig(invalidJsonPath)
		if err == nil {
			t.Fatal("Expected error when loading invalid JSON, got nil")
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
