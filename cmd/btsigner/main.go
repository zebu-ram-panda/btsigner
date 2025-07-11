package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/bittensor-lab/btsigner/internal/config"
	"github.com/bittensor-lab/btsigner/internal/crypto"
	"github.com/bittensor-lab/btsigner/pkg/server"
	"github.com/bittensor-lab/btsigner/pkg/signer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	keyPath := flag.String("key", "", "Path to key file (overrides config)")
	keyStorePath := flag.String("keystore", "", "Path to key store directory (enables multi-key support)")
	keyID := flag.String("key-id", "", "Key ID to use (with keystore)")
	genKey := flag.Bool("genkey", false, "Generate a new key")
	checkKey := flag.Bool("check-key", false, "Check a key without starting the server")
	flag.Parse()

	// Initialize logger
	logConfig := zap.NewProductionConfig()
	logConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, err := logConfig.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Override key path if specified
	if *keyPath != "" {
		cfg.Key.Path = *keyPath
	}

	var signerImpl signer.Signer

	// Check if using keystore
	if *keyStorePath != "" {
		// Use KeyStoreSigner for multi-key support
		keyStoreSigner, err := signer.NewKeyStoreSigner(*keyStorePath)
		if err != nil {
			logger.Fatal("Failed to create key store signer", zap.Error(err))
		}

		// Generate a new key if requested
		if *genKey {
			if *keyID == "" {
				logger.Fatal("Key ID is required when generating a key in a key store")
			}

			var password, confirmPassword []byte

			// Check for password in environment variable (for testing)
			if envPassword := os.Getenv("BTSIGNER_PASSWORD"); envPassword != "" {
				password = []byte(envPassword)

				// Check for confirmation password in environment variable
				if envConfirmPassword := os.Getenv("BTSIGNER_CONFIRM_PASSWORD"); envConfirmPassword != "" {
					confirmPassword = []byte(envConfirmPassword)
				} else {
					confirmPassword = password // Use same password if confirmation not provided
				}
			} else {
				// Interactive password entry
				fmt.Print("Enter password for new key: ")
				password, err = term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					logger.Fatal("Failed to read password", zap.Error(err))
				}
				fmt.Println()

				fmt.Print("Confirm password: ")
				confirmPassword, err = term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					logger.Fatal("Failed to read password confirmation", zap.Error(err))
				}
				fmt.Println()
			}

			if string(password) != string(confirmPassword) {
				logger.Fatal("Passwords do not match")
			}

			err = keyStoreSigner.GenerateKey(*keyID, password)
			if err != nil {
				logger.Fatal("Failed to generate key",
					zap.String("key_id", *keyID),
					zap.Error(err))
			}

			_, ss58Addr, err := keyStoreSigner.GetPublicKeyByID(*keyID)
			if err != nil {
				logger.Fatal("Failed to get public key",
					zap.String("key_id", *keyID),
					zap.Error(err))
			}

			logger.Info("Generated new key",
				zap.String("key_id", *keyID),
				zap.String("ss58_address", ss58Addr))

			return
		}

		// If key ID is specified, load that key
		if *keyID != "" {
			var password []byte

			// Check for password in environment variable (for testing)
			if envPassword := os.Getenv("BTSIGNER_PASSWORD"); envPassword != "" {
				password = []byte(envPassword)
			} else {
				// Interactive password entry
				fmt.Printf("Enter password to unlock key %s: ", *keyID)
				password, err = term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					logger.Fatal("Failed to read password", zap.Error(err))
				}
				fmt.Println()
			}

			err = keyStoreSigner.LoadKey(*keyID, password)
			if err != nil {
				logger.Fatal("Failed to load key",
					zap.String("key_id", *keyID),
					zap.Error(err))
			}

			keyStoreSigner.SetDefaultKeyID(*keyID)

			// Check key and exit if requested
			if *checkKey {
				_, ss58Addr, err := keyStoreSigner.GetPublicKeyByID(*keyID)
				if err != nil {
					logger.Fatal("Failed to get public key",
						zap.String("key_id", *keyID),
						zap.Error(err))
				}

				fmt.Printf("Key ID: %s\n", *keyID)
				fmt.Printf("SS58 Address: %s\n", ss58Addr)
				return
			}
		} else {
			// List available keys
			keyIDs := keyStoreSigner.ListKeyIDs()
			if len(keyIDs) == 0 {
				logger.Fatal("No keys found in key store. Use -genkey to generate a new key.")
			}

			fmt.Println("Available keys:")
			for _, id := range keyIDs {
				fmt.Printf("- %s\n", id)
			}

			fmt.Print("Enter key ID to use: ")
			var selectedKeyID string
			fmt.Scanln(&selectedKeyID)

			var password []byte

			// Check for password in environment variable (for testing)
			if envPassword := os.Getenv("BTSIGNER_PASSWORD"); envPassword != "" {
				password = []byte(envPassword)
			} else {
				// Interactive password entry
				fmt.Printf("Enter password to unlock key %s: ", selectedKeyID)
				password, err = term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					logger.Fatal("Failed to read password", zap.Error(err))
				}
				fmt.Println()
			}

			err = keyStoreSigner.LoadKey(selectedKeyID, password)
			if err != nil {
				logger.Fatal("Failed to load key",
					zap.String("key_id", selectedKeyID),
					zap.Error(err))
			}

			keyStoreSigner.SetDefaultKeyID(selectedKeyID)
		}

		signerImpl = keyStoreSigner
	} else {
		// Use traditional single key signer
		// Generate a new key if requested
		if *genKey {
			var password, confirmPassword []byte

			// Check for password in environment variable (for testing)
			if envPassword := os.Getenv("BTSIGNER_PASSWORD"); envPassword != "" {
				password = []byte(envPassword)

				// Check for confirmation password in environment variable
				if envConfirmPassword := os.Getenv("BTSIGNER_CONFIRM_PASSWORD"); envConfirmPassword != "" {
					confirmPassword = []byte(envConfirmPassword)
				} else {
					confirmPassword = password // Use same password if confirmation not provided
				}
			} else {
				// Interactive password entry
				fmt.Print("Enter password for new key: ")
				password, err = term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					logger.Fatal("Failed to read password", zap.Error(err))
				}
				fmt.Println()

				fmt.Print("Confirm password: ")
				confirmPassword, err = term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					logger.Fatal("Failed to read password confirmation", zap.Error(err))
				}
				fmt.Println()
			}

			if string(password) != string(confirmPassword) {
				logger.Fatal("Passwords do not match")
			}

			keyPair, err := crypto.GenerateKeyFile(cfg.Key.Path, password)
			if err != nil {
				logger.Fatal("Failed to generate key", zap.Error(err))
			}

			pubKey := keyPair.PublicKey()
			ss58Addr, err := crypto.PublicKeyToSS58(pubKey)
			if err != nil {
				logger.Fatal("Failed to convert public key to SS58", zap.Error(err))
			}

			logger.Info("Generated new key",
				zap.String("path", cfg.Key.Path),
				zap.String("ss58_address", ss58Addr))

			return
		}

		// Get password
		var password []byte

		// Check for password in environment variable (for testing)
		if envPassword := os.Getenv("BTSIGNER_PASSWORD"); envPassword != "" {
			password = []byte(envPassword)
		} else {
			// Interactive password entry
			fmt.Print("Enter password to unlock key: ")
			password, err = term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				logger.Fatal("Failed to read password", zap.Error(err))
			}
			fmt.Println()
		}

		// Create signer
		signerImpl, err = signer.NewSr25519Signer(cfg.Key.Path, password)
		if err != nil {
			logger.Fatal("Failed to create signer", zap.Error(err))
		}

		// Check key and exit if requested
		if *checkKey {
			_, ss58Addr, err := signerImpl.GetPublicKey()
			if err != nil {
				logger.Fatal("Failed to get public key", zap.Error(err))
			}

			fmt.Printf("Key Path: %s\n", cfg.Key.Path)
			fmt.Printf("SS58 Address: %s\n", ss58Addr)
			return
		}
	}

	defer signerImpl.Close()

	// Get public key for logging
	_, ss58Addr, err := signerImpl.GetPublicKey()
	if err != nil {
		logger.Fatal("Failed to get public key", zap.Error(err))
	}

	logger.Info("Loaded key", zap.String("ss58_address", ss58Addr))

	// Create and run server
	srv := server.NewServer(signerImpl, cfg, logger)
	if err := srv.Run(); err != nil {
		logger.Fatal("Server error", zap.Error(err))
	}
}
