package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidKeyFile = errors.New("invalid key file")
	ErrDecryptFailed  = errors.New("failed to decrypt key")
)

// KeyFile represents the encrypted key file format
type KeyFile struct {
	PublicKey  []byte `json:"public_key"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Salt       []byte `json:"salt"`
	Version    int    `json:"version"`
}

// Sr25519KeyPair holds the keypair for sr25519 operations
type Sr25519KeyPair struct {
	secretKey *schnorrkel.MiniSecretKey
	publicKey []byte
}

// LoadSr25519KeyPair loads an sr25519 keypair from an encrypted file
func LoadSr25519KeyPair(path string, passwordProvider func() (*SecureBytes, error)) (*Sr25519KeyPair, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var keyFile KeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return nil, ErrInvalidKeyFile
	}

	password, err := passwordProvider()
	if err != nil {
		return nil, err
	}
	defer password.Zero()

	// Derive key from password using Argon2id
	key := argon2.IDKey(password.Bytes(), keyFile.Salt, 1, 64*1024, 4, 32)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Decrypt the private key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	privateKeyBytes, err := aesgcm.Open(nil, keyFile.Nonce, keyFile.Ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	defer func() {
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
	}()

	// Create schnorrkel secret key
	var miniSecretKey [32]byte
	copy(miniSecretKey[:], privateKeyBytes)
	secretKey, err := schnorrkel.NewMiniSecretKeyFromRaw(miniSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	return &Sr25519KeyPair{
		secretKey: secretKey,
		publicKey: keyFile.PublicKey,
	}, nil
}

// PublicKey returns the public key bytes
func (kp *Sr25519KeyPair) PublicKey() []byte {
	return kp.publicKey
}

// Sign signs a message using sr25519
func (kp *Sr25519KeyPair) Sign(message []byte) ([]byte, error) {
	if kp.secretKey == nil {
		return nil, errors.New("nil secret key")
	}
	t := merlin.NewTranscript("substrate")
	t.AppendMessage([]byte("sign-message"), message)

	secretKey := kp.secretKey.ExpandEd25519()
	sig, err := secretKey.Sign(t)
	if err != nil {
		return nil, err
	}

	sigBytes := sig.Encode()
	return sigBytes[:], nil
}

// Zero wipes the secret key material from memory
func (kp *Sr25519KeyPair) Zero() error {
	if kp.secretKey != nil {
		privateKeyBytes := kp.secretKey.Encode()
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
		kp.secretKey = nil
	}
	return nil
}

// GenerateKeyFile creates a new encrypted key file
func GenerateKeyFile(path string, passwordProvider func() (*SecureBytes, error)) (*Sr25519KeyPair, error) {
	// Generate a new keypair
	miniSecretKey, err := schnorrkel.GenerateMiniSecretKey()
	if err != nil {
		return nil, err
	}

	// Get the private key bytes
	privateKeyBytes := miniSecretKey.Encode()

	// Get the public key
	publicKey := miniSecretKey.Public().Encode()

	// Generate salt for key derivation
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	password, err := passwordProvider()
	if err != nil {
		return nil, err
	}
	defer password.Zero()

	// Derive encryption key from password
	key := argon2.IDKey(password.Bytes(), salt, 1, 64*1024, 4, 32)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Encrypt the private key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, privateKeyBytes[:], nil)

	// Create key file
	keyFile := KeyFile{
		PublicKey:  publicKey[:],
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
		Version:    1,
	}

	// Write to file
	data, err := json.Marshal(keyFile)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}

	return &Sr25519KeyPair{
		secretKey: miniSecretKey,
		publicKey: publicKey[:],
	}, nil
}
