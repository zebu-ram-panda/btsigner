package crypto

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

const (
	// SS58Prefix is the prefix for Bittensor addresses
	SS58Prefix byte = 0x2A // 42 in decimal for Substrate/Polkadot
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key")
)

// PublicKeyToSS58 converts a public key to SS58 address format for Bittensor
func PublicKeyToSS58(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidPublicKey, len(publicKey))
	}

	// Create the SS58 format with prefix
	ss58Data := make([]byte, 0, 35) // prefix + pubkey + 2 checksum bytes
	ss58Data = append(ss58Data, SS58Prefix)
	ss58Data = append(ss58Data, publicKey...)

	// Calculate checksum
	checksumPrefix := []byte("SS58PRE")
	checksumData := append(checksumPrefix, ss58Data...)
	checksum := blake2b512(checksumData)
	ss58Data = append(ss58Data, checksum[:2]...)

	// Encode to base58
	address := base58Encode(ss58Data)
	return address, nil
}

// blake2b512 calculates the Blake2b-512 hash
func blake2b512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// Base58 alphabet used by SS58
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes data to base58 format
func base58Encode(data []byte) string {
	var result []byte

	// Convert to big integer
	x := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)

	// Perform base58 encoding
	for x.Cmp(zero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Add leading zeros (in base58 form)
	for _, b := range data {
		if b != 0 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}
