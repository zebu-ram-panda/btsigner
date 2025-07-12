package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bittensor-lab/btsigner/internal/crypto"
	"github.com/bittensor-lab/btsigner/pkg/signer"
)

const (
	// Test password for key generation
	testPassword = "test-password-123"
	
	// Test key paths
	singleKeyPath = "test_single_key.json"
	keystorePath  = "test_keystore"
)

// TestResult represents the result of a test
type TestResult struct {
	Name        string
	Success     bool
	Error       error
	Duration    time.Duration
	PublicKey   []byte
	SS58Address string
	Signature   []byte
}

// TestSuite manages and runs all tests
type TestSuite struct {
	results []TestResult
}

func (ts *TestSuite) addResult(result TestResult) {
	ts.results = append(ts.results, result)
}

func (ts *TestSuite) printResults() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("TEST RESULTS SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	
	passed := 0
	failed := 0
	
	for _, result := range ts.results {
		status := "✓ PASS"
		if !result.Success {
			status = "✗ FAIL"
			failed++
		} else {
			passed++
		}
		
		fmt.Printf("%s | %s | %v\n", status, result.Name, result.Duration)
		
		if result.PublicKey != nil {
			fmt.Printf("     Public Key: %x\n", result.PublicKey)
		}
		if result.SS58Address != "" {
			fmt.Printf("     SS58 Address: %s\n", result.SS58Address)
		}
		if result.Signature != nil {
			fmt.Printf("     Signature: %x\n", result.Signature)
		}
		if result.Error != nil {
			fmt.Printf("     Error: %v\n", result.Error)
		}
		fmt.Println()
	}
	
	fmt.Printf("Total: %d | Passed: %d | Failed: %d\n", len(ts.results), passed, failed)
	fmt.Println(strings.Repeat("=", 60))
}

func main() {
	fmt.Println("Bittensor Signer Key Generation and Signing Test Suite")
	fmt.Println(strings.Repeat("=", 60))
	
	ts := &TestSuite{}
	
	// Clean up any existing test files
	cleanup()
	defer cleanup()
	
	// Test 1: Single Key Generation
	ts.testSingleKeyGeneration()
	
	// Test 2: Single Key Signing
	ts.testSingleKeySigning()
	
	// Test 3: Keystore Creation and Key Generation
	ts.testKeystoreGeneration()
	
	// Test 4: Multiple Keys in Keystore
	ts.testMultipleKeysInKeystore()
	
	// Test 5: Keystore Signing
	ts.testKeystoreSigning()
	
	// Test 6: Stress Test - Multiple Signatures
	ts.testStressSignatures()
	
	// Test 7: Edge Cases
	ts.testEdgeCases()
	
	// Print final results
	ts.printResults()
}

func (ts *TestSuite) testSingleKeyGeneration() {
	start := time.Now()
	result := TestResult{
		Name:      "Single Key Generation",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("Test 1: Single Key Generation")
	fmt.Println(strings.Repeat("-", 30))
	
	// Generate a single key
	keyPair, err := crypto.GenerateKeyFile(singleKeyPath, []byte(testPassword))
	if err != nil {
		result.Error = fmt.Errorf("failed to generate key: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	// Get public key and SS58 address
	pubKey := keyPair.PublicKey()
	ss58Addr, err := crypto.PublicKeyToSS58(pubKey)
	if err != nil {
		result.Error = fmt.Errorf("failed to convert to SS58: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	result.Success = true
	result.PublicKey = pubKey
	result.SS58Address = ss58Addr
	result.Duration = time.Since(start)
	
	fmt.Printf("✓ Generated single key successfully\n")
	fmt.Printf("  Public Key: %x\n", pubKey)
	fmt.Printf("  SS58 Address: %s\n", ss58Addr)
	fmt.Printf("  Duration: %v\n", result.Duration)
	
	ts.addResult(result)
}

func (ts *TestSuite) testSingleKeySigning() {
	start := time.Now()
	result := TestResult{
		Name:      "Single Key Signing",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("\nTest 2: Single Key Signing")
	fmt.Println(strings.Repeat("-", 30))
	
	// Load the previously generated key
	s, err := signer.NewSr25519Signer(singleKeyPath, []byte(testPassword))
	if err != nil {
		result.Error = fmt.Errorf("failed to create signer: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer s.Close()
	
	// Get public key info
	pubKey, ss58Addr, err := s.GetPublicKey()
	if err != nil {
		result.Error = fmt.Errorf("failed to get public key: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	// Test signing with different payloads
	testPayloads := [][]byte{
		[]byte("hello world"),
		[]byte("test message for signing"),
		{0x01, 0x02, 0x03, 0x04, 0x05}, // binary data
	}
	
	ctx := context.Background()
	var lastSignature []byte
	
	for i, payload := range testPayloads {
		signature, err := s.Sign(ctx, payload)
		if err != nil {
			result.Error = fmt.Errorf("failed to sign payload %d: %w", i, err)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		if len(signature) == 0 {
			result.Error = fmt.Errorf("signature %d is empty", i)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		lastSignature = signature
		fmt.Printf("✓ Signed payload %d: %x -> %x\n", i+1, payload, signature)
	}
	
	result.Success = true
	result.PublicKey = pubKey
	result.SS58Address = ss58Addr
	result.Signature = lastSignature
	result.Duration = time.Since(start)
	
	fmt.Printf("✓ Single key signing test passed\n")
	fmt.Printf("  Duration: %v\n", result.Duration)
	
	ts.addResult(result)
}

func (ts *TestSuite) testKeystoreGeneration() {
	start := time.Now()
	result := TestResult{
		Name:      "Keystore Generation",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("\nTest 3: Keystore Generation")
	fmt.Println(strings.Repeat("-", 30))
	
	// Create keystore signer
	ksSigner, err := signer.NewKeyStoreSigner(keystorePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to create keystore signer: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer ksSigner.Close()
	
	// Generate a key in the keystore
	keyID := "test-key-1"
	err = ksSigner.GenerateKey(keyID, []byte(testPassword))
	if err != nil {
		result.Error = fmt.Errorf("failed to generate key in keystore: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	// Get public key info
	pubKey, ss58Addr, err := ksSigner.GetPublicKeyByID(keyID)
	if err != nil {
		result.Error = fmt.Errorf("failed to get public key by ID: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	result.Success = true
	result.PublicKey = pubKey
	result.SS58Address = ss58Addr
	result.Duration = time.Since(start)
	
	fmt.Printf("✓ Generated keystore key successfully\n")
	fmt.Printf("  Key ID: %s\n", keyID)
	fmt.Printf("  Public Key: %x\n", pubKey)
	fmt.Printf("  SS58 Address: %s\n", ss58Addr)
	fmt.Printf("  Duration: %v\n", result.Duration)
	
	ts.addResult(result)
}

func (ts *TestSuite) testMultipleKeysInKeystore() {
	start := time.Now()
	result := TestResult{
		Name:      "Multiple Keys in Keystore",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("\nTest 4: Multiple Keys in Keystore")
	fmt.Println(strings.Repeat("-", 30))
	
	// Create keystore signer
	ksSigner, err := signer.NewKeyStoreSigner(keystorePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to create keystore signer: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer ksSigner.Close()
	
	// Generate multiple keys
	keyIDs := []string{"validator-key", "cold-key", "hot-key"}
	
	for _, keyID := range keyIDs {
		err = ksSigner.GenerateKey(keyID, []byte(testPassword))
		if err != nil {
			result.Error = fmt.Errorf("failed to generate key %s: %w", keyID, err)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		// Get public key info
		pubKey, ss58Addr, err := ksSigner.GetPublicKeyByID(keyID)
		if err != nil {
			result.Error = fmt.Errorf("failed to get public key for %s: %w", keyID, err)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		fmt.Printf("✓ Generated key: %s\n", keyID)
		fmt.Printf("  Public Key: %x\n", pubKey)
		fmt.Printf("  SS58 Address: %s\n", ss58Addr)
	}
	
	// List all keys
	allKeyIDs := ksSigner.ListKeyIDs()
	fmt.Printf("✓ Total keys in keystore: %d\n", len(allKeyIDs))
	fmt.Printf("  Key IDs: %v\n", allKeyIDs)
	
	result.Success = true
	result.Duration = time.Since(start)
	
	ts.addResult(result)
}

func (ts *TestSuite) testKeystoreSigning() {
	start := time.Now()
	result := TestResult{
		Name:      "Keystore Signing",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("\nTest 5: Keystore Signing")
	fmt.Println(strings.Repeat("-", 30))
	
	// Create keystore signer
	ksSigner, err := signer.NewKeyStoreSigner(keystorePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to create keystore signer: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer ksSigner.Close()
	
	// Load keys (they should already exist from previous tests)
	keyIDs := []string{"test-key-1", "validator-key", "cold-key", "hot-key"}
	
	for _, keyID := range keyIDs {
		err = ksSigner.LoadKey(keyID, []byte(testPassword))
		if err != nil {
			// Skip if key doesn't exist
			continue
		}
		
		// Test signing with this key
		payload := []byte(fmt.Sprintf("test message for key %s", keyID))
		ctx := context.Background()
		
		signature, err := ksSigner.SignWithKey(ctx, keyID, payload)
		if err != nil {
			result.Error = fmt.Errorf("failed to sign with key %s: %w", keyID, err)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		if len(signature) == 0 {
			result.Error = fmt.Errorf("signature for key %s is empty", keyID)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		fmt.Printf("✓ Signed with key %s: %x\n", keyID, signature)
		result.Signature = signature
	}
	
	result.Success = true
	result.Duration = time.Since(start)
	
	fmt.Printf("✓ Keystore signing test passed\n")
	fmt.Printf("  Duration: %v\n", result.Duration)
	
	ts.addResult(result)
}

func (ts *TestSuite) testStressSignatures() {
	start := time.Now()
	result := TestResult{
		Name:      "Stress Test - 5000 Signatures",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("\nTest 6: Stress Test - 5000 Signatures")
	fmt.Println(strings.Repeat("-", 30))
	
	// Load single key signer
	s, err := signer.NewSr25519Signer(singleKeyPath, []byte(testPassword))
	if err != nil {
		result.Error = fmt.Errorf("failed to create signer: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer s.Close()
	
	// Generate many random payloads and sign them
	numSignatures := 5000
	ctx := context.Background()
	
	for i := 0; i < numSignatures; i++ {
		// Generate random payload
		payload := make([]byte, 32)
		rand.Read(payload)
		
		signature, err := s.Sign(ctx, payload)
		if err != nil {
			result.Error = fmt.Errorf("failed to sign payload %d: %w", i, err)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		if len(signature) == 0 {
			result.Error = fmt.Errorf("signature %d is empty", i)
			result.Duration = time.Since(start)
			ts.addResult(result)
			return
		}
		
		if i%500 == 0 {
			fmt.Printf("✓ Completed %d/%d signatures\n", i+1, numSignatures)
		}
	}
	
	result.Success = true
	result.Duration = time.Since(start)
	
	fmt.Printf("✓ Stress test passed - %d signatures in %v\n", numSignatures, result.Duration)
	fmt.Printf("  Average time per signature: %v\n", result.Duration/time.Duration(numSignatures))
	
	ts.addResult(result)
}

func (ts *TestSuite) testEdgeCases() {
	start := time.Now()
	result := TestResult{
		Name:      "Edge Cases",
		Success:   false,
		Duration:  0,
	}
	
	fmt.Println("\nTest 7: Edge Cases")
	fmt.Println(strings.Repeat("-", 30))
	
	// Load single key signer
	s, err := signer.NewSr25519Signer(singleKeyPath, []byte(testPassword))
	if err != nil {
		result.Error = fmt.Errorf("failed to create signer: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer s.Close()
	
	ctx := context.Background()
	
	// Test 1: Empty payload (should fail)
	_, err = s.Sign(ctx, []byte{})
	if err == nil {
		result.Error = fmt.Errorf("expected error for empty payload, got nil")
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	fmt.Printf("✓ Empty payload correctly rejected: %v\n", err)
	
	// Test 2: Cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Sign(cancelCtx, []byte("test"))
	if err == nil {
		result.Error = fmt.Errorf("expected error for cancelled context, got nil")
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	fmt.Printf("✓ Cancelled context correctly rejected: %v\n", err)
	
	// Test 3: Very large payload
	largePayload := make([]byte, 1024*1024) // 1MB
	rand.Read(largePayload)
	
	signature, err := s.Sign(ctx, largePayload)
	if err != nil {
		result.Error = fmt.Errorf("failed to sign large payload: %w", err)
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	if len(signature) == 0 {
		result.Error = fmt.Errorf("signature for large payload is empty")
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	
	fmt.Printf("✓ Large payload (1MB) signed successfully\n")
	
	result.Success = true
	result.Duration = time.Since(start)
	result.Signature = signature
	
	fmt.Printf("✓ Edge cases test passed\n")
	fmt.Printf("  Duration: %v\n", result.Duration)
	
	ts.addResult(result)
}

func cleanup() {
	// Remove test files
	os.Remove(singleKeyPath)
	os.RemoveAll(keystorePath)
}

func init() {
	// Ensure we're in the right directory
	if _, err := os.Stat("go.mod"); err != nil {
		fmt.Println("Please run this script from the root directory of the btsigner project")
		os.Exit(1)
	}
} 