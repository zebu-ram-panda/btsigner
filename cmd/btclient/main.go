package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/bittensor-lab/btsigner/pkg/client"
)

func main() {
	// Parse command line flags
	address := flag.String("address", "localhost:50051", "Address of the remote signer")
	tls := flag.Bool("tls", false, "Use TLS")
	caFile := flag.String("ca", "", "Path to CA certificate")
	certFile := flag.String("cert", "", "Path to client certificate")
	serverName := flag.String("server-name", "", "Server name override for TLS")

	getPublicKey := flag.Bool("get-public-key", false, "Get the public key")
	sign := flag.String("sign", "", "Sign a payload (hex encoded)")
	keyID := flag.String("key-id", "", "Key ID to use for signing (optional)")
	health := flag.Bool("health", false, "Check server health")

	flag.Parse()

	// Create client options
	opts := client.DefaultClientOptions()
	opts.Address = *address
	opts.TLSEnabled = *tls
	opts.CAPath = *caFile
	opts.CertPath = *certFile
	opts.ServerNameOverride = *serverName

	// Create client
	c, err := client.NewSignerClient(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	ctx := context.Background()

	// Execute requested command
	if *getPublicKey {
		pubKey, ss58Addr, err := c.GetPublicKey(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get public key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Public Key: %x\n", pubKey)
		fmt.Printf("SS58 Address: %s\n", ss58Addr)
	} else if *sign != "" {
		payload, err := hex.DecodeString(*sign)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode payload: %v\n", err)
			os.Exit(1)
		}

		var signature []byte
		if *keyID != "" {
			// Sign with specific key
			signature, err = c.SignExtrinsicWithKey(ctx, *keyID, payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to sign payload with key %s: %v\n", *keyID, err)
				os.Exit(1)
			}
			fmt.Printf("Signing with key: %s\n", *keyID)
		} else {
			// Sign with default key
			signature, err = c.SignExtrinsic(ctx, payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to sign payload: %v\n", err)
				os.Exit(1)
			}
		}

		fmt.Printf("Signature: %x\n", signature)
	} else if *health {
		if err := c.CheckHealth(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Server is healthy")
	} else {
		flag.Usage()
		os.Exit(1)
	}
}
