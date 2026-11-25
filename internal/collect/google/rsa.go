package google

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// rsaSign signs data with the RS256 algorithm using a PEM-encoded private key.
// Used by the service account JWT flow without external JWT library dependencies.
func rsaSign(data []byte, privateKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("rsaSign: failed to decode PEM block")
	}

	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("rsaSign: parse PKCS1: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("rsaSign: parse PKCS8: %w", err)
		}
		var ok bool
		if key, ok = k.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("rsaSign: not an RSA key")
		}
	default:
		return nil, fmt.Errorf("rsaSign: unsupported PEM block type %q", block.Type)
	}

	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
}
