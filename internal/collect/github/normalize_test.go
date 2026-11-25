package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestNormalizePEM_RepairsFlattenedKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	multi := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	// Simulate a key whose newlines were stripped (helm --set).
	flat := strings.ReplaceAll(multi, "\n", "")
	require.NotContains(t, flat, "\n", "precondition: flattened key is one line")

	_, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(flat))
	require.Error(t, err, "precondition: a flattened key does NOT parse")

	_, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(normalizePEM(flat)))
	require.NoError(t, err, "normalized single-line key must parse")

	// An already-multiline key still parses after normalize (passthrough).
	_, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(normalizePEM(multi)))
	require.NoError(t, err)
}
