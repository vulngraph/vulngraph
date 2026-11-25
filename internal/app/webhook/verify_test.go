package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyGitHubSignature(t *testing.T) {
	body := []byte(`{"zen":"keep it logically awesome"}`)
	secret := "s3cr3t"
	good := sign(secret, body)

	tests := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{"valid", secret, body, good, true},
		{"wrong secret", "other", body, good, false},
		{"tampered body", secret, append(body, '!'), good, false},
		{"empty secret never verifies", "", body, sign("", body), false},
		{"missing prefix", secret, body, hex.EncodeToString([]byte("x")), false},
		{"empty header", secret, body, "", false},
		{"garbage header", secret, body, "sha256=not-hex", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, verifyGitHubSignature(tt.secret, tt.body, tt.header))
		})
	}
}
