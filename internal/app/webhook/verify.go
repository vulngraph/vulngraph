package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// verifyGitHubSignature reports whether header is a valid GitHub
// X-Hub-Signature-256 for body under secret. GitHub sends "sha256=<hex>" where
// the hex is HMAC-SHA256(body, secret). An empty secret never verifies, and the
// comparison is constant-time so a caller can't probe the secret by timing.
func verifyGitHubSignature(secret string, body []byte, header string) bool {
	const prefix = "sha256="
	if secret == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(header[len(prefix):]))
}
