package govern

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// approvalTokenTTL bounds how long an email approval link stays valid. Kept
// short because the token is a bearer credential that records a verdict on a
// proposed fix: it runs nothing in Vulngraph, but an approval fires the
// approval webhook, whose receiver may act on it. Single use (the nonce),
// binding to the exact decisions (the set hash) and a non-mutating GET landing
// page are separate mitigations.
const approvalTokenTTL = 48 * time.Hour

// MinTokenSecretBytes is the shortest APPROVAL_TOKEN_SECRET accepted: the
// secret is an HMAC-SHA256 key for bearer links that record approval and
// denial verdicts, so it must carry at least the hash's 256 bits.
const MinTokenSecretBytes = 32

var (
	ErrTokenExpired     = errors.New("govern: approval token expired")
	ErrTokenInvalid     = errors.New("govern: approval token invalid")
	ErrTokenSecretShort = fmt.Errorf("govern: APPROVAL_TOKEN_SECRET must be at least %d bytes", MinTokenSecretBytes)
)

// ValidateTokenSecret reports whether secret is strong enough to sign links.
func ValidateTokenSecret(secret string) error {
	if len(secret) < MinTokenSecretBytes {
		return ErrTokenSecretShort
	}
	return nil
}

// LinkClaims is what an email approve/deny link authorises: one verdict on an
// exact set of decisions. SetHash binds the finding ids AND the context
// fingerprint each was decided under, so a link cannot approve a different
// set, or the same findings after their context changed. Nonce is shared by
// the approve and deny links of one email and is spent on first use.
type LinkClaims struct {
	FindingIDs  []string  `json:"ids"`
	SetHash     string    `json:"fs"`
	ActionClass string    `json:"ac"`
	Verdict     Verdict   `json:"v"`
	Nonce       string    `json:"n"`
	Recipient   string    `json:"to,omitempty"`
	ExpiresAt   time.Time `json:"-"`
}

type approvalTokenPayload struct {
	LinkClaims
	Exp int64 `json:"exp"`
}

// newLinkNonce returns a random nonce for one approval email.
func newLinkNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("newLinkNonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateApprovalToken signs c with HMAC-SHA256. A zero ExpiresAt means
// approvalTokenTTL from now. The token is safe to embed in URLs.
func GenerateApprovalToken(c LinkClaims, secret string) (string, error) {
	if err := ValidateTokenSecret(secret); err != nil {
		return "", fmt.Errorf("GenerateApprovalToken: %w", err)
	}
	if len(c.FindingIDs) == 0 || c.SetHash == "" || c.ActionClass == "" || c.Nonce == "" || !ValidVerdict(c.Verdict) {
		return "", fmt.Errorf("GenerateApprovalToken: %w: incomplete claims", ErrTokenInvalid)
	}
	exp := c.ExpiresAt
	if exp.IsZero() {
		exp = time.Now().Add(approvalTokenTTL)
	}
	raw, err := json.Marshal(approvalTokenPayload{LinkClaims: c, Exp: exp.Unix()})
	if err != nil {
		return "", fmt.Errorf("GenerateApprovalToken: marshal: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return encoded + "." + signToken(encoded, secret), nil
}

// ValidateApprovalToken checks the HMAC signature (before parsing anything)
// and the expiry, returning the signed claims.
func ValidateApprovalToken(token, secret string) (LinkClaims, error) {
	if ValidateTokenSecret(secret) != nil {
		return LinkClaims{}, ErrTokenInvalid
	}
	encoded, sig, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(sig, ".") {
		return LinkClaims{}, ErrTokenInvalid
	}
	if !hmac.Equal([]byte(sig), []byte(signToken(encoded, secret))) {
		return LinkClaims{}, ErrTokenInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return LinkClaims{}, ErrTokenInvalid
	}
	var p approvalTokenPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return LinkClaims{}, ErrTokenInvalid
	}
	if time.Now().Unix() > p.Exp {
		return LinkClaims{}, ErrTokenExpired
	}
	c := p.LinkClaims
	if len(c.FindingIDs) == 0 || c.SetHash == "" || c.ActionClass == "" || c.Nonce == "" || !ValidVerdict(c.Verdict) {
		return LinkClaims{}, ErrTokenInvalid
	}
	c.ExpiresAt = time.Unix(p.Exp, 0).UTC()
	return c, nil
}

func signToken(encoded, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
