// Package webhooksig signs Vulngraph's outbound webhooks (the decision handoff
// and the approval handoff) with one scheme, so a receiver verifies both with
// the same code.
//
// The signature is hex HMAC-SHA256, keyed by the webhook's secret, over
// "<timestamp>.<body>"; a receiver recomputes it with a constant-time compare
// and rejects a mismatch or a stale timestamp (replay).
package webhooksig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Signature headers.
const (
	SignatureHeader = "X-Graph-Signature" // "sha256=<hex>"
	TimestampHeader = "X-Graph-Timestamp" // unix seconds
)

// Sign returns the SignatureHeader value for body sent at timestamp.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// SetHeaders signs body as sent at now and sets both headers on h.
func SetHeaders(h http.Header, secret string, now time.Time, body []byte) {
	ts := strconv.FormatInt(now.Unix(), 10)
	h.Set(TimestampHeader, ts)
	h.Set(SignatureHeader, Sign(secret, ts, body))
}

// DefaultWindow is how far a receiver should let a timestamp stray from its
// own clock, either way, before refusing the request as a replay.
const DefaultWindow = 5 * time.Minute

// Verify errors.
var (
	ErrNoSecret     = errors.New("webhooksig: no secret configured")
	ErrBadSignature = errors.New("webhooksig: signature does not verify")
	ErrStale        = errors.New("webhooksig: timestamp outside the allowed window")
)

// Verify checks a received request's headers against its raw body: the
// signature with a constant-time compare, then the timestamp within window
// of now. For receivers written in Go; others recompute Sign's scheme.
func Verify(h http.Header, secret string, body []byte, now time.Time, window time.Duration) error {
	// An empty key is a key anyone holds: a receiver missing its config
	// must refuse everything, not accept anything signed with "".
	if secret == "" {
		return ErrNoSecret
	}
	ts := h.Get(TimestampHeader)
	if !hmac.Equal([]byte(h.Get(SignatureHeader)), []byte(Sign(secret, ts, body))) {
		return ErrBadSignature
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrStale
	}
	if d := now.Sub(time.Unix(sec, 0)); d > window || d < -window {
		return ErrStale
	}
	return nil
}
