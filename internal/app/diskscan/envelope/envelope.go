// Package envelope seals the credentials one disk-scan volume job needs so the
// scanner pod can use them without ever reading the connectors table or holding
// GRAPH_SECRET_KEY. The worker, which can decrypt the connector, copies only
// the keys the disk-scan principals use into an Access value and seals it under
// a key that opens nothing else (DISK_SCAN_ENVELOPE_KEY). The ciphertext
// travels in the job's args, bound to its run and connector and expiring with
// the run.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	version = 1
	keyLen  = 32
)

var (
	// ErrExpired means the envelope's lifetime has passed; the run must be planned again.
	ErrExpired = errors.New("envelope: expired")
	// ErrInvalid means the envelope is malformed, sealed under another key, or
	// bound to another run or connector.
	ErrInvalid = errors.New("envelope: invalid")
)

// Key is the envelope key.
type Key [keyLen]byte

// ParseKey reads a standard base64 encoding of exactly 32 bytes.
func ParseKey(b64 string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Key{}, fmt.Errorf("ParseKey: %w", err)
	}
	if len(raw) != keyLen {
		return Key{}, fmt.Errorf("ParseKey: key is %d bytes, want %d", len(raw), keyLen)
	}
	var k Key
	copy(k[:], raw)
	return k, nil
}

// Credentials is one set of cloud credentials. AWS sets are short-lived STS
// sessions minted for the run; Expires is zero only for a connector's own
// static keys, which have no role to assume and so nothing to shorten.
type Credentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token,omitempty"`
	Expires         time.Time `json:"expires,omitempty"`
}

// Valid reports whether the set can sign a request.
func (c *Credentials) Valid() bool {
	return c != nil && c.AccessKeyID != "" && c.SecretAccessKey != ""
}

// Access is what a volume job may use for one connector.
//
// Role and OtherRoles are identifiers kept for the opt-in comparison only: on
// AWS the scanner never assumes a role, because the credentials it uses are the
// two sessions below. Config holds non-secret locators on AWS (region,
// regions); on Azure it also holds the disk-scan client secret.
//
// AWSRead is a session of the connector's collection role, narrowed to the
// snapshot read actions. AWSWrite exists only in create_snapshots mode: a
// session of the disk-scan role, narrowed to create, tag and delete snapshots.
type Access struct {
	ConnectorID string            `json:"connector_id"`
	Type        string            `json:"type"`
	Role        string            `json:"role"`
	OtherRoles  []string          `json:"other_roles"`
	Config      map[string]string `json:"config"`
	AWSRead     *Credentials      `json:"aws_read,omitempty"`
	AWSWrite    *Credentials      `json:"aws_write,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at"`
}

func aad(runID, connectorID string) []byte {
	return []byte("disk-scan-envelope|" + runID + "|" + connectorID)
}

func gcm(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	return cipher.NewGCM(block)
}

// Seal encrypts the access for one run. The envelope expires at a.ExpiresAt.
func Seal(k Key, runID string, a Access) ([]byte, error) {
	if runID == "" || a.ConnectorID == "" || a.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("Seal: run, connector and expiry are required: %w", ErrInvalid)
	}
	plain, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("Seal: %w", err)
	}
	g, err := gcm(k)
	if err != nil {
		return nil, fmt.Errorf("Seal: %w", err)
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Seal: nonce: %w", err)
	}
	out := append([]byte{version}, nonce...)
	return g.Seal(out, nonce, plain, aad(runID, a.ConnectorID)), nil
}

// Open decrypts an envelope sealed for runID and connectorID.
func Open(k Key, runID, connectorID string, sealed []byte, now time.Time) (Access, error) {
	g, err := gcm(k)
	if err != nil {
		return Access{}, fmt.Errorf("Open: %w", err)
	}
	if len(sealed) < 1+g.NonceSize() || sealed[0] != version {
		return Access{}, fmt.Errorf("Open: %w", ErrInvalid)
	}
	nonce, ct := sealed[1:1+g.NonceSize()], sealed[1+g.NonceSize():]
	plain, err := g.Open(nil, nonce, ct, aad(runID, connectorID))
	if err != nil {
		return Access{}, fmt.Errorf("Open: %w", ErrInvalid)
	}
	var a Access
	if err := json.Unmarshal(plain, &a); err != nil {
		return Access{}, fmt.Errorf("Open: %w", ErrInvalid)
	}
	if a.ConnectorID != connectorID {
		return Access{}, fmt.Errorf("Open: %w", ErrInvalid)
	}
	if !now.Before(a.ExpiresAt) {
		return Access{}, fmt.Errorf("Open: %w", ErrExpired)
	}
	return a, nil
}
