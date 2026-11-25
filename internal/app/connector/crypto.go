package connector

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Connector config is stored under envelope encryption.
//
// The thing being protected is the platform's whole credential estate: read
// roles across every configured AWS account and GCP project, a GitHub App
// private key, an Okta API token, a Google Workspace service-account JSON,
// and — same cipher, same key — every alert-channel secret and TOTP seed.
//
// There is ONE key-encryption key: GRAPH_SECRET_KEY, a local AES-256 key in
// the environment of serve and the worker. Whoever holds it and the database
// (a pod or its environment) opens every row. Envelope encryption does not
// change that; it narrows the other cases:
//
//   - Per-row DEK. Every row is sealed under its own random 256-bit data key,
//     wrapped by the KEK. A leaked DEK opens exactly its own row.
//   - AAD binding. The data key AND the payload are bound to the row's identity,
//     so a ciphertext lifted from one connector cannot be replayed into another
//     row to make the platform authenticate as someone else's credential.
//   - Key-ID tagging. Each envelope names the KEK that wrapped it, so a retired
//     KEK can be trusted for reads while RewrapAll re-seals rows under the new
//     one: that is the rotation path (GRAPH_RETIRED_SECRET_KEYS, graph keys
//     rewrap).
//
// A KMS-held KEK would make unwrapping an IAM-authorized, auditable call; the
// format allows it (only the wrap and unwrap of the small DEK blob would
// change), but it is not implemented.
//
// Nothing here rewrites data on read. Every write, and the explicit RewrapAll
// pass after a key rotation, produces a v1 envelope; that is the only format a
// read accepts.
const (
	// envelopeMagic prefixes every v1 ciphertext.
	envelopeMagic = "GEK1"
	// dekSize is the per-row data key length (AES-256).
	dekSize = 32
	// kekIDLen is how many hex chars of the KEK fingerprint are stored. Long
	// enough that two configured KEKs cannot collide, short enough to stay cheap
	// on every row.
	kekIDLen = 16
)

// Cipher encrypts connector config at rest. It holds one CURRENT key-encryption
// key used for all writes, plus any number of retired KEKs kept for reads — the
// state a rotation passes through.
type Cipher struct {
	keks     map[string]cipher.AEAD // KEK id -> AEAD
	currentK string
}

// NewCipher builds a Cipher from a base64-encoded 32-byte key (GRAPH_SECRET_KEY).
func NewCipher(base64Key string) (*Cipher, error) {
	id, aead, err := loadKEK(base64Key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %w", err)
	}
	return &Cipher{keks: map[string]cipher.AEAD{id: aead}, currentK: id}, nil
}

// WithRetiredKey trusts an additional KEK for DECRYPTION only. This is the
// rotation path: deploy with the new key as GRAPH_SECRET_KEY and the old one
// retired, run RewrapAll, then drop the retired key. Rows sealed under the old
// KEK stay readable throughout, so no window exists in which a credential is
// unrecoverable.
func (c *Cipher) WithRetiredKey(base64Key string) (*Cipher, error) {
	id, aead, err := loadKEK(base64Key)
	if err != nil {
		return nil, fmt.Errorf("WithRetiredKey: %w", err)
	}
	if id == c.currentK {
		return nil, errors.New("WithRetiredKey: retired key is the current key")
	}
	c.keks[id] = aead
	return c, nil
}

// CurrentKeyID names the KEK new writes are sealed under.
func (c *Cipher) CurrentKeyID() string { return c.currentK }

func loadKEK(base64Key string) (string, cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return "", nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, fmt.Errorf("loadKEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("loadKEK: %w", err)
	}
	// A fingerprint OF the key, never the key: this lands in plaintext on every
	// row, so it is a salted digest truncated to an identifier.
	sum := sha256.Sum256(append([]byte("graph/kek-id/v1"), key...))
	return hex.EncodeToString(sum[:])[:kekIDLen], aead, nil
}

// EncryptWithAAD seals plaintext in a v1 envelope bound to aad. Decryption with
// a different aad fails: that is what stops a ciphertext being moved between
// rows.
func (c *Cipher) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	kek := c.keks[c.currentK]

	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("EncryptWithAAD: dek: %w", err)
	}
	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, fmt.Errorf("EncryptWithAAD: %w", err)
	}

	// Binding the wrap to the KEK id as well as the row's aad means a wrapped
	// DEK cannot be re-attributed to a different key or a different row.
	wrapNonce := make([]byte, kek.NonceSize())
	if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
		return nil, fmt.Errorf("EncryptWithAAD: wrap nonce: %w", err)
	}
	wrapped := kek.Seal(wrapNonce, wrapNonce, dek, wrapAAD(c.currentK, aad))
	if len(wrapped) > 255 {
		return nil, errors.New("EncryptWithAAD: wrapped dek does not fit its length prefix")
	}

	dataNonce := make([]byte, dekAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return nil, fmt.Errorf("EncryptWithAAD: data nonce: %w", err)
	}

	var out bytes.Buffer
	out.WriteString(envelopeMagic)
	out.WriteByte(byte(len(c.currentK)))
	out.WriteString(c.currentK)
	out.WriteByte(byte(len(wrapped)))
	out.Write(wrapped)
	out.Write(dekAEAD.Seal(dataNonce, dataNonce, plaintext, aad))
	return out.Bytes(), nil
}

// DecryptWithAAD opens a v1 envelope under the KEK it names. Anything else is
// refused: a ciphertext without the envelope header carries no row binding, so
// accepting one would let a value sealed without AAD stand in for any row.
func (c *Cipher) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	if !isEnvelope(ciphertext) {
		return nil, errors.New("DecryptWithAAD: not a v1 envelope")
	}
	plain, err := c.openEnvelope(ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("DecryptWithAAD: %w", err)
	}
	return plain, nil
}

func (c *Cipher) openEnvelope(ct, aad []byte) ([]byte, error) {
	buf := ct[len(envelopeMagic):]
	if len(buf) < 1 {
		return nil, errors.New("openEnvelope: truncated header")
	}
	idLen := int(buf[0])
	buf = buf[1:]
	if len(buf) < idLen+1 {
		return nil, errors.New("openEnvelope: truncated key id")
	}
	kekID := string(buf[:idLen])
	buf = buf[idLen:]

	wrappedLen := int(buf[0])
	buf = buf[1:]
	if len(buf) < wrappedLen {
		return nil, errors.New("openEnvelope: truncated wrapped key")
	}
	wrapped, rest := buf[:wrappedLen], buf[wrappedLen:]

	kek, ok := c.keks[kekID]
	if !ok {
		// Name the key, so the fix ("that KEK is not configured — retire it into
		// the cipher") is obvious rather than looking like data corruption.
		return nil, fmt.Errorf("openEnvelope: sealed under key %q, which is not configured", kekID)
	}
	ns := kek.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("openEnvelope: wrapped key shorter than nonce")
	}
	dek, err := kek.Open(nil, wrapped[:ns], wrapped[ns:], wrapAAD(kekID, aad))
	if err != nil {
		return nil, fmt.Errorf("openEnvelope: unwrap: %w", err)
	}
	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, fmt.Errorf("openEnvelope: %w", err)
	}
	dn := dekAEAD.NonceSize()
	if len(rest) < dn {
		return nil, errors.New("openEnvelope: payload shorter than nonce")
	}
	plain, err := dekAEAD.Open(nil, rest[:dn], rest[dn:], aad)
	if err != nil {
		return nil, fmt.Errorf("openEnvelope: %w", err)
	}
	return plain, nil
}

// IsCurrentEnvelope reports whether ct is already sealed as an envelope under
// the CURRENT KEK — i.e. whether RewrapAll can skip it.
func (c *Cipher) IsCurrentEnvelope(ct []byte) bool {
	if !isEnvelope(ct) {
		return false
	}
	buf := ct[len(envelopeMagic):]
	if len(buf) < 1 {
		return false
	}
	idLen := int(buf[0])
	if len(buf) < 1+idLen {
		return false
	}
	return string(buf[1:1+idLen]) == c.currentK
}

func isEnvelope(ct []byte) bool {
	return len(ct) > len(envelopeMagic) && string(ct[:len(envelopeMagic)]) == envelopeMagic
}

// wrapAAD binds a wrapped DEK to both the KEK that wrapped it and the row.
func wrapAAD(kekID string, aad []byte) []byte {
	out := make([]byte, 0, len(kekID)+1+len(aad))
	out = append(out, kekID...)
	out = append(out, '|')
	return append(out, aad...)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
