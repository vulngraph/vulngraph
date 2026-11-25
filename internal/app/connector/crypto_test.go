package connector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

func TestNewCipher_RejectsBadKey(t *testing.T) {
	_, err := NewCipher("not-base64!!!")
	require.Error(t, err)

	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err = NewCipher(short)
	require.ErrorContains(t, err, "32 bytes")
}

func TestCipher_RoundTrip(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)

	plaintext := []byte(`{"role_arn":"arn:aws:iam::1:role/x","region":"eu-west-1"}`)
	aad := []byte("connector:a")
	enc, err := c.EncryptWithAAD(plaintext, aad)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, enc, "ciphertext must differ from plaintext")

	dec, err := c.DecryptWithAAD(enc, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, dec)
}

func TestCipher_NonceMakesCiphertextUnique(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)

	a, err := c.EncryptWithAAD([]byte("same"), []byte("connector:a"))
	require.NoError(t, err)
	b, err := c.EncryptWithAAD([]byte("same"), []byte("connector:a"))
	require.NoError(t, err)
	require.NotEqual(t, a, b, "random nonce must make repeated encryptions differ")
}

func TestCipher_DecryptRejectsTampered(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)

	enc, err := c.EncryptWithAAD([]byte("secret"), []byte("connector:a"))
	require.NoError(t, err)
	enc[len(enc)-1] ^= 0xff // flip a ciphertext bit

	_, err = c.DecryptWithAAD(enc, []byte("connector:a"))
	require.Error(t, err, "GCM auth tag must reject tampering")
}

func TestCipher_DecryptRejectsWrongKey(t *testing.T) {
	c1, _ := NewCipher(testKey(t))
	c2, _ := NewCipher(testKey(t))

	enc, err := c1.EncryptWithAAD([]byte("secret"), []byte("connector:a"))
	require.NoError(t, err)
	_, err = c2.DecryptWithAAD(enc, []byte("connector:a"))
	require.Error(t, err)
}

// ---- envelope encryption ----

func TestCipher_WritesEnvelopeFormat(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)
	enc, err := c.EncryptWithAAD([]byte("secret"), []byte("connector:abc"))
	require.NoError(t, err)
	require.True(t, isEnvelope(enc), "writes must produce the envelope format")
	require.True(t, c.IsCurrentEnvelope(enc))
}

// Per-row data keys: two rows with identical plaintext must not share key
// material, so recovering one row's DEK yields exactly one row.
func TestCipher_EachRowGetsItsOwnDataKey(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)
	a, err := c.EncryptWithAAD([]byte("same"), []byte("connector:a"))
	require.NoError(t, err)
	b, err := c.EncryptWithAAD([]byte("same"), []byte("connector:b"))
	require.NoError(t, err)

	// Compare the UNWRAPPED data keys, not the ciphertext bytes: the wrap nonce
	// is random, so a shared DEK would still produce differing bytes and a
	// byte-comparison would pass while the property was gone.
	require.NotEqual(t, unwrapDEK(t, c, a, []byte("connector:a")), unwrapDEK(t, c, b, []byte("connector:b")))
}

// unwrapDEK opens the wrapped data key out of an envelope, so a test can assert
// on the key itself rather than on ciphertext bytes.
func unwrapDEK(t *testing.T, c *Cipher, envelope, aad []byte) []byte {
	t.Helper()
	require.True(t, isEnvelope(envelope))
	buf := envelope[len(envelopeMagic):]
	idLen := int(buf[0])
	buf = buf[1:]
	kekID := string(buf[:idLen])
	buf = buf[idLen:]
	wrapped := buf[1 : 1+int(buf[0])]

	kek := c.keks[kekID]
	require.NotNil(t, kek)
	dek, err := kek.Open(nil, wrapped[:kek.NonceSize()], wrapped[kek.NonceSize():], wrapAAD(kekID, aad))
	require.NoError(t, err)
	require.Len(t, dek, dekSize)
	return dek
}

// The point of the AAD: a ciphertext lifted from the admin-scoped connector's
// row must not open when pasted over a different connector's row.
func TestCipher_CiphertextCannotBeReplayedOntoAnotherRow(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)
	enc, err := c.EncryptWithAAD([]byte(`{"role_arn":"arn:aws:iam::1:role/admin"}`), []byte("connector:privileged"))
	require.NoError(t, err)

	_, err = c.DecryptWithAAD(enc, []byte("connector:unprivileged"))
	require.Error(t, err, "a ciphertext bound to one connector must not open under another's id")

	plain, err := c.DecryptWithAAD(enc, []byte("connector:privileged"))
	require.NoError(t, err)
	require.Contains(t, string(plain), "role/admin")
}

func TestCipher_EnvelopeRejectsTampering(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)
	enc, err := c.EncryptWithAAD([]byte("secret"), []byte("connector:a"))
	require.NoError(t, err)

	for _, at := range []int{len(enc) - 1, len(envelopeMagic) + 20} {
		tampered := append([]byte(nil), enc...)
		tampered[at] ^= 0xff
		_, err := c.DecryptWithAAD(tampered, []byte("connector:a"))
		require.Errorf(t, err, "tampering at offset %d was accepted", at)
	}
}

// ---- format ----

// A raw AES-GCM ciphertext under the KEK, with no envelope header and no row
// binding, is refused: accepting it would let a value sealed without AAD stand
// in for any row.
func TestCipher_NonEnvelopeCiphertextIsRefused(t *testing.T) {
	key := testKey(t)
	c, err := NewCipher(key)
	require.NoError(t, err)

	raw := rawGCMSeal(t, key, []byte(`{"api_token":"okta-sekret"}`))
	require.False(t, isEnvelope(raw))

	_, err = c.DecryptWithAAD(raw, []byte("connector:abc"))
	require.Error(t, err)
	_, err = c.DecryptWithAAD(raw, nil)
	require.Error(t, err)
	require.False(t, c.IsCurrentEnvelope(raw))
}

// Every write is a v1 envelope, bound or unbound.
func TestCipher_EveryWriteIsAnEnvelope(t *testing.T) {
	c, err := NewCipher(testKey(t))
	require.NoError(t, err)
	for _, aad := range [][]byte{nil, []byte("connector:a")} {
		enc, err := c.EncryptWithAAD([]byte("x"), aad)
		require.NoError(t, err)
		require.True(t, isEnvelope(enc))
		require.True(t, c.IsCurrentEnvelope(enc))
	}
}

// ---- rotation ----

func TestCipher_RotationKeepsOldRowsReadable(t *testing.T) {
	oldKey, newKey := testKey(t), testKey(t)

	oldCipher, err := NewCipher(oldKey)
	require.NoError(t, err)
	sealed, err := oldCipher.EncryptWithAAD([]byte("credential"), []byte("connector:a"))
	require.NoError(t, err)

	// New key current, old key retired for reads — the state a rotation deploys.
	rotated, err := NewCipher(newKey)
	require.NoError(t, err)
	rotated, err = rotated.WithRetiredKey(oldKey)
	require.NoError(t, err)

	plain, err := rotated.DecryptWithAAD(sealed, []byte("connector:a"))
	require.NoError(t, err, "rotation must not orphan rows sealed under the old key")
	require.Equal(t, []byte("credential"), plain)

	require.False(t, rotated.IsCurrentEnvelope(sealed), "an old-key row must be reported as needing a rewrap")

	resealed, err := rotated.EncryptWithAAD(plain, []byte("connector:a"))
	require.NoError(t, err)
	require.True(t, rotated.IsCurrentEnvelope(resealed))
}

// Dropping the old key AFTER the rewrap is the last step; before it, the row is
// unreadable and must say so by name rather than looking like corruption.
func TestCipher_UnknownKeyIDIsNamedInTheError(t *testing.T) {
	oldCipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	sealed, err := oldCipher.EncryptWithAAD([]byte("credential"), nil)
	require.NoError(t, err)

	other, err := NewCipher(testKey(t))
	require.NoError(t, err)
	_, err = other.DecryptWithAAD(sealed, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), oldCipher.CurrentKeyID())
}

func TestCipher_RetiringTheCurrentKeyIsRejected(t *testing.T) {
	key := testKey(t)
	c, err := NewCipher(key)
	require.NoError(t, err)
	_, err = c.WithRetiredKey(key)
	require.Error(t, err)
}

// The key id is a fingerprint, not the key.
func TestCipher_KeyIDDoesNotLeakTheKey(t *testing.T) {
	key := testKey(t)
	c, err := NewCipher(key)
	require.NoError(t, err)
	require.Len(t, c.CurrentKeyID(), kekIDLen)
	require.NotContains(t, key, c.CurrentKeyID())
}

// rawGCMSeal seals plaintext directly under the raw key: a random nonce prefixed
// to AES-256-GCM ciphertext, no envelope and no AAD.
func rawGCMSeal(t *testing.T, base64Key string, plaintext []byte) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(base64Key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return aead.Seal(nonce, nonce, plaintext, nil)
}
