package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

func testCipher(t *testing.T) *connector.Cipher {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	c, err := connector.NewCipher(base64.StdEncoding.EncodeToString(k))
	require.NoError(t, err)
	return c
}

// A channel secret opens only for the channel row it was sealed for: copying
// one channel's config_encrypted over another's must not hand the second
// channel the first one's Slack token or webhook URL.
func TestChannelSecret_BoundToChannelID(t *testing.T) {
	r := &PGRepo{cipher: testCipher(t)}

	enc, err := r.encrypt(Channel{ID: "chan-a", WebhookURL: "https://hooks.example.com/a"})
	require.NoError(t, err)
	assert.NotContains(t, string(enc), "hooks.example.com", "the stored value never holds the secret")

	cfg, err := r.decrypt("chan-a", enc)
	require.NoError(t, err)
	assert.Equal(t, "https://hooks.example.com/a", cfg.WebhookURL)

	_, err = r.decrypt("chan-b", enc)
	require.Error(t, err, "a ciphertext moved to another channel row must not open")
}

// PUT /api/alerts/channels/{id} passes the path id through as written, and
// Postgres matches a UUID in any of its accepted spellings. The secret sealed
// on that update must open under the canonical id every later read uses.
func TestChannelSecret_SealedUnderTheCanonicalID(t *testing.T) {
	r := &PGRepo{cipher: testCipher(t)}
	const canonical = "0b6e3f0a-6f4c-4a8e-9a57-2f1d7c3e9b10"
	for _, spelled := range []string{
		"0B6E3F0A-6F4C-4A8E-9A57-2F1D7C3E9B10",
		"{0b6e3f0a-6f4c-4a8e-9a57-2f1d7c3e9b10}",
		"urn:uuid:0b6e3f0a-6f4c-4a8e-9a57-2f1d7c3e9b10",
		"0b6e3f0a6f4c4a8e9a572f1d7c3e9b10",
	} {
		enc, err := r.encrypt(Channel{ID: spelled, BotToken: "bot-token-placeholder"})
		require.NoError(t, err)
		cfg, err := r.decrypt(canonical, enc)
		require.NoError(t, err, "a secret sealed via %q must open under the stored id", spelled)
		assert.Equal(t, "bot-token-placeholder", cfg.BotToken)
	}
}

// A channel whose secret does not open is reported by id, never silently
// dropped, and the log line carries no part of any secret.
func TestOpenSecret_UnopenableIsReportedByID(t *testing.T) {
	var buf bytes.Buffer
	prev := zlog.Logger
	zlog.Logger = zerolog.New(&buf)
	t.Cleanup(func() { zlog.Logger = prev })

	sealer := &PGRepo{cipher: testCipher(t)}
	enc, err := sealer.encrypt(Channel{ID: "chan-a", WebhookURL: "https://hooks.example.com/sealed-path"})
	require.NoError(t, err)

	opened, ok := sealer.openSecret(context.Background(), Channel{ID: "chan-a", Type: TypeWebhook}, enc)
	require.True(t, ok)
	assert.Equal(t, "https://hooks.example.com/sealed-path", opened.WebhookURL)
	assert.Empty(t, buf.String())

	other := &PGRepo{cipher: testCipher(t)} // a different master key
	got, ok := other.openSecret(context.Background(), Channel{ID: "chan-a", Type: TypeWebhook}, enc)
	require.False(t, ok)
	assert.Equal(t, "chan-a", got.ID, "the channel comes back, without a secret")
	assert.Empty(t, got.WebhookURL)
	assert.Contains(t, buf.String(), `"channel_id":"chan-a"`)
	assert.Contains(t, buf.String(), "channel secret did not open")
	assert.NotContains(t, buf.String(), "sealed-path")
}
