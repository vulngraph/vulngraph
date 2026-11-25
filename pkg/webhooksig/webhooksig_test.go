package webhooksig

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A pinned vector, so a change to the scheme (which every receiver depends
// on) is a deliberate test change. Cross-checked with
// `printf %s 1700000000.{"a":1} | openssl dgst -sha256 -hmac s3cret`.
func TestSign_KnownVector(t *testing.T) {
	require.Equal(t, "sha256=1698a50bc74d1ff1db85c4e0a5297c2ad9fdba245d5737cdb789e4cc6e098940",
		Sign("s3cret", "1700000000", []byte(`{"a":1}`)))
}

func TestSetHeaders(t *testing.T) {
	h := http.Header{}
	body := []byte(`{"a":1}`)
	SetHeaders(h, "s3cret", time.Unix(1700000000, 0), body)
	require.Equal(t, "1700000000", h.Get(TimestampHeader))
	require.Equal(t, Sign("s3cret", "1700000000", body), h.Get(SignatureHeader))
	require.NotEqual(t, Sign("other", "1700000000", body), h.Get(SignatureHeader))
}

func TestVerify(t *testing.T) {
	body := []byte(`{"a":1}`)
	sent := time.Unix(1700000000, 0)
	h := http.Header{}
	SetHeaders(h, "s3cret", sent, body)

	require.NoError(t, Verify(h, "s3cret", body, sent.Add(time.Minute), DefaultWindow))
	require.ErrorIs(t, Verify(h, "other", body, sent, DefaultWindow), ErrBadSignature)
	require.ErrorIs(t, Verify(h, "s3cret", []byte(`{"a":2}`), sent, DefaultWindow), ErrBadSignature)
	require.ErrorIs(t, Verify(h, "s3cret", body, sent.Add(10*time.Minute), DefaultWindow), ErrStale, "a replay")
	require.ErrorIs(t, Verify(h, "s3cret", body, sent.Add(-10*time.Minute), DefaultWindow), ErrStale)

	unkeyed := http.Header{}
	SetHeaders(unkeyed, "", sent, body)
	require.ErrorIs(t, Verify(unkeyed, "", body, sent, DefaultWindow), ErrNoSecret, "an empty secret verifies nothing")

	forged := h.Clone()
	forged.Set(TimestampHeader, "1700000600")
	require.ErrorIs(t, Verify(forged, "s3cret", body, sent.Add(10*time.Minute), DefaultWindow), ErrBadSignature,
		"the timestamp is signed, so moving it breaks the signature")
}
