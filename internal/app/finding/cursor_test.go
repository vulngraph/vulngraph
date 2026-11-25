package finding

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCursor_RoundTrip_Score(t *testing.T) {
	f := Finding{ID: "f-1", Score: 73, DetectedAt: time.Unix(1700, 0)}
	got, err := decodeCursor(EncodeCursor(f, true), true)
	require.NoError(t, err)
	require.True(t, got.byScore)
	require.Equal(t, uint8(73), got.score)
	require.Equal(t, "f-1", got.id)
}

func TestCursor_RoundTrip_Detected(t *testing.T) {
	ts := time.Unix(1_700_000_123, 456).UTC()
	f := Finding{ID: "f-2", DetectedAt: ts}
	got, err := decodeCursor(EncodeCursor(f, false), false)
	require.NoError(t, err)
	require.False(t, got.byScore)
	require.True(t, got.ts.Equal(ts))
	require.Equal(t, "f-2", got.id)
}

func TestCursor_IDWithDelimiter(t *testing.T) {
	f := Finding{ID: "weird|id|with|pipes", Score: 5}
	got, err := decodeCursor(EncodeCursor(f, true), true)
	require.NoError(t, err)
	require.Equal(t, "weird|id|with|pipes", got.id)
}

func TestCursor_SortModeMismatch(t *testing.T) {
	// A token encoded for score sort must not decode under detected sort.
	_, err := decodeCursor(EncodeCursor(Finding{ID: "x", Score: 1}, true), false)
	require.ErrorIs(t, err, ErrBadCursor)
}

func TestCursor_Malformed(t *testing.T) {
	for _, bad := range []string{"", "!!!notbase64!!!", "b25lcGFydA" /* "onepart" */} {
		_, err := decodeCursor(bad, true)
		require.ErrorIs(t, err, ErrBadCursor, "token %q", bad)
	}
}

func TestStaleCursor_RoundTrip(t *testing.T) {
	ts := time.Unix(1_700_000_123, 456).UTC()
	f := Finding{ID: "f-3", EnrichedAt: ts}
	got, err := decodeStaleCursor(EncodeStaleCursor(f))
	require.NoError(t, err)
	require.True(t, got.ts.Equal(ts))
	require.Equal(t, "f-3", got.id)
}

// A detected_at-keyed (or score-keyed) token must never decode as a stale
// (enriched_at-keyed) one and vice versa — a mode mismatch here silently seeks
// the wrong column instead of erroring, which is worse than ErrBadCursor.
func TestStaleCursor_SortModeMismatch(t *testing.T) {
	_, err := decodeStaleCursor(EncodeCursor(Finding{ID: "x"}, false))
	require.ErrorIs(t, err, ErrBadCursor)

	_, err = decodeCursor(EncodeStaleCursor(Finding{ID: "x"}), false)
	require.ErrorIs(t, err, ErrBadCursor)
}
