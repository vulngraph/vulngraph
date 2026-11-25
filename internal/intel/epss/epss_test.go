package epss

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalog_ScoreCaseInsensitive(t *testing.T) {
	c := NewCatalog(map[string]float64{"CVE-2021-44228": 0.97})
	s, ok := c.Score("cve-2021-44228")
	require.True(t, ok)
	require.InDelta(t, 0.97, s, 1e-9)
	_, ok = c.Score("CVE-0000-0000")
	require.False(t, ok)
	require.Equal(t, 1, c.Len())
}

func TestCache_EmptySafeAndSwap(t *testing.T) {
	cache := NewCache()
	_, ok := cache.Score("CVE-2021-44228") // empty catalog, must not panic
	require.False(t, ok)
	require.False(t, cache.Loaded(), "an empty cache has not been loaded")

	cache.Set(NewCatalog(map[string]float64{"CVE-2021-44228": 0.9}))
	s, ok := cache.Score("CVE-2021-44228")
	require.True(t, ok)
	require.InDelta(t, 0.9, s, 1e-9)
	require.True(t, cache.Loaded())
}

func TestParseCSV(t *testing.T) {
	// First line is the model-version comment; second is the header; then rows.
	csv := "#model_version:v2025.03.14,score_date:2026-06-15T00:00:00Z\n" +
		"cve,epss,percentile\n" +
		"CVE-2021-44228,0.97500,0.99999\n" +
		"CVE-2020-0001,0.00042,0.10000\n" +
		"malformed,notanumber,0.5\n"
	cat, err := parseCSV(strings.NewReader(csv))
	require.NoError(t, err)
	require.Equal(t, 2, cat.Len(), "malformed score row skipped, header/comment ignored")
	s, ok := cat.Score("CVE-2021-44228")
	require.True(t, ok)
	require.InDelta(t, 0.975, s, 1e-9)
	require.False(t, cat.ScoreDate().IsZero(), "score_date parsed from the comment")
	require.Equal(t, 2026, cat.ScoreDate().Year())
	require.Equal(t, 6, int(cat.ScoreDate().Month()))
}

func TestParseCSV_NoCommentStillParses(t *testing.T) {
	// Defensive: a feed without the leading comment must still parse rows (the
	// peeked header line is put back), and score_date is simply zero.
	csv := "cve,epss,percentile\n" +
		"CVE-2021-44228,0.97500,0.99999\n"
	cat, err := parseCSV(strings.NewReader(csv))
	require.NoError(t, err)
	require.Equal(t, 1, cat.Len())
	require.True(t, cat.ScoreDate().IsZero())
}

func TestParseScoreDate(t *testing.T) {
	require.Equal(t, 2026, parseScoreDate("#model_version:v1,score_date:2026-07-19T00:00:00+0000").Year())
	require.Equal(t, 2026, parseScoreDate("#score_date:2026-07-19").Year())
	require.True(t, parseScoreDate("#model_version:v1").IsZero(), "no score_date → zero")
	require.True(t, parseScoreDate("#score_date:garbage").IsZero(), "unparseable → zero")
}
