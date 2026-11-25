package llmusage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
)

func f(v float64) *float64 { return &v }

func TestPurposeInteractiveIsAPositiveList(t *testing.T) {
	for _, p := range []Purpose{PurposeChat, PurposeNLQuery, PurposeRefine, PurposeTemplateGen} {
		require.True(t, p.Interactive(), p)
	}
	for _, p := range []Purpose{PurposeReason, PurposeAdjudicate, PurposeCTTriage, PurposeDriftAnalysis, "something_new", ""} {
		require.False(t, p.Interactive(), "%q must be background (fails closed)", p)
	}
}

func TestPriceTableLookup(t *testing.T) {
	table := PriceTable{
		"claude-opus":     {Input: 1, Output: 2},
		"claude-opus-4-8": {Input: 3, Output: 4},
		"gpt":             {Input: 5, Output: 6},
	}
	for _, tc := range []struct {
		model string
		want  Price
		known bool
	}{
		{"claude-opus-4-8", Price{Input: 3, Output: 4}, true},
		{"claude-opus-4-8-20260101", Price{Input: 3, Output: 4}, true},
		{"claude-opus-5", Price{Input: 1, Output: 2}, true},
		{"gpt-5", Price{Input: 5, Output: 6}, true},
		{"llama3", DefaultPrice, false},
	} {
		got, known := table.Lookup(tc.model)
		require.Equal(t, tc.want, got, tc.model)
		require.Equal(t, tc.known, known, tc.model)
	}

	wildcard := PriceTable{"*": {Input: 0, Output: 0}}
	got, known := wildcard.Lookup("llama3")
	require.True(t, known)
	require.Equal(t, Price{}, got)
	_, known = PriceTable{}.Lookup("*")
	require.False(t, known)
}

func TestPriceCost(t *testing.T) {
	u := llm.Usage{InputTokens: 1_000_000, OutputTokens: 100_000, CacheReadTokens: 1_000_000, CacheWriteTokens: 1_000_000}
	// Unpriced cache classes are charged conservatively: reads at the input
	// price, writes at twice it.
	require.EqualValues(t, 3_000_000+1_500_000+3_000_000+6_000_000, Price{Input: 3, Output: 15}.CostMicroUSD(u))
	require.EqualValues(t, 3_000_000+1_500_000+300_000+3_750_000,
		Price{Input: 3, Output: 15, CacheRead: f(0.3), CacheWrite: f(3.75)}.CostMicroUSD(u))
	// Fractions round up: a call is never free because it was small.
	require.EqualValues(t, 1, Price{Input: 0.1}.CostMicroUSD(llm.Usage{InputTokens: 1}))
	require.EqualValues(t, 0, Price{}.CostMicroUSD(u))
}

func TestParsePriceTable(t *testing.T) {
	table, err := ParsePriceTable("")
	require.NoError(t, err)
	require.Empty(t, table)

	table, err = ParsePriceTable(`{"m":{"input":1.5,"output":7,"cache_read":0.15}}`)
	require.NoError(t, err)
	require.Equal(t, Price{Input: 1.5, Output: 7, CacheRead: f(0.15)}, table["m"])

	for _, bad := range []string{`not json`, `["m"]`, `{"m":{"input":-1}}`, `{"m":{"output":1,"cache_write":-2}}`} {
		_, err := ParsePriceTable(bad)
		require.Error(t, err, bad)
	}
}

func TestMonths(t *testing.T) {
	ts := time.Date(2026, 10, 8, 23, 30, 0, 0, time.FixedZone("x", -5*3600))
	require.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), MonthStart(ts))
	start, end, err := ParseMonth("2026-12")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), start)
	require.Equal(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), end)
	_, _, err = ParseMonth("2026-13")
	require.ErrorIs(t, err, ErrInvalidMonth)
	require.EqualValues(t, 12_340_000, USDToMicro(12.34))
}
