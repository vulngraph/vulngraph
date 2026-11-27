//go:build integration

package enrich

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestCancelledEnrichmentPreservesMeasuredOutput(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	id := "cancelled-enrich-" + uuid.NewString()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, table := range []string{"findings", "finding_enrichment", "signals"} {
			require.NoError(t, ch.Exec(cleanup, "DELETE FROM "+table+" WHERE id=? SETTINGS mutations_sync=1", id))
		}
	})
	findings := finding.NewService(finding.NewCHRepo(ch))
	signals := NewSignalCHRepo(ch)
	f := sampleFinding()
	f.ID = id
	f.ResourceID = id
	require.NoError(t, findings.RecordObserved(ctx, []finding.Finding{f}))
	healthy := NewService(findings, signals, []Source{BaseSeverity{}, fakeSource{name: "extra", factor: Factor{Source: "extra", Points: 5}, applied: true}})
	_, err = healthy.Enrich(ctx, f)
	require.NoError(t, err)
	before, err := findings.Get(ctx, id)
	require.NoError(t, err)
	beforeFactors, err := signals.Factors(ctx, id)
	require.NoError(t, err)
	cancelled, stop := context.WithCancel(ctx)
	defer stop()
	interrupted := NewService(findings, signals, []Source{BaseSeverity{}, cancellingSource{stop}})
	_, err = interrupted.Enrich(cancelled, f)
	require.ErrorIs(t, err, context.Canceled, "write budgets must not detach a cancelled measurement into a successful partial score")
	after, err := findings.Get(ctx, id)
	require.NoError(t, err)
	factors, err := signals.Factors(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before.Score, after.Score)
	require.Equal(t, before.EnrichedAt, after.EnrichedAt)
	require.Equal(t, beforeFactors, factors)
	// A fresh-context retry still executes and writes a measured result.
	score, err := healthy.Enrich(ctx, f)
	require.NoError(t, err)
	require.Empty(t, score.Unmeasured)
	retried, err := findings.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, score.Value, retried.Score)
	require.True(t, retried.EnrichedAt.After(before.EnrichedAt))
}
