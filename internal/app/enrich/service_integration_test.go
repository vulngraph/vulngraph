//go:build integration

package enrich

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func rawFinding(id string) finding.Finding {
	return finding.Finding{
		ID: id, Source: "cspm", Type: "exposure", Severity: finding.SeverityCritical,
		Title: "public bucket", Description: "world-readable", ResourceType: "s3_bucket",
		ResourceID: "r-" + id, ResourceName: "logs", Region: "eu-west-1",
		CheckID: "cis-s3-public", Remediation: "make private", DetectedAt: time.Now(),
	}
}

// Enrich writes its outputs to finding_enrichment, and they read back on the
// finding without blanking any findings column.
func TestService_Enrich_WritesEnrichmentOnly_EndToEnd(t *testing.T) {
	ctx, findingSvc, svc, id := enrichHarness(t)
	require.NoError(t, findingSvc.RecordObserved(ctx, []finding.Finding{rawFinding(id)}))
	f, err := findingSvc.Get(ctx, id)
	require.NoError(t, err)

	score, err := svc.Enrich(ctx, f)
	require.NoError(t, err)
	require.Equal(t, uint8(40), score.Value)

	got, err := findingSvc.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, uint8(40), got.Score, "the enriched score reads back on the finding")
	require.Equal(t, string(BandMonitor), got.ScoreBand)
	require.False(t, got.EnrichedAt.IsZero())
	require.Equal(t, "public bucket", got.Title)
	require.Equal(t, finding.SeverityCritical, got.Severity)
}

// A sync resolving the finding while enrich runs on its earlier (open) read
// must stay resolved: enrich owns no lifecycle column.
func TestService_Enrich_ResolveDuringEnrichDoesNotReopen(t *testing.T) {
	ctx, findingSvc, svc, id := enrichHarness(t)
	require.NoError(t, findingSvc.RecordObserved(ctx, []finding.Finding{rawFinding(id)}))
	stale, err := findingSvc.Get(ctx, id) // the enrich job's start-of-work read
	require.NoError(t, err)
	require.False(t, stale.Resolved())

	current, err := findingSvc.Get(ctx, id)
	require.NoError(t, err)
	require.NoError(t, findingSvc.Resolve(ctx, []finding.Finding{current}, finding.ReasonFixed))

	_, err = svc.Enrich(ctx, stale)
	require.NoError(t, err)

	got, err := findingSvc.Get(ctx, id)
	require.NoError(t, err)
	require.True(t, got.Resolved(), "an enrich of the pre-resolve read must not reopen the finding")
	require.Equal(t, finding.ReasonFixed, got.ResolutionReason)
	require.Equal(t, uint8(40), got.Score, "the enrichment itself still lands")
}

// A sync reopening the finding (regression) while enrich runs on its earlier
// (resolved) read must stay open.
func TestService_Enrich_ReopenDuringEnrichIsNotReResolved(t *testing.T) {
	ctx, findingSvc, svc, id := enrichHarness(t)
	require.NoError(t, findingSvc.RecordObserved(ctx, []finding.Finding{rawFinding(id)}))
	open, err := findingSvc.Get(ctx, id)
	require.NoError(t, err)
	require.NoError(t, findingSvc.Resolve(ctx, []finding.Finding{open}, finding.ReasonFixed))
	stale, err := findingSvc.Get(ctx, id) // the enrich job's start-of-work read
	require.NoError(t, err)
	require.True(t, stale.Resolved())

	require.NoError(t, findingSvc.RecordObserved(ctx, []finding.Finding{rawFinding(id)}))

	_, err = svc.Enrich(ctx, stale)
	require.NoError(t, err)

	got, err := findingSvc.Get(ctx, id)
	require.NoError(t, err)
	require.False(t, got.Resolved(), "an enrich of the pre-reopen read must not re-resolve the finding")
	require.False(t, got.LastObservedAt.IsZero())
}
