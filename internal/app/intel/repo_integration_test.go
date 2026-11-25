//go:build integration

package intel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Exercises the argMax candidate reads against real ClickHouse. UpdateStatus
// rewrites the full row at a fresh synced_at (ReplacingMergeTree version), so
// every reader must surface the LATEST status — the queries used to run
// `FINAL WHERE ...`, the filtered-FINAL full-scan anti-pattern (CLAUDE.md).
// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_CandidateLifecycle(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	id := "cand-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE phishing_candidates DELETE WHERE id = ?", id) })

	require.NoError(t, repo.BulkUpsertCandidates(ctx, []PhishingCandidate{{
		ID: id, Domain: "examp1e-" + suffix + ".com", MonitoredDomain: "example.com",
		Source: "crt_sh", SimilarityScore: 0.92, Issuer: "LE",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		Status: StatusPending, AIIsPhishing: true, AIConfidence: 0.9,
		AIReasoning: "heuristic: similarity score", TriageSource: TriageHeuristic, DetectedAt: now,
	}}))

	got, err := repo.GetCandidate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, StatusPending, got.Status)
	require.InDelta(t, 0.92, got.SimilarityScore, 0.001)
	// The AI verdict must round-trip.
	require.True(t, got.AIIsPhishing, "the persisted AI verdict must read back")
	require.Equal(t, TriageHeuristic, got.TriageSource, "what produced the verdict must read back")

	pending, _, err := repo.ListCandidates(ctx, StatusPending)
	require.NoError(t, err)
	require.True(t, containsCandidate(pending, id), "pending list surfaces the new candidate")

	ids, err := repo.ExistingCandidateIDs(ctx)
	require.NoError(t, err)
	require.True(t, ids[id], "non-dismissed candidate feeds re-detection dedup")

	// UpdateStatus writes a NEW version of the row; ClickHouse versions collide
	// on synced_at's one-second granularity, so wait out the tick to make the
	// rewrite deterministically newer (same caveat as finding.WithClock).
	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, repo.UpdateStatus(ctx, id, StatusDismissed, "tester"))

	got, err = repo.GetCandidate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, StatusDismissed, got.Status, "point lookup surfaces the latest version's status")
	require.Equal(t, TriageHeuristic, got.TriageSource, "UpdateStatus keeps the verdict's source")

	pending, _, err = repo.ListCandidates(ctx, StatusPending)
	require.NoError(t, err)
	require.False(t, containsCandidate(pending, id), "a dismissed candidate must leave the pending list — its stale pending version must not match")

	dismissed, _, err := repo.ListCandidates(ctx, StatusDismissed)
	require.NoError(t, err)
	require.True(t, containsCandidate(dismissed, id))

	ids, err = repo.ExistingCandidateIDs(ctx)
	require.NoError(t, err)
	require.True(t, ids[id],
		"a DISMISSED candidate must stay in the dedup set. It used to be excluded, and RunScan treats "+
			"'not in the set' as a new hit, so every manual dismissal came back as 'pending' within 6 hours")

	// The auto-dismissed bucket (cleared by triage or re-score) is its own
	// status: out of the human queue, still queryable, never deleted.
	autoID := "cand-auto-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE phishing_candidates DELETE WHERE id = ?", autoID) })
	require.NoError(t, repo.BulkUpsertCandidates(ctx, []PhishingCandidate{{
		ID: autoID, Domain: "microexample-" + suffix + ".com", MonitoredDomain: "example.com",
		Source: "crt_sh", SimilarityScore: 0.44, Issuer: "LE",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		Status: StatusAutoDismissed, AIIsPhishing: false, AIConfidence: 0.15,
		AIReasoning: "compound word, legitimate", DetectedAt: now,
	}}))

	pending, _, err = repo.ListCandidates(ctx, StatusPending)
	require.NoError(t, err)
	require.False(t, containsCandidate(pending, autoID), "an auto-dismissed candidate is not a human queue item")

	auto, _, err := repo.ListCandidates(ctx, StatusAutoDismissed)
	require.NoError(t, err)
	require.True(t, containsCandidate(auto, autoID), "auto-dismissed rows must stay reviewable")

	autoGot, err := repo.GetCandidate(ctx, autoID)
	require.NoError(t, err)
	require.False(t, autoGot.AIIsPhishing)
	require.NotEmpty(t, autoGot.AIReasoning, "the reasoning is the audit trail for a clearing decision")

	ids, err = repo.ExistingCandidateIDs(ctx)
	require.NoError(t, err)
	require.True(t, ids[autoID], "an auto-dismissed candidate must not be re-triaged on the next scan either")

	_, err = repo.GetCandidate(ctx, "missing-"+suffix)
	require.ErrorIs(t, err, ErrNotFound)
}

func containsCandidate(cs []PhishingCandidate, id string) bool {
	for _, c := range cs {
		if c.ID == id {
			return true
		}
	}
	return false
}
