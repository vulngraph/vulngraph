//go:build integration

package finding

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

// TestCHRepo_DistinctCheckIDsAppliesEphemeralLiveness is the finding-side twin
// of asset's TestCHRepo_LiveIDsAppliesEphemeralLiveness: it proves
// distinctCheckIDs' liveness gate against the REAL ClickHouse arithmetic
// (asset.EphemeralLivenessCond), rather than a Go reimplementation of it, and
// covers the three evidence states compliance.Service.Compute must never
// confuse (unmeasured is not zero):
//
//  1. live evidence -> check_id must still be reported as having an open
//     finding (control fails);
//  2. evidence on a verified-dead asset (a real assets row, gated type, stale
//     past the high-water + 72h grace) -> check_id must NOT be reported
//     (control does not fail on a corpse);
//  3. evidence whose asset liveness is UNKNOWN (no assets row at all for its
//     resource_id) -> check_id MUST still be reported — unknown must never
//     silently read as "resolved", or a control could pass on evidence we
//     simply never verified;
//  4. one check_id with its evidence split across a live asset and a dead
//     asset -> must still be reported, because ANY live/unknown finding keeps
//     the check_id failing regardless of how many other findings under it are
//     verified corpses.
//
// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_DistinctCheckIDsAppliesEphemeralLiveness(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	findingSvc := NewService(NewCHRepo(ch))
	assetSvc := asset.NewService(asset.NewCHRepo(ch))

	p := "it-dci-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)

	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id LIKE ?", p+"%")
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
	})

	// Anchor the k8s_pod high-water mark to `now` (same technique as
	// asset/liveness_integration_test.go) so this run's fixtures are judged
	// against a cutoff this test controls, not whatever pod happens to be
	// freshest in a shared database.
	livePod := p + "live-pod"
	deadPod := p + "dead-pod"
	deadPod2 := p + "dead-pod-2"
	staleRole := p + "stale-role"

	assets := []asset.Asset{
		{ID: livePod, Name: "live", Type: "k8s_pod", Provider: asset.ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now},
		{ID: deadPod, Name: "dead", Type: "k8s_pod", Provider: asset.ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
		{ID: deadPod2, Name: "dead2", Type: "k8s_pod", Provider: asset.ProviderKubernetes,
			DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
		// Non-ephemeral type, far staler than either dead pod: must NEVER be
		// excluded — EphemeralLivenessCond short-circuits to true for it: a
		// stale cloud-resource row is broken collection, not proof of deletion.
		{ID: staleRole, Name: "role", Type: "iam_role", Provider: asset.ProviderAWS,
			DiscoveredAt: now, LastSeen: now.Add(-150 * 24 * time.Hour)},
	}
	require.NoError(t, assetSvc.Ingest(ctx, assets, nil))

	unknownResourceID := p + "never-synced" // deliberately no matching assets row

	findings := []Finding{
		// State 1: live evidence.
		{ID: p + "f-live", Source: "cspm", Type: "exposure", Severity: SeverityMedium,
			Title: "live pod finding", ResourceType: "k8s_pod", ResourceID: livePod,
			CheckID: "it-dci-check-live", DetectedAt: now},
		// State 2: evidence on a verified-dead asset only.
		{ID: p + "f-dead", Source: "cspm", Type: "exposure", Severity: SeverityMedium,
			Title: "dead pod finding", ResourceType: "k8s_pod", ResourceID: deadPod,
			CheckID: "it-dci-check-dead", DetectedAt: now},
		// State 3: evidence whose asset liveness is unknown (no assets row).
		{ID: p + "f-unknown", Source: "cspm", Type: "exposure", Severity: SeverityMedium,
			Title: "no matching asset row", ResourceType: "k8s_pod", ResourceID: unknownResourceID,
			CheckID: "it-dci-check-unknown", DetectedAt: now},
		// State 4: split evidence — one live, one verified-dead, same check_id.
		{ID: p + "f-split-live", Source: "cspm", Type: "exposure", Severity: SeverityMedium,
			Title: "split: live half", ResourceType: "k8s_pod", ResourceID: livePod,
			CheckID: "it-dci-check-split", DetectedAt: now},
		{ID: p + "f-split-dead", Source: "cspm", Type: "exposure", Severity: SeverityMedium,
			Title: "split: dead half", ResourceType: "k8s_pod", ResourceID: deadPod2,
			CheckID: "it-dci-check-split", DetectedAt: now},
		// Non-ephemeral, very stale asset: must still be reported as failing.
		{ID: p + "f-stale-role", Source: "cspm", Type: "exposure", Severity: SeverityLow,
			Title: "stale but not ephemeral", ResourceType: "iam_role", ResourceID: staleRole,
			CheckID: "it-dci-check-nonephemeral", DetectedAt: now},
	}
	require.NoError(t, findingSvc.Record(ctx, findings))

	ids, err := findingSvc.DistinctCheckIDs(ctx, "")
	require.NoError(t, err)

	require.Contains(t, ids, "it-dci-check-live",
		"a finding on a live asset must keep its check_id (and control) failing")
	require.NotContains(t, ids, "it-dci-check-dead",
		"a finding whose ONLY asset is a verified corpse must not keep a control failing forever")
	require.Contains(t, ids, "it-dci-check-unknown",
		"unknown asset liveness (no assets row at all) must never silently read as resolved")
	require.Contains(t, ids, "it-dci-check-split",
		"one live asset among several must still fail the check_id, however many siblings are dead")
	require.Contains(t, ids, "it-dci-check-nonephemeral",
		"a non-ephemeral type must never be excluded no matter how stale — EphemeralLivenessCond "+
			"short-circuits true for it")

	// The compliance export's resource counts read the same open-and-alive
	// set: a verified corpse is never a failing resource, an unknown one is.
	byCheck, err := findingSvc.OpenResourcesByCheck(ctx,
		[]string{"it-dci-check-live", "it-dci-check-dead", "it-dci-check-unknown", "it-dci-check-split"})
	require.NoError(t, err)
	mine := func(id string) []string {
		var out []string
		for _, r := range byCheck[id] {
			if strings.HasPrefix(r, p) {
				out = append(out, r)
			}
		}
		return out
	}
	require.Equal(t, []string{livePod}, mine("it-dci-check-live"))
	require.Empty(t, mine("it-dci-check-dead"), "a verified corpse is not a failing resource")
	require.Equal(t, []string{unknownResourceID}, mine("it-dci-check-unknown"), "unknown liveness stays evidence")
	require.Equal(t, []string{livePod}, mine("it-dci-check-split"), "only the live half of split evidence counts")
	require.NotContains(t, byCheck, "it-dci-check-nonephemeral", "only the requested checks are read")
}
