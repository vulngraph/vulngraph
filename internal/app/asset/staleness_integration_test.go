//go:build integration

package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestProviderStaleness_ExcludesStructurallyStaleTypes is the regression guard
// for GraphAssetCollectionStalled firing on healthy collectors (gcp and
// kubernetes reading as mostly stale — false positives). A
// k8s_pod and a gce_instance are seeded old enough to be "stale" against a
// fresh high-water asset on the SAME provider — if structurallyStaleTypes were
// dropped from the query, they would inflate the ratio; excluded, only the
// genuinely-unrefreshed non-exempt type counts. IaC declarations are not
// resources, and an asset is counted once by id however many rows its type
// history left behind.
func TestProviderStaleness_ExcludesStructurallyStaleTypes(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	provider := Provider("it-staleness-" + time.Now().Format("150405.000000"))
	now := time.Now().Truncate(time.Second)
	old := now.Add(-48 * time.Hour) // older than the 24h margin used below

	assets := []Asset{
		// Fresh — sets this provider's high-water mark.
		{ID: string(provider) + "-fresh", Type: "s3_bucket", Provider: provider, DiscoveredAt: now, LastSeen: now},
		// Old and EXEMPT — must not count toward stale OR total.
		{ID: string(provider) + "-pod", Type: "k8s_pod", Provider: provider, DiscoveredAt: old, LastSeen: old},
		{ID: string(provider) + "-gce", Type: "gce_instance", Provider: provider, DiscoveredAt: old, LastSeen: old},
		// Old and NOT exempt — must count as stale.
		{ID: string(provider) + "-old-bucket", Type: "s3_bucket", Provider: provider, DiscoveredAt: old, LastSeen: old},
		// An IaC declaration, not a resource — must not count toward stale OR total.
		{ID: string(provider) + "-declared", Type: "declared_tf_resource", Provider: provider, DiscoveredAt: old, LastSeen: old},
		// A retyped asset's old row keeps its frozen last_seen.
		{ID: string(provider) + "-retyped", Type: "iam_role", Provider: provider, DiscoveredAt: old, LastSeen: old},
	}
	require.NoError(t, svc.Ingest(ctx, assets, nil))
	// The same id collected fresh under its new type: one asset, and not stale.
	require.NoError(t, svc.Ingest(ctx, []Asset{
		{ID: string(provider) + "-retyped", Type: "s3_bucket", Provider: provider, DiscoveredAt: now, LastSeen: now},
	}, nil))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE provider = ?", string(provider))
	})

	stats, err := repo.ProviderStaleness(ctx, 24*3600)
	require.NoError(t, err)

	var found *ProviderStaleness
	for i, s := range stats {
		if s.Provider == string(provider) {
			found = &stats[i]
		}
	}
	require.NotNil(t, found, "this run's provider must appear in the result")
	require.Equal(t, 3, found.Total,
		"k8s_pod, gce_instance and the IaC declaration must not count toward total, and the retyped asset counts once")
	require.Equal(t, 1, found.Stale, "only the old s3_bucket counts as stale, not the retyped asset's frozen row")
}

// TestProviderDimensionCounts_ExcludesPackageRegionAndSCPAccount is the
// regression guard for GraphConnectorCoverageGap's two false positives
// (region and account counts exceeding what was configured) — a package's "global" region placeholder and an
// aws_scp_set's account_id must not inflate the respective dimension counts.
func TestProviderDimensionCounts_ExcludesPackageRegionAndSCPAccount(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	provider := Provider("it-dims-" + time.Now().Format("150405.000000"))
	now := time.Now().Truncate(time.Second)

	assets := []Asset{
		// A real resource with a real region and account — must count.
		{ID: string(provider) + "-real", Type: "iam_role", Provider: provider, Region: "eu-west-1", AccountID: "111122223333", DiscoveredAt: now, LastSeen: now},
		// A package stamped with the "global" region placeholder — must NOT
		// count toward regions.
		{ID: string(provider) + "-pkg", Type: "package", Provider: provider, Region: "global", DiscoveredAt: now, LastSeen: now},
		// An SCP set stamped with its own account_id — must NOT count toward
		// accounts (it is an org-enumeration artifact, not a connector's own
		// account).
		{ID: string(provider) + "-scp", Type: "aws_scp_set", Provider: provider, Region: "eu-west-1", AccountID: "444455556666", DiscoveredAt: now, LastSeen: now},
	}
	require.NoError(t, svc.Ingest(ctx, assets, nil))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE provider = ?", string(provider))
	})

	dims, err := repo.ProviderDimensionCounts(ctx)
	require.NoError(t, err)

	var found *ProviderDimensions
	for i, d := range dims {
		if d.Provider == string(provider) {
			found = &dims[i]
		}
	}
	require.NotNil(t, found, "this run's provider must appear in the result")
	require.Equal(t, 1, found.Regions, "the package's 'global' placeholder must not count as a second region")
	require.Equal(t, 1, found.Accounts, "the aws_scp_set's account_id must not count toward connector account coverage")
}

// TestCHRepo_ScopeCandidateIDsNoForkOnProviderChange guards the forget
// mechanism (scopeCandidateIDs is explicitly "the one query whose wrong
// answer would be a deletion") against a provider fork. `assets` is ORDER BY
// (type, id), and scopeCandidateIDs and scopeStalenessByRegionType group by
// that dedupe key. Grouping by (provider, type, id) instead would surface a
// single provider-changed asset as TWO confirmed-absent forget candidates
// instead of one.
func TestCHRepo_ScopeCandidateIDsNoForkOnProviderChange(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	suffix := time.Now().Format("150405.000000")
	connectorID := "it-forget-" + suffix
	assetType := "package"
	id := "it-forget-pkg-" + suffix + "-pkg:npm/example@1.0.0"
	old := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	later := old.Add(time.Hour)

	// Discovered first under one provider, then again under a different
	// provider — both confirmed-absent (last_seen far in the past). Grouped by
	// (provider, type, id), this would surface as TWO candidate ids instead of
	// one.
	require.NoError(t, svc.Ingest(ctx, []Asset{{
		ID: id, Name: "example", Type: assetType, Provider: ProviderKubernetes,
		DiscoveredAt: old, LastSeen: old,
		Metadata: map[string]string{"prov_connector_id": connectorID},
	}}, nil))
	require.NoError(t, svc.Ingest(ctx, []Asset{{
		ID: id, Name: "example", Type: assetType, Provider: ProviderGitHub,
		DiscoveredAt: later, LastSeen: later,
		Metadata: map[string]string{"prov_connector_id": connectorID},
	}}, nil))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE id = ?", id)
	})

	confirmedBefore := time.Now()

	candidates, err := repo.ScopeCandidateIDs(ctx, connectorID, assetType, "", confirmedBefore, 100)
	require.NoError(t, err)
	var matches []ForgetCandidate
	for _, c := range candidates {
		if c.ID == id {
			matches = append(matches, c)
		}
	}
	require.Len(t, matches, 1, "a provider-changed asset must surface as ONE forget candidate, not one per provider")
	require.WithinDuration(t, later, matches[0].LastSeen, time.Second,
		"the most-recently-synced write's last_seen must win")

	scoped, err := repo.ScopeStaleness(ctx, connectorID, []string{assetType}, confirmedBefore, confirmedBefore)
	require.NoError(t, err)
	var total int
	for _, s := range scoped {
		if s.Type == assetType {
			total += s.Stored
		}
	}
	require.Equal(t, 1, total, "scopeStalenessByRegionType must count a provider-changed asset once, not per provider")
}
