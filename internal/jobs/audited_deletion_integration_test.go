//go:build integration

package jobs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/db"
)

type enumerationCollector struct {
	assets            []asset.Asset
	scope, typ        string
	complete, partial bool
}

func (c *enumerationCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	r := collect.Result{Assets: append([]asset.Asset(nil), c.assets...), Partial: c.partial}
	for i := range r.Assets {
		r.Assets[i].LastSeen = time.Now()
		r.Assets[i].DiscoveredAt = time.Now()
	}
	if c.complete {
		count := 0
		for _, a := range r.Assets {
			if a.Type == c.typ {
				count++
			}
		}
		r.MarkComplete(c.scope, []string{c.typ}, count)
	}
	return r, nil
}

func TestAuditedFamiliesRetireOnlyProvenAbsence(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" || os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated databases")
	}
	ctx := t.Context()
	pool, err := db.NewPool(ctx, os.Getenv("TEST_DATABASE_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 0)
	require.NoError(t, err)
	defer ch.Close()
	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	conns := connector.NewService(connector.NewPGRepo(pool), cipher)
	inv := asset.NewService(asset.NewCHRepo(ch))
	findings := finding.NewService(finding.NewCHRepo(ch))
	for _, tc := range []struct {
		kind                          connector.Type
		typ, uncovered, scope, region string
		cfg                           map[string]string
	}{
		{connector.TypeAzure, "azure_vm", "azure_sql_server", "subscription/compute:vms", "westeurope", map[string]string{"subscription_id": "subscription"}},
		{connector.TypeGitHub, "github_repo", "package", "123/github:repos", "global", map[string]string{"app_id": "1", "installation_id": "123", "private_key_pem": "fixture"}},
		{connector.TypeKubernetes, "k8s_pod", "container", "cluster-a/kubernetes:pods", "cluster-a", nil},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			c, err := conns.Create(ctx, tc.kind, "audit-"+uuid.NewString(), tc.cfg, "")
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = pool.Exec(ctx, "DELETE FROM asset_deletions WHERE connector_id=$1", c.ID)
				_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id=$1", c.ID)
			})
			keep, gone, unknown := c.ID+"-keep", c.ID+"-gone", c.ID+"-uncovered"
			ids := []string{keep, gone, unknown}
			t.Cleanup(func() {
				for _, id := range ids {
					_ = ch.Exec(ctx, "DELETE FROM assets WHERE id=? SETTINGS mutations_sync=1", id)
					_ = ch.Exec(ctx, "DELETE FROM findings WHERE resource_id=? SETTINGS mutations_sync=1", id)
				}
			})
			producer := &enumerationCollector{scope: tc.scope, typ: tc.typ, complete: true, assets: []asset.Asset{
				{ID: keep, Name: keep, Type: tc.typ, Provider: asset.Provider(tc.kind), Region: tc.region},
				{ID: gone, Name: gone, Type: tc.typ, Provider: asset.Provider(tc.kind), Region: tc.region},
				{ID: unknown, Name: unknown, Type: tc.uncovered, Provider: asset.Provider(tc.kind), Region: tc.region},
			}}
			registry := collect.NewRegistry()
			registry.Register(tc.kind, producer)
			w := &SyncWorker{connectors: conns, registry: registry, assets: inv, findings: findings, checks: checks.Default()}
			job := &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: c.ID}}
			require.NoError(t, w.Work(ctx, job))
			require.NoError(t, findings.RecordObserved(ctx, []finding.Finding{
				{ID: gone, ResourceID: gone, ResourceType: tc.typ, Source: "fixture", Type: "exposure", Severity: finding.SeverityHigh, Title: "gone finding"},
				{ID: unknown, ResourceID: unknown, ResourceType: tc.uncovered, Source: "fixture", Type: "exposure", Severity: finding.SeverityHigh, Title: "uncovered finding"},
			}))
			// Model a later sweep. Retirement conservatively preserves an
			// observation in the same whole second as its deletion proof.
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			producer.assets = producer.assets[:1]
			for _, partial := range []bool{true, false} {
				producer.partial, producer.complete = partial, partial
				require.NoError(t, w.Work(ctx, job))
				proofs, err := conns.AssetDeletions(ctx, ids)
				require.NoError(t, err)
				require.Empty(t, proofs, "partial or unproven enumeration cannot authorize deletion")
				hashes, err := conns.GetAssetHashes(ctx, c.ID)
				require.NoError(t, err)
				require.Len(t, hashes, 3)
			}
			producer.complete = true
			require.NoError(t, w.Work(ctx, job))
			proofs, err := conns.AssetDeletions(ctx, ids)
			require.NoError(t, err)
			require.Contains(t, proofs, gone)
			require.NotContains(t, proofs, unknown)
			require.NotContains(t, proofs, keep)
			resolved, err := findings.Get(ctx, gone)
			require.NoError(t, err)
			require.Equal(t, finding.ReasonResourceGone, resolved.ResolutionReason)
			unresolved, err := findings.Get(ctx, unknown)
			require.NoError(t, err)
			require.Empty(t, unresolved.ResolutionReason)
			retire := &InventoryRetirementWorker{proofs: conns, assets: inv, findings: findings}
			require.NoError(t, retire.Work(ctx, &river.Job[InventoryRetirementArgs]{}))
			live, err := inv.LiveIDs(ctx, ids)
			require.NoError(t, err)
			require.NotContains(t, live, gone)
			require.Contains(t, live, keep)
			require.Contains(t, live, unknown)
		})
	}
}
