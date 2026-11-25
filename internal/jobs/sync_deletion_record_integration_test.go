//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/db"
)

// scriptedCollector returns its sweeps in order: the instances each lists, and
// whether the region's ec2 enumeration completed and the sweep was partial.
type scriptedCollector struct {
	sweeps []scriptedSweep
	n      *int
}

type scriptedSweep struct {
	ids               []string
	complete, partial bool
}

func (s scriptedCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	sw := s.sweeps[min(*s.n, len(s.sweeps)-1)]
	*s.n++
	now := time.Now()
	var res collect.Result
	for _, id := range sw.ids {
		res.Assets = append(res.Assets, asset.Asset{ID: id, Name: id, Type: "ec2_instance", Provider: asset.ProviderAWS,
			Region: "eu-west-1", AccountID: "111", DiscoveredAt: now, LastSeen: now})
	}
	if sw.complete {
		res.MarkComplete("eu-west-1/ec2:instances", []string{"ec2_instance"}, len(sw.ids))
	}
	res.Partial = sw.partial
	return res, nil
}

// The sync records a proven deletion only for a COMPLETE sweep whose scope it
// covered — the evidence vm_vuln, base_image and package departures read in
// place of a lapsed last_seen. A partial sweep that missed an instance, or one
// that proved no enumeration, records nothing.
func TestSyncWorker_RecordsDeletionsOnlyFromCompleteSweeps(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	connSvc := connector.NewService(connector.NewPGRepo(pool), cipher)
	suffix := time.Now().Format("150405.000000")
	keep, partialMiss, uncovered, deleted := "i-keep-"+suffix, "i-partial-"+suffix, "i-uncovered-"+suffix, "i-deleted-"+suffix
	ids := []string{keep, partialMiss, uncovered, deleted}
	created, err := connSvc.Create(ctx, connector.TypeGitHub, "it-del-"+suffix,
		map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "k"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM asset_deletions WHERE asset_id = ANY($1)", ids)
		for _, id := range ids {
			_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", id)
		}
	})

	n := 0
	registry := collect.NewRegistry()
	registry.Register(connector.TypeGitHub, scriptedCollector{n: &n, sweeps: []scriptedSweep{
		{ids: ids, complete: true},
		{ids: []string{keep, uncovered, deleted}, complete: true, partial: true}, // partial: misses partialMiss
		{ids: []string{keep, partialMiss, deleted}},                              // no completeness: misses uncovered
		{ids: []string{keep, partialMiss, uncovered}, complete: true},            // complete: deleted is gone
	}})
	w := &SyncWorker{connectors: connSvc, registry: registry, assets: asset.NewService(asset.NewCHRepo(ch)),
		findings: finding.NewService(finding.NewCHRepo(ch)), checks: checks.Default()}
	for range 4 {
		// A sync that changes nothing may be skipped as a no-op; the scripted
		// sweeps all differ, so each one reconciles.
		require.NoError(t, w.Work(ctx, &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: created.ID}}))
	}

	got, err := connSvc.AssetDeletions(ctx, ids)
	require.NoError(t, err)
	require.Contains(t, got, deleted, "a complete, covered sweep's deletion is recorded")
	require.NotContains(t, got, partialMiss, "a partial sweep proves no deletion")
	require.NotContains(t, got, uncovered, "a sweep with no completed enumeration proves no deletion")
	require.NotContains(t, got, keep)
}
