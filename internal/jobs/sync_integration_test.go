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

const (
	pgDSN = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
	chDSN = "clickhouse://graph:graph@localhost:9000/graph"
)

// stubCollector returns a fixed asset, standing in for a real provider.
type stubCollector struct{ assetID string }

func (s stubCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	now := time.Now()
	return collect.Result{Assets: []asset.Asset{
		// Public repo so the github-public-repo CSPM check fires.
		{ID: s.assetID, Name: "repo", Type: "github_repo", Provider: asset.ProviderGitHub,
			Metadata: map[string]string{"visibility": "public"}, DiscoveredAt: now, LastSeen: now},
	}}, nil
}

// Exercises the full sync path against live Postgres + ClickHouse: load and
// decrypt the connector, run its collector, ingest assets, record the outcome.
func TestSyncWorker_Work_EndToEnd(t *testing.T) {
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
	assetSvc := asset.NewService(asset.NewCHRepo(ch))
	findingSvc := finding.NewService(finding.NewCHRepo(ch))

	suffix := time.Now().Format("150405.000000")
	assetID := "org/repo-" + suffix
	created, err := connSvc.Create(ctx, connector.TypeGitHub, "it-"+suffix,
		map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "k"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", assetID)
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", assetID)
	})

	registry := collect.NewRegistry()
	registry.Register(connector.TypeGitHub, stubCollector{assetID: assetID})

	w := &SyncWorker{connectors: connSvc, registry: registry, assets: assetSvc,
		findings: findingSvc, checks: checks.Default()}
	require.NoError(t, w.Work(ctx, &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: created.ID}}))

	// Asset was ingested...
	got, err := assetSvc.Get(ctx, assetID)
	require.NoError(t, err)
	require.Equal(t, "repo", got.Name)

	// ...the connector's sync result was recorded...
	c, err := connSvc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, connector.SyncOK, c.SyncStatus)
	require.NotNil(t, c.LastSyncedAt)

	// ...and the CSPM check produced a finding for the public repo.
	found, err := findingSvc.List(ctx, finding.Filter{Source: "cspm"})
	require.NoError(t, err)
	var foundCheck bool
	for _, f := range found {
		if f.ResourceID == assetID && f.CheckID == "github-public-repo" {
			foundCheck = true
		}
	}
	require.True(t, foundCheck, "expected a github-public-repo finding for the synced public repo")
}

// A connector type with no registered collector cancels the job (no retry) and
// records the failure rather than erroring forever.
func TestSyncWorker_Work_NoCollector(t *testing.T) {
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
	created, err := connSvc.Create(ctx, connector.TypeAWS, "it-aws-"+suffix,
		map[string]string{"role_arn": "arn:x", "region": "eu-west-1"}, "")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID) })

	w := &SyncWorker{connectors: connSvc, registry: collect.NewRegistry(),
		assets:   asset.NewService(asset.NewCHRepo(ch)),
		findings: finding.NewService(finding.NewCHRepo(ch)), checks: checks.Default()}
	err = w.Work(ctx, &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: created.ID}})
	require.Error(t, err) // JobCancel error — River will not retry

	c, err := connSvc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, connector.SyncError, c.SyncStatus)
	require.Contains(t, c.SyncError, "no collector registered")
}

// driftStubCollector returns one externally-reachable asset (a public IP
// set) — a drift-scan candidate once ingested as changed.
type driftStubCollector struct{ assetID string }

func (s driftStubCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	now := time.Now()
	return collect.Result{Assets: []asset.Asset{
		{ID: s.assetID, Name: "ext-host", Type: "ec2_instance", Provider: asset.ProviderAWS,
			PublicIP: "203.0.113.10", DiscoveredAt: now, LastSeen: now},
	}}, nil
}

func testKey(t *testing.T) string {
	t.Helper()
	// 32 zero bytes base64 — fine for a test; never used outside it.
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
