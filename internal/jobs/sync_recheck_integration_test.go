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

// eolStubCollector returns one stable EC2 instance on an end-of-life release:
// its content never changes between sweeps.
type eolStubCollector struct{ assetID string }

func (s eolStubCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	return collect.Result{Assets: []asset.Asset{
		{ID: s.assetID, Name: "eol-host", Type: "ec2_instance", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"package_ecosystem": "CentOS:7", "state": "running"}},
	}}, nil
}

// A sweep that short-circuits (nothing changed) still runs the time-dependent
// checks once per UTC day: the end-of-life finding is re-observed on the
// skipped sweep, and the stored fingerprint's day advances so the next sweep
// that day does not repeat it.
func TestSyncWorker_Work_SkippedSweepRechecksTimeDependent(t *testing.T) {
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
	findingSvc := finding.NewService(finding.NewCHRepo(ch))

	suffix := time.Now().Format("150405.000000")
	assetID := "i-eol-" + suffix
	created, err := connSvc.Create(ctx, connector.TypeGitHub, "it-eol-"+suffix,
		map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "k"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", assetID)
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", assetID)
	})

	registry := collect.NewRegistry()
	registry.Register(connector.TypeGitHub, eolStubCollector{assetID: assetID})
	w := &SyncWorker{connectors: connSvc, registry: registry, assets: asset.NewService(asset.NewCHRepo(ch)),
		findings: findingSvc, checks: checks.Default()}
	job := &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: created.ID}}
	eolFinding := func() finding.Finding {
		t.Helper()
		fs, err := findingSvc.ByResourceIDs(ctx, []string{assetID})
		require.NoError(t, err)
		for _, f := range fs {
			if f.CheckID == "aws-ec2-os-end-of-life" {
				return f
			}
		}
		t.Fatal("no aws-ec2-os-end-of-life finding")
		return finding.Finding{}
	}

	require.NoError(t, w.Work(ctx, job))
	first := eolFinding()

	// Pretend the last full evaluation was on an earlier day.
	c, err := connSvc.Get(ctx, created.ID)
	require.NoError(t, err)
	fp := splitSyncFingerprint(c.SyncFingerprint)
	require.Equal(t, clockDay(time.Now()), fp.day)
	fp.day = "2000-01-01"
	require.NoError(t, connSvc.UpdateSyncFingerprint(ctx, created.ID, combineSyncFingerprint(fp)))

	time.Sleep(1100 * time.Millisecond) // last_observed_at has second precision
	require.NoError(t, w.Work(ctx, job))
	require.True(t, eolFinding().LastObservedAt.After(first.LastObservedAt),
		"the skipped sweep must re-run the time-dependent check")

	c, err = connSvc.Get(ctx, created.ID)
	require.NoError(t, err)
	after := splitSyncFingerprint(c.SyncFingerprint)
	require.Equal(t, clockDay(time.Now()), after.day)
	require.Equal(t, fp.assetFP, after.assetFP, "the asset fingerprint is untouched: the sweep was a no-change skip")
}
