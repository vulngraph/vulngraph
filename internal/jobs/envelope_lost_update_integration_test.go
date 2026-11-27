//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

type envelopeFindingSource struct{}

func (envelopeFindingSource) List(_ context.Context, f finding.Filter) ([]finding.Finding, error) {
	if f.Severity != finding.SeverityHigh {
		return nil, nil
	}
	return []finding.Finding{{ResourceID: "score-update-barrier", Severity: finding.SeverityHigh}}, nil
}

type envelopeAssetBarrier struct {
	*asset.Service
	read    chan struct{}
	release chan struct{}
}

func (b *envelopeAssetBarrier) ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error) {
	rows, err := b.Service.ByIDs(ctx, ids)
	close(b.read)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
	}
	return rows, err
}

func TestEnvelopeHistoricalConcurrentScoreWrite(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" || os.Getenv("PERF_ENVELOPE_REPRODUCE_HISTORICAL_LOST_UPDATE") != "1" {
		t.Skip("explicit opt-in required: this historical implementation is expected to fail the correctness oracle")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 8)
	require.NoError(t, err)
	defer ch.Close()
	inv := asset.NewService(asset.NewCHRepo(ch))
	before := asset.Asset{ID: "score-update-barrier", Name: "revision-0", Type: "ec2_instance", Provider: asset.ProviderAWS, LastSeen: time.Now(), Metadata: map[string]string{"revision": "0"}}
	require.NoError(t, inv.Ingest(ctx, []asset.Asset{before}, nil))
	barrier := &envelopeAssetBarrier{Service: inv, read: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("score writer panic: %v", p)
			}
		}()
		historicalEnvelopeScoreWrite(ctx, envelopeFindingSource{}, barrier)
	}()
	select {
	case <-barrier.read:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	after := before
	after.Name = "revision-1"
	after.Metadata = map[string]string{"revision": "1"}
	after.LastSeen = time.Now().Add(time.Second)
	require.NoError(t, inv.Ingest(ctx, []asset.Asset{after}, nil))
	close(barrier.release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var versions []map[string]any
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var name, metadata string
			var score uint8
			var version, lastSeen time.Time
			if err := rows.Scan(&name, &metadata, &score, &version, &lastSeen); err != nil {
				return err
			}
			versions = append(versions, map[string]any{"name": name, "metadata": metadata, "risk_score": score, "synced_at": version, "last_seen": lastSeen})
		}
		return rows.Err()
	}, "SELECT name,metadata,risk_score,synced_at,last_seen FROM assets WHERE id='score-update-barrier' ORDER BY synced_at"))
	got, err := inv.ByIDs(ctx, []string{before.ID})
	require.NoError(t, err)
	b, err := json.MarshalIndent(map[string]any{"raw_versions": versions, "latest": got}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "score-write-interleaving.json"), b, 0600))
	require.Len(t, got, 1)
	require.Equal(t, after.Name, got[0].Name, "a derived score update must not overwrite a newer observation")
	require.Equal(t, after.Metadata["revision"], got[0].Metadata["revision"])
	require.Equal(t, after.LastSeen.Unix(), got[0].LastSeen.Unix(), "derived write must not move liveness backward")
}

// Historical implementation retained solely for deterministic regression evidence.
func historicalEnvelopeScoreWrite(ctx context.Context, src FindingLister, store *envelopeAssetBarrier) {
	found, err := src.List(ctx, finding.Filter{Severity: finding.SeverityHigh})
	if err != nil || len(found) == 0 {
		return
	}
	rows, err := store.ByIDs(ctx, []string{found[0].ResourceID})
	if err != nil {
		return
	}
	for i := range rows {
		rows[i].RiskScore = 60
	}
	_ = store.Ingest(ctx, rows, nil)
}
