//go:build integration

package enrich

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	"golang.org/x/sync/errgroup"
)

func TestCoalescedEnrichmentIsImmediatelyReadable(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	// A server/caller configured for asynchronous acknowledgement must not
	// weaken Batch's immediate-read contract.
	ctx = ch.WithQuerySettings(ctx, map[string]any{
		"async_insert": 1, "wait_for_async_insert": 0,
		"async_insert_use_adaptive_busy_timeout": 0, "async_insert_busy_timeout_ms": 1000,
	})
	prefix := "coalesced-" + uuid.NewString()
	defer func() {
		for _, table := range []string{"findings", "finding_enrichment", "signals"} {
			require.NoError(t, ch.Exec(ctx, "DELETE FROM "+table+" WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		}
	}()
	findings := finding.NewService(finding.NewCHRepo(ch))
	signals := NewSignalCHRepo(ch)
	const total = 129
	var input []finding.Finding
	for i := range total {
		input = append(input, finding.Finding{ID: fmt.Sprintf("%s-%d", prefix, i), ResourceID: prefix, Source: "cspm", Type: "exposure", Severity: finding.SeverityHigh})
	}
	require.NoError(t, findings.RecordObserved(ctx, input))
	var group errgroup.Group
	group.SetLimit(32)
	for i, f := range input {
		group.Go(func() (err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("enrichment writer panic: %v", p)
				}
			}()
			detail := fmt.Sprint(i)
			if i == total-1 {
				detail = strings.Repeat("wide factor ", 500000)
			}
			value := uint8(i%80 + 1)
			if err := signals.WriteFactors(ctx, f.ID, prefix, Score{Value: value, Band: BandMonitor, Factors: []Factor{{Source: "fixture", Points: int(value), Detail: detail}}}); err != nil {
				return err
			}
			factors, err := signals.Factors(ctx, f.ID)
			if err != nil {
				return err
			}
			if len(factors) != 1 || factors[0].Detail != detail {
				return fmt.Errorf("factors not readable immediately for %s", f.ID)
			}
			if err := findings.RecordEnrichment(ctx, []finding.Enrichment{{ID: f.ID, Score: value, ScoreBand: "monitor", EnrichedAt: time.Now(), OwnerTeam: "team-" + fmt.Sprint(i)}}); err != nil {
				return err
			}
			got, err := findings.Get(ctx, f.ID)
			if err != nil {
				return err
			}
			if got.Score != value || got.OwnerTeam != "team-"+fmt.Sprint(i) {
				return fmt.Errorf("enrichment not readable immediately for %s", f.ID)
			}
			return nil
		})
	}
	require.NoError(t, group.Wait())
}
