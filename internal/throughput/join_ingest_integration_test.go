//go:build integration

package throughput

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

type joinPartCount struct {
	Parts uint64 `json:"parts"`
	Rows  uint64 `json:"physical_rows"`
	Bytes uint64 `json:"bytes_on_disk"`
}

func joinParts(ctx context.Context, ch *db.CH) (map[string]joinPartCount, error) {
	out := map[string]joinPartCount{}
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var table string
			var count joinPartCount
			if e := rows.Scan(&table, &count.Parts, &count.Rows, &count.Bytes); e != nil {
				return e
			}
			out[table] = count
		}
		return rows.Err()
	}, `SELECT table,count(),sum(rows),sum(bytes_on_disk) FROM system.parts WHERE database=currentDatabase() AND active AND table IN ('assets','graph_edges','findings','finding_enrichment') GROUP BY table`)
	return out, err
}

// Observe normal merge quiescence, without OPTIMIZE FINAL or a forced merge.
// The retained part/row counts describe what "settled" actually means here.
func settleJoinParts(ctx context.Context, ch *db.CH) (map[string]joinPartCount, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var previous map[string]joinPartCount
	quiet := 0
	for {
		current, err := joinParts(ctx, ch)
		if err != nil {
			return previous, err
		}
		var active uint64
		err = ch.Select(ctx, func(rows driver.Rows) error {
			if !rows.Next() {
				return fmt.Errorf("missing active merge count")
			}
			return rows.Scan(&active)
		}, `SELECT count() FROM system.merges WHERE database=currentDatabase()`)
		if err != nil {
			return current, err
		}
		if active == 0 && reflect.DeepEqual(previous, current) {
			quiet++
		} else {
			quiet = 0
		}
		previous = current
		if quiet == 5 {
			return current, nil
		}
		if err := joinArrival(ctx, time.Now().Add(time.Second)); err != nil {
			return current, fmt.Errorf("waiting for five quiet merge samples: %w", err)
		}
	}
}

// The same 200 observations/second enter both chunk-size cohorts. Both wait for
// the same five-second collection window; only native write chunking differs.
func joinObservationWindow(wave int, stamp int64, start time.Time) ([]finding.Finding, []finding.Enrichment) {
	var findings []finding.Finding
	var enrichments []finding.Enrichment
	for i := wave * 1000; i < (wave+1)*1000; i++ {
		observed := start.Add(time.Duration(i) * time.Second / 200)
		marker := fmt.Sprintf("join-observation-%d", i)
		f := finding.Finding{ID: fmt.Sprintf("large-f-%d", i), Source: "noise", Type: "vulnerability", Severity: finding.SeverityHigh,
			Title: "Large finding", Description: marker + strings.Repeat("x", 256), ResourceID: fmt.Sprintf("resource-%d", i%10000),
			CheckID: fmt.Sprintf("large-check-%d", i%100), Remediation: "fix", DetectedAt: time.Unix(stamp-int64(i%1000), 0).UTC(), LastObservedAt: observed.Truncate(time.Second)}
		if i%100 == 0 {
			f.Description = marker + strings.Repeat("x", 16384)
		}
		if i%100 == 1 {
			f.Source = "sample"
		}
		if (i%100)%13 == 0 {
			f.Severity = finding.SeverityCritical
		}
		if i%17 == 0 {
			f.ResolvedAt = time.Unix(stamp+2, 0).UTC()
		}
		findings = append(findings, f)
		if i%19 != 0 {
			enrichments = append(enrichments, finding.Enrichment{ID: f.ID, Score: uint8(90 + i%10), ScoreBand: "high", KnownExploited: i%7 == 0,
				OwnerTeam: fmt.Sprintf("team-%d", (i+2)%23), OwnerSource: "tag", Environment: "prod", EnrichedAt: observed, MustFixReason: marker})
		}
	}
	return findings, enrichments
}

func writeJoinChunks(ctx context.Context, repo *finding.CHRepo, findings []finding.Finding, enrichments []finding.Enrichment, chunkRows int) error {
	byID := map[string]finding.Enrichment{}
	for _, e := range enrichments {
		byID[e.ID] = e
	}
	for start := 0; start < len(findings); start += chunkRows {
		chunk := findings[start:min(start+chunkRows, len(findings))]
		if err := repo.Upsert(ctx, chunk); err != nil {
			return err
		}
		var enriched []finding.Enrichment
		for _, f := range chunk {
			if e, ok := byID[f.ID]; ok {
				enriched = append(enriched, e)
			}
		}
		if err := repo.UpsertEnrichment(ctx, enriched); err != nil {
			return err
		}
	}
	return nil
}
