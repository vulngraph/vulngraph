package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// SeverityCount is one severity's finding count.
type SeverityCount struct {
	Severity Severity
	N        int
}

// unenrichedOpenFindings counts open findings the enrichment pipeline has never
// reached, grouped by severity. Same dedup shape as summaryOpenFindings: the
// inner GROUP BY (source, id) collapses ReplacingMergeTree versions via argMax on
// synced_at, not FINAL (a filtered FINAL full-scans the table; CLAUDE.md), and
// the resolved_at HAVING drops resolved findings.
//
// synced_at is the ordering key on purpose. Using detected_at instead silently
// returns the wrong answer: detected_at is not identity-stable (checks.eval
// re-stamps it on every re-run of a changed asset, and a check-registry
// backfill bumps it for all assets), so argMax over it can select a
// pre-enrichment version of a finding that has in fact been enriched since.
//
// Enriched_at comes from finding_enrichment, not findings. The LEFT JOIN's
// unmatched side reads back as finding_enrichment's own column default under
// join_use_nulls=0 (the ClickHouse default) — toDateTime64(0,3), which compares
// equal-or-before toDateTime('2000-01-01') — so "no finding_enrichment row"
// and "enriched_at is the epoch" mean the same thing here.
const unenrichedOpenFindings = `SELECT sev, count()
	FROM (
		SELECT id,
			argMax(severity, synced_at)    AS sev,
			argMax(resolved_at, synced_at) AS resolved_at
		FROM findings
		GROUP BY source, id
		HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
	) legacy
	LEFT JOIN (
		SELECT id, max(enriched_at) AS enr FROM finding_enrichment GROUP BY id
	) fe ON legacy.id = fe.id
	WHERE fe.enr < toDateTime('2000-01-01 00:00:00')
	GROUP BY sev`

// UnenrichedCounts returns the never-enriched open findings per severity — the
// depth of the enrich backlog, which no band- or score-based query can see
// (these findings have neither).
func (r *CHRepo) UnenrichedCounts(ctx context.Context) ([]SeverityCount, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out []SeverityCount
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				sev string
				n   uint64 // count() is UInt64; downcast explicitly (CLAUDE.md)
			)
			if err := rows.Scan(&sev, &n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, SeverityCount{Severity: Severity(sev), N: int(n)})
		}
		return rows.Err()
	}, unenrichedOpenFindings)
	if err != nil {
		return nil, fmt.Errorf("UnenrichedCounts: %w", err)
	}
	return out, nil
}

// UnenrichedCounts reports the enrich backlog depth per severity.
func (s *Service) UnenrichedCounts(ctx context.Context) ([]SeverityCount, error) {
	return s.repo.UnenrichedCounts(ctx)
}

// ClassificationCoverage is one source's must-fix classification coverage.
type ClassificationCoverage struct {
	Source string
	// Blank counts open ENRICHED findings still carrying must_fix_class = ''. The
	// classifier (MustFixRoutine) always names a verdict, so this is a
	// fail-open/stale-row count and is expected to be ~0.
	Blank      int64
	Classified int64 // open findings the classifier reached an opinion about
}

// mustFixCoverageBySource splits each source's OPEN findings into classified vs
// blank must_fix_class. Same dedup shape and the same synced_at ordering-key
// rationale as unenrichedOpenFindings above — argMax over detected_at would pick
// pre-classification versions of findings that have since been classified.
//
// Never-enriched findings are excluded: they are blank because nothing has run yet,
// which UnenrichedCounts already reports. Counting them here would blur "the
// classifier cannot form an opinion about this source" — the signal we want —
// with "the queue is behind", which is a different problem with a different fix.
//
// must_fix_class and enriched_at come from finding_enrichment. Note `fe.enr`,
// not `fe.enriched_at`: aliasing the join subquery's max(enriched_at) as
// "enriched_at" would make argMax's bare `enriched_at` version-column
// reference inside that same subquery resolve to the alias instead of the raw
// column — the same "bare identifier resolves against a SELECT-list alias"
// hazard selectFindingsArgMax's own comment documents for
// source/resource_id/check_id.
const mustFixCoverageBySource = `SELECT src,
		countIf(mfc = '')  AS blank,
		countIf(mfc != '') AS classified
	FROM (
		SELECT id, source AS src,
			argMax(resolved_at, synced_at) AS resolved_at
		FROM findings
		GROUP BY source, id
		HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
	) legacy
	LEFT JOIN (
		SELECT id, argMax(must_fix_class, enriched_at) AS mfc, max(enriched_at) AS enr
		FROM finding_enrichment GROUP BY id
	) fe ON legacy.id = fe.id
	WHERE fe.enr >= toDateTime('2000-01-01 00:00:00')
	GROUP BY src`

// MustFixCoverage returns, per source, how many open enriched findings the
// must-fix classifier reached an opinion about versus left blank.
func (r *CHRepo) MustFixCoverage(ctx context.Context) ([]ClassificationCoverage, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out []ClassificationCoverage
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				src               string
				blank, classified uint64 // countIf is UInt64; downcast explicitly (CLAUDE.md)
			)
			if err := rows.Scan(&src, &blank, &classified); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, ClassificationCoverage{
				Source: src, Blank: int64(blank), Classified: int64(classified),
			})
		}
		return rows.Err()
	}, mustFixCoverageBySource)
	if err != nil {
		return nil, fmt.Errorf("MustFixCoverage: %w", err)
	}
	return out, nil
}

// MustFixCoverage reports per-source must-fix classification coverage — the
// signal that a whole source can never reach must_fix (see obs.UnclassifiedStat).
func (s *Service) MustFixCoverage(ctx context.Context) ([]ClassificationCoverage, error) {
	return s.repo.MustFixCoverage(ctx)
}
