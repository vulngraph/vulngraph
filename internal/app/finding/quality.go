package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// checkQualityQ counts each check's open findings and its resolutions by reason —
// the standing per-check scoreboard.
//
// Dedup shape matches summaryOpenFindings: the inner GROUP BY (source, id)
// collapses ReplacingMergeTree versions via argMax on synced_at, never FINAL (a
// filtered FINAL full-scans the table; CLAUDE.md). synced_at, NOT detected_at —
// detected_at is re-stamped whenever a changed asset is re-checked, so argMax
// over it would select an arbitrary older version and silently report the
// wrong state.
//
// The row cap is applied as a LIMIT one greater than CheckQualityLimit, so the
// caller can tell whether anything was dropped and report it rather than silently
// truncating the scoreboard.
const checkQualityQ = `SELECT check_id, source,
		countIf(resolved_at < toDateTime('2000-01-01 00:00:00'))                                  AS open,
		countIf(resolved_at >= toDateTime('2000-01-01 00:00:00') AND reason = 'fixed')            AS fixed,
		countIf(resolved_at >= toDateTime('2000-01-01 00:00:00') AND reason = 'resource_gone')    AS resource_gone,
		countIf(resolved_at >= toDateTime('2000-01-01 00:00:00') AND reason = 'manual')           AS manual,
		countIf(resolved_at >= toDateTime('2000-01-01 00:00:00') AND reason = '')                 AS unknown
	FROM (
		SELECT source,
			argMax(check_id, synced_at)          AS check_id,
			argMax(resolved_at, synced_at)       AS resolved_at,
			argMax(resolution_reason, synced_at) AS reason
		FROM findings
		GROUP BY source, id
	)
	GROUP BY check_id, source
	ORDER BY (fixed + resource_gone + manual) DESC, open DESC
	LIMIT %d`

// CheckQualityLimit caps how many checks the scoreboard reports. Comfortably above
// the ~124-check registry so every real check is covered; the cap exists because
// GuardDuty finding types arrive as check_ids too (Trojan:EC2/…, Exfiltration:S3/…)
// and that set is open-ended, so an uncapped query would grow Prometheus series
// without bound. Ordered by resolution volume, so what falls off the end is the
// least-evidenced, and CheckQuality logs the count it dropped.
const CheckQualityLimit = 400

// CheckQualityTimeout bounds the scoreboard query.
//
// It must stay AT OR BELOW internal/obs's scrapeBudget (8s), the deadline the
// only caller — the /metrics scrape path — already puts on the context.
// context.WithTimeout keeps the EARLIER deadline, so a larger number here
// would be a value that can never take effect. The two are pinned in
// opposite directions by TestCheckQualityTimeoutFitsTheScrapeBudget here and
// TestScrapeBudgetIsShorterThanTheScrapeInterval in obs, so the relationship
// cannot silently invert; if scrapeBudget ever changes, grep this comment and
// sourceActivityTimeout's (which points back here) before touching either.
//
// The timeout is kept rather than deferring wholly to the caller because
// CLAUDE.md requires a per-query deadline: the next caller may arrive without a
// budget of its own, and this is a full-table aggregate over `findings`.
const CheckQualityTimeout = 8 * time.Second

// CheckQuality returns per-check resolution outcomes, most-resolved first, plus the
// number of checks that did not fit the limit.
func (r *CHRepo) CheckQuality(ctx context.Context) ([]CheckQuality, int, error) {
	qCtx, cancel := context.WithTimeout(ctx, CheckQualityTimeout)
	defer cancel()

	// One row over the limit tells the caller whether anything was dropped without
	// a second COUNT(DISTINCT) pass over the table.
	query := fmt.Sprintf(checkQualityQ, CheckQualityLimit+1)

	var out []CheckQuality
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				q                                  CheckQuality
				open, fixed, gone, manual, unknown uint64 // count() is UInt64; downcast explicitly (CLAUDE.md)
			)
			if err := rows.Scan(&q.CheckID, &q.Source, &open, &fixed, &gone, &manual, &unknown); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			q.Open, q.Fixed, q.ResourceGone = int(open), int(fixed), int(gone)
			q.Manual, q.Unknown = int(manual), int(unknown)
			out = append(out, q)
		}
		return rows.Err()
	}, query)
	if err != nil {
		return nil, 0, fmt.Errorf("CheckQuality: %w", err)
	}

	dropped := 0
	if len(out) > CheckQualityLimit {
		dropped = len(out) - CheckQualityLimit
		out = out[:CheckQualityLimit]
	}
	return out, dropped, nil
}

// CheckQuality reports per-check resolution outcomes and how many checks were
// dropped by the reporting limit.
func (s *Service) CheckQuality(ctx context.Context) ([]CheckQuality, int, error) {
	return s.repo.CheckQuality(ctx)
}
