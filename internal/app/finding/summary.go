package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Summary is an aggregate count of current open findings for the overview dashboard:
// the total, plus a breakdown by raw severity and by enriched score band. Unlike
// the paginated list, it counts every matching finding, not just a page.
type Summary struct {
	Total      int
	BySeverity map[Severity]int
	ByBand     map[string]int // keyed by enrich band; unenriched findings (empty band) are excluded
	// ByOwner and ByEnvironment are the findings list's owner/environment facets.
	// ByOwner is keyed by owner team, with OwnerUnowned for findings resolved to
	// nobody and "" for findings whose owner has not been resolved yet — kept as
	// its own bucket so the backlog is visible rather than folded into either.
	// ByEnvironment is keyed by prod|staging|dev|unknown, "" likewise unstamped.
	ByOwner       map[string]int
	ByEnvironment map[string]int
}

// summaryOpenFindings counts current open findings grouped by severity, score
// band, owner and environment. The inner GROUP BY (source, id) collapses
// ReplacingMergeTree versions via argMax, not FINAL — a source-filtered FINAL
// full-scans the table (skip indexes don't apply under FINAL; CLAUDE.md).
// HAVING drops resolved findings: a fixed issue must not linger in the
// dashboard counts. %s is the optional pre-aggregation source filter (source is
// baked into the deterministic finding ID, so it cannot differ across versions).
//
// band/owner/env come from finding_enrichment via a LEFT JOIN, not from
// `findings`. The LEFT JOIN's unmatched side reads back "" under
// join_use_nulls=0 (the ClickHouse default) — the never-enriched sentinel each bucket keeps.
// The owner key folds owner_source into the team: "none" becomes OwnerUnowned
// so "unowned" and "not yet resolved" never share a bucket. The outer GROUP BY
// is over four low-cardinality keys (owner teams number in the tens to
// hundreds), so its state stays small at any corpus size.
const summaryOpenFindings = `SELECT sev, band, owner, env, count()
	FROM (
		SELECT legacy.sev AS sev, fe.band AS band, fe.owner AS owner, fe.env AS env
		FROM (
			SELECT id,
				argMax(severity, synced_at)   AS sev,
				argMax(resolved_at, synced_at) AS resolved_at
			FROM findings
			%s
			GROUP BY source, id
			HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
		) legacy
		LEFT JOIN (
			SELECT id,
				argMax(score_band, enriched_at) AS band,
				if(argMax(owner_source, enriched_at) = 'none', '` + OwnerUnowned + `',
				   argMax(owner_team, enriched_at)) AS owner,
				argMax(environment, enriched_at) AS env
			FROM finding_enrichment
			GROUP BY id
		) fe ON legacy.id = fe.id
	)
	GROUP BY sev, band, owner, env`

// Summary counts current open findings, grouped by severity, score band, owner
// and environment. Filter.Source narrows it; other Filter fields are ignored (a
// severity breakdown filtered by severity is meaningless).
func (r *CHRepo) Summary(ctx context.Context, f Filter) (Summary, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := summaryLatestRows
	var args []any
	if f.Source != "" {
		query = fmt.Sprintf(summaryOpenFindings, "WHERE source = ?")
		args = append(args, f.Source)
	}

	s := newSummary()
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var (
				sev, band, owner, env string
				n                     uint64 // count() is UInt64; downcast explicitly (CLAUDE.md)
			)
			if err := rows.Scan(&sev, &band, &owner, &env, &n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			s.add(Severity(sev), band, owner, env, int(n))
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return Summary{}, fmt.Errorf("Summary: %w", err)
	}
	return s, nil
}

func newSummary() Summary {
	return Summary{
		BySeverity: map[Severity]int{}, ByBand: map[string]int{},
		ByOwner: map[string]int{}, ByEnvironment: map[string]int{},
	}
}

// add folds one grouped count into every breakdown.
func (s *Summary) add(sev Severity, band, owner, env string, n int) {
	s.Total += n
	s.BySeverity[sev] += n
	if band != "" {
		s.ByBand[band] += n
	}
	s.ByOwner[owner] += n
	s.ByEnvironment[env] += n
}

// Summary reports aggregate counts of current findings for the overview.
func (s *Service) Summary(ctx context.Context, f Filter) (Summary, error) {
	return s.repo.Summary(ctx, f)
}
