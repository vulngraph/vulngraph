package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// openIDsBehindCutoffQ walks the IDs of open findings whose enrichment predates a
// cutoff, in a single deterministic pass ordered by id.
//
// It exists because a full re-enrichment pass needs pages far larger than
// DefaultLimit (200), which List clamps to silently. The same reasoning as
// asset.ListAllForSync: the page cap is for the web UI and must never truncate a
// bulk walk. IDs only — the enrich worker re-reads each finding anyway, so
// carrying full rows here would move ~640 bytes per finding for nothing.
//
// It deliberately does NOT order by `enriched_at ASC` on the tempting theory
// that the pass is self-balancing and needs no cursor (re-enriching a finding
// bumps its enriched_at, pushing it to the back of that ordering): that
// self-balancing claim is false whenever more open findings sit at
// enriched_at=0 than one page holds, since the page then fills from the
// epoch-stamped head every round and the walk never reaches anything behind
// it. Worse, enrichment columns share a row with producer facts, so a
// re-observation landing mid-write can reset enriched_at back to 0 — a moving
// target no ordering over that column can converge on. A monotone walk over
// id, a key nothing in the pipeline mutates, converges regardless and still
// visits the epoch cohort rather than hiding it.
//
// The sentinel comparison on resolved_at matches Finding.Resolved(): ClickHouse
// DateTime has no NULL, so an unresolved row reads back as the epoch.
//
// enr comes from finding_enrichment via a LEFT JOIN. A finding with no
// finding_enrichment row reads back enr as the join's type-default sentinel
// (toDateTime64(0,3) under join_use_nulls=0, the ClickHouse default) — the "never
// enriched" signal, which is exactly the epoch cohort this query exists to
// surface: it must keep visiting findings with no finding_enrichment row, not
// silently drop them.
const openIDsBehindCutoffQ = `SELECT legacy.id FROM (
	SELECT id,
		argMax(resolved_at, synced_at) AS res
	FROM findings GROUP BY source, id
) legacy
LEFT JOIN (
	SELECT id, max(enriched_at) AS enr FROM finding_enrichment GROUP BY id
) fe ON legacy.id = fe.id
WHERE res < toDateTime('2000-01-01') AND fe.enr < ? AND legacy.id > ?
ORDER BY legacy.id ASC LIMIT ?`

// reenrichPageTimeout bounds one page read. The whole-corpus argMax collapse
// takes on the order of a second at large scale, so this is generous;
// it exists so a degraded ClickHouse fails the page rather than hanging the job.
const reenrichPageTimeout = 60 * time.Second

// OpenIDsBehindCutoff returns up to limit IDs of open findings enriched before
// cutoff, ordered by id and starting strictly after afterID. Pass "" for afterID
// to start at the beginning — every finding id sorts after the empty string.
//
// An empty result means the walk has passed the last open finding behind the
// cutoff, which is what ends the pass.
func (r *CHRepo) OpenIDsBehindCutoff(ctx context.Context, cutoff time.Time, afterID string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, reenrichPageTimeout)
	defer cancel()

	var out []string
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, id)
		}
		return rows.Err()
	}, openIDsBehindCutoffQ, cutoff, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("OpenIDsBehindCutoff: %w", err)
	}
	return out, nil
}

// OpenIDsBehindCutoff walks the open findings still behind a re-enrichment cutoff.
func (s *Service) OpenIDsBehindCutoff(ctx context.Context, cutoff time.Time, afterID string, limit int) ([]string, error) {
	return s.repo.OpenIDsBehindCutoff(ctx, cutoff, afterID, limit)
}
