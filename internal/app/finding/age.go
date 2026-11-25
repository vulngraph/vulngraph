package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// This file is a size split of repo.go + service.go (CLAUDE.md's 800-line cap),
// not a new layer: the query and CHRepo method below are the repo.go role, the
// Service method the service.go role, and both stay subject to the same rules.

// AgeIntegrity is the observable state of the first-observation timestamp across
// open findings — the signal that first_detected_at is actually holding rather
// than silently reverting to "last detected" for every re-observed finding.
//
//   - Preserved counts findings whose stored first observation is older than the
//     OLDEST detected_at any surviving row version still carries. The comparison
//     is deliberately against min(detected_at), not the latest one: the
//     column defaults first_detected_at to each row's own detected_at, so on
//     day one min(first_detected_at) and min(detected_at) are the same value for
//     every id, and this metric is 0 by construction. It can only become
//     non-zero once a pinned value SURVIVES a merge that collapsed the row
//     versions holding the old detected_at — precisely the event the pin exists
//     to cause.
//   - Missing counts open findings with no first observation recorded at all.
//     This should be 0 forever; a non-zero value means some writer is putting
//     rows in `findings` without a first_detected_at, which the min-over-nonzero
//     read otherwise hides from every other consumer (deliberately — unknown
//     must not demote).
//
// OldestSeconds is the age of the oldest open finding. It does NOT start at
// zero — some sources already carry an upstream first-seen timestamp — so read
// it as a trend, not a threshold: it should climb, and a fall means history is
// being lost again.
type AgeIntegrity struct {
	Preserved     int64
	Missing       int64
	OldestSeconds int64
}

// findingAgeIntegrity aggregates the first-observation state over OPEN findings.
//
// GROUP BY id, not FINAL: the min-over-nonzero read of first_detected_at is a
// fact about the id's whole version history, which FINAL (newest row only)
// cannot express — the same reason firstDetectedAtAgg exists. It is a full-table
// aggregate either way, so no skip index is being given up.
//
// The 60-second margin on the Preserved predicate keeps same-sweep clock jitter
// between the pin and the producer's own `now` from counting as preserved
// history. It has to be a margin and not `!=`: a genuinely-new finding writes
// first_detected_at == detected_at, and a large corpus of those differing by a
// sub-second rounding artefact would read as a working pin.
const findingAgeIntegrity = `SELECT
		countIf(fd > toDateTime(0) AND fd < oldest_detected - 60)         AS preserved,
		countIf(fd <= toDateTime(0))                                     AS missing,
		toInt64(maxIf(dateDiff('second', fd, now()), fd > toDateTime(0))) AS oldest_seconds
	FROM (
		SELECT id,
			` + firstDetectedAtAgg + `        AS fd,
			min(detected_at)                  AS oldest_detected,
			argMax(resolved_at, synced_at)    AS resolved_at
		FROM findings
		GROUP BY id
		HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
	)`

// AgeIntegrity reports the first-observation state of the open corpus.
func (r *CHRepo) AgeIntegrity(ctx context.Context) (AgeIntegrity, error) {
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var out AgeIntegrity
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var preserved, missing uint64 // countIf is UInt64; downcast explicitly
			var oldest int64
			if err := rows.Scan(&preserved, &missing, &oldest); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = AgeIntegrity{
				Preserved: int64(preserved), Missing: int64(missing), OldestSeconds: oldest,
			}
		}
		return rows.Err()
	}, findingAgeIntegrity)
	if err != nil {
		return AgeIntegrity{}, fmt.Errorf("AgeIntegrity: %w", err)
	}
	return out, nil
}

// AgeIntegrity reports whether the immutable first-observation timestamp is
// actually holding across re-observations — the signal that the age
// fix is live rather than shipped-and-inert.
func (s *Service) AgeIntegrity(ctx context.Context) (AgeIntegrity, error) {
	out, err := s.repo.AgeIntegrity(ctx)
	if err != nil {
		return AgeIntegrity{}, fmt.Errorf("AgeIntegrity: %w", err)
	}
	return out, nil
}
