package belief

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

// ErrNotFound is returned when no belief exists for a finding.
var ErrNotFound = errors.New("belief: not found")

// insertBeliefs writes belief rows; ReplacingMergeTree (ORDER BY finding_id,
// provenance) upserts in place on the max created_at. A sweep cache hit
// re-writes the same row with the same created_at and a later checked_at;
// readers take max(checked_at), so which tied row a merge keeps is moot.
const insertBeliefs = `INSERT INTO beliefs
	(finding_id, resource_id, claim, severity, confidence, status, provenance, evidence, created_at, input_fingerprint, checked_at)`

// selectBeliefByFinding reads a finding's current belief PER provenance (the sort
// key is (finding_id, provenance), so deterministic and adjudicator beliefs are
// distinct rows). Filtered lookup → argMax form, never FINAL
// (CLAUDE.md). GetByFinding then picks the effective one (see Effective).
const selectBeliefByFinding = `SELECT
	provenance, argMax(resource_id, created_at), argMax(claim, created_at),
	argMax(severity, created_at), argMax(confidence, created_at), argMax(status, created_at),
	argMax(evidence, created_at), max(created_at), argMax(input_fingerprint, created_at),
	max(checked_at)
FROM beliefs WHERE finding_id = ? GROUP BY finding_id, provenance`

// selectCrystallizationInputs returns one row per corroboration-survivor belief:
// the latest adjudicator belief per finding that is still `confirmed` (the gate
// never downgraded it to `proposed`), joined to its finding's structural signature
// dims. argMax GROUP BY, never FINAL (CLAUDE.md); the findings join is restricted
// to the (small) adjudicated set via the CTE so it never full-scans findings.
//
// score_band/must_fix_class come from finding_enrichment via a LEFT JOIN,
// scoped by the same adjudicated id set the findings join restricts to — the
// enrichment side needs the same restriction, or it full-scans finding_enrichment
// instead. Those two columns are plain (not aggregates) from that join, so they
// join the outer GROUP BY alongside f.id/adj.sev.
const selectCrystallizationInputs = `WITH adj AS (
	SELECT finding_id, argMax(severity, created_at) AS sev, argMax(status, created_at) AS st
	FROM beliefs WHERE provenance = 'adjudicator' GROUP BY finding_id
)
SELECT
	argMax(f.resource_type, f.synced_at),
	fe.score_band,
	fe.must_fix_class,
	adj.sev
FROM adj
INNER JOIN findings f ON f.id = adj.finding_id
LEFT JOIN (
	SELECT id,
		argMax(score_band, enriched_at)     AS score_band,
		argMax(must_fix_class, enriched_at) AS must_fix_class
	FROM finding_enrichment
	WHERE id IN (SELECT finding_id FROM adj)
	GROUP BY id
) fe ON fe.id = f.id
WHERE adj.st = 'confirmed'
GROUP BY f.id, adj.sev, fe.score_band, fe.must_fix_class`

// selectAdjudicationBacklog is the coverage cursor: it returns the eligible
// high-band findings that have NOT been freshly adjudicated or re-checked,
// least-recently-checked first, so consecutive sweeps advance through the
// backlog instead of re-reading the same score-desc head forever. Every
// processed finding gets a belief row (a new verdict, or a cache hit's
// checked_at stamp), moving it out of this set on the next sweep.
//
// Eligibility mirrors belief.NeedsAdjudication exactly, expressed on the
// finding columns: score >= minScore is the high band, and the must_fix_class
// IN list is the unresolved set — the complement of decisiveMustFixClasses (a
// decisive must_fix/controlled/contained is left to the deterministic path).
// The Go gate still runs on the hydrated rows as the authoritative filter;
// this SQL predicate must stay a faithful mirror
// (TestAdjudicationBacklogSQLMirrorsNeedsAdjudication holds the two sides
// equal) — the mirror is a LIST here and a complement there, so it drifts in
// the dangerous direction: the Go gate fails open on an unknown class
// (adjudicate it) while this list fails closed (select nothing).
//
// A finding re-enters the set when checked_at < enriched_at (re-enriched since
// its verdict was last formed or re-affirmed) or adj_at < staleBefore (past the
// revalidation horizon). checked_at, not adj_at, is what keeps the cursor
// moving: enrich re-stamps enriched_at at least daily even when nothing
// changed, and a sweep cache hit (same input fingerprint) writes no new
// verdict, so keyed on adj_at those findings stayed in the set forever and,
// sorting first, starved genuinely changed findings for up to the
// revalidation window. A cache hit stamps checked_at instead (Adjudicator.Run).
// The real-change test stays the Go fingerprint compare: it hashes graph
// context this query cannot see, so the cursor's job is only to offer each
// finding once per enrichment, least-recently-checked first.
//
// A LEFT JOIN miss fills both timestamps with the epoch, so never-adjudicated
// findings are included and sort first. Filtered lookup →
// argMax GROUP BY, never FINAL (CLAUDE.md); the beliefs CTE is the small
// adjudicated set.
//
// score/must_fix_class/enriched_at come from finding_enrichment via a LEFT
// JOIN; resolved_at stays on findings (a lifecycle column, carried by the
// `legacy` CTE). fe's version column is aliased enr_at, NOT enriched_at:
// aliasing it enriched_at would make a bare `enriched_at` inside
// argMax(score, enriched_at)/argMax(must_fix_class, enriched_at) in the same
// SELECT list resolve to that alias instead of the raw column
// (ILLEGAL_AGGREGATION — see internal/app/finding/unenriched.go's
// mustFixCoverageBySource comment for the same hazard).
const selectAdjudicationBacklog = `WITH adj AS (
	SELECT finding_id, max(created_at) AS adj_at, max(checked_at) AS checked_at
	FROM beliefs WHERE provenance = 'adjudicator' GROUP BY finding_id
), legacy AS (
	SELECT id, argMax(resolved_at, synced_at) AS resolved_at
	FROM findings GROUP BY id
), eligible AS (
	SELECT legacy.id AS id,
		fe.score AS score,
		fe.enr_at AS enriched_at
	FROM legacy
	LEFT JOIN (
		SELECT id,
			argMax(score, enriched_at)          AS score,
			argMax(must_fix_class, enriched_at) AS must_fix_class,
			max(enriched_at)                    AS enr_at
		FROM finding_enrichment GROUP BY id
	) fe ON fe.id = legacy.id
	WHERE legacy.resolved_at < toDateTime('2000-01-01 00:00:00')
		AND fe.score >= ?
		AND fe.must_fix_class IN ('', 'elevated', 'routine')
		AND fe.enr_at >= toDateTime('2000-01-01 00:00:00')
)
SELECT e.id
FROM eligible e LEFT JOIN adj ON adj.finding_id = e.id
WHERE adj.checked_at < e.enriched_at OR adj.adj_at < ?
ORDER BY adj.checked_at ASC, e.score DESC
LIMIT ?`

// CHRepo persists beliefs to ClickHouse.
type CHRepo struct{ ch *db.CH }

// NewCHRepo constructs the ClickHouse-backed belief store.
func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// Upsert writes beliefs; RMT dedups re-inserted findings on merge.
//
// Called once per finding from the enrich path, so in production this batch is
// almost always a single row — one row per part, driving disproportionate
// merge amplification relative to the table's small size.
//
// Server-side async insert (wait_for_async_insert=0) would coalesce those, but
// is NOT safe on this table: beliefs has a read-after-write contract async
// insert breaks. AdjudicationCandidates reads beliefs to exclude findings
// whose belief was just written, and GetByFinding must return a belief the
// caller has only just persisted (TestCHRepo_RoundTrip,
// TestCHRepo_AdjudicationCandidates). Left synchronous deliberately; the
// merge cost has to be paid elsewhere (batching the per-finding enrich job).
func (r *CHRepo) Upsert(ctx context.Context, bs []Belief) error {
	if len(bs) == 0 {
		return nil
	}
	err := r.ch.Batch(ctx, insertBeliefs, func(b driver.Batch) error {
		for _, x := range bs {
			ev, err := json.Marshal(x.Evidence)
			if err != nil {
				return fmt.Errorf("marshal evidence: %w", err)
			}
			if err := b.Append(x.FindingID, x.ResourceID, x.Claim, string(x.Severity),
				x.Confidence, x.Status, x.Provenance, string(ev), x.CreatedAt, x.Fingerprint,
				x.LastChecked()); err != nil {
				return fmt.Errorf("append: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("Upsert: %w", err)
	}
	return nil
}

// GetByFinding returns a finding's effective belief — the most recent of its
// adjudicator and deterministic beliefs, the adjudicator counted as of its last
// check (see Effective). Returns ErrNotFound if neither exists.
func (r *CHRepo) GetByFinding(ctx context.Context, findingID string) (Belief, error) {
	bs, err := r.byFinding(ctx, findingID)
	if err != nil {
		return Belief{}, fmt.Errorf("GetByFinding: %w", err)
	}
	b, ok := Effective(bs)
	if !ok {
		return Belief{}, ErrNotFound
	}
	return b, nil
}

// GetByProvenance returns a finding's current belief of one provenance, or
// ErrNotFound. The adjudication sweep's cache reads its own verdict this way:
// GetByFinding may legitimately return the newer deterministic belief.
func (r *CHRepo) GetByProvenance(ctx context.Context, findingID, provenance string) (Belief, error) {
	bs, err := r.byFinding(ctx, findingID)
	if err != nil {
		return Belief{}, fmt.Errorf("GetByProvenance: %w", err)
	}
	for _, b := range bs {
		if b.Provenance == provenance {
			return b, nil
		}
	}
	return Belief{}, ErrNotFound
}

// byFinding reads a finding's beliefs, one per provenance.
func (r *CHRepo) byFinding(ctx context.Context, findingID string) ([]Belief, error) {
	var out []Belief
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var b Belief
			var sev, ev string
			if err := rows.Scan(&b.Provenance, &b.ResourceID, &b.Claim, &sev,
				&b.Confidence, &b.Status, &ev, &b.CreatedAt, &b.Fingerprint, &b.CheckedAt); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			b.FindingID = findingID
			b.Severity = finding.Severity(sev)
			if err := json.Unmarshal([]byte(ev), &b.Evidence); err != nil {
				return fmt.Errorf("unmarshal evidence: %w", err)
			}
			out = append(out, b)
		}
		return nil
	}, selectBeliefByFinding, findingID)
	if err != nil {
		return nil, fmt.Errorf("byFinding: %w", err)
	}
	return out, nil
}

// AdjudicationCandidates returns the finding ids to adjudicate this sweep —
// eligible high-band findings not freshly adjudicated, least-recently-adjudicated
// first (see selectAdjudicationBacklog). staleBefore is the revalidation horizon:
// a belief adjudicated before it re-enters the set even if its inputs are unchanged.
func (r *CHRepo) AdjudicationCandidates(ctx context.Context, minScore uint8, staleBefore time.Time, limit int) ([]string, error) {
	qCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var out []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, id)
		}
		return nil
	}, selectAdjudicationBacklog, minScore, staleBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("AdjudicationCandidates: %w", err)
	}
	return out, nil
}

// CrystallizationInputs returns the corroboration-survivor adjudicator beliefs
// (confirmed, never gate-downgraded) as (structural signature, severity) rows.
func (r *CHRepo) CrystallizationInputs(ctx context.Context) ([]CrystallizationInput, error) {
	var out []CrystallizationInput
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var rt, band, mfc, sev string
			if err := rows.Scan(&rt, &band, &mfc, &sev); err != nil {
				return err
			}
			out = append(out, CrystallizationInput{
				Sig:      PatternSignature{ResourceType: rt, Band: band, MustFixClass: mfc},
				Severity: finding.Severity(sev),
			})
		}
		return nil
	}, selectCrystallizationInputs)
	if err != nil {
		return nil, fmt.Errorf("CrystallizationInputs: %w", err)
	}
	return out, nil
}
