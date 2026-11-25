package respond

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const (
	insertAudit = `INSERT INTO audit_events (id, ts, actor, action, target_type, target_id, details)`

	selectAudit = `SELECT id, ts, actor, action, target_type, target_id, details
		FROM audit_events ORDER BY ts DESC LIMIT ?`

	// selectDecisions reads the agent decision trail (not governor verdicts),
	// newest first, with an optional keyset seek for pagination.
	selectDecisions = `SELECT id, ts, actor, action, target_type, target_id, details
		FROM audit_events WHERE action = 'decision'`

	// selectDecisionByID fetches a single decision audit event by its ID.
	selectDecisionByID = `SELECT id, ts, actor, action, target_type, target_id, details
		FROM audit_events WHERE action = 'decision' AND id = ? LIMIT 1`

	// selectDecisionsSummary aggregates the whole decision trail in one pass.
	// audit_events is append-only MergeTree (no versions), so plain aggregates
	// are exact — no argMax needed. Details is the JSON written by auditFor.
	selectDecisionsSummary = `SELECT
			count()                                                 AS total,
			countIf(outcome = 'observed')                           AS observed,
			countIf(outcome = 'escalated')                          AS escalated,
			countIf(outcome = 'parked_for_approval')                AS parked,
			countIf(outcome = 'suppressed_by_verdict')              AS suppressed_by_verdict,
			-- excludes suppressed_by_verdict: a denied pattern can carry
			-- safety='safe' (it's forwarded, not recomputed), and a human
			-- explicitly refused this action, so it is not a quick win.
			countIf(safety = 'safe' AND action_class != 'observe'
				AND outcome != 'suppressed_by_verdict')             AS quick_wins
		FROM (
			SELECT
				JSONExtractString(details, 'outcome')      AS outcome,
				JSONExtractString(details, 'safety_band')  AS safety,
				JSONExtractString(details, 'action_class') AS action_class
			FROM audit_events WHERE action = 'decision'
		)`

	// selectDecisionClassCounts feeds the banner's action-class, confidence-band
	// and escalation-reason tallies from ONE scan, split three ways in Go
	// (cardinality is tiny: ~6 classes x ~4 bands x ~3 reasons). Folding the
	// reason in keeps DecisionsSummary at one pass per aggregate rather than
	// adding a fifth full JSONExtract scan of audit_events to the same 10s
	// budget. Empty values are dropped in Go, not SQL, so a row missing a field
	// falls out naturally rather than needing a WHERE clause to remember.
	selectDecisionClassCounts = `SELECT
			JSONExtractString(details, 'action_class')       AS action_class,
			JSONExtractString(details, 'confidence_band')    AS confidence_band,
			JSONExtractString(details, 'escalation_reason')  AS escalation_reason,
			count()                                          AS n
		FROM audit_events WHERE action = 'decision'
		GROUP BY action_class, confidence_band, escalation_reason`

	// selectEscalationHotspots finds findings escalated >= 3 times. LIMIT is a
	// placeholder, not a bare literal: the live TopEscalatedRepeats path
	// (handler.go) takes hotspotLimit as a real parameter, so a hardcoded LIMIT
	// here would silently stop matching it on any change to that constant.
	selectEscalationHotspots = `SELECT target_id, count() AS n, max(ts) AS latest
		FROM audit_events
		WHERE action = 'decision'
		  AND target_id != ''
		  AND JSONExtractString(details, 'outcome') = 'escalated'
		GROUP BY target_id
		HAVING n >= 3
		ORDER BY n DESC
		LIMIT ?`

	// selectDecisionUniqueResources counts distinct resources behind the
	// decision trail's finding targets. resource_id is baked into the
	// deterministic finding id, so it is immutable across row versions and a
	// plain (non-deduped) read is version-safe under uniqExact.
	selectDecisionUniqueResources = `SELECT uniqExact(resource_id)
		FROM findings
		WHERE id IN (
			SELECT DISTINCT target_id FROM audit_events
			WHERE action = 'decision' AND target_type = 'finding' AND target_id != ''
		)`
)

const (
	defaultAuditLimit  = 100
	decisionsPageLimit = 100
	// hotspotLimit caps the repeatedly-escalated findings the summary surfaces —
	// a "these keep coming back" panel, not a list to page through. Passed as
	// selectEscalationHotspots' own LIMIT parameter (not a hardcoded literal in
	// the query text) so this constant and the CH fallback path can never drift
	// apart.
	hotspotLimit = 5
)

// CHRepo writes and reads the audit trail in ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

func (r *CHRepo) Record(ctx context.Context, e AuditEvent) error {
	if e.ID == "" {
		// Stable per (target, action, ts) for cross-referencing. The audit table
		// is append-only MergeTree, so this is a correlation id, not a dedup key.
		e.ID = dbutil.DeterministicID(e.TargetID, e.Action, e.TS.Format(time.RFC3339Nano))
	}
	err := r.ch.Batch(ctx, insertAudit, func(b driver.Batch) error {
		return b.Append(e.ID, e.TS, e.Actor, e.Action, e.TargetType, e.TargetID, e.Details)
	})
	if err != nil {
		return fmt.Errorf("Record: %w", err)
	}
	return nil
}

// ListDecisions returns the agent decision trail newest-first, one keyset page.
// A non-empty cursorTS/cursorID seeks past a prior page ((ts,id) < (cursor)).
// filter's predicates (if any) are ANDed in ahead of the cursor seek, using
// the same JSONExtractString(details, ...) idiom as selectDecisionsSummary,
// so a filtered page's keyset pagination continues correctly — page 2 seeks
// past page 1 within the same filtered set, never the unfiltered one.
func (r *CHRepo) ListDecisions(ctx context.Context, cursorTS time.Time, cursorID string, limit int, filter DecisionFilter) ([]AuditEvent, error) {
	if limit <= 0 || limit > decisionsPageLimit {
		limit = decisionsPageLimit
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := selectDecisions
	args := []any{}

	switch filter.Outcome {
	case "":
		// no outcome predicate
	case OutcomeNeedsAction:
		query += " AND JSONExtractString(details, 'outcome') IN ('escalated', 'parked_for_approval')"
	case OutcomeSafeToFix:
		// Exact match to selectDecisionsSummary's quick_wins countIf, including
		// the suppressed_by_verdict exclusion (a denied pattern can carry
		// safety='safe' forwarded rather than recomputed, and a human already
		// refused it, so it is not a quick win). Keeping this identical to the
		// summary's predicate is what makes the banner's "N safe to fix" count
		// and the list this filter shows agree.
		query += " AND JSONExtractString(details, 'safety_band') = 'safe'" +
			" AND JSONExtractString(details, 'action_class') != 'observe'" +
			" AND JSONExtractString(details, 'outcome') != 'suppressed_by_verdict'"
	default:
		query += " AND JSONExtractString(details, 'outcome') = ?"
		args = append(args, filter.Outcome)
	}

	if filter.ActionClass != "" {
		query += " AND JSONExtractString(details, 'action_class') = ?"
		args = append(args, filter.ActionClass)
	}

	if !cursorTS.IsZero() {
		query += " AND (ts, id) < (?, ?)"
		args = append(args, cursorTS, cursorID)
	}
	query += " ORDER BY ts DESC, id DESC LIMIT ?"
	args = append(args, limit)

	var out []AuditEvent
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var e AuditEvent
			if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Details); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, e)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ListDecisions: %w", err)
	}
	return out, nil
}

// DecisionsSummary aggregates the whole decision trail (four bounded queries,
// each exact — see the query docs above). Any failed leg fails the call: a
// partial summary rendered as a complete one is a degraded-input bug class.
func (r *CHRepo) DecisionsSummary(ctx context.Context) (DecisionsSummary, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var s DecisionsSummary
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var total, observed, esc, parked, suppressed, quick uint64
			if err := rows.Scan(&total, &observed, &esc, &parked, &suppressed, &quick); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			s.Total, s.Observed = int(total), int(observed)
			s.Escalated, s.Parked, s.QuickWins = int(esc), int(parked), int(quick)
			s.SuppressedByVerdict = int(suppressed)
		}
		return nil
	}, selectDecisionsSummary)
	if err != nil {
		return DecisionsSummary{}, fmt.Errorf("DecisionsSummary: %w", err)
	}

	s.ActionClasses, s.ConfidenceBands = map[string]int{}, map[string]int{}
	s.EscalationReasons = map[string]int{}
	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var class, band, reason string
			var n uint64
			if err := rows.Scan(&class, &band, &reason, &n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if class != "" {
				s.ActionClasses[class] += int(n)
			}
			if band != "" {
				s.ConfidenceBands[band] += int(n)
			}
			if reason != "" {
				s.EscalationReasons[reason] += int(n)
			}
		}
		return nil
	}, selectDecisionClassCounts)
	if err != nil {
		return DecisionsSummary{}, fmt.Errorf("DecisionsSummary: classes: %w", err)
	}

	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var h EscalationHotspot
			var n uint64
			if err := rows.Scan(&h.TargetID, &n, &h.Latest); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			h.Count = int(n)
			s.Hotspots = append(s.Hotspots, h)
		}
		return nil
	}, selectEscalationHotspots, hotspotLimit)
	if err != nil {
		return DecisionsSummary{}, fmt.Errorf("DecisionsSummary: hotspots: %w", err)
	}

	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var n uint64
			if err := rows.Scan(&n); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			s.UniqueResources = int(n)
		}
		return nil
	}, selectDecisionUniqueResources)
	if err != nil {
		return DecisionsSummary{}, fmt.Errorf("DecisionsSummary: resources: %w", err)
	}
	return s, nil
}

// GetDecision fetches a single decision audit event by ID.
func (r *CHRepo) GetDecision(ctx context.Context, id string) (AuditEvent, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out []AuditEvent
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var e AuditEvent
			if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Details); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, e)
		}
		return nil
	}, selectDecisionByID, id)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("GetDecision: %w", err)
	}
	if len(out) == 0 {
		return AuditEvent{}, ErrNotFound
	}
	return out[0], nil
}

// List returns recent audit events, newest first.
func (r *CHRepo) List(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > defaultAuditLimit {
		limit = defaultAuditLimit
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out []AuditEvent
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var e AuditEvent
			if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Details); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, e)
		}
		return nil
	}, selectAudit, limit)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return out, nil
}
