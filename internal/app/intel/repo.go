package intel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// ── Postgres repo ────────────────────────────────────────────────────────────

// PGRepo persists monitored domains in Postgres.
type PGRepo struct {
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo {
	return &PGRepo{pool: pool}
}

func (r *PGRepo) AddDomain(ctx context.Context, domain string) (MonitoredDomain, error) {
	var out MonitoredDomain
	err := r.pool.QueryRow(ctx,
		`INSERT INTO intel_monitored_domains (domain)
		 VALUES ($1)
		 ON CONFLICT (domain) DO NOTHING
		 RETURNING id, domain, created_at`,
		strings.ToLower(domain),
	).Scan(&out.ID, &out.Domain, &out.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return MonitoredDomain{}, ErrDomainExists
		}
		return MonitoredDomain{}, fmt.Errorf("AddDomain: %w", err)
	}
	return out, nil
}

func (r *PGRepo) RemoveDomain(ctx context.Context, domain string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM intel_monitored_domains WHERE domain = $1`,
		strings.ToLower(domain),
	)
	if err != nil {
		return fmt.Errorf("RemoveDomain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PGRepo) ListDomains(ctx context.Context) ([]MonitoredDomain, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, domain, created_at FROM intel_monitored_domains ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListDomains: %w", err)
	}
	defer rows.Close()

	var out []MonitoredDomain
	for rows.Next() {
		var d MonitoredDomain
		if err := rows.Scan(&d.ID, &d.Domain, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListDomains scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ── ClickHouse repo ──────────────────────────────────────────────────────────

// CHRepo reads and writes phishing_candidates in ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo {
	return &CHRepo{ch: ch}
}

const insertCandidate = `INSERT INTO phishing_candidates
(id, domain, monitored_domain, source, similarity_score, issuer,
 not_before, not_after, status, ai_is_phishing, ai_confidence, ai_reasoning,
 triage_source, detected_at, confirmed_by, confirmed_at, synced_at)`

// The reads below collapse ReplacingMergeTree versions with argMax(col,
// synced_at) GROUP BY id, never a filtered FINAL: skip indexes don't apply
// under FINAL (use_skip_indexes_if_final is off), so `FINAL WHERE id = ?`
// full-scans the table — the CPU-saturating pattern CLAUDE.md warns about on
// findings/assets. status is rewritten by UpdateStatus, so it can differ
// across versions of the same id and must be filtered post-aggregation
// (HAVING), never on the raw column.

// selectCandidateByID is the point lookup for one candidate's latest version.
const selectCandidateByID = `SELECT id,
		argMax(domain, synced_at), argMax(monitored_domain, synced_at), argMax(source, synced_at),
		argMax(similarity_score, synced_at), argMax(issuer, synced_at),
		argMax(not_before, synced_at), argMax(not_after, synced_at),
		argMax(status, synced_at), argMax(ai_is_phishing, synced_at),
		argMax(ai_confidence, synced_at), argMax(ai_reasoning, synced_at), argMax(triage_source, synced_at),
		argMax(detected_at, synced_at), argMax(confirmed_by, synced_at), argMax(confirmed_at, synced_at)
	FROM phishing_candidates
	WHERE id = ?
	GROUP BY id`

// selectCandidatesByStatus lists candidates whose CURRENT status matches.
// %s is the status IN placeholder list.
const selectCandidatesByStatus = `SELECT id,
		argMax(domain, synced_at), argMax(monitored_domain, synced_at), argMax(source, synced_at),
		argMax(similarity_score, synced_at) AS similarity_score, argMax(issuer, synced_at),
		argMax(not_before, synced_at), argMax(not_after, synced_at),
		argMax(status, synced_at) AS status, argMax(ai_is_phishing, synced_at),
		argMax(ai_confidence, synced_at), argMax(ai_reasoning, synced_at), argMax(triage_source, synced_at),
		argMax(detected_at, synced_at) AS detected_at, argMax(confirmed_by, synced_at), argMax(confirmed_at, synced_at)
	FROM phishing_candidates
	GROUP BY id
	HAVING status IN (%s)
	ORDER BY similarity_score DESC, detected_at DESC
	LIMIT 500`

// countCandidatesByStatus is selectCandidatesByStatus's true population size —
// auto_dismissed only ever grows (nothing evicts adjudicated rows), so once a
// status bucket crosses the LIMIT the returned slice length would silently
// freeze at 500; the UI needs the real count to disclose that.
const countCandidatesByStatus = `SELECT count() FROM (
		SELECT id, argMax(status, synced_at) AS status
		FROM phishing_candidates
		GROUP BY id
		HAVING status IN (%s)
	)`

// selectAdjudicatedIDs feeds re-detection dedup: EVERY id ever written.
//
// It must not exclude dismissed ids ("HAVING argMax(status, synced_at) !=
// 'dismissed'"), or every manual dismissal resurrects on the next scan:
// RunScan treats "not in this set" as new (service.go), so a dismissed
// candidate would come straight back as 'pending' within 6 hours and no amount
// of triage could ever empty the queue. A candidate id is
// sha256(domain|monitored_domain) — stable and content-free — so a re-observed
// certificate for a domain a human already judged is the SAME decision, not a
// new one. Re-detection cannot add information here; only a new domain can.
//
// The cost of including them is that a candidate's cert dates and AI reasoning
// are never refreshed after the first sighting. Pending rows behave the same
// way, and it is the safe direction: this path only ever INSERTS, so nothing is resolved or deleted by
// absence.
const selectAdjudicatedIDs = `SELECT DISTINCT id FROM phishing_candidates`

func (r *CHRepo) BulkUpsertCandidates(ctx context.Context, candidates []PhishingCandidate) error {
	if len(candidates) == 0 {
		return nil
	}
	now := time.Now()
	return r.ch.Batch(ctx, insertCandidate, func(b driver.Batch) error {
		for _, c := range candidates {
			if err := b.Append(
				c.ID, c.Domain, c.MonitoredDomain, c.Source,
				c.SimilarityScore, c.Issuer,
				c.NotBefore, c.NotAfter,
				string(c.Status), boolToUInt8(c.AIIsPhishing), c.AIConfidence, c.AIReasoning,
				string(c.TriageSource), c.DetectedAt, c.ConfirmedBy, c.ConfirmedAt,
				now,
			); err != nil {
				return fmt.Errorf("append candidate %s: %w", c.Domain, err)
			}
		}
		return nil
	})
}

func (r *CHRepo) UpdateStatus(ctx context.Context, id string, status CandidateStatus, by string) error {
	now := time.Now()
	var confirmedAt *time.Time
	if status == StatusConfirmed {
		confirmedAt = &now
	}
	existing, err := r.getCandidate(ctx, id)
	if err != nil {
		return fmt.Errorf("UpdateStatus get: %w", err)
	}
	existing.Status = status
	existing.ConfirmedBy = by
	existing.ConfirmedAt = confirmedAt
	return r.ch.Batch(ctx, insertCandidate, func(b driver.Batch) error {
		return b.Append(
			existing.ID, existing.Domain, existing.MonitoredDomain, existing.Source,
			existing.SimilarityScore, existing.Issuer,
			existing.NotBefore, existing.NotAfter,
			string(existing.Status), boolToUInt8(existing.AIIsPhishing), existing.AIConfidence, existing.AIReasoning,
			string(existing.TriageSource), existing.DetectedAt, existing.ConfirmedBy, existing.ConfirmedAt,
			now,
		)
	})
}

// GetCandidate returns one phishing candidate by id.
func (r *CHRepo) GetCandidate(ctx context.Context, id string) (PhishingCandidate, error) {
	return r.getCandidate(ctx, id)
}

func (r *CHRepo) getCandidate(ctx context.Context, id string) (PhishingCandidate, error) {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var c PhishingCandidate
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		if !rows.Next() {
			return ErrNotFound
		}
		var confirmedAt *time.Time
		var status string // argMax returns a plain String the driver won't scan into the named type
		var isPhishing uint8
		var source string
		if err := rows.Scan(
			&c.ID, &c.Domain, &c.MonitoredDomain, &c.Source,
			&c.SimilarityScore, &c.Issuer,
			&c.NotBefore, &c.NotAfter,
			&status, &isPhishing, &c.AIConfidence, &c.AIReasoning, &source,
			&c.DetectedAt, &c.ConfirmedBy, &confirmedAt,
		); err != nil {
			return fmt.Errorf("scan candidate: %w", err)
		}
		c.Status = CandidateStatus(status)
		c.TriageSource = TriageSource(source)
		c.AIIsPhishing = isPhishing != 0
		c.ConfirmedAt = confirmedAt
		return nil
	}, selectCandidateByID, id)
	return c, err
}

// ListCandidates returns phishing candidates filtered by status, plus the true
// population count for that status (the list itself is capped at 500).
// When status is empty, defaults to pending.
func (r *CHRepo) ListCandidates(ctx context.Context, status CandidateStatus) ([]PhishingCandidate, int, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	filter := StatusPending
	if status != "" {
		filter = status
	}

	ph, args := dbutil.CHIn([]string{string(filter)})
	query := fmt.Sprintf(selectCandidatesByStatus, ph)

	var out []PhishingCandidate
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var c PhishingCandidate
			var confirmedAt *time.Time
			var status string // argMax returns a plain String the driver won't scan into the named type
			var isPhishing uint8
			var source string
			if err := rows.Scan(
				&c.ID, &c.Domain, &c.MonitoredDomain, &c.Source,
				&c.SimilarityScore, &c.Issuer,
				&c.NotBefore, &c.NotAfter,
				&status, &isPhishing, &c.AIConfidence, &c.AIReasoning, &source,
				&c.DetectedAt, &c.ConfirmedBy, &confirmedAt,
			); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			c.Status = CandidateStatus(status)
			c.TriageSource = TriageSource(source)
			c.AIIsPhishing = isPhishing != 0
			c.ConfirmedAt = confirmedAt
			out = append(out, c)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListCandidates: %w", err)
	}

	var total uint64
	countQuery := fmt.Sprintf(countCandidatesByStatus, ph)
	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&total); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}
		return nil
	}, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListCandidates: count: %w", err)
	}
	return out, int(total), nil
}

// ExistingCandidateIDs returns every candidate id already on record — including
// dismissed and auto-dismissed ones — so a scan never re-opens a decision that
// has already been made. See selectAdjudicatedIDs.
func (r *CHRepo) ExistingCandidateIDs(ctx context.Context) (map[string]bool, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	seen := map[string]bool{}
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			seen[id] = true
		}
		return nil
	}, selectAdjudicatedIDs)
	return seen, err
}

// boolToUInt8 maps a Go bool onto the ClickHouse UInt8 the column is declared as
// (the driver will not append a bool into a UInt8).
func boolToUInt8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
