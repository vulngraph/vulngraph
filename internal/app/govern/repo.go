package govern

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// PGRepo stores governor verdicts in Postgres.
type PGRepo struct {
	q *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool)} }

// Upsert records (or overwrites) the standing verdict for a finding, snapshotting
// the context fingerprint it was resolved against.
func (r *PGRepo) Upsert(ctx context.Context, findingID, clusterKey string, verdict Verdict, actor, note, fingerprint string) error {
	err := r.q.UpsertDecisionVerdict(ctx, sqlcgen.UpsertDecisionVerdictParams{
		FindingID:   findingID,
		ClusterKey:  clusterKey,
		Verdict:     string(verdict),
		Actor:       actor,
		Note:        note,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return fmt.Errorf("Upsert: %w", err)
	}
	return nil
}

// ResolvedFingerprints maps each verdict-carrying finding id to the context
// fingerprint captured when it was resolved, so the queue can re-surface findings
// whose fingerprint has since changed.
func (r *PGRepo) ResolvedFingerprints(ctx context.Context) (map[string]string, error) {
	rows, err := r.q.ListResolvedVerdicts(ctx)
	if err != nil {
		return nil, fmt.Errorf("ResolvedFingerprints: %w", err)
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.FindingID] = row.Fingerprint
	}
	return out, nil
}

// UpsertPattern records (or overwrites) the standing verdict for a (check_id,
// action_class, resource_type) pattern — the finding-independent twin of
// Upsert. Latest verdict wins. resourceType scopes the ruling to one kind of
// resource: denying "remediate" for one check on s3_bucket must never
// suppress the same check on rds_instance, let alone every s3 bucket that
// will ever exist.
func (r *PGRepo) UpsertPattern(ctx context.Context, checkID, actionClass, resourceType string, verdict Verdict, actor string) error {
	err := r.q.UpsertPatternVerdict(ctx, sqlcgen.UpsertPatternVerdictParams{
		CheckID:      checkID,
		ActionClass:  actionClass,
		ResourceType: resourceType,
		Verdict:      string(verdict),
		DecidedBy:    actor,
	})
	if err != nil {
		return fmt.Errorf("UpsertPattern: %w", err)
	}
	return nil
}

// PatternVerdict returns the latest standing verdict for a (check_id,
// action_class, resource_type) pattern, and when it was decided. found is
// false, with no error, when none has ever been recorded — a
// sentinel-error-free "not found" contract. decidedAt lets the caller
// (respond.Decide) refuse to act on a ruling that has gone stale.
func (r *PGRepo) PatternVerdict(ctx context.Context, checkID, actionClass, resourceType string) (Verdict, time.Time, bool, error) {
	row, err := r.q.GetPatternVerdict(ctx, sqlcgen.GetPatternVerdictParams{
		CheckID:      checkID,
		ActionClass:  actionClass,
		ResourceType: resourceType,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, false, nil
		}
		return "", time.Time{}, false, fmt.Errorf("PatternVerdict: %w", err)
	}
	return Verdict(row.Verdict), row.DecidedAt, true, nil
}

// Consume spends an email approval link's nonce. first is false when the
// nonce was already spent — the link is a replay or the other half of a pair.
// Expired rows are purged opportunistically: an expired link is refused by
// its own signed expiry, so its row no longer guards anything.
func (r *PGRepo) Consume(ctx context.Context, nonce string, expiresAt time.Time) (bool, error) {
	if err := r.q.PurgeExpiredApprovalLinkNonces(ctx, time.Now()); err != nil {
		return false, fmt.Errorf("Consume: purge: %w", err)
	}
	n, err := r.q.ConsumeApprovalLinkNonce(ctx, sqlcgen.ConsumeApprovalLinkNonceParams{Nonce: nonce, ExpiresAt: expiresAt})
	if err != nil {
		return false, fmt.Errorf("Consume: %w", err)
	}
	return n == 1, nil
}

// Spent reports whether an email approval link's nonce has been used.
func (r *PGRepo) Spent(ctx context.Context, nonce string) (bool, error) {
	spent, err := r.q.ApprovalLinkNonceSpent(ctx, nonce)
	if err != nil {
		return false, fmt.Errorf("Spent: %w", err)
	}
	return spent, nil
}
