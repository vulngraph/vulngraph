package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGRepo reads and writes the automation_policy table directly via pgxpool.
// The table is a single-row singleton (id = 'default'), so sqlc generation
// would add overhead with no benefit.
type PGRepo struct {
	pool *pgxpool.Pool
}

// NewPGRepo returns a PGRepo backed by pool.
func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{pool: pool} }

const getQuery = `
SELECT id, suggest_threshold, action_rules, updated_at, updated_by
FROM automation_policy
WHERE id = 'default'`

// Get returns the current remediation policy. Returns ErrNotFound if the row
// is missing (should not happen after migration, but guarded).
func (r *PGRepo) Get(ctx context.Context) (Policy, error) {
	row := r.pool.QueryRow(ctx, getQuery)

	var p Policy
	var rulesJSON []byte
	err := row.Scan(&p.ID, &p.SuggestThreshold, &rulesJSON, &p.UpdatedAt, &p.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("Get: %w", err)
	}
	if err := json.Unmarshal(rulesJSON, &p.ActionRules); err != nil {
		return Policy{}, fmt.Errorf("Get: unmarshal action_rules: %w", err)
	}
	return p, nil
}

// updateQuery returns the values it replaced, read under the row lock the
// update takes, so the audit row's before value is the one overwritten.
const updateQuery = `
UPDATE automation_policy a
SET suggest_threshold = $1,
    action_rules      = $2,
    updated_at        = now(),
    updated_by        = $3
FROM (SELECT p.id, p.suggest_threshold, p.action_rules FROM automation_policy p WHERE p.id = 'default' FOR UPDATE) AS prev
WHERE a.id = prev.id
RETURNING prev.suggest_threshold, prev.action_rules`

// Update persists p to the automation_policy row and returns the policy it
// replaced (threshold and rules). A missing row is ErrNotFound.
func (r *PGRepo) Update(ctx context.Context, p Policy) (Policy, error) {
	rulesJSON, err := json.Marshal(p.ActionRules)
	if err != nil {
		return Policy{}, fmt.Errorf("Update: marshal action_rules: %w", err)
	}
	var prev Policy
	var prevRules []byte
	err = r.pool.QueryRow(ctx, updateQuery, p.SuggestThreshold, rulesJSON, p.UpdatedBy).Scan(&prev.SuggestThreshold, &prevRules)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("Update: %w", err)
	}
	if err := json.Unmarshal(prevRules, &prev.ActionRules); err != nil {
		return Policy{}, fmt.Errorf("Update: unmarshal previous action_rules: %w", err)
	}
	return prev, nil
}
