package auth

import (
	"context"
	"fmt"
)

// WithUserAdministration serializes the last-admin check and all its writes
// across replicas. Bootstrap takes the same transaction-scoped lock.
func (r *PGRepo) WithUserAdministration(ctx context.Context, fn func(UserAdminRepo) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("WithUserAdministration: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := r.q.WithTx(tx)
	if err := q.LockUserAdministration(ctx); err != nil {
		return fmt.Errorf("WithUserAdministration: lock: %w", err)
	}
	if err := fn(&PGRepo{pool: r.pool, q: q, cipher: r.cipher, tx: tx}); err != nil {
		return fmt.Errorf("WithUserAdministration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("WithUserAdministration: commit: %w", err)
	}
	return nil
}
