package main

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/migrate"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Backoff bounds for waitForMigrations: fast enough to start promptly once the
// serve pod's migrate init container finishes, slow enough not to hammer a
// database that is mid-migration.
const (
	migrationWaitMinBackoff = time.Second
	migrationWaitMaxBackoff = 30 * time.Second
)

type migrationStatusFunc func(ctx context.Context) ([]migrate.DBStatus, error)

// waitForMigrations blocks until every migration set reports Applied >= Target.
//
// Only the serve pod runs `graph migrate` (its init container), so on an
// upgrade the worker and scanner start alongside it, not after it. Starting
// early means querying columns that do not exist yet (a MaxAttempts-1 job
// then fails permanently), and writing into a ClickHouse table that a
// migration is rebuilding by INSERT ... SELECT + EXCHANGE loses those writes.
// Blocking here, before any River client or ingest starts, keeps the pod
// unready (its readiness endpoint is not served yet) until the schema matches
// the binary. A database AHEAD of the binary (a rollback, or old pods during a
// rollout) is fine: migrations are additive.
//
// A Status error is retried, not fatal: the databases may still be starting.
func waitForMigrations(ctx context.Context, status migrationStatusFunc, minBackoff, maxBackoff time.Duration) error {
	logger := log.FromContext(ctx)
	backoff := minBackoff
	waited := false
	for {
		statuses, err := status(ctx)
		if err == nil {
			pending := pendingMigrations(statuses)
			if len(pending) == 0 {
				if waited {
					logger.Info().Msg("migrations applied — starting")
				}
				return nil
			}
			logger.Info().Strs("pending", pending).Dur("retry_in", backoff).
				Msg("waiting for migrations (applied by the serve pod's migrate init container)")
		} else {
			logger.Warn().Err(err).Dur("retry_in", backoff).Msg("migration status unavailable — retrying")
		}
		waited = true

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("waitForMigrations: %w", ctx.Err())
		case <-timer.C:
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// pendingMigrations describes each migration set still behind the binary.
func pendingMigrations(statuses []migrate.DBStatus) []string {
	var out []string
	for _, s := range statuses {
		if s.Pending {
			out = append(out, fmt.Sprintf("%s %d<%d", s.DB, s.Applied, s.Target))
		}
	}
	return out
}

// migrateStatus reads migration status for the databases getenv points at.
func migrateStatus(getenv func(string) string) migrationStatusFunc {
	return func(ctx context.Context) ([]migrate.DBStatus, error) {
		statuses, err := migrate.Status(ctx, pgDSN(getenv), chDSN(getenv))
		if err != nil {
			return nil, fmt.Errorf("migrateStatus: %w", err)
		}
		return statuses, nil
	}
}
