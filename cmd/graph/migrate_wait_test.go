package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/migrate"
)

type scriptedStatus struct {
	steps []func() ([]migrate.DBStatus, error)
	calls int
}

func (s *scriptedStatus) status(context.Context) ([]migrate.DBStatus, error) {
	step := s.steps[min(s.calls, len(s.steps)-1)]
	s.calls++
	return step()
}

func caughtUp() ([]migrate.DBStatus, error) {
	return []migrate.DBStatus{{DB: "postgres", Applied: 40, Target: 40}, {DB: "clickhouse", Applied: 36, Target: 35}}, nil
}

func chPending() ([]migrate.DBStatus, error) {
	return []migrate.DBStatus{{DB: "postgres", Applied: 40, Target: 40}, {DB: "clickhouse", Applied: 34, Target: 35, Pending: true}}, nil
}

func unreachable() ([]migrate.DBStatus, error) { return nil, errors.New("connection refused") }

func TestWaitForMigrations_ReturnsAtOnceWhenApplied(t *testing.T) {
	s := &scriptedStatus{steps: []func() ([]migrate.DBStatus, error){caughtUp}}
	require.NoError(t, waitForMigrations(context.Background(), s.status, time.Hour, time.Hour))
	require.Equal(t, 1, s.calls, "no sleep when nothing is pending — and a DB ahead of the binary is not pending")
}

func TestWaitForMigrations_RetriesErrorsAndPendingUntilApplied(t *testing.T) {
	s := &scriptedStatus{steps: []func() ([]migrate.DBStatus, error){unreachable, chPending, chPending, caughtUp}}
	require.NoError(t, waitForMigrations(context.Background(), s.status, time.Millisecond, 2*time.Millisecond))
	require.Equal(t, 4, s.calls)
}

func TestWaitForMigrations_BoundedByContext(t *testing.T) {
	s := &scriptedStatus{steps: []func() ([]migrate.DBStatus, error){chPending}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitForMigrations(ctx, s.status, time.Millisecond, 5*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Greater(t, s.calls, 1, "it polls while waiting")
}

func TestPendingMigrations(t *testing.T) {
	statuses, _ := chPending()
	require.Equal(t, []string{"clickhouse 34<35"}, pendingMigrations(statuses))
	statuses, _ = caughtUp()
	require.Empty(t, pendingMigrations(statuses))
}
