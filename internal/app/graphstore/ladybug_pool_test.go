package graphstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
)

// slowQuery runs for minutes on any machine: a 10^10-row cross product.
const slowQuery = "UNWIND range(1, 100000) AS a UNWIND range(1, 100000) AS b WITH a, b WHERE (a * b) % 7 = 3 RETURN sum(a + b)"

func runQuery(conn *ladybug.Connection, q string) error {
	res, err := conn.Query(q)
	if res != nil {
		defer res.Close()
	}
	return err
}

func TestRunBounded_EngineTimeoutInterruptsSlowQuery(t *testing.T) {
	db, err := openLadybug(":memory:", 64, 1, 1)
	require.NoError(t, err)
	defer db.close()

	start := time.Now()
	err = db.withRead(context.Background(), 200*time.Millisecond, func(c *ladybug.Connection) error {
		return runQuery(c, slowQuery)
	})
	require.Error(t, err, "a query past its timeout must fail, not run to completion")
	require.Less(t, time.Since(start), 10*time.Second)

	// The same connection must be usable afterwards (timeout reset, no stale interrupt).
	require.NoError(t, db.withRead(context.Background(), defaultQueryTimeout, func(c *ladybug.Connection) error {
		return runQuery(c, "RETURN 1")
	}))
}

func TestRunBounded_ContextCancelInterruptsSlowQuery(t *testing.T) {
	db, err := openLadybug(":memory:", 64, 1, 1)
	require.NoError(t, err)
	defer db.close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	err = db.withCypher(ctx, time.Hour, func(c *ladybug.Connection) error {
		return runQuery(c, slowQuery)
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 10*time.Second)

	require.NoError(t, db.withCypher(context.Background(), defaultQueryTimeout, func(c *ladybug.Connection) error {
		return runQuery(c, "RETURN 1")
	}), "an interrupt must not leak onto the next query on the connection")
}

// The engine drops an interrupt that arrives before the query starts
// executing (a loaded runner can take longer than the cancel delay to get
// there), so a cancel racing query start must still stop the query.
func TestRunBounded_ImmediateCancelInterruptsSlowQuery(t *testing.T) {
	db, err := openLadybug(":memory:", 64, 1, 1)
	require.NoError(t, err)
	defer db.close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err = db.withCypher(ctx, time.Hour, func(c *ladybug.Connection) error {
		return runQuery(c, slowQuery)
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 10*time.Second)
}

func TestRunBounded_PoolAcquisitionHonoursContext(t *testing.T) {
	db, err := openLadybug(":memory:", 64, 1, 1)
	require.NoError(t, err)
	defer db.close()

	// Hold every untrusted-Cypher slot.
	held := make([]*ladybug.Connection, 0, cypherPoolSize)
	for range cypherPoolSize {
		held = append(held, <-db.cypherPool)
	}
	defer func() {
		for _, c := range held {
			db.cypherPool <- c
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = db.withCypher(ctx, defaultQueryTimeout, func(*ladybug.Connection) error {
		return errors.New("must not run")
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// A saturated Cypher pool must not block internal reads.
	require.NoError(t, db.withRead(context.Background(), defaultQueryTimeout, func(c *ladybug.Connection) error {
		return runQuery(c, "RETURN 1")
	}))
}
