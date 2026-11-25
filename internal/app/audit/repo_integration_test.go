//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
// Record through the real CHRepo lands one audit_events row with every column
// in place, even when the request's context is already cancelled: the change
// it records has committed.
func TestCHRepo_RecordWritesTheRow(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	target := "it-audit-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id = ?", target) })

	at := time.Now().UTC().Truncate(time.Second)
	svc := NewService(NewCHRepo(ch))
	svc.now = func() time.Time { return at }
	reqCtx, cancel := context.WithCancel(auth.ContextWithUser(ctx, auth.User{ID: "u-1", Email: "admin@example.com"}))
	cancel()
	svc.Record(reqCtx, "connector.mode_change", "connector", target, map[string]any{"before": "read_only", "after": "read_write"})

	type row struct {
		id, actor, action, targetType, details string
		ts                                     time.Time
	}
	var rows []row
	require.NoError(t, ch.Select(ctx, func(r driver.Rows) error {
		for r.Next() {
			var x row
			if err := r.Scan(&x.id, &x.ts, &x.actor, &x.action, &x.targetType, &x.details); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return nil
	}, `SELECT id, ts, actor, action, target_type, details FROM audit_events WHERE target_id = ?`, target))

	require.Len(t, rows, 1)
	got := rows[0]
	require.NotEmpty(t, got.id)
	require.True(t, at.Equal(got.ts), "ts %s, want %s", got.ts, at)
	require.Equal(t, "admin@example.com", got.actor)
	require.Equal(t, "connector.mode_change", got.action)
	require.Equal(t, "connector", got.targetType)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.details), &d))
	require.Equal(t, map[string]any{"before": "read_only", "after": "read_write", "actor_user_id": "u-1"}, d)
}
