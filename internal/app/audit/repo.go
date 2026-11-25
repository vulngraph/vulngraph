package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// insertAudit appends one row. Same table and column order as the executor's,
// suppress's and respond's rows: one table, one shape.
const insertAudit = `INSERT INTO audit_events (id, ts, actor, action, target_type, target_id, details)`

const auditWriteTimeout = 5 * time.Second

// CHRepo appends audit events to ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// Write appends one event. audit_events is a plain MergeTree, so nothing here
// overwrites an earlier row.
func (r *CHRepo) Write(ctx context.Context, e Event) error {
	id := dbutil.DeterministicID(e.TargetID, e.Action, e.Actor, e.TS.Format(time.RFC3339Nano))

	// The change being recorded has already been committed, so a cancelled
	// request must not lose its row and a slow ClickHouse must not hold the
	// request open.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

	err := r.ch.Batch(writeCtx, insertAudit, func(b driver.Batch) error {
		return b.Append(id, e.TS, e.Actor, e.Action, e.TargetType, e.TargetID, e.Details)
	})
	if err != nil {
		return fmt.Errorf("Write: %w", err)
	}
	return nil
}
