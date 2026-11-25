//go:build integration

package httpsrv

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/db"
)

// TestAuditTrail_SuppressAndUnsuppress drives the real wired chain and asserts
// the audit rows land in ClickHouse. Unit tests pin the service's decisions;
// this pins the thing they cannot: that the INSERT's column order and types
// match the real `audit_events` table.
func TestAuditTrail_SuppressAndUnsuppress(t *testing.T) {
	srv, login := buildServer(t)
	admin := login("admin")
	ctx := context.Background()

	findingID := "audit-probe-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		ch, err := db.NewCH(ctx, chDSN, 0)
		if err != nil {
			return
		}
		defer func() { _ = ch.Close() }()
		_ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id = ?", findingID)
	})

	expiry := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	renewed := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	require.Equal(t, http.StatusCreated,
		do(srv, http.MethodPost, "/api/findings/"+findingID+"/suppress", admin,
			`{"reason":"integration probe","expires_at":"`+expiry+`"}`).Code)
	require.Equal(t, http.StatusOK,
		do(srv, http.MethodPost, "/api/findings/"+findingID+"/suppress/review", admin,
			`{"expires_at":"`+renewed+`"}`).Code)
	require.Equal(t, http.StatusNoContent,
		do(srv, http.MethodDelete, "/api/findings/"+findingID+"/suppress", admin, "").Code)

	rows := readAuditRows(t, findingID)
	require.Len(t, rows, 3, "suppress, review, then unsuppress must leave three audit rows")

	byAction := map[string]auditRow{}
	for _, r := range rows {
		byAction[r.action] = r
	}
	sup, ok := byAction[suppress.AuditActionSuppress]
	require.True(t, ok)
	require.Equal(t, suppress.AuditTargetFinding, sup.targetType)
	require.Contains(t, sup.actor, "admin-", "the actor must be the session user, not the request body")
	require.Contains(t, sup.details, "integration probe")
	require.Contains(t, sup.details, expiry)

	review, ok := byAction[suppress.AuditActionReview]
	require.True(t, ok, "a renewal moves the expiry and must leave a trace")
	require.Equal(t, sup.actor, review.actor)
	require.Contains(t, review.details, renewed)
	require.Contains(t, review.details, expiry, "the replaced expiry is recorded")

	unsup, ok := byAction[suppress.AuditActionUnsuppress]
	require.True(t, ok, "the hard DELETE must still leave a trace")
	require.Equal(t, sup.actor, unsup.actor)
}

type auditRow struct {
	actor, action, targetType, targetID, details string
}

func readAuditRows(t *testing.T, targetID string) []auditRow {
	t.Helper()
	ctx := context.Background()
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	defer func() { _ = ch.Close() }()

	var out []auditRow
	err = ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var r auditRow
			if err := rows.Scan(&r.actor, &r.action, &r.targetType, &r.targetID, &r.details); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	}, `SELECT actor, action, target_type, target_id, details
	    FROM audit_events WHERE target_id = ?`, targetID)
	require.NoError(t, err)
	return out
}
