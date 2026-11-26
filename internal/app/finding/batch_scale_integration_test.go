//go:build integration

package finding

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestRecordObservedLargeBatchPreservesFirstDetection(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := context.Background()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	defer ch.Close()
	prefix := fmt.Sprintf("batch-%d-", time.Now().UnixNano())
	defer func() {
		require.NoError(t, ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
	}()
	old := time.Now().Add(-7 * 24 * time.Hour).Truncate(time.Second)
	fs := make([]Finding, 10001)
	for i := range fs {
		fs[i] = Finding{ID: fmt.Sprintf("%s%032d", prefix, i), Source: "fixture", ResourceID: fmt.Sprintf("%sresource-%d", prefix, i), ResourceType: "ec2_instance", Severity: SeverityHigh, CheckID: "fixture", DetectedAt: old}
	}
	svc := NewService(NewCHRepo(ch))
	require.NoError(t, svc.RecordObserved(ctx, fs))
	for i := range fs {
		fs[i].DetectedAt = time.Now()
		fs[i].FirstDetectedAt = time.Time{}
	}
	require.NoError(t, svc.RecordObserved(ctx, fs))
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.ID
	}
	stored, err := svc.ByIDs(ctx, ids)
	require.NoError(t, err)
	require.Len(t, stored, len(fs))
	for _, f := range stored {
		require.Equal(t, old.Unix(), f.FirstDetectedAt.Unix())
	}
}
