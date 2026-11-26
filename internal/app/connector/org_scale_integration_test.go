//go:build integration

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/testutil/benchconfig"
)

func TestAWSOrgThroughput(t *testing.T) {
	if os.Getenv("PERF_ISOLATED") != "1" || os.Getenv("PERF_CONNECTOR_DIR") == "" {
		t.Skip("run scripts/benchmark-connectors.sh")
	}
	ctx := context.Background()
	pool, err := db.NewPool(ctx, os.Getenv("PERF_POSTGRES_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	type measurement struct {
		Size    int     `json:"accounts"`
		Phase   string  `json:"phase"`
		Seconds float64 `json:"seconds"`
	}
	var report []measurement
	for _, n := range []int{100, 1000, 10000} {
		if n > benchconfig.MaxSize(t) {
			continue
		}
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			disc := &fakeDiscoverer{}
			for i := range n {
				disc.accounts = append(disc.accounts, active(fmt.Sprintf("%012d", 900000000000+i)))
			}
			svc := NewService(NewPGRepo(pool), cipher).WithOrgDiscoverer(disc)
			name := fmt.Sprintf("org-scale-%d-%d", n, time.Now().UnixNano())
			org, err := svc.Create(ctx, TypeAWSOrg, name, orgConfig(nil), "")
			require.NoError(t, err)
			defer func() {
				_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE name LIKE $1", name+"%")
				require.NoError(t, err)
			}()
			original := map[string]OrgAccount{}
			for _, phase := range []string{"initial", "unchanged", "unchanged_again"} {
				start := time.Now()
				res, err := svc.ReconcileOrg(ctx, org.ID)
				elapsed := time.Since(start).Seconds()
				require.NoError(t, err)
				require.Zero(t, res.Errors)
				if phase == "initial" {
					require.Len(t, res.Created, n)
				} else {
					require.Empty(t, res.Created)
				}
				rows, err := svc.OrgAccounts(ctx, org.ID)
				require.NoError(t, err)
				require.Len(t, rows, n)
				for _, row := range rows {
					require.NotNil(t, row.Child)
					require.True(t, row.Child.Enabled)
					if prev, ok := original[row.AccountID]; ok {
						require.True(t, prev.FirstSeenAt.Equal(row.FirstSeenAt))
						require.True(t, prev.StatusChangedAt.Equal(row.StatusChangedAt))
						require.True(t, row.LastSeenAt.After(prev.LastSeenAt))
					} else {
						original[row.AccountID] = row
					}
				}
				report = append(report, measurement{n, phase, elapsed})
				t.Logf("aws_org/%d/%s: %.4fs", n, phase, elapsed)
			}
			disc.err = context.DeadlineExceeded
			_, err = svc.ReconcileOrg(ctx, org.ID)
			require.Error(t, err)
			rows, err := svc.OrgAccounts(ctx, org.ID)
			require.NoError(t, err)
			require.Len(t, rows, n)
			for _, row := range rows {
				require.True(t, row.Child.Enabled, "failed discovery must preserve children")
			}
		})
	}
	b, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_CONNECTOR_DIR"), "aws_org.json"), b, 0600))
}
