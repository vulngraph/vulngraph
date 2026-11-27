//go:build integration

package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

const envelopeOracleAssets = `SELECT id,name,type,metadata,risk_score FROM asset_current_with_derivations`
const envelopeOracleEdges = `SELECT src_id,dst_id,edge_type,JSONExtractString(properties,'origin') FROM graph_edges FINAL WHERE ` + graphschema.EdgeFreshnessCond

// Stream the isolated fixture once per table. Per-ID readback would repeatedly
// scan the same granules and warm caches between waves. The bitmap is one bit
// per configured resource; no second inventory is retained by this oracle.
func envelopeVerifyStream(t *testing.T, ctx context.Context, ch *db.CH, sizes []int, scopes []envelopeScope, wave int) int {
	t.Helper()
	offsets := make([]int, len(sizes))
	total := 0
	for c, n := range sizes {
		offsets[c], total = total, total+n
	}
	identity := func(id string) (int, int, int) {
		t.Helper()
		c, i, err := envelopeIdentity(id)
		require.NoError(t, err)
		require.GreaterOrEqual(t, c, 0)
		require.Less(t, c, len(sizes))
		require.GreaterOrEqual(t, i, 0)
		require.Less(t, i, sizes[c])
		return c, i, offsets[c] + i
	}
	seen := make([]uint64, (total+63)/64)
	mark := func(index int) {
		t.Helper()
		mask := uint64(1) << (index % 64)
		require.Zero(t, seen[index/64]&mask, "duplicate resource or relationship")
		seen[index/64] |= mask
	}
	count, stable := 0, 0
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id, name, kind, metadata string
			var risk uint8
			if err := rows.Scan(&id, &name, &kind, &metadata, &risk); err != nil {
				return err
			}
			if id == "envelope-stable" {
				stable++
				require.Equal(t, "container_image", kind)
				continue
			}
			c, i, index := identity(id)
			if wave == 4 {
				require.NotEqual(t, 1, i, "confirmed deletion must remain absent: %s", id)
			}
			mark(index)
			count++
			wantType := "ec2_instance"
			if i == 0 {
				wantType = "iam_role"
			}
			switch scopes[c].Kind {
			case "gcp":
				wantType = "gce_instance"
				if i == 0 {
					wantType = "gcp_service_account"
				}
			case "kubernetes":
				wantType = "k8s_pod"
				if i == 0 {
					wantType = "k8s_service_account"
				}
			case "github":
				wantType = "github_repo"
			}
			require.Equal(t, wantType, kind, id)
			wantName := id
			var wantRisk uint8
			if i%100 == 1 {
				revision := 0
				wantRisk = 60
				if wave >= 2 {
					revision, wantRisk = 1, 80
				}
				wantName += fmt.Sprintf("-revision-%d", revision)
			}
			require.Equal(t, wantName, name)
			require.Equal(t, wantRisk, risk, id)
			var payload struct {
				Value string `json:"payload"`
			}
			require.NoError(t, json.Unmarshal([]byte(metadata), &payload))
			size := 256
			if i%100 == 0 {
				size = 16384
			}
			require.Len(t, payload.Value, size, id)
			digest := sha256.Sum256([]byte(id))
			expected := hex.EncodeToString(digest[:])
			for start := 0; start < size; start += len(expected) {
				require.Equal(t, expected, payload.Value[start:start+len(expected)], id)
			}
		}
		return rows.Err()
	}, envelopeOracleAssets))
	want := total
	if wave == 4 {
		want -= len(sizes)
	}
	require.Equal(t, want, count)
	require.Equal(t, 1, stable)
	clear(seen)
	count = 0
	retainedOrphans := 0
	cross := map[string]bool{}
	wantCross := 0
	for _, scope := range scopes {
		if scope.Kind == "kubernetes" && scope.CloudTarget >= 0 {
			wantCross += 2
		}
	}
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var source, target, kind, origin string
			if err := rows.Scan(&source, &target, &kind, &origin); err != nil {
				return err
			}
			c, i, index := identity(source)
			if i == 0 {
				require.Equal(t, "kubernetes", string(scopes[c].Kind))
				require.GreaterOrEqual(t, scopes[c].CloudTarget, 0)
				require.Contains(t, []string{"executes_as", "federated_access"}, kind)
				require.Equal(t, fmt.Sprintf("serviceAccount:envelope-%04d@synthetic.invalid", scopes[c].CloudTarget), target)
				key := source + "/" + kind
				require.False(t, cross[key])
				cross[key] = true
				continue
			}
			mark(index)
			wantTarget, wantKind := envelopeID(c, 0), "executes_as"
			switch scopes[c].Kind {
			case "aws":
				wantKind = "has_role"
			case "gcp":
				wantTarget = fmt.Sprintf("serviceAccount:envelope-%04d@synthetic.invalid", c)
			case "kubernetes":
				wantTarget = fmt.Sprintf("synthetic-cluster-%04d/namespace/workloads/serviceaccount/envelope", c)
			case "github":
				wantTarget = envelopeID(scopes[c].CloudTarget, 0)
				wantKind = "federated_access"
			}
			require.Equal(t, wantKind, kind)
			require.Equal(t, wantTarget, target)
			if wave == 4 && i == 1 {
				// Retirement preserves edge writes newer than its proof. A
				// concurrent correlation can restamp an older input; retain and
				// disclose these physical rows, but require exact absent endpoints
				// above and exact live topology in the independent native oracle.
				require.Equal(t, "correlate", origin, source)
				retainedOrphans++
				continue
			}
			count++
		}
		return rows.Err()
	}, envelopeOracleEdges))
	require.Equal(t, want-len(sizes), count)
	require.Len(t, cross, wantCross)
	return retainedOrphans
}
