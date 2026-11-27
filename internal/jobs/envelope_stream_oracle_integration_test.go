//go:build integration

package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

const envelopeOracleAssets = `SELECT id,name,type,metadata,risk_score FROM asset_current_with_derivations`
const envelopeOracleEdges = `SELECT src_id,dst_id,edge_type FROM graph_edges FINAL WHERE ` + graphschema.EdgeFreshnessCond

// Stream the isolated fixture once per table. Per-ID readback would repeatedly
// scan the same granules and warm caches between waves. The bitmap is one bit
// per configured resource; no second inventory is retained by this oracle.
func envelopeVerifyStream(t *testing.T, ctx context.Context, ch *db.CH, sizes []int, wave int) {
	t.Helper()
	offsets := make([]int, len(sizes))
	total := 0
	for c, n := range sizes {
		offsets[c], total = total, total+n
	}
	identity := func(id string) (int, int, int) {
		t.Helper()
		require.True(t, strings.HasPrefix(id, "envelope-"), id)
		account, index, ok := strings.Cut(strings.TrimPrefix(id, "envelope-"), "-")
		require.True(t, ok, id)
		c, err := strconv.Atoi(account)
		require.NoError(t, err)
		i, err := strconv.Atoi(index)
		require.NoError(t, err)
		require.GreaterOrEqual(t, c, 0)
		require.Less(t, c, len(sizes))
		require.GreaterOrEqual(t, i, 0)
		require.Less(t, i, sizes[c])
		if wave == 4 {
			require.NotEqual(t, 1, i, "confirmed deletion must remain absent")
		}
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
			_, i, index := identity(id)
			mark(index)
			count++
			wantType := "ec2_instance"
			if i == 0 {
				wantType = "iam_role"
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
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var source, target, kind string
			if err := rows.Scan(&source, &target, &kind); err != nil {
				return err
			}
			c, i, index := identity(source)
			require.NotZero(t, i, "role has no outgoing relationship")
			mark(index)
			count++
			require.Equal(t, "executes_as", kind)
			require.Equal(t, envelopeID(c, 0), target)
		}
		return rows.Err()
	}, envelopeOracleEdges))
	require.Equal(t, want-len(sizes), count)
}
