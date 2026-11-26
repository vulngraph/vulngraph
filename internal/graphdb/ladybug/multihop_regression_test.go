package ladybug

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// This is the graph from upstream ladybug#1341/#1342. The second node group
// has no outgoing E edges. Visiting it must not hide the first group's edges
// from subsequent bound nodes in the same scan. Keep this in normal CI: a
// small graph or a mocked row count cannot detect an affected engine binary.
func TestMultiHopAfterMissingRelationshipNodeGroup(t *testing.T) {
	config := DefaultSystemConfig()
	config.BufferPoolSize = 256 * 1024 * 1024
	config.MaxNumThreads = 2
	db, err := OpenInMemoryDatabase(config)
	require.NoError(t, err)
	defer db.Close()
	conn, err := OpenConnection(db)
	require.NoError(t, err)
	defer conn.Close()

	exec := func(q string) {
		t.Helper()
		res, queryErr := conn.Query(q)
		require.NoError(t, queryErr)
		res.Close()
	}
	exec("CREATE NODE TABLE N(id INT64 PRIMARY KEY)")
	exec("UNWIND range(0, 131111) AS i CREATE (:N {id: i})")
	exec("CREATE REL TABLE E(FROM N TO N)")
	for _, edge := range [][2]int{
		{1, 2}, {2, 3}, {1, 3}, {10, 17}, {10, 131080}, {10, 18},
		{17, 5}, {18, 6}, {5, 7}, {6, 8}, {11, 12}, {12, 13},
	} {
		exec(fmt.Sprintf("MATCH (a:N {id: %d}), (b:N {id: %d}) CREATE (a)-[:E]->(b)", edge[0], edge[1]))
	}

	for _, tc := range []struct {
		name  string
		query string
		want  [][]int64
	}{
		{"variable_length", "MATCH (a:N {id: 10})-[:E*1..3]->(b:N) RETURN b.id", [][]int64{{5}, {6}, {7}, {8}, {17}, {18}, {131080}}},
		{"path_count", "MATCH (a:N)-[:E*1..2]->(b:N) RETURN count(*)", [][]int64{{18}}},
		{"two_hop", "MATCH (a:N)-[:E]->(m:N)-[:E]->(b:N) WHERE a.id < 12 RETURN a.id, m.id, b.id", [][]int64{{1, 2, 3}, {10, 17, 5}, {10, 18, 6}, {11, 12, 13}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, queryErr := conn.Query(tc.query)
			require.NoError(t, queryErr)
			defer res.Close()
			var rows [][]int64
			for res.HasNext() {
				tuple, nextErr := res.Next()
				require.NoError(t, nextErr)
				values, valuesErr := tuple.GetAsSlice()
				tuple.Close()
				require.NoError(t, valuesErr)
				row := make([]int64, len(values))
				for i, value := range values {
					var ok bool
					row[i], ok = value.(int64)
					require.True(t, ok, "expected INT64, got %T", value)
				}
				rows = append(rows, row)
			}
			require.ElementsMatch(t, tc.want, rows)
		})
	}
}
