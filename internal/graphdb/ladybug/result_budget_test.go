package ladybug

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoundedConversionPreservesGraphValues(t *testing.T) {
	conn := bareConn(t)
	for _, query := range []string{
		"CREATE NODE TABLE BudgetNode(id INT64, label STRING, PRIMARY KEY(id))",
		"CREATE REL TABLE BudgetEdge(FROM BudgetNode TO BudgetNode, weight INT64)",
		"CREATE (:BudgetNode {id: 1, label: 'a'}), (:BudgetNode {id: 2, label: 'b'})",
		"MATCH (a:BudgetNode {id: 1}), (b:BudgetNode {id: 2}) CREATE (a)-[:BudgetEdge {weight: 2}]->(b)",
	} {
		res, err := conn.Query(query)
		require.NoError(t, err)
		res.Close()
	}
	for _, query := range []string{
		"MATCH (a:BudgetNode)-[r:BudgetEdge]->(b:BudgetNode) RETURN a, r, b",
		"MATCH p=(a:BudgetNode)-[:BudgetEdge*1..2]->(b:BudgetNode) RETURN p",
		"RETURN [1, 2, 3] AS xs, {name: 'ok', nested: [4, 5]} AS obj, 12.34 AS amount",
	} {
		t.Run(query, func(t *testing.T) {
			res, err := conn.Query(query)
			require.NoError(t, err)
			defer res.Close()
			require.True(t, res.HasNext())
			row, err := res.Next()
			require.NoError(t, err)
			defer row.Close()
			want, err := row.GetAsMap()
			require.NoError(t, err)
			got, err := row.GetAsMapBounded(&ResultBudget{Bytes: 1 << 20, Values: 10000, MaxCellBytes: 65536, MaxCollectionItems: 4096, MaxDepth: 16})
			require.NoError(t, err)
			require.Equal(t, want, got)
			_, err = row.GetAsMapBounded(nil)
			require.ErrorIs(t, err, ErrResultLimit)
		})
	}
}
