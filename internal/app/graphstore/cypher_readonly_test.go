package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// RunCypherBudget must reject write/DDL Cypher before touching the engine, so
// the public /api/graph/cypher endpoint cannot mutate the graph regardless of
// whether it routes through the in-process replica or the worker RPC.
func TestRunCypherBudget_RejectsWrites(t *testing.T) {
	s := &Service{} // guard runs before any field access; no live Ladybug needed.
	writes := []string{
		"MATCH (n) DETACH DELETE n",
		"MATCH (a:Asset) SET a.score = 100",
		"CREATE (n:Asset {id:'x'})",
		"MERGE (n:Asset {id:'x'})",
		"MATCH (a:Asset) REMOVE a.score",
		"DROP TABLE Asset",
	}
	for _, q := range writes {
		_, err := s.RunCypherBudget(context.Background(), q, QueryBudget{})
		require.ErrorIs(t, err, ErrReadOnly, "write query must be rejected: %s", q)
	}
}
