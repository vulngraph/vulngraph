package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/explore"
)

// countAssetNodes returns the number of Asset nodes in the live graph.
func countAssetNodes(t *testing.T, s *Service) int64 {
	t.Helper()
	return countRows(t, s, "MATCH (n:Asset) RETURN count(n)")
}

// countRows runs a single-count query on the read pool and returns the count.
func countRows(t *testing.T, s *Service, query string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, s.withRead(context.Background(), defaultQueryTimeout, func(conn *ladybug.Connection) error {
		res, err := conn.Query(query)
		if err != nil {
			return err
		}
		defer res.Close()
		tup, err := res.Next()
		if err != nil {
			return err
		}
		defer tup.Close()
		v, err := tup.GetValue(0)
		if err != nil {
			return err
		}
		n = v.(int64)
		return nil
	}))
	return n
}

// TestRunCypherBudget_LexerBypassesWriteNothing runs the comment-lexing bypasses
// against real liblbug. Executed raw, each one really deletes or creates a node
// (proving the engine lexes them as writes); through RunCypherBudget each must be
// refused and the graph left untouched.
func TestRunCypherBudget_LexerBypassesWriteNothing(t *testing.T) {
	bypasses := []string{
		`MATCH (n:Asset) /* **/ ' */ DETACH DELETE n //'`,
		`RETURN 1 /* **/ ' */; CREATE (:Asset {id:'evil'}) //'`,
	}
	for _, q := range bypasses {
		t.Run(q, func(t *testing.T) {
			s, err := Open("", 64, 1, 1, "")
			require.NoError(t, err)
			defer s.Close()
			wc, err := s.db.newWriteConn()
			require.NoError(t, err)
			defer wc.Close()
			res, err := wc.Query("CREATE (:Asset {id:'a1'})")
			require.NoError(t, err)
			res.Close()
			require.EqualValues(t, 1, countAssetNodes(t, s))

			_, err = s.RunCypherBudget(context.Background(), q, QueryBudget{})
			require.ErrorIs(t, err, ErrReadOnly)
			require.EqualValues(t, 1, countAssetNodes(t, s), "a refused query must not have written")

			// The same string executed raw does write: the guard is what stops it.
			res, err = wc.Query(q)
			require.NoError(t, err, "the engine must accept the bypass for this test to mean anything")
			res.Close()
			require.NotEqualValues(t, 1, countAssetNodes(t, s))
		})
	}
}

// openSeededGraph opens an in-memory graph holding two Asset nodes joined by
// one ExposedToInternet edge, plus the write connection that seeded it.
func openSeededGraph(t *testing.T) (*Service, *ladybug.Connection) {
	t.Helper()
	s, err := Open("", 64, 1, 1, "")
	require.NoError(t, err)
	t.Cleanup(s.Close)
	wc, err := s.db.newWriteConn()
	require.NoError(t, err)
	t.Cleanup(wc.Close)
	for _, q := range []string{
		"CREATE (:Asset {id:'a1', score: 7})",
		"CREATE (:Asset {id:'internet'})",
		"MATCH (a:Asset {id:'a1'}), (b:Asset {id:'internet'}) CREATE (a)-[:ExposedToInternet]->(b)",
	} {
		res, err := wc.Query(q)
		require.NoError(t, err, q)
		res.Close()
	}
	return s, wc
}

// graphFingerprint is the state a refused write must leave unchanged.
func graphFingerprint(t *testing.T, s *Service) [3]int64 {
	t.Helper()
	return [3]int64{
		countAssetNodes(t, s),
		countRows(t, s, "MATCH ()-[r]->() RETURN count(r)"),
		countRows(t, s, "MATCH (n:Asset) WHERE n.score = 7 RETURN count(n)"),
	}
}

// TestExecCypher_EngineRefusesWrites is the engine-side half of read-only
// enforcement: execCypher is called directly, as if graphquery.IsReadOnly had
// been bypassed, and must still refuse every write the engine plans — before
// executing it. The digit-glued keywords are the shape that once slipped past
// the guard's \b boundary.
func TestExecCypher_EngineRefusesWrites(t *testing.T) {
	writes := []string{
		"MATCH (n:Asset) WHERE 1=1SET n.score=0 RETURN n",
		"MATCH ()-[r]->() WHERE 1=1DELETE r",
		"MATCH (n:Asset) DETACH DELETE n",
		"CREATE (:Asset {id:'evil'})",
		"MERGE (:Asset {id:'evil'})",
	}
	for _, q := range writes {
		t.Run(q, func(t *testing.T) {
			s, _ := openSeededGraph(t)
			before := graphFingerprint(t, s)
			err := s.withCypher(context.Background(), func(conn *ladybug.Connection) error {
				_, e := execCypher(conn, q, DefaultBudget)
				return e
			})
			require.ErrorIs(t, err, ErrReadOnly)
			var rej *explore.QueryRejection
			require.ErrorAs(t, err, &rej, "an engine refusal is the caller's 400, like the guard's")
			require.Equal(t, before, graphFingerprint(t, s), "a refused query must not have written")
		})
	}
}

// TestRunCypherBudget_DigitGluedWritesWriteNothing runs the guard-bypass shapes
// end to end against real liblbug: refused, and the graph left unchanged.
func TestRunCypherBudget_DigitGluedWritesWriteNothing(t *testing.T) {
	s, _ := openSeededGraph(t)
	before := graphFingerprint(t, s)
	for _, q := range []string{
		"MATCH (n:Asset) WHERE 1=1SET n.score=0 RETURN n",
		"MATCH ()-[r]->() WHERE 1=1DELETE r",
		"MATCH (n:Asset) WITH n LIMIT 1CREATE (:Asset {id:'evil'})",
	} {
		_, err := s.RunCypherBudget(context.Background(), q, QueryBudget{})
		require.ErrorIs(t, err, ErrReadOnly, q)
	}
	require.Equal(t, before, graphFingerprint(t, s))
}

// TestRunCypherBudget_ReadsStillRunThroughEngineCheck pins that preparing and
// checking every query does not refuse ordinary reads.
func TestRunCypherBudget_ReadsStillRunThroughEngineCheck(t *testing.T) {
	s, _ := openSeededGraph(t)
	tests := []struct {
		query string
		nodes int
		rows  int
	}{
		{"MATCH (n:Asset) RETURN n", 2, 0},
		{"MATCH (a:Asset {id:'a1'})-[*1..2]->(b) RETURN b", 1, 0},
		{"MATCH (n:Asset {id:'a1'}) RETURN label(n) AS l", 0, 1},
		{"MATCH (n:Asset {id:'a1'}) RETURN n.id AS id UNION MATCH (m:Asset {id:'internet'}) RETURN m.id AS id", 0, 2},
		{"MATCH (n:Asset) RETURN count(n) AS c", 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			res, err := s.RunCypherBudget(context.Background(), tt.query, QueryBudget{})
			require.NoError(t, err)
			require.Len(t, res.Nodes, tt.nodes)
			require.Len(t, res.Rows, tt.rows)
		})
	}
}
