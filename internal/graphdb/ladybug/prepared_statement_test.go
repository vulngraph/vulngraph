package ladybug

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreparedStatementIsReadOnly(t *testing.T) {
	conn := bareConn(t)
	res, err := conn.Query("CREATE NODE TABLE N(id STRING, x INT64, PRIMARY KEY(id))")
	require.NoError(t, err)
	res.Close()
	res, err = conn.Query("CREATE REL TABLE R(FROM N TO N)")
	require.NoError(t, err)
	res.Close()

	tests := []struct {
		query    string
		readOnly bool
	}{
		{"MATCH (n:N) RETURN n", true},
		{"MATCH (a:N)-[*1..3]->(b:N) RETURN b", true},
		{"MATCH (n) RETURN label(n)", true},
		{"MATCH (n:N) RETURN n.id UNION MATCH (m:N) RETURN m.id", true},
		{"RETURN 1", true},
		{"CREATE (:N {id: 'a'})", false},
		{"MERGE (:N {id: 'a'})", false},
		{"MATCH (n:N) WHERE 1=1SET n.x = 0 RETURN n", false},
		{"MATCH ()-[r]->() WHERE 1=1DELETE r", false},
		{"MATCH (n:N) DETACH DELETE n", false},
		{"DROP TABLE R", false},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			stmt, err := conn.Prepare(tt.query)
			require.NoError(t, err)
			defer stmt.Close()
			require.Equal(t, tt.readOnly, stmt.IsReadOnly())
		})
	}
}
