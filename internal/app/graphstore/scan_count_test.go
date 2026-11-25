package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
)

// scanCount used to leave the count at 0 on a missing row or an unexpected
// type, so a failed read looked like an empty graph. Each failure must be an
// error, and only a real count — zero included — a value.
func TestScanCount(t *testing.T) {
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	for name, tc := range map[string]struct {
		query   string
		want    int64
		wantErr string
	}{
		"count of an empty table":  {query: `MATCH (n:Asset) RETURN count(n) AS c`, want: 0},
		"no row":                   {query: `MATCH (n:Asset) RETURN n.id AS c`, wantErr: "no row"},
		"count column is a string": {query: `RETURN 'x' AS c`, wantErr: "type string"},
		"no count column":          {query: `RETURN 1 AS d`, wantErr: "type <nil>"},
	} {
		t.Run(name, func(t *testing.T) {
			var n int64
			var cErr error
			require.NoError(t, svc.withRead(context.Background(), defaultQueryTimeout, func(conn *ladybug.Connection) error {
				res, qErr := conn.Query(tc.query)
				if qErr != nil {
					return qErr
				}
				defer res.Close()
				n, cErr = scanCount(res)
				return nil
			}))
			if tc.wantErr != "" {
				require.ErrorContains(t, cErr, tc.wantErr)
				return
			}
			require.NoError(t, cErr)
			require.Equal(t, tc.want, n)
		})
	}
}
