package ladybug

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDriver drives the database/sql driver end to end: DDL and inserts through
// ExecContext, then a plain and a named-parameter read through QueryContext.
func TestDriver(t *testing.T) {
	ctx := nextContext()
	dbPath := strings.ReplaceAll(getDatabasePath(t), "\\", "/")
	cc, err := sql.Open(Name, fmt.Sprintf("ladybug://%s", dbPath))
	require.NoError(t, err)
	defer closeQuiet(cc)

	for _, expr := range []string{
		"CREATE NODE TABLE User(name STRING, age INT64, PRIMARY KEY (name))",
		"CREATE REL TABLE Follows(FROM User TO User, since INT64)",
		"CREATE (:User {name: 'Adam', age: 30})",
		"CREATE (:User {name: 'Karissa', age: 40})",
		"MATCH (a:User {name: 'Adam'}), (b:User {name: 'Karissa'}) CREATE (a)-[:Follows {since: 2020}]->(b)",
	} {
		_, err := cc.ExecContext(ctx, expr)
		require.NoError(t, err, expr)
	}

	query := func(q string, args ...any) [][]string {
		rows, err := cc.QueryContext(ctx, q, args...)
		require.NoError(t, err, q)
		defer closeQuiet(rows)
		cols, err := rows.Columns()
		require.NoError(t, err)
		var out [][]string
		for rows.Next() {
			set := make([]any, len(cols))
			for i := range set {
				set[i] = new(sql.NullString)
			}
			require.NoError(t, rows.Scan(set...))
			row := make([]string, len(cols))
			for i, v := range set {
				row[i] = v.(*sql.NullString).String
			}
			out = append(out, row)
		}
		require.NoError(t, rows.Err())
		return out
	}

	require.Equal(t, [][]string{{"Adam", "2020", "Karissa"}},
		query("MATCH (a:User)-[e:Follows]->(b:User) RETURN a.name, e.since, b.name"))
	require.Equal(t, [][]string{{"30"}},
		query("MATCH (a:User) WHERE a.name = $name RETURN a.age", sql.Named("name", "Adam")))
}
