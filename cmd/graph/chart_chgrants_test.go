package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// sqlUse is one statement in the code that needs a ClickHouse privilege beyond
// SELECT and INSERT on the graph database.
type sqlUse struct {
	file, kind, table string
	text              string // the statement, for the failure message
}

func (u sqlUse) key() sqlUse { return sqlUse{file: u.file, kind: u.kind, table: u.table} }

// The statement kinds that need a privilege beyond SELECT and INSERT. They run
// on every string in the code, with the parts of a + concatenation joined and
// anything that is not a literal read as %s, and whitespace (multi-line raw
// strings) collapsed. The verbs that start a statement match only there (the
// string's start, after a ';' or after a leading %s), and the ones with prose
// twins in check and remediation text (CREATE, DROP, GRANT, RESTORE, ...) only
// in upper case, the way the code writes SQL; the reads, table functions and
// dictionary functions match anywhere. Each captures the table it acts on where there is one. A
// statement assembled with strings.Builder or strings.Join, or whose verb is
// itself a %s, is not seen: keep each statement's verb and table in a literal.
var (
	chAlterRe      = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+(\S+)\s+(\w+)`)
	chDeleteRe     = regexp.MustCompile(`(?i)^DELETE\s+FROM\s+(\S+)`)
	chUpdateRe     = regexp.MustCompile(`(?i)^UPDATE\s+(\S+)\s+SET\b`)
	chOptimizeRe   = regexp.MustCompile(`(?i)^OPTIMIZE\s+TABLE\s+(\S+)`)
	chSystemReadRe = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+system\.(\w+)`)
	chOtherRe      = []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"DDL", regexp.MustCompile(`^(?:CREATE|DROP|ATTACH|DETACH|RENAME|EXCHANGE|UNDROP)\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?` +
			`(?:TABLES?|DATABASES?|VIEW|MATERIALIZED|LIVE|WINDOW|DICTIONARY|FUNCTION|USER|ROLE|ROW|POLICY|QUOTA|SETTINGS|PROFILE|INDEX|NAMED|IF)\b`)},
		{"TRUNCATE", regexp.MustCompile(`^TRUNCATE\s+[\w.%\x60]`)},
		{"SYSTEM", regexp.MustCompile(`^SYSTEM\s+(?:FLUSH|DROP|RELOAD|SHUTDOWN|KILL|STOP|START|SYNC|RESTART|RESTORE|FREEZE|UNFREEZE|WAIT|ENABLE|DISABLE|PREWARM|UNLOAD|LOAD|REFRESH|CANCEL|CLEAR|NOTIFY|JEMALLOC)\b`)},
		{"KILL", regexp.MustCompile(`^KILL\s+(?:QUERY|MUTATION)\b`)},
		{"BACKUP", regexp.MustCompile(`^(?:BACKUP|RESTORE)\s+(?:TABLE|DATABASE|DICTIONARY|VIEW|TEMPORARY|ALL)\b`)},
		{"GRANT", regexp.MustCompile(`^(?:(?:GRANT|REVOKE)\s+[\w ,()*]+\s+ON\s+\S+\s+(?:TO|FROM)|SET\s+(?:DEFAULT\s+)?ROLE)\s`)},
	}
	// A table function: FROM, JOIN (but not ARRAY JOIN, which takes an
	// expression) or INSERT INTO FUNCTION, then a name and its parenthesis.
	chTableFuncRe = regexp.MustCompile(`(ARRAY\s+)?\b(?:FROM|JOIN|INSERT\s+INTO\s+FUNCTION)\s+[a-zA-Z_]\w*\(`)
	// A dictionary read, which needs dictGet on the dictionary.
	chDictGetRe = regexp.MustCompile(`\bdict(?:Get\w*|Has|IsIn)\s*\(`)
	sqlSpace    = regexp.MustCompile(`\s+`)
)

// chExternalTablePkg is clickhouse-go's external-table package: a query that
// sends one needs CREATE TEMPORARY TABLE.
const chExternalTablePkg = "github.com/ClickHouse/clickhouse-go/v2/ext"

// notClickHouse are the files whose matches are not ClickHouse statements,
// with why. Matches in a file that imports pgx (and not clickhouse-go), or in
// sqlc's output, are Postgres and need no entry: there only the kinds Postgres
// has no syntax for (ALTER TABLE ... DELETE or UPDATE, OPTIMIZE) count.
var notClickHouse = map[string]string{
	"internal/app/graphstore/schema.go": "Ladybug's Cypher DDL for the in-memory graph",
	"internal/migrate/scanner.go":       "the scanner role's Postgres grants (database/sql with the pgx driver)",
}

// dynamicTables are the statements whose table is filled in at run time, with
// the tables it can be.
var dynamicTables = map[sqlUse][]string{
	{file: "internal/app/asset/optimize.go", kind: "OPTIMIZE", table: "%s"}: asset.OptimizableTables,
}

// codeSQLUses walks the Go code (tests excluded) and returns every use of a
// privileged statement kind outside Postgres code, and the system tables it
// reads.
func codeSQLUses(t *testing.T) []sqlUse {
	t.Helper()
	var uses []sqlUse
	for _, dir := range []string{"../../internal", "../../cmd", "../../pkg"} {
		require.NoError(t, filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			require.NoError(t, err)
			rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
			pg := f.Name.Name == "sqlcgen"
			ch := false
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				switch {
				case p == chExternalTablePkg:
					uses = append(uses, sqlUse{file: rel, kind: "external table"})
				case strings.HasPrefix(p, "github.com/ClickHouse/clickhouse-go/"):
					ch = true
				case strings.HasPrefix(p, "github.com/jackc/pgx/"):
					pg = true
				}
			}
			postgres := pg && !ch
			for _, s := range fileStrings(f) {
				uses = append(uses, statementUses(rel, s, postgres)...)
			}
			return nil
		}))
	}
	return uses
}

// fileStrings returns the file's string literals, a + concatenation of them
// as one string with every operand that is not a literal read as %s.
func fileStrings(f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if n.Op != token.ADD {
				return true
			}
			var b strings.Builder
			if concat(&b, n) {
				out = append(out, b.String())
				return false
			}
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				if s, err := strconv.Unquote(n.Value); err == nil {
					out = append(out, s)
				}
			}
		}
		return true
	})
	return out
}

// concat writes e's operands to b and reports whether any was a string literal.
func concat(b *strings.Builder, e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			l := concat(b, e.X)
			r := concat(b, e.Y)
			return l || r
		}
	case *ast.ParenExpr:
		return concat(b, e.X)
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if s, err := strconv.Unquote(e.Value); err == nil {
				b.WriteString(s)
				return true
			}
		}
	}
	b.WriteString("%s")
	return false
}

// statementUses returns the privileged statement kinds in s. In Postgres code
// only the kinds Postgres has no syntax for count.
func statementUses(file, s string, postgres bool) []sqlUse {
	s = sqlSpace.ReplaceAllString(s, " ")
	var out []sqlUse
	add := func(kind, table string) {
		table = strings.TrimPrefix(strings.Trim(table, "`\"();,"), "graph.")
		if strings.Contains(table, "%") {
			table = "%s"
		}
		out = append(out, sqlUse{file: file, kind: kind, table: table, text: s})
	}
	for _, m := range chSystemReadRe.FindAllStringSubmatch(s, -1) {
		add("SELECT", "system."+m[1])
	}
	if !postgres {
		for _, m := range chTableFuncRe.FindAllStringSubmatch(s, -1) {
			if m[1] == "" {
				add("table function", "")
			}
		}
		if chDictGetRe.MatchString(s) {
			add("dictGet", "")
		}
	}
	for _, stmt := range strings.Split(s, ";") {
		stmt = strings.TrimSpace(stmt)
		for strings.HasPrefix(stmt, "%s") {
			stmt = strings.TrimSpace(stmt[2:])
		}
		if m := chAlterRe.FindStringSubmatch(stmt); m != nil {
			switch verb := strings.ToUpper(m[2]); {
			case verb == "DELETE" || verb == "UPDATE":
				add("ALTER "+verb, m[1])
			case !postgres:
				add("DDL", m[1])
			}
		}
		if m := chOptimizeRe.FindStringSubmatch(stmt); m != nil {
			add("OPTIMIZE", m[1])
		}
		if postgres {
			continue
		}
		if m := chDeleteRe.FindStringSubmatch(stmt); m != nil {
			add("ALTER DELETE", m[1])
		}
		if m := chUpdateRe.FindStringSubmatch(stmt); m != nil {
			add("ALTER UPDATE", m[1])
		}
		for _, o := range chOtherRe {
			if o.re.MatchString(stmt) {
				add(o.kind, "")
			}
		}
	}
	return out
}

// migrationTables returns the tables every migration in migrations/<dir>
// creates.
func migrationTables(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("../../migrations/" + dir + "/*.sql")
	require.NoError(t, err)
	out := map[string]bool{}
	for _, f := range files {
		for _, m := range regexp.MustCompile(`(?m)^CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)`).FindAllStringSubmatch(readRepoFile(t, f), -1) {
			out[m[1]] = true
		}
	}
	require.NotEmpty(t, out, dir)
	return out
}

// The ClickHouse app user holds exactly the privileges the code uses: rows on
// the graph database, and for every other statement kind the code runs, the
// privilege it needs on the tables it names. A kind with no grant to map to
// (DDL, TRUNCATE, SYSTEM, BACKUP or RESTORE, a table function such as
// dictionary(), a dictGet, an external table) fails here
// unless its file is in notClickHouse, and a statement whose table is built at
// run time fails unless dynamicTables says which tables it can be. A grant
// beyond them (DDL, ALL, any ALTER on audit_events) fails too.
func TestClickHouseAppGrantsMatchTheCode(t *testing.T) {
	u := readCHUsers(t)
	got := map[string][]string{}
	for _, g := range u.Users.App.Grants {
		m := chGrant.FindStringSubmatch(g)
		require.NotNil(t, m, "unparsed grant %q", g)
		for _, priv := range strings.Split(m[1], ",") {
			priv = strings.TrimSpace(priv)
			require.NotContains(t, []string{"ALL", "ALTER", "CREATE", "DROP", "TRUNCATE"}, priv, "the app user must not hold %s", priv)
			got[priv] = append(got[priv], m[2]+"."+m[3])
		}
		require.NotEqual(t, "audit_events", m[3], "the app user may only insert and read audit_events, through graph.*")
	}

	uses := codeSQLUses(t)
	pgTables, chTables := migrationTables(t, "postgres"), migrationTables(t, "clickhouse")
	want := map[string][]string{"SELECT": {"graph.*"}, "INSERT": {"graph.*"}}
	seen := map[string]bool{}
	var seenOptimize, seenDelete bool
	var unmapped []string
	exempted := map[string]bool{}
	for _, use := range uses {
		if _, ok := notClickHouse[use.file]; ok {
			exempted[use.file] = true
			continue
		}
		if pgTables[use.table] && !chTables[use.table] {
			continue // Postgres, in a file that uses both
		}
		var tables []string
		switch use.kind {
		case "ALTER DELETE", "ALTER UPDATE", "OPTIMIZE":
			tables = []string{use.table}
			if use.table == "%s" {
				dynamic, ok := dynamicTables[use.key()]
				require.True(t, ok, "%s runs %s on a table built at run time: list the tables it can be in dynamicTables", use.file, use.kind)
				tables = slices.Clone(dynamic)
			}
			seenOptimize = seenOptimize || use.kind == "OPTIMIZE"
			seenDelete = seenDelete || use.kind == "ALTER DELETE"
			for i := range tables {
				tables[i] = "graph." + tables[i]
			}
		case "SELECT":
			tables = []string{use.table}
		default:
			unmapped = append(unmapped, use.file+": "+use.kind+": "+use.text)
			continue
		}
		for _, table := range tables {
			if !seen[use.kind+" "+table] {
				seen[use.kind+" "+table] = true
				want[use.kind] = append(want[use.kind], table)
			}
		}
	}
	require.Empty(t, unmapped, "statements the app user has no grant for: if one is ClickHouse, the code must not run it as graph; "+
		"if it is not, add its file to notClickHouse with why")
	require.True(t, seenDelete && seenOptimize, "the walk found no ALTER TABLE ... DELETE or OPTIMIZE: the scan is broken")
	for k := range want {
		slices.Sort(want[k])
	}
	for k := range got {
		slices.Sort(got[k])
	}
	require.Equal(t, want, got)
	for file := range notClickHouse {
		require.True(t, exempted[file], "stale notClickHouse entry %s: nothing in it matches", file)
	}
	keys := make([]sqlUse, len(uses))
	for i, use := range uses {
		keys[i] = use.key()
	}
	for use := range maps.Keys(dynamicTables) {
		require.Contains(t, keys, use, "stale dynamicTables entry")
	}
}

// The statement scan finds a kind wherever the code writes it: a
// Sprintf'd table, a multi-line raw string, a concatenation, a lightweight
// DELETE or UPDATE, and the kinds no grant covers.
func TestStatementUsesFindsEveryForm(t *testing.T) {
	for _, tc := range []struct {
		src      string
		postgres bool
		want     []sqlUse
	}{
		{src: "ALTER TABLE %s DELETE WHERE id = ?", want: []sqlUse{{file: "f", kind: "ALTER DELETE", table: "%s"}}},
		{src: "ALTER TABLE\n\t\tfindings\n\t\tUPDATE x = 1 WHERE id = ?", want: []sqlUse{{file: "f", kind: "ALTER UPDATE", table: "findings"}}},
		{src: "DELETE FROM graph.assets WHERE id = ?", want: []sqlUse{{file: "f", kind: "ALTER DELETE", table: "assets"}}},
		{src: "UPDATE signals SET x = 1 WHERE id = ?", want: []sqlUse{{file: "f", kind: "ALTER UPDATE", table: "signals"}}},
		{src: "OPTIMIZE TABLE `beliefs` FINAL", want: []sqlUse{{file: "f", kind: "OPTIMIZE", table: "beliefs"}}},
		{src: "SELECT sum(rows) FROM system.parts WHERE table = ?", want: []sqlUse{{file: "f", kind: "SELECT", table: "system.parts"}}},
		{src: "CREATE TEMPORARY TABLE t (a UInt8)", want: []sqlUse{{file: "f", kind: "DDL", table: ""}}},
		{src: "ALTER TABLE assets ADD COLUMN x UInt8", want: []sqlUse{{file: "f", kind: "DDL", table: "assets"}}},
		{src: "TRUNCATE TABLE signals", want: []sqlUse{{file: "f", kind: "TRUNCATE", table: ""}}},
		{src: "SYSTEM FLUSH LOGS", want: []sqlUse{{file: "f", kind: "SYSTEM", table: ""}}},
		{src: "KILL QUERY WHERE 1", want: []sqlUse{{file: "f", kind: "KILL", table: ""}}},
		{src: "SELECT * FROM url('http://x', 'CSV')", want: []sqlUse{{file: "f", kind: "table function", table: ""}}},
		{src: "INSERT INTO FUNCTION s3('x') SELECT 1", want: []sqlUse{{file: "f", kind: "table function", table: ""}}},
		{src: "DELETE FROM sessions WHERE id = $1", postgres: true},
		{src: "SELECT * FROM unnest($1::text[])", postgres: true},
		{src: "SELECT k FROM assets ARRAY JOIN JSONExtractKeys(metadata) AS k"},
		{src: "loaded from snapshot (skipped ClickHouse read)"},
		{src: "ALTER TABLE x DELETE WHERE 1", postgres: true, want: []sqlUse{{file: "f", kind: "ALTER DELETE", table: "x"}}},
		{src: "SELECT id FROM findings WHERE id IN (%s)"},
		{src: "LoginOAuth: invalid auto-create role %q"},
		{src: "create api key failed"},
		{src: "revoke sessions"},
		{src: "GRANT SELECT ON graph.* TO someone", want: []sqlUse{{file: "f", kind: "GRANT", table: ""}}},
		{src: "TRUNCATE signals", want: []sqlUse{{file: "f", kind: "TRUNCATE", table: ""}}},
		{src: "DROP TABLE IF EXISTS x", want: []sqlUse{{file: "f", kind: "DDL", table: ""}}},
		{src: "SELECT 1; DROP TABLE findings", want: []sqlUse{{file: "f", kind: "DDL", table: ""}}},
		{src: "%s DELETE FROM findings WHERE 1", want: []sqlUse{{file: "f", kind: "ALTER DELETE", table: "findings"}}},
		{src: "BACKUP TABLE graph.findings TO Disk('backups', 'f.zip')", want: []sqlUse{{file: "f", kind: "BACKUP", table: ""}}},
		{src: "RESTORE DATABASE graph FROM Disk('backups', 'f.zip')", want: []sqlUse{
			{file: "f", kind: "table function", table: ""}, {file: "f", kind: "BACKUP", table: ""},
		}},
		{src: "SELECT dictGetString('graph.d', 'name', toUInt64(1))", want: []sqlUse{{file: "f", kind: "dictGet", table: ""}}},
		{src: "SELECT 1 WHERE dictHas('graph.d', 1)", want: []sqlUse{{file: "f", kind: "dictGet", table: ""}}},
		{src: "SELECT * FROM dictionary('graph.d')", want: []sqlUse{{file: "f", kind: "table function", table: ""}}},
		{src: "restore the backup table from the last snapshot"},
		{src: "SELECT dictGet('d', 'x', 1)", postgres: true},
	} {
		var got []sqlUse
		for _, u := range statementUses("f", tc.src, tc.postgres) {
			got = append(got, u.key())
		}
		require.Equal(t, tc.want, got, tc.src)
	}

	f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package x
const q = "ALTER TABLE " + table + " DELETE WHERE " + cond`, 0)
	require.NoError(t, err)
	require.Contains(t, fileStrings(f), "ALTER TABLE %s DELETE WHERE %s")
}
