package correlate

import (
	"go/ast"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// scanFieldColumn maps each field scanAssets scans into to the ClickHouse column
// that must supply it. This is the ONLY hand-written part of the seam test: the
// SELECT order is read from the query consts and the Scan order is read from the
// source, so neither side can drift without this test noticing.
var scanFieldColumn = map[string]string{
	"ID":        "id",
	"Name":      "name",
	"Type":      "type",
	"AccountID": "account_id",
	"PublicIP":  "public_ip",
	"PrivateIP": "private_ip",
	"Domain":    "domain",
	"Tags":      "tags",
	"metaJSON":  "metadata",
}

// loadView must select every column scanAssets reads, in the same
// order. `name` was missing for months and nothing caught it: asset.Name was ""
// for EVERY asset in EVERY correlation Graph, which silently killed the rules
// that match on it (DeploysTo's compute-service branch is gated behind
// `if name != ""`). The rules' own tests build Graph by hand with Name set, so they could
// not see it — the gap was between the query and the scan, and only a test at
// that seam can catch it.
//
// Column ORDER matters as much as presence: a transposition corrupts every asset
// in every Graph, silently, because Scan is positional — swapping &a.Name and
// &a.Type compiles (both are string) and leaves every asset's Name holding its
// type. Asserting the SELECT order alone cannot see that; the Scan call itself
// has to be read.
//
// The Scan side is read from the AST rather than made data-driven in production:
// scanAssets runs per row over the whole correlation view (hundreds of thousands
// of rows), where a []any rebuilt per call allocates and gives up the
// compile-time type check positional Scan arguments provide. The production
// shape is right; the test is what has to be mechanical.
func TestCorrelateScanOrderMatchesSelectOrder(t *testing.T) {
	scanned := scanAssetsColumns(t)
	require.Equal(t, "tuple(name,type,account_id,public_ip,private_ip,domain,tags,", strings.Split(projectedCorrelationTuple, "\n")[0])
	require.Equal(t, []string{"id", "row.1 AS name", "row.2 AS type", "row.3 AS account_id", "row.4 AS public_ip", "row.5 AS private_ip", "row.6 AS domain", "row.7 AS tags", "row.8 AS metadata"}, projectedSelectItems(loadViewSource))
	require.Len(t, scanned, len(scanFieldColumn),
		"scanAssets scans a different number of values than scanFieldColumn maps — update the map")

	for _, q := range []struct{ name, sql string }{
		{"loadView", loadView},
	} {
		t.Run(q.name, func(t *testing.T) {
			require.Equal(t, selectColumns(q.sql), scanned,
				"%s selects columns in a different order than scanAssets scans them — "+
					"Scan is positional, so this silently corrupts every asset in every Graph", q.name)
		})
	}
}

// Seed fields are activation only; full metadata belongs to the later view.
func TestCorrelateSeedSelectMatchesScanOrder(t *testing.T) {
	require.Equal(t, []string{"id", "type", "account_id"}, selectColumns(loadByIDs))
	require.Equal(t, selectColumns(loadByIDs), scanFunctionColumns(t, "loadSeedPage"))
}

// selectColumns returns the column names a query's SELECT clause projects, in
// order, unwrapping the argMax(col, synced_at) aggregate form. The metadata
// column is no longer a bare argMax: it is wrapped in the server-side key
// projection (projectMetadataExpr), so that exact
// expression text — still one comma-balanced unit — is special-cased to the
// "metadata" column name rather than falling through to the argMax unwrap
// (which only handles a single unqualified column name as argMax's first
// argument, not a nested expression).
func selectColumns(query string) []string {
	clause := query[strings.Index(query, "SELECT")+len("SELECT") : strings.Index(query, "FROM")]

	var cols []string
	depth, start := 0, 0
	take := func(end int) {
		item := strings.TrimSpace(clause[start:end])
		if item == "" {
			return
		}
		if _, alias, ok := strings.Cut(item, " AS "); ok {
			item = alias
		}
		switch item {
		case projectMetadataExpr:
			item = "metadata"
		default:
			if rest, ok := strings.CutPrefix(item, "argMax("); ok {
				item, _, _ = strings.Cut(rest, ",")
			}
		}
		cols = append(cols, strings.TrimSpace(item))
	}
	for i, r := range clause {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				take(i)
				start = i + 1
			}
		}
	}
	take(len(clause))
	return cols
}

// scanAssetsColumns returns the columns scanAssets' rows.Scan call consumes, in
// argument order, by reading the source.
func scanAssetsColumns(t *testing.T) []string { return scanFunctionColumns(t, "scanCorrelationAsset") }
func scanFunctionColumns(t *testing.T, name string) []string {
	t.Helper()
	var cols []string
	found := false
	for _, f := range parsePackage(t) {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Scan" {
					return true
				}
				found = true
				for _, arg := range call.Args {
					name := scanTargetName(arg)
					col, ok := scanFieldColumn[name]
					require.True(t, ok,
						"scanAssets scans into %q, which scanFieldColumn does not map to a column", name)
					cols = append(cols, col)
				}
				return false
			})
		}
	}
	require.True(t, found, "no rows.Scan call found in scanAssets — the AST walk is broken")
	return cols
}

// scanTargetName names a Scan argument: &a.Name → "Name", &metaJSON → "metaJSON".
func scanTargetName(e ast.Expr) string {
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.Ident:
		return v.Name
	}
	return ""
}

// TestLoadViewProjectsAllReadMetadataKeys is the safety net the metadata-key
// projection calls for: loadView's metadata column is now a server-side KEY
// projection (metadataProjectedKeys in repo.go), so a rule that starts
// reading a Metadata["…"] key not in that list would silently get "" for
// every asset instead of a build failure or a runtime error — the exact
// silent-drop class this package's other AST guards
// (TestCorrelationTypesHasNoUnusedTypes and friends) exist to catch for
// asset types.
//
// This walks every non-test .go file in the package (parsePackage, shared
// with correlation_types_test.go) for `x.Metadata["literal"]` accesses and
// requires each literal key found to be in metadataProjectedKeys. Add the new
// key to metadataProjectedKeys FIRST, in the same commit as the rule change
// that starts reading it.
func TestLoadViewProjectsAllReadMetadataKeys(t *testing.T) {
	projected := make(map[string]bool, len(metadataProjectedKeys))
	for _, k := range metadataProjectedKeys {
		projected[k] = true
	}

	found := map[string]bool{}
	for _, f := range parsePackage(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			idx, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			sel, ok := idx.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Metadata" {
				return true
			}
			lit, ok := idx.Index.(*ast.BasicLit)
			if !ok {
				// A dynamic (non-literal) key can't be enumerated statically —
				// fail loudly rather than silently pass a case this guard
				// cannot actually check.
				t.Fatalf("Metadata[...] indexed with a non-literal key at a position this AST guard cannot verify — "+
					"add the key(s) it can read to metadataProjectedKeys by inspection and extend this test, or keep "+
					"the access literal: %#v", idx.Index)
				return true
			}
			key, err := strconv.Unquote(lit.Value)
			require.NoError(t, err, "malformed string literal in Metadata[...] index")
			found[key] = true
			return true
		})
	}
	require.NotEmpty(t, found, "no Metadata[\"...\"] reads found — the AST walk is broken")

	for key := range found {
		require.True(t, projected[key],
			"rule reads Metadata[%q] but that key is not in metadataProjectedKeys (repo.go) — "+
				"the server-side metadata projection would silently drop it; add it to the list", key)
	}
}

func projectedSelectItems(query string) []string {
	items := strings.Split(strings.TrimPrefix(strings.Split(query, "FROM")[0], "SELECT"), ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	return items
}
