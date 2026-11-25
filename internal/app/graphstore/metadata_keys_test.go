package graphstore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectMetadataKeys returns every metadata key the package's real code indexes,
// mapped to the file that does it.
//
// Parsed as an AST rather than grepped: the first version of this guard used a regex
// and immediately reported a false positive on domain.go, which discusses
// Metadata["exec_role"] in a doc comment describing a correlate rule. A guard that
// fires on prose gets neutered by whoever hits it next, so it reads declarations.
//
// Two receiver shapes count, because the thirteen keys are split across them:
//
//	a.Metadata["x"]  — the loader indexing the asset directly (node_rows.go)
//	meta["x"]        — the helpers that take the map as a parameter
//	                   (assetEncrypted, assetPublic, assetPublicTier, appendCertValues)
//
// Deriving from only the first form would miss five keys and silently blank every
// DSPM encryption and public-exposure signal in the graph.
func collectMetadataKeys(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		require.NoError(t, parseErr, "parsing %s", name)
		ast.Inspect(file, func(n ast.Node) bool {
			ix, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			lit, ok := ix.Index.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			isMeta := false
			switch x := ix.X.(type) {
			case *ast.SelectorExpr: // a.Metadata["x"]
				isMeta = x.Sel.Name == "Metadata"
			case *ast.Ident: // meta["x"] inside the helpers
				isMeta = x.Name == "meta"
			}
			if !isMeta {
				return true
			}
			key, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if _, seen := found[key]; !seen {
				found[key] = name
			}
			return true
		})
	}
	return found
}

// TestSyncMetadataKeysCoverNodeLoader pins SyncMetadataKeys to what the package
// actually reads.
//
// This guard is the reason the projection is safe to do at all. An under-declared key
// does not error — the loader reads "" and writes a zero into the graph column, so a
// missing "storage_encrypted" would silently mark every RDS instance unencrypted and
// a missing "trust_entry" would blank the identity trust node. That is exactly how the
// label-promotion drops and the identity-suppression bug stayed invisible: a
// wrong answer, produced confidently, with nothing failing anywhere.
//
// Equality is asserted in BOTH directions. A key declared but no longer read is also a
// failure: it means the projection still pays to decode something dead, which is the
// cost this registry exists to remove.
func TestSyncMetadataKeysCoverNodeLoader(t *testing.T) {
	used := collectMetadataKeys(t)
	require.NotEmpty(t, used, "found no metadata reads at all — the AST walk stopped matching, "+
		"which would leave this guard vacuously green while the projection silently rots")

	wantKeys := make([]string, 0, len(used))
	for k := range used {
		wantKeys = append(wantKeys, k)
	}
	sort.Strings(wantKeys)

	declared := append([]string(nil), SyncMetadataKeys...)
	require.True(t, sort.StringsAreSorted(declared),
		"SyncMetadataKeys must stay sorted so this comparison is stable")

	for _, k := range wantKeys {
		require.Contains(t, declared, k,
			"%s reads Metadata[%q] but SyncMetadataKeys does not declare it. The bulk sync asks "+
				"ClickHouse for only the declared keys, so this read gets \"\" at runtime and "+
				"writes a zero/empty value into the graph — silently. Add it to the registry.", used[k], k)
	}
	for _, k := range declared {
		require.Contains(t, wantKeys, k,
			"SyncMetadataKeys declares %q but nothing in the package reads it. Remove it — the "+
				"projection exists to stop decoding keys the loader does not use.", k)
	}
}

// TestGraphstoreReadsNoAssetTags guards the SkipTags half of SyncProjection.
//
// The bulk sync asks asset readers to leave Tags nil, which is only safe while nothing
// in this package reads them. At large scale, retaining them costs hundreds of MB
// of LIVE heap (hundreds of bytes per asset across millions of entries) for data
// the loader never looks at, and with allocator retention that is closer to double that in
// RSS on a worker with a tight cgroup memory limit.
//
// The failure mode if someone adds a Tags read is silent and type-safe: a nil map reads
// as empty, so the new code compiles, runs, and produces a wrong-but-plausible answer
// on every asset. That is the same shape as the label-promotion drops and the
// RunsImage.image_ref empty column — which is why this is a source-level guard rather
// than a comment asking nicely.
func TestGraphstoreReadsNoAssetTags(t *testing.T) {
	require.True(t, SyncProjection().SkipTags,
		"the sync projection must skip Tags; if that changed deliberately, this guard and "+
			"the rationale in asset.SyncProjection need updating together")

	for key, file := range collectTagKeys(t) {
		t.Fatalf("%s reads Tags[%q], but the bulk sync leaves Tags nil (SyncProjection.SkipTags), "+
			"so it will read empty on every asset in the graph — silently. Either stop reading "+
			"Tags here, or set SkipTags=false and account for the heap it costs.", file, key)
	}
}

// collectTagKeys returns every asset-Tags read in the package's real code, mapped to the
// file doing it. AST-based for the same reason collectMetadataKeys is: an earlier
// regex version of that guard fired on a doc comment.
func collectTagKeys(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		require.NoError(t, parseErr, "parsing %s", name)
		ast.Inspect(file, func(n ast.Node) bool {
			// Both a.Tags["x"] and a bare a.Tags passed onward: either one means this
			// package depends on data the projection drops.
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Tags" {
				return true
			}
			found["Tags"] = name
			return true
		})
	}
	return found
}

// TestSyncEdgePropertyKeysCoverEveryReader pins the edge-property projection to what the
// package actually reads, in both directions.
//
// The bulk sync now narrows Edge.Properties, and a missing key does not error: the map
// read returns "" and the value silently becomes empty. For a rel column that is the
// RunsImage.image_ref bug (empty on every row). For the exposure tier it is
// worse — dropping public_access would flatten every graded exposure back to "possible"
// (assetPublicTier has no absent-tier-means-confirmed default, so the failure mode
// is silent DOWNgrading of confirmed exposure rather than silent upgrading; both are
// wrong answers about internet reachability).
func TestSyncEdgePropertyKeysCoverEveryReader(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range SyncEdgePropertyKeys() {
		declared[k] = true
	}

	// Every rel spec's rowKey must be present: those are the CSV property columns.
	for relTable, spec := range ladybugRelSpec {
		for _, p := range spec.prop {
			require.True(t, declared[p.rowKey],
				"rel %q declares property column %q (rowKey %q) but SyncEdgePropertyKeys does "+
					"not include it — the sync would drop the value and the column would load "+
					"empty on every row", relTable, p.col, p.rowKey)
		}
	}

	// Every literal Properties["x"] read in the package must be declared.
	for key, file := range collectEdgePropertyKeys(t) {
		require.True(t, declared[key],
			"%s reads Edge.Properties[%q] but the sync projection drops it, so it reads empty "+
				"at runtime — silently. Add it to SyncEdgePropertyKeys.", file, key)
	}

	// The via fallback chain and the exposure tier are read through identifiers rather
	// than literals in some paths, so assert them explicitly.
	for _, k := range []string{"via", "origin", "matched", asset.EdgePropPublicAccess} {
		require.True(t, declared[k], "%q must stay in the projection: %s", k,
			"via/origin/matched are edgeRowValue's fallback chain and public_access is the exposure tier")
	}
}

// collectEdgePropertyKeys returns every Edge.Properties["literal"] read in the package's
// real code. AST-based, for the same reason the metadata equivalent is.
func collectEdgePropertyKeys(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		switch name {
		case "metadata_keys.go":
			continue // the registry names keys in comments and in its own literal
		case "repo_cypher.go":
			// Marshals Cypher RESULTS — explore.Node/explore.Edge, whose Properties is
			// map[string]any — not asset.Edge.Properties. The AST cannot tell the two
			// receivers apart without full type information, and those reads have
			// nothing to do with what the sync projects.
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		require.NoError(t, parseErr, "parsing %s", name)
		ast.Inspect(file, func(n ast.Node) bool {
			ix, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			sel, ok := ix.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Properties" {
				return true
			}
			lit, ok := ix.Index.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true // identifier index (e.g. a rowKey variable) — covered above
			}
			if key, uerr := strconv.Unquote(lit.Value); uerr == nil {
				if _, seen := found[key]; !seen {
					found[key] = name
				}
			}
			return true
		})
	}
	return found
}
