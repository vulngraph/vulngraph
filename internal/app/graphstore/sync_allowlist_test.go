package graphstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestSyncEdgeTypesAreMapped locks the three edge allowlists together: every
// edge_type that asset.AllEdgesForSync loads from ClickHouse (asset.SyncEdgeTypes)
// must resolve to a known rel table (edgeTypeToRel) that has an UNWIND insert
// template (edgeUnwindQ). Without this, a type added to the SQL filter but missing
// a graphstore mapping is fetched into memory and then silently dropped in
// bulkSync — for a security graph that means missing edges and missing attack
// paths, with no error. This test fails the moment the allowlists drift.
func TestSyncEdgeTypesAreMapped(t *testing.T) {
	for _, edgeType := range asset.SyncEdgeTypes {
		rel, known := RelTableFor(edgeType)
		if !known {
			t.Errorf("edge_type %q is loaded for sync but has no edgeTypeToRel mapping — "+
				"it falls back to the generic Edge table, which has no insert template and "+
				"is silently dropped in bulkSync", edgeType)
			continue
		}
		if _, ok := edgeUnwindQ[rel]; !ok {
			t.Errorf("edge_type %q maps to rel table %q, but edgeUnwindQ has no UNWIND "+
				"template for it — edges of this type are silently dropped in bulkSync",
				edgeType, rel)
		}
	}
}

// TestNamedQueryRelsAreFedBySync closes the gap that let connected_via_sg be
// referenced by 7 named queries yet never loaded: a rel can be in ladybugRelSpec
// (so it "exists" in Ladybug) while NO edge_type in asset.SyncEdgeTypes actually
// fetches edges for it — the query then silently returns empty (positive match)
// or over-reports (negation). Every rel a named query traverses must be fed by a
// synced edge_type, unless it's a documented known-gap.
func TestNamedQueryRelsAreFedBySync(t *testing.T) {
	// Rels loaded into Ladybug by at least one synced edge_type.
	fed := map[string]bool{}
	for _, et := range asset.SyncEdgeTypes {
		if rel, ok := RelTableFor(et); ok {
			fed[rel] = true
		}
	}
	// Conditional reroutes in buildEdgeRows feed these rels from a synced edge_type
	// whose REGISTRY default maps elsewhere (RelTableFor only sees the default) —
	// same list as graphschema_test.go's TestRegistryConsistency fedRels, MINUS
	// DeploysToService: that reroute exists in code but no deploys_to_service
	// edges exist in ClickHouse in practice, so it stays a documented knownUnfed
	// gap below rather than being marked fed here.
	for _, rerouted := range []string{"RunsIn", "ExecutesAsK8sWorkload", "DefinedInK8sWorkload", "DefinedInAsset", "DefinedInIamRole", "AccessesK8sWorkload", "RunsImageAsset"} {
		fed[rerouted] = true
	}
	// knownUnfed: rel tables named queries reference that nothing currently feeds.
	// These are latent same-class bugs tracked separately — NOT license to add more.
	// DeploysToService (Repo→Asset) has no edge_type mapping and no deploys_to_service
	// edges exist in ClickHouse, so the LB "no IaC owner" negations over-report.
	knownUnfed := map[string]bool{"DeploysToService": true}

	for rel := range namedQueryRelTables(t) {
		if fed[rel] || knownUnfed[rel] {
			continue
		}
		t.Errorf("named query traverses rel %q but no asset.SyncEdgeTypes entry feeds it — "+
			"the query silently returns empty; add the edge_type to the sync allowlist "+
			"or fix the query", rel)
	}
}

// TestUnwindQTablesExistInDDL catches the RunsImage class of bug: a rel table
// appears in edgeUnwindQ (and thus edgeTypeToRel) but the CREATE REL TABLE
// statement is missing from schemaDDL. At runtime Ladybug throws a binder error
// "Table X does not exist" and silently drops all edges of that type.
func TestUnwindQTablesExistInDDL(t *testing.T) {
	for relTable := range edgeUnwindQ {
		if !strings.Contains(schemaDDL, "CREATE REL TABLE IF NOT EXISTS "+relTable+"(") {
			t.Errorf("edgeUnwindQ has rel table %q but schemaDDL has no CREATE REL TABLE for it — "+
				"Ladybug will throw a binder error at runtime and silently drop all edges of this type",
				relTable)
		}
	}
}

// TestNeighborRelsMatchSchema ensures every rel label that neighbors traverses
// (and the literal endpoint labels it pairs them with) actually exists in the Ladybug
// schema. neighbors emits these as literal Cypher, so a rel renamed/removed in
// schemaDDL would only surface as a prepare error at runtime on /api/graph/expand —
// this catches it at build time instead.
func TestNeighborRelsMatchSchema(t *testing.T) {
	for _, rs := range neighborRels {
		// quoteLabel backtick-escapes "Group" to match the actual
		// schemaDDL text — Ladybug's Cypher parser rejects the keyword bare.
		decl := fmt.Sprintf("CREATE REL TABLE IF NOT EXISTS %s(FROM %s TO %s", rs.label, quoteLabel(rs.from), quoteLabel(rs.to))
		if !strings.Contains(schemaDDL, decl) {
			t.Errorf("neighborRels %q (%s→%s) has no matching REL TABLE in schemaDDL: want %q",
				rs.label, rs.from, rs.to, decl)
		}
	}
}
