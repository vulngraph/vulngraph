package graphstore

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
)

// These tests pin the query shapes the previous engine fork crashed or misanswered on
// (ADR 095) against the LadybugDB engine Vulngraph now links, on Vulngraph's real schema
// and loader. Each asserts the answer, not just the absence of a crash, so a
// LadybugDB upgrade that regresses one fails here instead of in production.

func loadShapesFixture(t *testing.T) *ladybug.Connection {
	t.Helper()
	assets, edges, sigs := copyFixture()
	_, wc := openTestDB(t)
	_, err := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), sigs, true, 4, nil)
	require.NoError(t, err)
	return wc
}

// denseFixture is a graph dense enough that the fork's variable-length paths
// died with std::length_error: n load balancers, each routing to fanout others.
func denseFixture(n, fanout int) ([]asset.Asset, []asset.Edge) {
	assets := make([]asset.Asset, n)
	var edges []asset.Edge
	for i := range n {
		assets[i] = asset.Asset{ID: fmt.Sprintf("lb-%d", i), Name: "lb", Type: "load_balancer", Provider: "aws"}
		for k := 1; k <= fanout; k++ {
			dst := (i*7 + k*13) % n
			edges = append(edges, asset.Edge{
				SrcID: assets[i].ID, SrcType: "load_balancer",
				DstID: fmt.Sprintf("lb-%d", dst), DstType: "load_balancer", EdgeType: "routes_to",
			})
		}
	}
	return assets, edges
}

// reachWithin is the reference answer: distinct nodes reachable from seed in
// 1..depth forward hops, excluding seed unless a cycle returns to it.
func reachWithin(edges []asset.Edge, seed string, depth int) int {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.SrcID] = append(adj[e.SrcID], e.DstID)
	}
	seen := map[string]bool{}
	frontier := []string{seed}
	for range depth {
		var next []string
		for _, id := range frontier {
			for _, dst := range adj[id] {
				if !seen[dst] {
					seen[dst] = true
					next = append(next, dst)
				}
			}
		}
		frontier = next
	}
	return len(seen)
}

func rows(t *testing.T, res *ladybug.QueryResult) [][]any {
	t.Helper()
	defer res.Close()
	var out [][]any
	for res.HasNext() {
		tup, err := res.Next()
		require.NoError(t, err)
		vals, err := tup.GetAsSlice()
		require.NoError(t, err)
		out = append(out, vals)
	}
	return out
}

func queryRows(t *testing.T, conn *ladybug.Connection, q string) [][]any {
	t.Helper()
	res, err := conn.Query(q)
	require.NoError(t, err, q)
	return rows(t, res)
}

func TestEngineShapes_VariableLengthPathOnDenseGraph(t *testing.T) {
	assets, edges := denseFixture(20000, 8)
	_, wc := openTestDB(t)
	_, err := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), nil, true, 4, nil)
	require.NoError(t, err)

	for _, depth := range []int{2, 4} {
		q := fmt.Sprintf(`MATCH (a:Asset {id: 'lb-1'})-[:Accesses*1..%d]->(b:Asset) RETURN count(DISTINCT b)`, depth)
		require.Equal(t, int64(reachWithin(edges, "lb-1", depth)), countQuery(t, wc, q), q)
	}
}

func TestEngineShapes_CypherPoolCapsPathDepth(t *testing.T) {
	assets, edges := denseFixture(2000, 4)
	db, wc := openTestDB(t)
	_, err := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), nil, true, 4, nil)
	require.NoError(t, err)

	cypher := func(q string) ([][]any, error) {
		var out [][]any
		err := db.withCypher(context.Background(), 10*time.Second, func(conn *ladybug.Connection) error {
			res, err := conn.Query(q)
			if err != nil {
				return err
			}
			out = rows(t, res)
			return nil
		})
		return out, err
	}

	_, err = cypher(`MATCH (a:Asset {id: 'lb-1'})-[:Accesses*1..20]->(b:Asset) RETURN count(DISTINCT b)`)
	require.ErrorContains(t, err, "exceeds maximum")

	got, err := cypher(`MATCH (a:Asset {id: 'lb-1'})-[:Accesses*]->(b:Asset) RETURN count(DISTINCT b)`)
	require.NoError(t, err)
	require.EqualValues(t, reachWithin(edges, "lb-1", cypherMaxPathDepth), got[0][0])
}

func TestEngineShapes_LabelFunction(t *testing.T) {
	wc := loadShapesFixture(t)
	got := queryRows(t, wc, `MATCH (a:Asset {id: 'lb-1'})-[r:HasRole]->(b:IamRole) RETURN label(a), label(r), label(b)`)
	require.Equal(t, [][]any{{"Asset", "HasRole", "IamRole"}}, got)
}

func TestEngineShapes_UnionAllWithInParam(t *testing.T) {
	wc := loadShapesFixture(t)
	stmt, err := wc.Prepare(`MATCH (a:Asset) WHERE a.id IN $ids RETURN a.id AS id
UNION ALL MATCH (r:IamRole) WHERE r.id IN $ids RETURN r.id AS id`)
	require.NoError(t, err)
	defer stmt.Close()

	// Executed twice: the fork's crash was in prepare, and LadybugDB caches the plan.
	for range 2 {
		res, err := wc.Execute(stmt, map[string]any{"ids": []any{"lb-1", "role-1", "absent"}})
		require.NoError(t, err)
		var ids []string
		for _, r := range rows(t, res) {
			ids = append(ids, r[0].(string))
		}
		sort.Strings(ids)
		require.Equal(t, []string{"lb-1", "role-1"}, ids)
	}
}

func TestEngineShapes_UntypedRelationshipAcrossLabels(t *testing.T) {
	assets, edges, sigs := copyFixture()
	edges = append(edges, asset.Edge{SrcID: "lb-1", SrcType: "load_balancer", DstID: "repo-1", DstType: "github_repo", EdgeType: "defined_in"})
	_, wc := openTestDB(t)
	_, err := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), sigs, true, 4, nil)
	require.NoError(t, err)
	// lb-1 has one loaded edge into each of three labels: Asset (internet),
	// IamRole and Repo. The fork could silently drop the cross-label rows.
	typed := countQuery(t, wc, `MATCH (a:Asset {id: 'lb-1'})-[:ExposedToInternet]->(b) RETURN count(b)`) +
		countQuery(t, wc, `MATCH (a:Asset {id: 'lb-1'})-[:HasRole]->(b) RETURN count(b)`) +
		countQuery(t, wc, `MATCH (a:Asset {id: 'lb-1'})-[:DefinedInAsset]->(b) RETURN count(b)`)
	require.Equal(t, int64(3), typed)
	require.Equal(t, typed, countQuery(t, wc, `MATCH (a {id: 'lb-1'})-[]->(b) RETURN count(b)`))
}

func TestEngineShapes_ColumnNamesAndMapsOnEveryValueShape(t *testing.T) {
	wc := loadShapesFixture(t)
	res, err := wc.Query(`MATCH (a:Asset {id: 'lb-1'})-[r:HasRole]->(b:IamRole)
RETURN a, r, b, a.id AS id, 'literal' AS tag, 1 AS one`)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "r", "b", "id", "tag", "one"}, res.GetColumnNames())

	require.True(t, res.HasNext())
	tup, err := res.Next()
	require.NoError(t, err)
	m, err := tup.GetAsMap()
	require.NoError(t, err)
	res.Close()

	require.Equal(t, "Asset", m["a"].(ladybug.Node).Label)
	rel := m["r"].(ladybug.Relationship)
	require.Equal(t, "HasRole", rel.Label)
	require.Equal(t, m["a"].(ladybug.Node).ID, rel.SourceID)
	require.Equal(t, m["b"].(ladybug.Node).ID, rel.DestinationID)
	require.Equal(t, "lb-1", m["id"])
	require.Equal(t, "literal", m["tag"])
	require.EqualValues(t, 1, m["one"])
}

func TestEngineShapes_BoolParameter(t *testing.T) {
	wc := loadShapesFixture(t)
	stmt, err := wc.Prepare(`MATCH (a:Asset) WHERE $flag = true OR a.id = 'lb-1' RETURN count(a)`)
	require.NoError(t, err)
	defer stmt.Close()

	count := func(all bool) any {
		res, err := wc.Execute(stmt, map[string]any{"flag": all})
		require.NoError(t, err)
		return rows(t, res)[0][0]
	}
	require.EqualValues(t, 1, count(false))
	require.Equal(t, countQuery(t, wc, `MATCH (a:Asset) RETURN count(a)`), count(true))
}

func TestEngineShapes_OrderByWithAliasAndAggregateInWith(t *testing.T) {
	wc := loadShapesFixture(t)
	direct := queryRows(t, wc, `MATCH (a:Asset) RETURN a.id ORDER BY a.score DESC, a.id`)
	viaAlias := queryRows(t, wc, `MATCH (a:Asset) WITH a, a.score AS s RETURN a.id ORDER BY s DESC, a.id`)
	require.Equal(t, []any{"lb-1"}, direct[0])
	require.Equal(t, direct, viaAlias)

	perRole := queryRows(t, wc, `MATCH (src)-[:HasRole|CanAssume]->(r:IamRole) WITH r, count(src) AS n RETURN r.id, n ORDER BY r.id`)
	require.Equal(t, [][]any{{"role-1", int64(1)}, {"role-2", int64(1)}}, perRole)
}

func TestEngineShapes_PatternNegationAndChainedHops(t *testing.T) {
	wc := loadShapesFixture(t)
	// Of the Asset nodes, only lb-1 has a HasRole edge.
	without := queryRows(t, wc, `MATCH (a:Asset) WHERE NOT (a)-[:HasRole]->(:IamRole) AND a.id <> 'internet' RETURN a.id ORDER BY a.id`)
	with := queryRows(t, wc, `MATCH (a:Asset) WHERE (a)-[:HasRole]->(:IamRole) RETURN a.id`)
	require.Equal(t, [][]any{{"lb-1"}}, with)
	require.NotContains(t, without, []any{"lb-1"})
	require.NotEmpty(t, without)

	chained := queryRows(t, wc, `MATCH (a:Asset {id: 'lb-1'})-[:HasRole]->(r:IamRole)-[:CanAssume]->(r2:IamRole) RETURN r.id, r2.id`)
	separate := queryRows(t, wc, `MATCH (a:Asset {id: 'lb-1'})-[:HasRole]->(r:IamRole) MATCH (r)-[:CanAssume]->(r2:IamRole) RETURN r.id, r2.id`)
	require.Equal(t, [][]any{{"role-1", "role-2"}}, chained)
	require.Equal(t, separate, chained)
}
