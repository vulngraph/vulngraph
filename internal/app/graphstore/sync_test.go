package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

type stubAssets struct{ a []asset.Asset }

func (s stubAssets) ListAll(context.Context, asset.SyncProjection) (asset.AssetSyncResult, error) {
	return asset.AssetSyncResult{Assets: s.a}, nil
}

type stubEdges struct{ e []asset.Edge }

func (s stubEdges) AllEdges(context.Context, asset.SyncProjection) (asset.EdgeSyncResult, error) {
	return asset.EdgeSyncResult{Edges: s.e}, nil
}

// VerifyExpiredEphemeral: no asset-table model in this stub, so nothing is ever
// a verified corpse. Tests that need the real check exercise bulkSyncCopy's
// verifier parameter directly (copy_load_test.go).
func (s stubEdges) VerifyExpiredEphemeral(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

type stubSignals struct{ m map[string]NodeSignals }

func (s stubSignals) SignalsByResource(context.Context) (map[string]NodeSignals, error) {
	return s.m, nil
}

// TestSyncFromSources_ProjectsSignalsAndEdges exercises the whole rebuild path on an
// in-memory Ladybug: it covers the INT32 signal round-trip, the edge allowlist
// mapping (has_role must reach the graph), the topology-derived exposed/toxic
// signals, and the build-and-swap (the graph is queryable after sync).
func TestSyncFromSources_ProjectsSignalsAndEdges(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	// Use load_balancer (→ NodeAsset) so that signal columns (has_kev, exposed, etc.)
	// are present on the node. EC2Instance/SecurityGroup/K8sWorkload/Subnet carry only
	// basic fields (no signal columns) in their dedicated tables.
	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50},
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: 70},
	}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{"via": "sg-1"}},
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role",
			EdgeType: "has_role", Properties: map[string]string{}},
	}
	// lb-1 carries KEV + exploitable + privesc findings; exposed/toxic_combo are derived
	// from the exposed_to_internet edge at sync time.
	sigs := map[string]NodeSignals{
		"lb-1": {HasKEV: true, Exploitable: true, MaxScore: 90, PrivescCount: 2},
	}

	require.NoError(t, svc.SyncFromSources(ctx,
		0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

	// Signal projection: `n.has_kev = 1` selects lb-1 with every flag populated. This
	// is the killer security query the signal columns exist for.
	res, err := svc.RunCypher(ctx, `MATCH (n:Asset) WHERE n.has_kev = 1 RETURN n`, 100, 100)
	require.NoError(t, err)
	require.Len(t, res.Nodes, 1)
	got := res.Nodes[0]
	require.Equal(t, "lb-1", got.ID)
	require.True(t, got.HasKEV, "has_kev")
	require.True(t, got.Exploitable, "exploitable")
	require.True(t, got.Exposed, "exposed (derived from exposed_to_internet edge)")
	require.True(t, got.ToxicCombo, "toxic_combo (exposed && privesc>0)")
	require.Equal(t, 90, got.MaxScore)
	require.Equal(t, 2, got.PrivescCount)

	// Edge mapping: the has_role edge (Asset→IamRole) must be present — proves the
	// allowlisted type reached the graph rather than being silently dropped. Use a
	// label-specific pattern so the assertion holds regardless of Ladybug's type() support.
	roleRes, err := svc.RunCypher(ctx,
		`MATCH (:Asset {id: 'lb-1'})-[:HasRole]->(d:IamRole) RETURN d`, 100, 100)
	require.NoError(t, err)
	require.Len(t, roleRes.Nodes, 1, "has_role edge missing from graph")
	require.Equal(t, "role-1", roleRes.Nodes[0].ID)

	exposedRes, err := svc.RunCypher(ctx,
		`MATCH (:Asset {id: 'lb-1'})-[:ExposedToInternet]->(d:Asset {id: 'internet'}) RETURN d`, 100, 100)
	require.NoError(t, err)
	require.Len(t, exposedRes.Nodes, 1, "exposed_to_internet edge missing from graph")
}

// TestRunCypher_ScalarResults guards the scalar/aggregate path: a `RETURN count(...)`
// must surface a value in Result.Rows/Columns (not an empty graph — the bug that made
// every "how many …?" question appear to fail). A node query still yields nodes and no
// scalar rows; a mixed grouping query yields a labeled column plus its aggregate.
func TestRunCypher_ScalarResults(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50},
		{ID: "lb-2", Name: "api", Type: "load_balancer", Provider: "gcp", RiskScore: 40},
	}
	require.NoError(t, svc.SyncFromSources(ctx,
		0, stubAssets{assets}, stubEdges{nil}, stubSignals{nil}))

	// Aggregate: count of assets. Must come back as one scalar row, zero nodes —
	// the value itself is Ladybug's node count, which we don't couple to here; the
	// point is the scalar surfaces at all (the bug returned an empty graph).
	agg, err := svc.RunCypher(ctx, `MATCH (n:Asset) RETURN count(n) AS n`, 100, 100)
	require.NoError(t, err)
	require.Empty(t, agg.Nodes, "aggregate query must not return nodes")
	require.Equal(t, []string{"n"}, agg.Columns)
	require.Len(t, agg.Rows, 1)
	n, ok := agg.Rows[0]["n"].(int64)
	require.True(t, ok, "count must surface as an int64 scalar, got %T", agg.Rows[0]["n"])
	require.Positive(t, n)

	// Node query: still returns nodes (the two seeded assets plus Ladybug's built-in
	// internet/secret sentinels), and no scalar rows.
	nodesRes, err := svc.RunCypher(ctx, `MATCH (n:Asset) RETURN n`, 100, 100)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(nodesRes.Nodes), 2)
	require.Empty(t, nodesRes.Rows, "node query must not populate scalar rows")

	// Grouped aggregate: a dimension column plus its count. Yields a labeled column
	// pair and one row per distinct provider (aws, gcp, and the property-less sentinels).
	grouped, err := svc.RunCypher(ctx,
		`MATCH (n:Asset) WHERE n.provider IN ['aws','gcp'] RETURN n.provider AS provider, count(*) AS c ORDER BY provider`, 100, 100)
	require.NoError(t, err)
	require.Empty(t, grouped.Nodes)
	require.ElementsMatch(t, []string{"provider", "c"}, grouped.Columns)
	require.Len(t, grouped.Rows, 2)
}

// TestRunCypher_ContainsDataTraversable guards the DSPM route: contains_data edges
// (Asset→DataClass) must be loaded into Ladybug so `MATCH (a)-[:ContainsData]->(dc)`
// returns the classified assets. Regressing this to a not-loaded drop empties the whole
// DSPM page — the exact bug this test exists to catch.
func TestRunCypher_ContainsDataTraversable(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{
		{ID: "bucket-1", Name: "customer-data", Type: "s3_bucket", Provider: "aws", RiskScore: 60},
		{ID: "dataclass:pii", Name: "PII", Type: "data_class", Provider: ""},
	}
	edges := []asset.Edge{
		{SrcID: "bucket-1", SrcType: "s3_bucket", DstID: "dataclass:pii", DstType: "data_class",
			EdgeType: "contains_data", Properties: map[string]string{"via": "pii"}},
	}
	require.NoError(t, svc.SyncFromSources(ctx,
		0, stubAssets{assets}, stubEdges{edges}, stubSignals{nil}))

	res, err := svc.RunCypher(ctx,
		`MATCH (a:Asset)-[r:ContainsData]->(dc:DataClass) RETURN a, r, dc`, 100, 100)
	require.NoError(t, err)
	require.NotEmpty(t, res.Edges, "contains_data edge missing — DSPM route would render empty")
	var srcIDs []string
	for _, e := range res.Edges {
		srcIDs = append(srcIDs, e.SrcID)
	}
	require.Contains(t, srcIDs, "bucket-1")
}

// TestRunCypher_EncryptedPublicSignals guards the DSPM data-store signals: the
// encrypted/public node columns must project from asset Metadata into Ladybug so
// "unencrypted sensitive data" and "publicly-accessible store" queries work.
func TestRunCypher_EncryptedPublicSignals(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{
		// Public, unencrypted S3 bucket — the classic toxic combination.
		{ID: "bkt-open", Name: "customer-pii", Type: "s3_bucket", Provider: "aws",
			Metadata: map[string]string{"public": "true", "encryption": ""}},
		// Private, encrypted RDS.
		{ID: "db-safe", Name: "billing", Type: "rds_instance", Provider: "aws",
			Metadata: map[string]string{"publicly_accessible": "false", "storage_encrypted": "true"}},
		// GCS: encryption is never collected, so the store is unknown.
		{ID: "gcs-unread", Name: "exports", Type: "gcs_bucket", Provider: "gcp",
			Metadata: map[string]string{"public": "false"}},
	}
	require.NoError(t, svc.SyncFromSources(ctx,
		0, stubAssets{assets}, stubEdges{nil}, stubSignals{nil}))

	openRes, err := svc.RunCypher(ctx, `MATCH (a:Asset {id: 'bkt-open'}) RETURN a`, 10, 10)
	require.NoError(t, err)
	require.Len(t, openRes.Nodes, 1)
	require.True(t, openRes.Nodes[0].Public, "public S3 bucket must carry public=1")
	require.Equal(t, explore.EncryptionUnencrypted, openRes.Nodes[0].Encryption, "unencrypted S3 bucket must carry encrypted=0")

	safeRes, err := svc.RunCypher(ctx, `MATCH (a:Asset {id: 'db-safe'}) RETURN a`, 10, 10)
	require.NoError(t, err)
	require.Len(t, safeRes.Nodes, 1)
	require.False(t, safeRes.Nodes[0].Public, "private RDS must carry public=0")
	require.Equal(t, explore.EncryptionEncrypted, safeRes.Nodes[0].Encryption, "encrypted RDS must carry encrypted=1")

	unreadRes, err := svc.RunCypher(ctx, `MATCH (a:Asset {id: 'gcs-unread'}) RETURN a`, 10, 10)
	require.NoError(t, err)
	require.Len(t, unreadRes.Nodes, 1)
	require.Equal(t, explore.EncryptionUnknown, unreadRes.Nodes[0].Encryption, "an unobserved store must never be served as encrypted")
}

// TestNeighbors_ReturnsEdgeLabels guards /api/graph/expand: every edge neighbors
// returns must carry its rel-table label.
func TestNeighbors_ReturnsEdgeLabels(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	// Use load_balancer (→ NodeAsset) so that the node lives in the Asset table
	// and is reachable by neighborRels (which covers Asset↔IamRole traversals).
	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50},
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: 70},
	}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{"via": "sg-1"}},
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role",
			EdgeType: "has_role", Properties: map[string]string{}},
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	outEdges, nbrs, _, err := svc.Neighbors(ctx, []string{"lb-1"}, nil, explore.DirectionOut)
	require.NoError(t, err)
	labels := map[string]string{}
	for _, e := range outEdges {
		require.Equal(t, "lb-1", e.SrcID)
		labels[e.EdgeType] = e.DstID
	}
	require.Equal(t, "role-1", labels["HasRole"], "HasRole edge missing/mislabelled: %v", labels)
	require.Equal(t, "internet", labels["ExposedToInternet"], "ExposedToInternet edge missing: %v", labels)

	// Neighbour nodes are returned with their identity (proves node-object parsing).
	ids := map[string]bool{}
	for _, n := range nbrs {
		ids[n.ID] = true
	}
	require.True(t, ids["role-1"], "neighbor role-1 missing: %v", ids)

	// Edge-type filter (Go-side) narrows to a single rel label.
	filtered, _, _, err := svc.Neighbors(ctx, []string{"lb-1"}, []string{"HasRole"}, explore.DirectionOut)
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	require.Equal(t, "HasRole", filtered[0].EdgeType)
}

// TestNamedQueries_ReturnGraph guards the named-query catalog: each query must
// RETURN node/relationship objects (not scalar projections), or execCypher yields
// an empty graph. This fixture-drives a few representative queries end to end.
func TestNamedQueries_ReturnGraph(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 128, 0, 0, "") // named-query test runs multiple complex traversals; 128MB avoids OOM in test env
	require.NoError(t, err)
	defer svc.Close()

	// Use load_balancer (→ NodeAsset) so that named queries targeting :Asset nodes
	// (e.g. internet_exposed_high_risk, top_composite_risk, blast_radius) find the
	// fixture node. EC2Instance nodes live in a dedicated table without signal columns.
	assets := []asset.Asset{
		{ID: "i-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 90},
		{ID: "role-1", Name: "AdminRole", Type: "iam_role", Provider: "aws", RiskScore: 80},
		{ID: "repo-1", Name: "org/ci", Type: "github_repo", Provider: "github"},
	}
	edges := []asset.Edge{
		{SrcID: "i-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{"via": "sg-1"}},
		{SrcID: "i-1", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role",
			EdgeType: "has_role", Properties: map[string]string{}},
		{SrcID: "repo-1", SrcType: "github_repo", DstID: "role-1", DstType: "iam_role",
			EdgeType: "federated_access", Properties: map[string]string{"trust_type": "oidc", "subject": "repo:org/ci"}},
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	run := func(name string) ([]explore.Node, []explore.Edge) {
		res, err := svc.RunNamedQuery(ctx, name, nil)
		require.NoError(t, err, name)
		return res.Nodes, res.Edges
	}
	ids := func(nodes []explore.Node) map[string]bool {
		m := map[string]bool{}
		for _, n := range nodes {
			m[n.ID] = true
		}
		return m
	}
	edgeTypes := func(edges []explore.Edge) map[string]bool {
		m := map[string]bool{}
		for _, e := range edges {
			m[e.EdgeType] = true
		}
		return m
	}

	// Single-hop query: returns the asset, the internet sentinel, and the edge between.
	nodes, eds := run("internet_exposed_high_risk")
	require.True(t, ids(nodes)["i-1"], "internet_exposed_high_risk missing i-1: %v", ids(nodes))
	require.True(t, edgeTypes(eds)["ExposedToInternet"], "missing ExposedToInternet edge: %v", edgeTypes(eds))
	// Edge endpoints must resolve (two-pass node/edge collection in execCypher).
	for _, e := range eds {
		if e.EdgeType == "ExposedToInternet" {
			require.Equal(t, "i-1", e.SrcID)
			require.Equal(t, "internet", e.DstID)
		}
	}

	// Federation query: repo + role nodes and the FederatedAccess edge between them.
	nodes, eds = run("github_oidc_to_aws_roles")
	require.True(t, ids(nodes)["repo-1"] && ids(nodes)["role-1"], "oidc query missing nodes: %v", ids(nodes))
	require.True(t, edgeTypes(eds)["FederatedAccess"], "missing FederatedAccess edge: %v", edgeTypes(eds))

	// Aggregation query (WITH/composite ordering): still returns the asset node.
	nodes, _ = run("top_composite_risk")
	require.True(t, ids(nodes)["i-1"], "top_composite_risk missing i-1: %v", ids(nodes))

	// Parameterised, variable-length query: reaches role-1 from i-1 within 3 hops.
	blast, err := svc.RunNamedQuery(ctx, "blast_radius", map[string]string{"id": "i-1"})
	require.NoError(t, err)
	nodes = blast.Nodes
	require.True(t, ids(nodes)["role-1"], "blast_radius missing role-1: %v", ids(nodes))

	// BlastRadiusCount uses the same label(reached) IN [...] predicate (Ladybug has no
	// node-label WHERE predicate); from i-1 it reaches role-1 (and the internet node).
	count, err := svc.BlastRadiusCount(ctx, "i-1", 3)
	require.NoError(t, err)
	require.GreaterOrEqual(t, count, 1, "BlastRadiusCount should reach role-1")
}

// TestBlastRadiusCountCache verifies that blastRadiusCache is populated on first
// call and cleared on SyncFromSources. Uses nodes with an ExposedToInternet edge
// which is in the sync allowlist and the Ladybug schema, guaranteeing insertion.
func TestBlastRadiusCountCache(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{
		{ID: "a1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 80},
		{ID: "internet", Name: "internet", Type: "internet", Provider: "internet", RiskScore: 0},
	}
	// ExposedToInternet is definitely in edgeTypeToRel and the schema.
	edges := []asset.Edge{{SrcID: "a1", DstID: "internet", EdgeType: "ExposedToInternet"}}
	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil)
	require.NoError(t, err)

	// First call — result stored in cache regardless of value.
	count1, err := svc.BlastRadiusCount(ctx, "a1", 2)
	require.NoError(t, err)

	// Cache entry must exist after first call.
	_, cached := svc.blastRadiusCache.Load("a1:2")
	require.True(t, cached, "blastRadiusCache should be populated after first call")

	// Second call — must return same value (cache hit, no Ladybug query).
	count2, err := svc.BlastRadiusCount(ctx, "a1", 2)
	require.NoError(t, err)
	require.Equal(t, count1, count2, "cache hit must return identical value")

	// After sync the cache must be cleared.
	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil)
	require.NoError(t, err)
	_, cached = svc.blastRadiusCache.Load("a1:2")
	require.False(t, cached, "blastRadiusCache must be cleared after SyncFromSources")
}
