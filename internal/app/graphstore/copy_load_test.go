package graphstore

import (
	"context"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
)

// relTokenRE matches the rel-type tokens inside a Cypher pattern, e.g.
// `[:ExposedToInternet]` or the alternation `[:A|B|C]`. Must include digits —
// rel names like ExecutesAsK8sWorkload/AccessesK8sWorkload contain one, and a
// letters-only class silently truncates the capture there (e.g. to
// "AccessesK"), which previously went unnoticed only because no named query's
// Cypher text referenced ExecutesAsK8sWorkload literally by name.
var relTokenRE = regexp.MustCompile(`\[:([A-Za-z0-9|]+)`)

// namedQueryRelTables returns every rel table referenced by any NamedQuery.
func namedQueryRelTables(t *testing.T) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, q := range NamedQueries {
		if q.Inventory {
			continue
		} // exercised through the bounded inventory backend
		for _, m := range relTokenRE.FindAllStringSubmatch(q.Query, -1) {
			for _, tok := range splitAlternation(m[1]) {
				out[tok] = struct{}{}
			}
		}
	}
	return out
}

func splitAlternation(s string) []string {
	var out []string
	for _, p := range regexp.MustCompile(`\|`).Split(s, -1) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TestLadybugQueryableRelTablesCoverNamedQueries pins the loaded-set rule: every rel type any named
// query traverses MUST be loaded into Ladybug. Fails if a future query references a
// rel table we dropped from ladybugRelSpec — preventing a silently-empty result.
func TestLadybugQueryableRelTablesCoverNamedQueries(t *testing.T) {
	used := namedQueryRelTables(t)
	require.NotEmpty(t, used, "expected to extract rel tokens from NamedQueries")
	var missing []string
	for rel := range used {
		if !ladybugQueryableRelTable(rel) {
			missing = append(missing, rel)
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing,
		"named queries reference rel tables not loaded into Ladybug (add to ladybugRelSpec or they return empty): %v", missing)
}

// TestBuildEdgeRowsAppliesA3 verifies the loaded-set filter: a query-traversed edge type
// is kept; a high-volume/topology edge type with no named-query usage is dropped
// at the Ladybug-insert step (it still exists in the Go edge slice for BFS).
func TestBuildEdgeRowsAppliesA3(t *testing.T) {
	edges := []asset.Edge{
		{SrcID: "a1", DstID: "internet", EdgeType: "exposed_to_internet"},
		{SrcID: "v1", DstID: "v2", EdgeType: "peered_with"},    // not loaded
		{SrcID: "r1", DstID: "role1", EdgeType: "has_policy"},  // not loaded (no query traverses it)
		{SrcID: "a2", DstID: "ds1", EdgeType: "contains_data"}, // kept: DSPM route traverses it
	}
	byRel := buildEdgeRows(edges)
	require.Contains(t, byRel, "ExposedToInternet")
	require.NotContains(t, byRel, "PeeredWith", "peered_with must be dropped (no named query)")
	require.NotContains(t, byRel, "HasPolicy", "has_policy must be dropped (no traversal)")
	require.Contains(t, byRel, "ContainsData", "contains_data must be loaded — the DSPM route queries it")
}

// openTestDB opens a fresh in-memory Ladybug DB with the schema applied.
func openTestDB(t *testing.T) (*ladybugDB, *ladybug.Connection) {
	t.Helper()
	db, err := openAndInit(64, 0, 0)
	require.NoError(t, err)
	t.Cleanup(db.close)
	wc, err := db.newWriteConn()
	require.NoError(t, err)
	t.Cleanup(wc.Close)
	return db, wc
}

func countQuery(t *testing.T, conn *ladybug.Connection, q string) int64 {
	t.Helper()
	res, err := conn.Query(q)
	require.NoError(t, err, q)
	defer res.Close()
	require.True(t, res.HasNext(), "no row for %q", q)
	tup, err := res.Next()
	require.NoError(t, err)
	v, err := tup.GetValue(0)
	require.NoError(t, err)
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	default:
		t.Fatalf("unexpected count type %T", v)
		return 0
	}
}

// copyFixture is a representative graph touching several node labels and many
// rel tables, including escaping-prone names.
func copyFixture() ([]asset.Asset, []asset.Edge, map[string]NodeSignals) {
	assets := []asset.Asset{
		{ID: "lb-1", Name: `web,"prod"`, Type: "load_balancer", Provider: "aws", RiskScore: 50}, // escaping
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: 70},
		{ID: "role-2", Name: "deployer", Type: "iam_role", Provider: "aws"},
		{ID: "pkg-1", Name: "log4j", Type: "package", Provider: "", Metadata: map[string]string{"ecosystem": "maven", "version": "2.14"}},
		{ID: "pod-1", Name: "api", Type: "k8s_pod", Provider: "gcp", RiskScore: 30},
		{ID: "repo-1", Name: "org/api", Type: "github_repo", Provider: "github"},
		{ID: "ec2-1", Name: "bastion", Type: "ec2_instance", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet", Properties: map[string]string{"via": "sg-1"}},
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role", EdgeType: "has_role"},
		{SrcID: "role-1", SrcType: "iam_role", DstID: "role-2", DstType: "iam_role", EdgeType: "can_assume"},
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "pkg-1", DstType: "package", EdgeType: "runs_package"},
		{SrcID: "repo-1", SrcType: "github_repo", DstID: "pkg-1", DstType: "package", EdgeType: "depends_on"},
		{SrcID: "repo-1", SrcType: "github_repo", DstID: "pod-1", DstType: "k8s_pod", EdgeType: "deploys_to"},
		{SrcID: "pod-1", SrcType: "k8s_pod", DstID: "role-2", DstType: "iam_role", EdgeType: "executes_as"},
		{SrcID: "repo-1", SrcType: "github_repo", DstID: "role-1", DstType: "iam_role", EdgeType: "federated_access", Properties: map[string]string{"trust_type": "oidc", "subject": "repo:org/api:ref"}},
		// not loaded (no named query): still present in the slice for BFS.
		{SrcID: "v1", SrcType: "vpc", DstID: "v2", DstType: "vpc", EdgeType: "peered_with"},
	}
	sigs := map[string]NodeSignals{"lb-1": {HasKEV: true, MaxScore: 90}}
	return assets, edges, sigs
}

// TestBulkSyncCopyEquivalence loads the same fixture via the UNWIND loader and
// the COPY loader into separate DBs and asserts identical node/edge counts and
// identical named-query results — COPY must be a drop-in replacement.
func TestBulkSyncCopyEquivalence(t *testing.T) {
	ctx := context.Background()
	assets, edges, sigs := copyFixture()

	_, wcUnwind := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wcUnwind, assets, edges, sigs))

	_, wcCopy := openTestDB(t)
	_, copyErr := bulkSyncCopy(ctx, wcCopy, assets, edges, newReachOverlay(edges), sigs, true, 4, nil)
	require.NoError(t, copyErr)

	checks := []string{
		`MATCH (a:Asset) RETURN count(a)`,
		`MATCH (r:IamRole) RETURN count(r)`,
		`MATCH (p:Package) RETURN count(p)`,
		`MATCH (w:K8sWorkload) RETURN count(w)`,
		`MATCH (r:Repo) RETURN count(r)`,
		`MATCH ()-[e:ExposedToInternet]->() RETURN count(e)`,
		`MATCH ()-[e:HasRole]->() RETURN count(e)`,
		`MATCH ()-[e:CanAssume]->() RETURN count(e)`,
		`MATCH ()-[e:RunsPackage]->() RETURN count(e)`,
		`MATCH ()-[e:DependsOn]->() RETURN count(e)`,
		`MATCH ()-[e:DeploysTo]->() RETURN count(e)`,
		`MATCH ()-[e:ExecutesAsK8sWorkload]->() RETURN count(e)`,
		`MATCH ()-[e:FederatedAccess]->() RETURN count(e)`,
		// An unloaded rel table must be empty in BOTH (UNWIND also honors the loaded set).
		`MATCH ()-[e:PeeredWith]->() RETURN count(e)`,
	}
	for _, q := range checks {
		require.Equal(t, countQuery(t, wcUnwind, q), countQuery(t, wcCopy, q), "mismatch for %q", q)
	}

	// COPY produced real edges, not an empty graph.
	require.Equal(t, int64(1), countQuery(t, wcCopy, `MATCH ()-[e:ExposedToInternet]->() RETURN count(e)`))
	require.Equal(t, int64(1), countQuery(t, wcCopy, `MATCH ()-[e:ExecutesAsK8sWorkload]->() RETURN count(e)`))
}

// TestFederatedAccessRoundTripsProvenance pins provenance round-tripping: a
// federated_access edge's provenance/confidence/workflow_path
// properties — written by the ci_access correlate rule and the
// verify_ci_role job — must survive both the UNWIND and COPY load paths into
// real Ladybug rel columns, not just trust_type/subject. Without those columns on
// the FederatedAccess REL TABLE, e.provenance is null and the
// CI-workflow-federation preset (`WHERE e.provenance IN ['gh_workflow', ...]`)
// returns zero rows.
func TestFederatedAccessRoundTripsProvenance(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "role-1", Name: "deployer", Type: "iam_role", Provider: "aws"},
		{ID: "repo-1", Name: "org/api", Type: "github_repo", Provider: "github"},
	}
	edges := []asset.Edge{
		{
			SrcID: "repo-1", SrcType: "github_repo", DstID: "role-1", DstType: "iam_role",
			EdgeType: "federated_access",
			Properties: map[string]string{
				"trust_type":    "oidc",
				"subject":       "repo:org/api:ref",
				"provenance":    "gh_workflow",
				"confidence":    "high",
				"workflow_path": ".github/workflows/deploy.yml",
			},
		},
	}
	sigs := map[string]NodeSignals{}

	assertProvenance := func(t *testing.T, conn *ladybug.Connection) {
		t.Helper()
		res, err := conn.Query(`MATCH ()-[e:FederatedAccess]->() RETURN e.provenance, e.confidence, e.workflow_path, e.trust_type, e.subject`)
		require.NoError(t, err)
		defer res.Close()
		require.True(t, res.HasNext(), "no FederatedAccess edge found")
		tup, err := res.Next()
		require.NoError(t, err)
		provenance, err := tup.GetValue(0)
		require.NoError(t, err)
		confidence, err := tup.GetValue(1)
		require.NoError(t, err)
		workflowPath, err := tup.GetValue(2)
		require.NoError(t, err)
		trustType, err := tup.GetValue(3)
		require.NoError(t, err)
		subject, err := tup.GetValue(4)
		require.NoError(t, err)
		assert.Equal(t, "gh_workflow", provenance)
		assert.Equal(t, "high", confidence)
		assert.Equal(t, ".github/workflows/deploy.yml", workflowPath)
		assert.Equal(t, "oidc", trustType)
		assert.Equal(t, "repo:org/api:ref", subject)
	}

	_, wcUnwind := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wcUnwind, assets, edges, sigs))
	assertProvenance(t, wcUnwind)

	_, wcCopy := openTestDB(t)
	_, copyErr := bulkSyncCopy(ctx, wcCopy, assets, edges, newReachOverlay(edges), sigs, true, 4, nil)
	require.NoError(t, copyErr)
	assertProvenance(t, wcCopy)
}

// TestDefinedInIamRoleRoundTripsProvenance verifies a defined_in edge sourced
// from an iam_role (IAM-role ownership) routes to the typed
// DefinedInIamRole rel table (IamRole→Repo) and round-trips confidence and
// provenance through both the UNWIND (bulkSync) and COPY (bulkSyncCopy) load
// paths — mirroring TestFederatedAccessRoundTripsProvenance above. Without this
// routing, an iam_role-sourced defined_in edge would fall through to the default
// DefinedInAsset (Asset→Repo) and be silently dropped at the Ladybug endpoint
// pre-filter.
func TestDefinedInIamRoleRoundTripsProvenance(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "role-1", Name: "deploy-role", Type: "iam_role", Provider: "aws"},
		{ID: "repo-1", Name: "org/infra", Type: "github_repo", Provider: "github"},
	}
	edges := []asset.Edge{
		{
			SrcID: "role-1", SrcType: "iam_role", DstID: "repo-1", DstType: "github_repo",
			EdgeType: "defined_in",
			Properties: map[string]string{
				"provenance": "iac_terraform",
				"confidence": "high",
			},
		},
	}
	sigs := map[string]NodeSignals{}

	assertProvenance := func(t *testing.T, conn *ladybug.Connection) {
		t.Helper()
		res, err := conn.Query(`MATCH ()-[e:DefinedInIamRole]->() RETURN e.provenance, e.confidence`)
		require.NoError(t, err)
		defer res.Close()
		require.True(t, res.HasNext(), "no DefinedInIamRole edge found")
		tup, err := res.Next()
		require.NoError(t, err)
		provenance, err := tup.GetValue(0)
		require.NoError(t, err)
		confidence, err := tup.GetValue(1)
		require.NoError(t, err)
		assert.Equal(t, "iac_terraform", provenance)
		assert.Equal(t, "high", confidence)
	}

	_, wcUnwind := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wcUnwind, assets, edges, sigs))
	assertProvenance(t, wcUnwind)

	_, wcCopy := openTestDB(t)
	_, copyErr := bulkSyncCopy(ctx, wcCopy, assets, edges, newReachOverlay(edges), sigs, true, 4, nil)
	require.NoError(t, copyErr)
	assertProvenance(t, wcCopy)
}

// TestBuildEdgeRowsRoutesIamRoleDefinedInToTypedTable is a narrower unit check
// (no Ladybug connection) that buildEdgeRows itself picks RelDefinedInIamRole for
// an iam_role-sourced defined_in edge, and that the K8sWorkload and Asset routes
// are unaffected.
func TestBuildEdgeRowsRoutesIamRoleDefinedInToTypedTable(t *testing.T) {
	edges := []asset.Edge{
		{SrcID: "role-1", SrcType: "iam_role", DstID: "repo-1", DstType: "github_repo", EdgeType: "defined_in"},
		{SrcID: "svc-1", SrcType: "k8s_service", DstID: "repo-1", DstType: "github_repo", EdgeType: "defined_in"},
		{SrcID: "wl-1", SrcType: "k8s_deployment", DstID: "repo-1", DstType: "github_repo", EdgeType: "defined_in"},
	}
	byRel := buildEdgeRows(edges)
	require.Len(t, byRel[RelDefinedInIamRole].rows, 1, "iam_role-sourced defined_in must route to DefinedInIamRole")
	require.Len(t, byRel[RelDefinedInAsset].rows, 1, "Asset-sourced defined_in must route to the default DefinedInAsset")
	require.Len(t, byRel[RelDefinedInK8sWorkload].rows, 1, "k8s-workload-sourced defined_in must still route to DefinedInK8sWorkload")
}

// TestNodeLabelFor_K8sServiceAccount pins the IRSA/GKE-Workload-Identity
// service account mapping: a k8s_service_account asset must land
// in the K8sWorkload node table, not the generic Asset catch-all, so its
// executes_as edge routes to the dedicated K8sWorkload→IamRole rel table.
func TestNodeLabelFor_K8sServiceAccount(t *testing.T) {
	require.Equal(t, NodeK8sWorkload, NodeLabelFor("k8s_service_account"))
}

// TestExecutesAs_K8sServiceAccountRoutesToK8sWorkloadTable verifies an
// executes_as edge sourced from a k8s_service_account (IRSA/GKE-Workload-Identity)
// lands in ExecutesAsK8sWorkload, not the generic Asset→IamRole ExecutesAs
// table — the routing gap fixed by mapping k8s_service_account to
// NodeK8sWorkload in assetTypeToNode.
func TestExecutesAs_K8sServiceAccountRoutesToK8sWorkloadTable(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "role-1", Name: "irsa-role", Type: "iam_role", Provider: "aws"},
		{ID: "sa-1", Name: "irsa-sa", Type: "k8s_service_account", Provider: "kubernetes"},
	}
	edges := []asset.Edge{
		{SrcID: "sa-1", SrcType: "k8s_service_account", DstID: "role-1", DstType: "iam_role", EdgeType: "executes_as"},
	}

	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wc, assets, edges, nil))

	require.Equal(t, int64(1), countQuery(t, wc, `MATCH (w:K8sWorkload)-[e:ExecutesAsK8sWorkload]->(r:IamRole) RETURN count(e)`))
	require.Equal(t, int64(0), countQuery(t, wc, `MATCH ()-[e:ExecutesAs]->() RETURN count(e)`))
}

// TestBuildEdgeRowsRoutesTargetsToK8sWorkloadTable verifies a targets edge
// (k8s service selector-matches workload, exposure-chain last hop) whose destination
// is a k8s_deployment/k8s_pod lands in AccessesK8sWorkload, not the generic
// Asset→Asset Accesses table — the routing gap, since fixed, that silently
// dropped these edges (k8s_service_to_workload, k8s_exposed_service_to_
// workload, and github_to_k8s_to_exposed all returned zero rows because of it).
func TestBuildEdgeRowsRoutesTargetsToK8sWorkloadTable(t *testing.T) {
	edges := []asset.Edge{
		{SrcID: "svc-1", SrcType: "k8s_service", DstID: "pod-1", DstType: "k8s_pod", EdgeType: "targets"},
	}
	byRel := buildEdgeRows(edges)
	require.Len(t, byRel["AccessesK8sWorkload"].rows, 1)
	require.Empty(t, byRel["Accesses"].rows)
}

// TestAccessesK8sWorkload_TargetsToK8sPodRoutesToTypedTable is the end-to-end
// counterpart of TestBuildEdgeRowsRoutesTargetsToK8sWorkloadTable: verifies the
// edge actually loads into Ladybug under the typed rel table via bulkSync.
func TestAccessesK8sWorkload_TargetsToK8sPodRoutesToTypedTable(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "svc-1", Name: "svc", Type: "k8s_service", Provider: "kubernetes"},
		{ID: "pod-1", Name: "pod", Type: "k8s_pod", Provider: "kubernetes"},
	}
	edges := []asset.Edge{
		{SrcID: "svc-1", SrcType: "k8s_service", DstID: "pod-1", DstType: "k8s_pod", EdgeType: "targets"},
	}

	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wc, assets, edges, nil))

	require.Equal(t, int64(1), countQuery(t, wc, `MATCH (s:Asset)-[e:AccessesK8sWorkload]->(w:K8sWorkload) RETURN count(e)`))
	require.Equal(t, int64(0), countQuery(t, wc, `MATCH ()-[e:Accesses]->() RETURN count(e)`))
}

// TestBulkSyncCopyEscaping verifies a name with a comma and a double-quote
// round-trips through the CSV COPY path intact.
func TestBulkSyncCopyEscaping(t *testing.T) {
	ctx := context.Background()
	assets, edges, sigs := copyFixture()
	_, wc := openTestDB(t)
	_, copyErr := bulkSyncCopy(ctx, wc, assets, edges, newReachOverlay(edges), sigs, true, 2, nil)
	require.NoError(t, copyErr)

	res, err := wc.Query(`MATCH (a:Asset {id:'lb-1'}) RETURN a.name`)
	require.NoError(t, err)
	defer res.Close()
	require.True(t, res.HasNext())
	tup, err := res.Next()
	require.NoError(t, err)
	name, err := tup.GetValue(0)
	require.NoError(t, err)
	require.Equal(t, `web,"prod"`, name)
}

// TestBulkSyncCopyControlChars reproduces four CSV load failure modes:
//  1. Embedded newline in name: "Orders Database (Primary,\nReplica)" shifted
//     account_id into score (INT32) — Ladybug's CSV parser counted columns wrong.
//  2. Embedded comma in name: "app-sg - 22,80,443,3000,5000,8080,8443" caused "expected 7
//     values per row, but got more" — both parallel and serial Ladybug readers fail on
//     commas inside quoted fields regardless of RFC-4180 quoting.
//  3. Embedded pipe in name: would desync a pipe-delimited file.
//  4. Duplicate IDs: must collapse to one node rather than aborting COPY.
//
// The fix: pipe-delimited COPY (w.Comma='|', DELIM='|') + sanitize |/\r\n in
// formatCSVValue so the delimiter never appears in a field value.
func TestBulkSyncCopyControlChars(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "i-nasty", Name: "Orders Database (Primary,\nReplica)", Type: "ec2_instance",
			Provider: "aws", Region: "eu-west-1", AccountID: "334455667788"},
		{ID: "i-quote", Name: "name with \" quote\r\nand CRLF", Type: "ec2_instance",
			Provider: "aws", Region: "eu-west-1", AccountID: "111122223333", RiskScore: 5},
		{ID: "i-ok", Name: "bastion", Type: "ec2_instance", Provider: "aws",
			Region: "eu-west-1", AccountID: "999988887777", RiskScore: 9},
		// Comma-heavy name — an SG port-list naming pattern that broke the parallel and
		// serial Ladybug CSV readers ("expected 7 values per row, but got more").
		{ID: "sg-1", Name: "app-sg - 22,80,443,3000,5000,8080,8443", Type: "security_group",
			Provider: "aws", Region: "eu-west-1", AccountID: "334455667788", RiskScore: 3},
		// Embedded pipe — must be sanitized to a space so it does not act as the field delimiter.
		{ID: "sg-2", Name: "allow|pipe", Type: "security_group",
			Provider: "aws", Region: "eu-west-1", AccountID: "334455667788", RiskScore: 1},
		// Duplicate ID (different type variant) must collapse to one node, not abort COPY.
		{ID: "i-ok", Name: "bastion-dup", Type: "ec2_instance", Provider: "aws",
			Region: "eu-west-1", AccountID: "999988887777"},
	}
	_, wc := openTestDB(t)
	_, copyErr := bulkSyncCopy(ctx, wc, assets, nil, reachOverlay{}, nil, true, 2, nil)
	require.NoError(t, copyErr,
		"COPY must survive embedded newlines, commas, tabs, and duplicate IDs")

	// ec2_instance/security_group land on Asset — Asset.type still discriminates.
	require.Equal(t, int64(3), countQuery(t, wc,
		`MATCH (e:Asset) WHERE e.type = 'ec2_instance' RETURN count(e)`), "dup ID must collapse")
	require.Equal(t, int64(2), countQuery(t, wc,
		`MATCH (s:Asset) WHERE s.type = 'security_group' RETURN count(s)`))
	// account_id (STRING) must hold the account, not be shifted into score (INT32).
	require.Equal(t, int64(1), countQuery(t, wc,
		`MATCH (e:Asset {id:'i-nasty'}) WHERE e.account_id = '334455667788' RETURN count(e)`))
	// The comma-heavy SG name round-trips intact (no column split with TAB delimiter).
	require.Equal(t, int64(1), countQuery(t, wc,
		`MATCH (s:Asset {id:'sg-1'}) WHERE s.name = 'app-sg - 22,80,443,3000,5000,8080,8443' RETURN count(s)`))
}
