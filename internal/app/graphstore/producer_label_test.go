package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// This file exists because of a bug class that recurred several times, each
// instance found by hand and fixed individually without ever guarding the
// class: `executes_as`, `defined_in`, `targets`, `binds`, and the batch below.
//
// The mechanism: a rel table is declared with typed endpoints
// (`Binds: FROM Asset TO Asset`), and its UNWIND insert does
// `MATCH (s:Asset {id: r.src})`. But `assetTypeToNode` promotes some asset types
// to their own node table — `ec2_instance` → `EC2Instance`,
// `k8s_service_account` → `K8sWorkload`, `security_group` → `SecurityGroup`. When
// a producer emits an edge whose `SrcType`/`DstType` promotes off the label its
// rel table expects, the MATCH finds nothing and **Ladybug silently skips the row**.
// No error, no warning, no metric — the edge simply never exists, and every query
// that traverses it returns empty or, worse, satisfies a `NOT EXISTS` clause and
// manufactures a false positive.
//
// Every existing graph test validates the registry against ITSELF (derivations
// match pins, checksum matches DDL). None of them compares what the PRODUCERS
// actually emit against what the rel tables actually accept — which is precisely
// where those bugs lived. This test closes that.
//
// Adding a new edge producer means adding its triple here. That is the point: an
// unlisted producer is an unverified producer.

// producerEdge is one (edge_type, src_type, dst_type) triple a correlate rule or
// collector really emits, transcribed from the producer.
type producerEdge struct {
	edgeType string
	srcType  string
	dstType  string
	producer string // file:line, so a failure points at the code to fix
}

// producerEdges are the triples emitted across the codebase. Transcribed by
// reading each producer — there is no way to derive these from the type system,
// because SrcType/DstType are plain strings assigned at the emit site.
var producerEdges = []producerEdge{
	{"has_role", "ec2_instance", "iam_role", "correlate/ec2_iam.go:55"},
	{"executes_as", "k8s_pod", "iam_role", "correlate/executes_as.go"},
	{"executes_as", "lambda_function", "iam_role", "correlate/executes_as.go"},
	{"binds", "k8s_service_account", "k8s_cluster_role_binding", "collect/kubernetes/rbac.go"},
	{"binds", "k8s_cluster_role_binding", "k8s_cluster_role", "collect/kubernetes/rbac.go"},
	{"binds", "k8s_role_binding", "k8s_role", "collect/kubernetes/rbac.go"},
	{"binds", "k8s_role_binding", "k8s_cluster_role", "collect/kubernetes/rbac.go"},
	{"can_assume", "iam_role", "iam_role", "correlate/iam.go"},
	// allows_action (iam_role→iam_policy, correlate/iam_permissions.go) is
	// deliberately absent: its AllowsAction rel is declared bfs_only in the
	// registry, so it is never routed into Ladybug by design. See knownBrokenProducers.
	{"accesses_secret", "iam_role", "secretsmanager_secret", "correlate/secret_access.go"},
	{"can_escalate_to", "iam_role", "iam_role", "jobs/sync.go:255"},
	{"exposed_to_internet", "ec2_instance", "internet", "correlate/reachability.go:145"},
	{"exposed_to_internet", "security_group", "internet", "correlate/reachability.go:145"},
	{"protected_by", "load_balancer", "security_group", "collect/aws/elb.go:50"},
	{"connected_via_sg", "ec2_instance", "security_group", "correlate/shared_sg.go"},
	{"sg_allows_from", "security_group", "security_group", "correlate/secgroups.go:102"},
	{"dns_points_to", "dns_record", "ec2_instance", "correlate/dns.go"},
	{"deploys_to", "github_repo", "k8s_deployment", "correlate/deploys.go"},
	{"targets", "k8s_service", "k8s_deployment", "correlate/k8s_service.go"},

	// ── Transcribed from graph_edges ─────────────────────────────
	//
	// The list above was a hand-picked sample, and that is precisely how two
	// defects shipped with this guard already in place: the
	// guard was sound, its INPUT was incomplete. Every triple below was absent,
	// and three of them were broken. So the list is now seeded from what
	// ClickHouse actually holds (every (edge_type, src_type, dst_type) shape in
	// the 48h fresh window whose edge type routes to a Loaded rel), not from
	// reading producers and hoping the reading was exhaustive.
	//
	// Regenerate with:
	//   SELECT edge_type, src_type, dst_type, count() FROM (
	//     SELECT src_id, src_type, dst_id, dst_type, edge_type FROM graph_edges
	//     WHERE synced_at > now() - INTERVAL 48 HOUR
	//     GROUP BY src_id, src_type, dst_id, dst_type, edge_type)
	//   GROUP BY edge_type, src_type, dst_type
	//
	// Edge types whose rel is declared bfs_only/inherit_only in the registry
	// (runs_image, runs_container, has_policy, owns, allows_action, peered_with)
	// are deliberately EXCLUDED, exactly as allows_action always was: they route
	// nowhere on purpose, and listing them would assert a bug where there is a
	// documented design decision. Unsynced types (runs_in, in_subnet,
	// member_of_zone) are excluded for the same reason — they are never fetched.
	{"can_assume", "iam_user", "iam_role", "correlate/iam.go"},
	{"can_escalate_to", "iam_user", "iam_role", "jobs/sync.go"},
	{"can_escalate_to", "iam_role", "iam_user", "jobs/sync.go"},
	{"connected_via_sg", "load_balancer", "security_group", "correlate/shared_sg.go"},
	{"connected_via_sg", "rds_instance", "security_group", "correlate/shared_sg.go"},
	{"contains_data", "secretsmanager_secret", "data_class", "correlate/dspm.go"},
	{"contains_data", "s3_bucket", "data_class", "correlate/dspm.go"},
	{"contains_data", "gcs_bucket", "data_class", "correlate/dspm.go"},
	{"defined_in", "gcp_service_account", "github_repo", "correlate/iac.go"},
	{"defined_in", "iam_user", "github_repo", "correlate/iac.go"},
	// container_image → repo, from the image-reference harvest (correlate/
	// image_ownership.go). It is the join that makes the supply chain traversable
	// end to end — k8s_pod →RunsImage→ container_image →DefinedInAsset→ github_repo
	// →DependsOn→ package — so a silent label drop here would take the whole chain
	// with it. container_image carries no label of its own, so it promotes to Asset
	// and routes to DefinedInAsset.
	{"defined_in", "container_image", "github_repo", "correlate/image_ownership.go"},
	{"defined_in", "k8s_service", "github_repo", "correlate/iac.go"},
	{"defined_in", "k8s_deployment", "github_repo", "correlate/iac.go"},
	{"defined_in", "k8s_daemonset", "github_repo", "correlate/iac.go"},
	{"defined_in", "k8s_job", "github_repo", "correlate/iac.go"},
	{"depends_on", "github_repo", "package", "collect/github/sbom.go"},
	{"deploys_to", "github_repo", "k8s_pod", "correlate/deploys.go"},
	{"dns_points_to", "dns_record", "dns_record", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "elastic_ip", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "load_balancer", "correlate/dns.go"},
	{"executes_as", "gce_instance", "gcp_service_account", "correlate/executes_as.go"},
	{"executes_as", "cloud_function", "gcp_service_account", "correlate/executes_as.go"},
	{"executes_as", "k8s_pod", "gcp_service_account", "correlate/executes_as.go"},
	{"executes_as", "ecs_service", "iam_role", "correlate/executes_as.go"},
	{"executes_as", "cloudrun_service", "gcp_service_account", "correlate/executes_as.go"},
	// GKE Workload Identity. Absent from this list, so the guard
	// never saw it; every fresh row was discarded at COPY.
	{"federated_access", "k8s_service_account", "gcp_service_account", "correlate/gcp_wif.go"},
	{"federated_access", "github_repo", "iam_role", "correlate/federation_trust.go"},
	{"federated_access", "github_repo", "gcp_service_account", "correlate/ci_access.go"},
	{"grants_access_to", "sso_permission_set", "cloud_account", "collect/aws/identitycenter.go"},
	{"grants_admin", "sso_permission_set", "cloud_account", "collect/aws/identitycenter.go"},
	{"protected_by", "ec2_instance", "security_group", "collect/aws/aws.go"},
	{"routes_to", "k8s_ingress", "k8s_service", "correlate/k8s_ingress.go"},
	{"runs_package", "container_image", "package", "scanner/imagevuln"},
	// runs_image has exactly ONE producer and ONE shape — verified against graph_edges:
	// all deduped-fresh rows are k8s_pod → container_image. Its rel is
	// Loaded (and K8sWorkload→Asset), so it needs a triple here.
	{"runs_image", "k8s_pod", "container_image", "collect/kubernetes/kubernetes.go:567"},
	// The ECS and Cloud Run collectors emit the same edge from Asset-labelled
	// services; buildEdgeRows reroutes them to RunsImageAsset.
	{"runs_image", "ecs_service", "container_image", "collect/aws/ecs.go"},
	{"runs_image", "cloudrun_service", "container_image", "collect/gcp/cloudrun.go"},
	{"routes_to", "load_balancer", "ecs_service", "collect/aws/ecs.go"},
	{"sg_allows_from", "gce_instance", "gce_instance", "correlate/secgroups.go"},
	{"targets", "k8s_service", "k8s_pod", "correlate/k8s_service.go"},
	{"targets", "k8s_service", "k8s_statefulset", "correlate/k8s_service.go"},
	{"targets", "k8s_service", "k8s_job", "correlate/k8s_service.go"},

	// ── Transcribed from graph_edges ─────────────────────────────
	//
	// The earlier pass above said it was seeded from "every shape in the 48h
	// fresh window", and it was not: dozens of shapes routing to Loaded rels were
	// still missing, and one of them — exposed_to_internet from a K8sWorkload-labelled
	// source — was the seventh instance of the class.
	// The transcription is now exhaustive against the query in the comment above,
	// re-run since, and TestProducerEdgesCoverEveryLoadedEdgeType below
	// asserts that every edge_type reaching a Loaded rel appears here at all, so
	// "the guard was sound but its input was incomplete" cannot recur silently for
	// a whole edge type.
	{"exposed_to_internet", "gce_instance", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "load_balancer", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "gcp_forwarding_rule", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "k8s_ingress", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "ecs_service", "internet", "correlate/reachability.go"},
	// K8sWorkload-labelled sources against an Asset→Asset rel.
	{"exposed_to_internet", "k8s_pod", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "k8s_deployment", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "s3_bucket", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "gcs_bucket", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "azure_webapp", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "azure_public_ip", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "cloudrun_service", "internet", "correlate/reachability.go"},
	{"exposed_to_internet", "cloudsql_instance", "internet", "correlate/reachability.go"},
	{"accesses_secret", "iam_role", "secret_wildcard", "correlate/secret_access.go"},
	{"accesses_secret", "iam_role", "ssm_parameter", "correlate/secret_access.go"},
	{"accesses_secret", "gcp_service_account", "gcp_secret", "correlate/secret_access.go"},
	{"accesses_secret", "iam_user", "secret_wildcard", "correlate/secret_access.go"},
	{"accesses_secret", "iam_user", "ssm_parameter", "correlate/secret_access.go"},
	{"accesses_secret", "iam_user", "secretsmanager_secret", "correlate/secret_access.go"},
	{"assigned_to", "sso_group", "sso_permission_set", "collect/aws/identitycenter.go"},
	{"binds", "k8s_service_account", "k8s_role_binding", "collect/kubernetes/rbac.go"},
	{"can_assume", "gcp_service_account", "gcp_service_account", "correlate/iam.go"},
	// can_assume/aws_account->iam_role (many fresh rows) is deliberately absent:
	// `aws_account` is not an asset type at all (no rows in assets), it is the
	// SrcType a trust-policy principal ARN is stamped with. Nearly all of those src_ids
	// are cross-account root ARNs that are not assets and never will be; the rest
	// resolve to iam_user assets, which ARE IamRole-labelled and load fine. The
	// loader keys on the endpoint's REAL asset type (nodeLabel), not on SrcType, so
	// this is endpoint attrition, not a label mismatch — listing it would assert a
	// bug against a type that has no node under any label.
	{"contains_data", "ssm_parameter", "data_class", "correlate/dspm.go"},
	{"contains_data", "gcp_secret", "data_class", "correlate/dspm.go"},
	{"contains_data", "cloudsql_instance", "data_class", "correlate/dspm.go"},
	{"contains_data", "rds_instance", "data_class", "correlate/dspm.go"},
	{"contains_data", "azure_sql_database", "data_class", "correlate/dspm.go"},
	{"contains_data", "azure_sql_server", "data_class", "correlate/dspm.go"},
	{"defined_in", "iam_role", "github_repo", "correlate/iac.go"},
	{"defined_in", "lambda_function", "github_repo", "correlate/iac.go"},
	{"defined_in", "ecs_service", "github_repo", "correlate/iac.go"},
	{"deploys_to", "github_repo", "lambda_function", "correlate/deploys.go"},
	{"deploys_to", "github_repo", "cloud_function", "correlate/deploys.go"},
	{"dns_points_to", "dns_record", "gcp_forwarding_rule", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "gce_instance", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "k8s_service", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "k8s_ingress", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "api_gateway", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "gcp_ssl_certificate", "correlate/dns.go"},
	{"dns_points_to", "dns_record", "acm_certificate", "correlate/dns.go"},
	{"executes_as", "lambda_function", "iam_role", "correlate/executes_as.go"},
	{"has_role", "ec2_instance", "iam_role", "correlate/ec2_iam.go"},
	{"routes_to", "k8s_ingress", "k8s_service", "correlate/k8s_ingress.go"},
	{"targets", "k8s_service", "k8s_daemonset", "correlate/k8s_service.go"},

	// ── The identity graph ───────────────────────────────────────────────────
	//
	// These three are NOT transcribed from graph_edges, and that is the
	// point: two of them are shapes no producer has ever emitted into a loaded
	// table, and the third has never had a row because its connector does not
	// exist yet. The lesson of v42/v44/v45 was that this list's INPUT is what
	// fails, so a new producer is transcribed here as it is written rather than
	// after ClickHouse proves it broken.
	//
	// federated_access/human_identity->iam_role (correlate/human_identity.go:92)
	// is the EIGHTH instance of the label class and the first caught before it
	// shipped. human_identity is absent from assetTypeToNode so it carries the
	// catch-all Asset label; the default FederatedAccess table is Repo→IamRole.
	// Zero rows today (no Okta/Google connector, human_identity count is 0), and
	// this triple fails without the FederatedAccessAsset reroute regardless —
	// which is exactly what a guard catching it before release looks like.
	{"federated_access", "human_identity", "iam_role", "correlate/human_identity.go:92"},
	// member_of, both shapes, from the Okta collector.
	{"member_of", "human_identity", "sso_group", "collect/okta/okta.go:127"},
	{"member_of", "sso_group", "sso_group", "collect/okta/okta.go:202"},
	// The pod→ServiceAccount hop. Both endpoints are K8sWorkload-labeled,
	// so it routes to ExecutesAsK8sServiceAccount; the K8sWorkload→IamRole reroute
	// that serves every other k8s executes_as row would drop it on the dst label.
	{"executes_as", "k8s_pod", "k8s_service_account", "correlate/k8s_service_account.go"},
}

// knownBrokenProducers is EMPTY, and must stay that way.
//
// It previously held 8 triples that were silently discarded at Ladybug load. Seven of
// them traced to exactly two label promotions — `ec2_instance` → EC2Instance and
// `security_group` → SecurityGroup — and both labels were removed rather than adding
// seven reroute tables, so the class is fixed at its root: those column lists were
// identical to Asset's and discriminated nothing Asset.type does not.
//
// The eighth, `allows_action/iam_role->iam_policy`, was never a label mismatch at
// all: AllowsAction is declared bfs_only in the registry (DropReason:
// "permission-category detail — surfaced through findings, not graph traversal"),
// so buildEdgeRows routes it nowhere ON PURPOSE. Listing it as broken conflated a
// deliberate design decision with a bug. It is excluded from producerEdges instead,
// where the registry's own DropReason is the documentation.
//
// Never add an entry here. A producer triple that does not route to a matching rel
// table is an edge that Ladybug discards with no error, no warning and no metric — the
// bug class that recurred before this guard existed. Fix the routing or
// the label, not the test.
var knownBrokenProducers = map[string]bool{}

// TestProducerEdgesCoverEveryLoadedEdgeType closes the hole that let three
// defects ship WITH the class guard already in place: the guard only
// checks triples it is given, so an edge type absent from producerEdges is
// unverified, and three of them were broken.
//
// It cannot assert that every (src_type, dst_type) SHAPE is listed — that set
// lives in ClickHouse, not in the type system. It can assert the weaker
// invariant that no synced edge type feeding a Loaded rel is missing ENTIRELY,
// which is the granularity at which "we forgot federated_access from k8s" and
// "we forgot exposed_to_internet from k8s" both begin.
func TestProducerEdgesCoverEveryLoadedEdgeType(t *testing.T) {
	covered := map[string]bool{}
	for _, pe := range producerEdges {
		covered[pe.edgeType] = true
	}
	for _, et := range graphschema.EdgeTypes {
		if et.Tier == graphschema.TierUnsynced {
			continue // never fetched — nothing to verify
		}
		tables := append([]string{et.Rel}, et.Reroutes...)
		loaded := false
		for _, tbl := range tables {
			if tbl != "" && ladybugQueryableRelTable(tbl) {
				loaded = true
			}
		}
		if !loaded {
			continue // declared bfs_only/inherit_only — routes nowhere on purpose
		}
		require.True(t, covered[et.Type],
			"edge_type %q is fetched and feeds a Loaded rel table, but no producerEdges "+
				"triple names it — TestProducerEdgeLabelsMatchRelTables therefore never "+
				"checks it, which is exactly how federated_access and "+
				"exposed_to_internet shipped broken with this guard in place. "+
				"Add its (src_type, dst_type) shapes from the ClickHouse query above.",
			et.Type)
	}
}

// TestProducerEdgeLabelsMatchRelTables is the class guard. For every triple a
// producer emits, route it exactly as the loader would and assert the row lands in
// a rel table whose declared endpoints match the labels those asset types actually
// promote to. A mismatch here is an edge that Ladybug will silently discard.
func TestProducerEdgeLabelsMatchRelTables(t *testing.T) {
	for _, pe := range producerEdges {
		key := pe.edgeType + "/" + pe.srcType + "->" + pe.dstType
		t.Run(key, func(t *testing.T) {
			// Endpoint types the graph excludes BY DESIGN are not label bugs. A type
			// in asset.NeverSyncTypes is filtered out at the SQL fetch, so its node
			// never exists under ANY label and the edge is correctly accounted as
			// endpoint_absent, never as a mismatch. Asserting on them conflates a
			// documented exclusion with a defect — the same conflation the
			// allows_action note below describes. Example: dns_points_to/
			// dns_record->elastic_ip (many rows) — elastic_ip is NeverSync AND has
			// no node loader entry at all, so NodeLabelFor's ElasticIP mapping is
			// vestigial and those rows can never load whatever the rel declares.
			if neverKeepTypes[pe.srcType] || neverKeepTypes[pe.dstType] {
				t.Skipf("%s: endpoint type is in asset.NeverSyncTypes — excluded from the graph by design, so this can never be a label mismatch", pe.producer)
			}
			if knownBrokenProducers[key] {
				t.Skipf("KNOWN BROKEN — edge silently discarded at Ladybug load. "+
					"%s. See knownBrokenProducers for the root cause and the fix.", pe.producer)
			}
			rows := buildEdgeRows([]asset.Edge{{
				SrcID: "src", SrcType: pe.srcType,
				DstID: "dst", DstType: pe.dstType,
				EdgeType: pe.edgeType,
			}})

			var relTable string
			for rel, r := range rows {
				if len(r.rows) > 0 {
					relTable = rel
				}
			}
			require.NotEmpty(t, relTable,
				"%s: edge_type %q is not routed to any loaded rel table — it never reaches the graph",
				pe.producer, pe.edgeType)

			spec, ok := ladybugRelSpec[relTable]
			require.True(t, ok, "%s: rel table %q is not loaded into Ladybug", pe.producer, relTable)

			wantFrom, wantTo := NodeLabelFor(pe.srcType), NodeLabelFor(pe.dstType)
			require.Equal(t, spec.from, wantFrom,
				"%s: %s emits SrcType %q which is labelled %s, but rel table %s expects FROM %s — "+
					"the loader's MATCH will find nothing and Ladybug will SILENTLY DISCARD every such edge. "+
					"Fix by adding a reroute in buildEdgeRows to a rel table typed %s→%s (see the "+
					"executes_as/targets/binds precedents), not by changing the producer.",
				pe.producer, pe.edgeType, pe.srcType, wantFrom, relTable, spec.from, wantFrom, wantTo)
			require.Equal(t, spec.to, wantTo,
				"%s: %s emits DstType %q which is labelled %s, but rel table %s expects TO %s — "+
					"same silent-discard failure as above, on the destination side.",
				pe.producer, pe.edgeType, pe.dstType, wantTo, relTable, spec.to)
		})
	}
}

// TestProducerEndpointsAreNotSyncExcluded closes the SIXTH variant of the bug class this
// file's header documents.
//
// The existing guards check that a producer's endpoint TYPE promotes to the node LABEL
// its rel table declares. They cannot see the other way an endpoint goes missing: the
// asset type being excluded from the sync at the SQL level by asset.NeverSyncTypes. That
// exclusion happens before filterLadybugAssets runs, so retentionEdgeTypes — the mechanism
// that exists precisely to keep an edge's endpoints alive — is powerless against it, and
// the edge is discarded at COPY as endpointAbsent, the one drop reason operators are
// explicitly told is normal attrition.
//
// Example: elastic_ip was in NeverSyncTypes while producerEdges declared
// {"dns_points_to", "dns_record", "elastic_ip"}, so most fresh dns_points_to
// edges never loaded and dns_chain_exposure was missing most of its input. The
// declaration and the exclusion had coexisted, each individually defensible, with
// nothing comparing them.
func TestProducerEndpointsAreNotSyncExcluded(t *testing.T) {
	excluded := make(map[string]bool, len(asset.NeverSyncTypes))
	for _, ty := range asset.NeverSyncTypes {
		excluded[ty] = true
	}

	for _, pe := range producerEdges {
		if !retentionEdgeTypes[pe.edgeType] {
			// Not a retention edge: its endpoints are not promised a place in the
			// graph, so exclusion is a legitimate scope decision rather than a
			// contradiction.
			continue
		}
		for _, ep := range []struct{ role, ty string }{{"src", pe.srcType}, {"dst", pe.dstType}} {
			require.Falsef(t, excluded[ep.ty],
				"%s emits %s edges with %s type %q, and %q is in asset.NeverSyncTypes. "+
					"%s is a retention edge, so the graph promises to keep its endpoints — but "+
					"NeverSyncTypes excludes them at the SQL level, before filterLadybugAssets can, "+
					"so every one of these edges is dropped at COPY as endpointAbsent: silently, "+
					"and under the drop reason operators are told to ignore. Either remove %q from "+
					"NeverSyncTypes, or stop declaring the edge a retention edge.",
				pe.producer, pe.edgeType, ep.role, ep.ty, ep.ty, pe.edgeType, ep.ty)
		}
	}
}

// TestOwnsProducersMatchDeclaredRelEndpoints guards the declared-vs-emitted
// endpoint mismatch specifically for "owns", the one edge type
// TestProducerEdgeLabelsMatchRelTables cannot check: Owns/OwnsAsset are
// declared bfs_only (DropReason), so neither is in ladybugRelSpec,
// relTableForEdge returns "" for every owns edge today, and the class guard
// above deliberately skips it — same as allows_action. That is correct for
// BEHAVIOR (nothing loads, so nothing can be silently discarded) but it means
// the registry's declared From/To for owns could drift from what the
// producers actually emit with nothing catching it until the day Owns (or
// OwnsAsset) is promoted to Loaded. This test checks the DECLARATION itself
// directly against graphschema.Rels — not graphstore.ladybugRelSpec, which is
// empty for owns today — so it holds regardless of Owns' load status.
func TestOwnsProducersMatchDeclaredRelEndpoints(t *testing.T) {
	relsByName := map[string]graphschema.Rel{}
	for _, r := range graphschema.Rels {
		relsByName[r.Name] = r
	}
	var ownsEdgeType graphschema.EdgeType
	found := false
	for _, e := range graphschema.EdgeTypes {
		if e.Type == "owns" {
			ownsEdgeType = e
			found = true
			break
		}
	}
	require.True(t, found, "owns edge type missing from registry")

	candidates := append([]string{ownsEdgeType.Rel}, ownsEdgeType.Reroutes...)

	producers := []producerEdge{
		// collect/aws/aws.go's ownsEdge is unexported (not callable from this
		// package's test), and its SrcType/DstType are fixed string literals at
		// its one call site (aws.go:954) that have been stable since Owns
		// existed — transcribed by hand, same as every other entry in
		// producerEdges above.
		{"owns", "cloud_account", "ec2_instance", "collect/aws/aws.go"},
	}

	for _, pe := range producers {
		t.Run(pe.srcType+"->"+pe.dstType, func(t *testing.T) {
			wantFrom, wantTo := NodeLabelFor(pe.srcType), NodeLabelFor(pe.dstType)
			matched := false
			for _, rn := range candidates {
				r, ok := relsByName[rn]
				require.True(t, ok, "owns names unknown rel %q", rn)
				if r.From == wantFrom && r.To == wantTo {
					matched = true
					break
				}
			}
			require.True(t, matched,
				"%s emits owns edges (%s -> %s, labels %s -> %s) that no rel table in owns' "+
					"default+Reroutes set (%v) declares — this is the declared-vs-emitted endpoint mismatch: "+
					"Owns/OwnsAsset are bfs_only today so nothing loads and nothing discards, but the "+
					"declared registry must still be correct so promoting either to Loaded does not "+
					"silently drop this producer's rows",
				pe.producer, pe.srcType, pe.dstType, wantFrom, wantTo, candidates)
		})
	}
}

// TestEveryMappedLabelIsLoadable closes the dead-label class at the root.
//
// assetTypeToNode promotes asset types to node labels, and the COPY loader emits rows
// only for labels present in nodeCSVCols (streamNodeRows skips anything absent from
// nodeUnwindQ). A type mapped to a label that neither declares is therefore loaded into
// the Go heap, filtered, digested — and then never becomes a node. Every edge touching
// it is discarded at COPY, as endpointAbsent if the type is also SQL-excluded or as
// label_mismatch if it is not.
//
// Three such labels existed simultaneously, all from one batch: NodeElasticIP,
// NodeDNSZone and NodeIamPolicy. The consequence was real for the first —
// most dns_points_to edges lost, leaving dns_chain_exposure without most of its
// input — and was harmless for the other two only by accident, because their edge types
// happen to be unfed by other decisions (member_of_zone TierUnsynced; has_policy and
// allows_action not_loaded). "Harmless by coincidence" is not a property to rely on:
// the moment anyone loads has_policy, IamPolicy endpoints would start vanishing
// silently.
//
// Labels may still be DECLARED in graphschema without being loadable — rel tables name
// them, and the registry tracks unfed tables deliberately with a DropReason. What must
// not happen is an ASSET TYPE being routed to one.
func TestEveryMappedLabelIsLoadable(t *testing.T) {
	for assetType, label := range assetTypeToNode {
		_, hasCols := nodeCSVCols[label]
		_, hasUnwind := nodeUnwindQ[label]
		require.Truef(t, hasCols && hasUnwind,
			"assetTypeToNode routes %q to label %q, but that label is not loadable "+
				"(nodeCSVCols: %v, nodeUnwindQ: %v). Assets of this type will be read, filtered "+
				"and digested, then never emitted as nodes, and every edge touching them will be "+
				"discarded at COPY — silently. Either wire the label into nodeCSVCols and "+
				"nodeUnwindQ, or map the type to NodeAsset as v41/v51/v52 did.",
			assetType, label, hasCols, hasUnwind)
	}
}
