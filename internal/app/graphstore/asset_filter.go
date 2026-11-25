package graphstore

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// retentionEdgeTypes are the edge types whose endpoints must survive
// filterLadybugAssets — an endpoint dropped here has its edge silently discarded at
// Ladybug insert (copyStats.droppedEndpointMiss). It is seeded from the graphschema
// registry's Reach edge types so it can NEVER drift from them again: a reachable
// node that is pruned breaks the very attack-path/reachability queries the graph
// exists to answer — this registry is the single source of truth for the edge
// pipeline (docs/adr/048-graphschema-registry.md). The non-reach entries below
// are query-traversed context edges (SSO/DSPM/SBOM/DNS/SG) that are not
// attacker-movement but still anchor named-query subgraphs.
//
// Deliberately EXCLUDED so pure-topology endpoints stay pruned (node-count
// budget): in_vpc, runs_in, member_of_zone, in_subnet, owns — adjacency that no
// named query traverses from a zero-value node.
var retentionEdgeTypes = func() map[string]bool {
	m := graphschema.ReachEdgeTypes() // can_assume, executes_as, routes_to, targets, …
	for _, t := range []string{
		"exposed_to_internet", // internet seed
		"federated_access",    // Repo→IamRole trust (reach-excluded but query-traversed)
		"protected_by",
		"dns_points_to",
		"sg_allows_from",
		"connected_via_sg",
		"peered_with",
		"deploys_to",
		"depends_on",
		"runs_package",
		// RunsImage is a Loaded, expand-traversable rel, so its pod endpoint must
		// survive the prune or the edge is dropped as endpointAbsent and the pod
		// half of "where does this package run" goes missing.
		"runs_image",
		"binds",
		// contains_data (DSPM). ContainsData is a Loaded rel the DSPM route's
		// Cypher traverses, but a data-bearing asset that is score-0 and not in
		// alwaysKeepTypes would otherwise be pruned and its edge dropped as
		// endpointAbsent, silently losing a large share of the DSPM graph.
		"contains_data",
		// SSO access graph: the ONLY reason sso_group/sso_permission_set/
		// cloud_account nodes (score-0, not always-keep) exist in Ladybug.
		"assigned_to",
		"grants_access_to",
		// defined_in: IaC ownership, so a declaring repo survives the prune
		// alongside the resource it declares.
		"defined_in",
		// member_of is the human half of that same access graph, and needs
		// retention for the identical reason: an Okta group node is score-0,
		// carries no findings, and is not in alwaysKeepTypes, so without this its
		// endpoints are pruned and every membership edge drops as endpointAbsent.
		// It also retains the human_identity nodes, which are score-0 by
		// construction.
		"member_of",
	} {
		m[t] = true
	}
	return m
}()

// alwaysKeepTypes are asset types retained regardless of edge count or risk score.
// These carry inherent security value as traversal targets or sentinels.
var alwaysKeepTypes = map[string]bool{
	"internet":            true, // ExposedToInternet sentinel
	"container_image":     true, // pod→image traversal for "pods running CVE-X image"
	"gcp_secret":          true,
	"s3_bucket":           true,
	"gcs_bucket":          true,
	"rds_instance":        true,
	"cloud_sql_instance":  true,
	"cloudsql_instance":   true,
	"acm_certificate":     true,
	"k8s_certificate":     true,
	"gcp_ssl_certificate": true,
	// IAM types are always kept — escalation chains need them even at score=0.
	"iam_role":                true,
	"iam_user":                true,
	"iam_group":               true,
	"gcp_service_account":     true,
	"azure_service_principal": true,
	"azure_managed_identity":  true,
	// Repos are always kept — DeploysTo and FederatedAccess queries depend on them.
	"github_repo": true,
	// dns_zone and dns_record are deliberately NOT always-keep. dns_zone's only
	// edge (member_of_zone) is TierUnsynced and never fetched, so a zone anchors
	// no query. dns_record is the same shape at much larger volume: the vast
	// majority carry no dns_points_to edge and no risk_score, so unconditional
	// retention loaded a large population of nodes no query can traverse from
	// and no signal attaches to. Both follow the normal retention rule
	// (edge or score) — a record that resolves to real infrastructure keeps its
	// dns_points_to edge and survives; one that only resolves to another record
	// does not, and no query loses anything because none could traverse to
	// either pruned population. Both types stay visible in ClickHouse and the
	// asset API like any other pruned type.
	//
	// Every consumer that scores or acts on dns_record findings is
	// Ladybug-free: the three layers of subdomain-takeover detection are a
	// check predicate over the collected asset, a live DNS/HTTP probe, and a
	// ClickHouse finding rollup keyed by resource id, not graph membership, so
	// none of them depend on dns_record being a Ladybug node.
	//
	// Caveat that matters for the NEXT type someone prunes: the `RiskScore > 0`
	// arm below is NOT a "has a finding" safety net. assets.risk_score is
	// collector-supplied, never derived from findings, so pruning is blind to
	// findings by construction — this is only safe here because every finding
	// consumer above was checked directly, not inferred from risk_score.
}

// neverKeepTypes mirrors asset.NeverSyncTypes as a set for O(1) lookup.
// These types are excluded from Ladybug both at the SQL fetch level (asset.NeverSyncTypes)
// and here as a second-pass guard. The single source of truth is asset.NeverSyncTypes.
var neverKeepTypes = func() map[string]bool {
	m := make(map[string]bool, len(asset.NeverSyncTypes))
	for _, t := range asset.NeverSyncTypes {
		m[t] = true
	}
	return m
}()

// NodeBudget is the node count this filter is designed to keep the graph under.
//
// It is deliberately NOT enforced: nothing refuses or trims a build that
// exceeds it. Refusing would leave a stale graph serving (or none, on a cold
// pod) on the strength of a proxy this comment calls weak below, and trimming
// would silently drop real topology. Crossing it is an alert, not an error.
//
// It is exported and emitted as graph_ladybug_node_budget so nodes-vs-budget is a
// gauge with an alert, not just a sentence in a comment — a stale budget that
// nothing compares against the live graph is worse than no budget at all.
//
// Derived from an example large-worker sizing and a per-node rule of thumb,
// not chosen freehand:
//
//	cgroup limit                          20,480 MiB   example sizing
//	− GOMEMLIMIT                           8,192 MiB   Go fills whatever it is given
//	= room above Go's ceiling             12,288 MiB
//	× 4/5 (alert with 20% unspent)         9,830 MiB
//	÷ ~23 KiB/node non-Go (rule of thumb)  ≈ 430,000 nodes (rounded down)
//
// TestNodeBudgetFitsTheDeployedMemoryLimit holds this constant and the helm
// values to this arithmetic, so neither can move alone. When the cgroup limit,
// GOMEMLIMIT, or the per-node non-Go cost changes, re-run the whole
// table rather than nudging the constant — a prediction that doesn't model
// filterLadybugAssets' edge coupling (pruning a node population also drops the
// retention edges that were keeping other nodes alive) will miss.
//
// It is still not a promise about RAM: node count is a WEAK proxy, since
// different asset cohorts carry very different per-node memory cost. Prefer
// the peak-vs-limit alert (GraphWorkerMemoryPeakNearLimit) as the memory
// signal; this one only answers "has the corpus grown past what the budget
// was sized for".
const NodeBudget = 430_000

// filterLadybugAssets removes assets that add no value to the in-memory Ladybug graph.
// The goal is to keep Ladybug's node count under NodeBudget so it fits its memory
// allowance as the inventory grows.
//
// An asset is retained if ALL of the following are true:
//   - Its type is NOT in neverKeepTypes (pure topology, never in a query)
//   - AND: it appears in at least one security edge, OR has RiskScore > 0,
//     OR its type is in alwaysKeepTypes
//
// Assets excluded by this filter are still in ClickHouse and returned by the
// asset API; they are simply not traversable via Ladybug Cypher. No named query
// may reference a never-keep type.
func filterLadybugAssets(assets []asset.Asset, edges []asset.Edge) []asset.Asset {
	if len(assets) == 0 {
		return assets
	}

	// Retain assets that appear in a query-traversed edge (retentionEdgeTypes,
	// registry-derived). Pure-topology edges (runs_in → Accesses, in_vpc → InVPC)
	// are excluded so they can't recreate the large clusters of zero-value nodes
	// the spoke-hub design removed.
	hasSecurityEdge := make(map[string]bool, len(edges))
	for i := range edges {
		if retentionEdgeTypes[edges[i].EdgeType] {
			hasSecurityEdge[edges[i].SrcID] = true
			hasSecurityEdge[edges[i].DstID] = true
		}
	}

	out := assets[:0]
	for _, a := range assets {
		if neverKeepTypes[a.Type] {
			continue // hard exclude — never loaded into Ladybug
		}
		if hasSecurityEdge[a.ID] || a.RiskScore > 0 || alwaysKeepTypes[a.Type] {
			out = append(out, a)
		}
	}
	return out
}
