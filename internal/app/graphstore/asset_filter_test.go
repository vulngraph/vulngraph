package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// Every Reach edge type MUST retain its endpoints: a reachable node pruned here
// has its reach edge silently dropped at Ladybug insert, breaking the attack-path
// queries the graph exists to answer. This pins retentionEdgeTypes ⊇ the registry
// Reach set so the two can never drift (routes_to/targets regressed
// exactly this way when the set was hand-maintained).
func TestRetentionEdgeTypesCoverReachEdges(t *testing.T) {
	for et := range graphschema.ReachEdgeTypes() {
		require.True(t, retentionEdgeTypes[et],
			"reach edge %q must be in retentionEdgeTypes or its reachable endpoints get pruned", et)
	}
}

// TestRetentionEdgeTypesCoverLoadedRels is the generalisation of the test above,
// and it is the one that would have caught the contains_data gap.
//
// The Reach-set pin only covers attacker-movement edges. But the same failure
// applies to ANY edge whose rel table is Loaded: filterLadybugAssets prunes an
// endpoint, and the edge — declared traversable, referenced by real Cypher — is
// dropped at COPY as endpointAbsent, the one outcome operators are explicitly
// told not to alert on. contains_data once lost a large share of the
// DSPM graph to exactly this, because "contains_data" was absent from retentionEdgeTypes and
// secretsmanager_secret/ssm_parameter/azure_sql_* are absent from alwaysKeepTypes.
//
// The invariant: an edge type that is FETCHED and feeds a LOADED rel must retain
// its endpoints. Anything else is a contradiction in the registry — declaring a
// table traversable while pruning the nodes it traverses between.
func TestRetentionEdgeTypesCoverLoadedRels(t *testing.T) {
	for _, et := range graphschema.EdgeTypes {
		if et.Tier == graphschema.TierUnsynced {
			continue // never fetched — nothing to retain
		}
		loaded := false
		for _, tbl := range append([]string{et.Rel}, et.Reroutes...) {
			if tbl == "" {
				continue
			}
			if r, ok := graphschema.RelByName(tbl); ok && r.Loaded {
				loaded = true
			}
		}
		if !loaded {
			continue // bfs_only / inherit_only — deliberately not traversable
		}
		require.True(t, retentionEdgeTypes[et.Type],
			"edge_type %q feeds a Loaded (traversable) rel table but is not in "+
				"retentionEdgeTypes: filterLadybugAssets will prune its score-0 endpoints and "+
				"the edge is then dropped at COPY as endpointAbsent — silent, and explicitly "+
				"exempt from the drop alarm. Either retain it, or declare its rel unloaded "+
				"with a DropReason in the registry.", et.Type)
	}
}

// The k8s exposure chain reaches a score-0 service/pod only via
// routes_to/targets. Those endpoints must survive the filter or the chain
// vanishes from Ladybug.
func TestFilterLadybugAssets_KeepsK8sReachChain(t *testing.T) {
	assets := []asset.Asset{
		{ID: "ingress", Type: "k8s_ingress", RiskScore: 0},
		{ID: "svc", Type: "k8s_service", RiskScore: 0},
		{ID: "pod", Type: "k8s_pod", RiskScore: 0},
	}
	edges := []asset.Edge{
		{SrcID: "ingress", DstID: "svc", EdgeType: "routes_to"},
		{SrcID: "svc", DstID: "pod", EdgeType: "targets"},
	}
	got := filterLadybugAssets(assets, edges)
	ids := make([]string, len(got))
	for i, a := range got {
		ids[i] = a.ID
	}
	require.ElementsMatch(t, []string{"ingress", "svc", "pod"}, ids,
		"routes_to/targets endpoints must be retained")
}

func TestFilterLadybugAssets(t *testing.T) {
	mkAsset := func(id, typ string, score uint8) asset.Asset {
		return asset.Asset{ID: id, Type: typ, RiskScore: score}
	}

	assets := []asset.Asset{
		mkAsset("a1", "gce_instance", 0),   // has edge — keep
		mkAsset("a2", "k8s_configmap", 0),  // no edge, score=0, not always-keep — drop
		mkAsset("a3", "gcp_secret", 0),     // always-keep — keep
		mkAsset("a4", "ec2_instance", 42),  // score>0 — keep
		mkAsset("a5", "subnet", 0),         // no edge, score=0 — drop
		mkAsset("internet", "internet", 0), // always-keep sentinel — keep
		// Neither is kept: member_of_zone is not a retention edge, and
		// dns_zone is not in alwaysKeepTypes: member_of_zone is never fetched, so a
		// zone anchors no query.
		mkAsset("dns1", "dns_record", 0),
		mkAsset("zone1", "dns_zone", 0),
	}
	edges := []asset.Edge{
		{SrcID: "a1", DstID: "internet", EdgeType: "exposed_to_internet"},
		{SrcID: "dns1", DstID: "zone1", EdgeType: "member_of_zone"}, // not a retention edge
	}

	got := filterLadybugAssets(assets, edges)
	ids := make([]string, len(got))
	for i, a := range got {
		ids[i] = a.ID
	}
	require.ElementsMatch(t, []string{"a1", "a3", "a4", "internet"}, ids)
}

// TestFilterLadybugAssets_DNSRecordsAreEdgeGated pins the retention rule that took
// a large share of the node count out of the graph.
//
// dns_record was in alwaysKeepTypes on the justification "They're low-volume". At
// scale that is false by orders of magnitude,
// and only a tiny fraction carried a dns_points_to edge while ZERO carried a
// risk score — so unconditional retention was loading a huge number of nodes that no query
// can traverse from.
//
// The rule that matters is asymmetric and worth pinning in both directions: a
// record that resolves to real infrastructure MUST survive (dns_chain_exposure and
// the enrich production-traffic safety guard both traverse dns_points_to), and a
// record that resolves to nothing must not. Getting the first half wrong would
// silently break exposure reasoning, which is the failure mode this whole filter
// keeps producing (see the contains_data and runs_image comments above).
func TestFilterLadybugAssets_DNSRecordsAreEdgeGated(t *testing.T) {
	assets := []asset.Asset{
		{ID: "rec-resolving", Type: "dns_record"},            // dns_points_to → keep
		{ID: "rec-dangling", Type: "dns_record"},             // no edge at all → drop
		{ID: "rec-zone-only", Type: "dns_record"},            // member_of_zone only → drop
		{ID: "rec-scored", Type: "dns_record", RiskScore: 7}, // score>0 → keep
		{ID: "zone1", Type: "dns_zone"},                      // not always-keep → drop
		{ID: "lb1", Type: "load_balancer"},                   // dns_points_to target
	}
	edges := []asset.Edge{
		{SrcID: "rec-resolving", DstID: "lb1", EdgeType: "dns_points_to"},
		{SrcID: "rec-zone-only", DstID: "zone1", EdgeType: "member_of_zone"},
	}

	got := filterLadybugAssets(assets, edges)
	ids := make([]string, len(got))
	for i, a := range got {
		ids[i] = a.ID
	}
	require.ElementsMatch(t, []string{"rec-resolving", "rec-scored", "lb1"}, ids,
		"a DNS record that resolves to infrastructure must be retained; one that resolves "+
			"to nothing must not")
	require.True(t, retentionEdgeTypes["dns_points_to"],
		"dns_points_to must stay a retention edge — it is the only thing keeping resolving "+
			"records in the graph now that dns_record is not unconditionally kept")
	require.False(t, alwaysKeepTypes["dns_record"],
		"dns_record must not return to alwaysKeepTypes: it is a large share of the node count and "+
			"nearly all of it carries no traversable signal")
}

// SSO nodes are score-0 and not always-keep; they must be retained solely
// because they participate in an SSO edge. Without the SSO edge
// types in securityEdgeTypes the whole subgraph is filtered out of Ladybug and
// the Cypher presets return nothing.
func TestFilterLadybugAssets_KeepsSSOSubgraph(t *testing.T) {
	assets := []asset.Asset{
		{ID: "sso_group:Example Cloud Admins", Type: "sso_group", RiskScore: 0},
		{ID: "sso_permission_set:AdministratorAccess", Type: "sso_permission_set", RiskScore: 0},
		{ID: "aws:444455556666", Type: "cloud_account", RiskScore: 0},
		{ID: "orphan_group", Type: "sso_group", RiskScore: 0}, // no edge — drop
	}
	edges := []asset.Edge{
		{SrcID: "sso_group:Example Cloud Admins", DstID: "sso_permission_set:AdministratorAccess", EdgeType: "assigned_to"},
		{SrcID: "sso_permission_set:AdministratorAccess", DstID: "aws:444455556666", EdgeType: "grants_admin"},
		{SrcID: "sso_permission_set:AdministratorAccess", DstID: "aws:444455556666", EdgeType: "grants_access_to"},
	}

	got := filterLadybugAssets(assets, edges)
	ids := make([]string, len(got))
	for i, a := range got {
		ids[i] = a.ID
	}
	require.ElementsMatch(t, []string{
		"sso_group:Example Cloud Admins",
		"sso_permission_set:AdministratorAccess",
		"aws:444455556666",
	}, ids)
}
