package graphstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// TestRegistryDerivationsMatchLegacy pins the graphschema-derived lists to the
// exact hand-maintained literals they replaced. A registry edit that
// changes what Ladybug loads/traverses must consciously update this pin — that is
// the point: no more silent drift between the fetch, mapping, and load layers.
func TestRegistryDerivationsMatchLegacy(t *testing.T) {
	// has_role moved bulk→critical: it is a reach edge, and
	// the capped bulk tier truncates — every Reach type must be uncapped.
	// routes_to + targets moved bulk→critical: they are the k8s
	// exposure-chain reach edges, and the reach invariant requires every reach
	// edge to be uncapped (a capped reach edge truncates and the BFS misses paths).
	assert.ElementsMatch(t, []string{
		"exposed_to_internet", "can_assume", "executes_as", "federated_access",
		"can_escalate_to", "deploys_to", "sg_allows_from", "accesses_secret",
		"protected_by", "binds", "owns", "has_policy", "allows_action",
		"connected_via_sg", "has_role", "routes_to", "targets",
		// grants_admin: a permission set granting admin on an account is
		// an attack-path edge, so it's uncapped critical + reach like the other
		// privilege-escalation edges, not bulk like the other 3 SSO edge types.
		"grants_admin",
		// The runtime Inherit types moved bulk→critical. Inheritance is
		// reachability, and the bulk tier's shared 500k cap — applied
		// after ORDER BY edge_type — was starving these to ZERO rows on every
		// build, which emptied graphstore's inheritAdj and made ReachComplete()
		// false forever. graphschema.TestReachAndInheritTypesAreCritical is the
		// invariant; this is the conscious pin.
		"runs_image", "runs_container",
		// member_of is critical-tier. It is not a Reach type, so the
		// invariant test does not force the tier — this is the deliberate choice:
		// the bulk tier's shared cap is at its limit and starves alphabetically-late
		// types to zero, and member_of at zero rows silently deletes the whole
		// identity half of the SSO graph rather than thinning it.
		"member_of",
		// defined_in moved bulk→critical when it became an Inherit
		// type. It is the IaC-ownership half of repo reachability: every defined_in
		// rel points <resource> → Repo, so the declaring repo takes the declared
		// resource's hop count. Same invariant as the runs_* types above —
		// inheritance IS reachability, so it cannot sit under the bulk cap.
		"defined_in",
	}, graphschema.TierEdgeTypes(graphschema.TierCritical), "critical tier drifted")

	assert.ElementsMatch(t, []string{
		"dns_points_to",
		"peered_with", "contains_data",
		// in_vpc LEFT this tier (→ unsynced): InVPC was Loaded but
		// every in_vpc destination type is in NeverSyncTypes, so all fetched
		// rows were discarded again at COPY (loaded=0 on every build) and no query,
		// expand branch or frontend template traverses the table.
		// SSO graph: assignment/access-grant/declared-in context, not
		// attack-path edges.
		// defined_in LEFT this tier (→ critical): see the Inherit note
		// in the critical list above.
		"assigned_to", "grants_access_to",
		// runs_in LEFT this tier (→ unsynced): un-starving it revealed
		// that most of its rows are k8s_pod→k8s_namespace, whose destination type is
		// in NeverSyncTypes and whose K8sWorkload-labelled source made every row a
		// label mismatch on Accesses — a ReachRel, so the WARN fired every build.
		//
		// member_of_zone and in_subnet LEFT this tier (→ unsynced):
		// MemberOfZone/InSubnet are not Loaded rels, so all fetched rows were
		// discarded again at COPY while starving the alphabetically-later bulk
		// types — including runs_in, which does feed a loaded rel — out of the
		// fetch entirely.
	}, graphschema.TierEdgeTypes(graphschema.TierBulk), "bulk tier drifted")

	wantLoaded := []string{
		"ExposedToInternet", "DnsPointsTo", "ConnectedViaSG", "AllowsFrom",
		"ProtectedBy", "HasRole", "ExecutesAs", "ExecutesAsK8sWorkload",
		"CanAssume", "CanEscalateTo", "DeploysTo", "DeploysToService",
		"Binds", "AccessesSecret", "FederatedAccess",
		// Directly-exposed k8s workload, split out of ExposedToInternet
		// (Asset→Asset) because k8s_pod/k8s_deployment are K8sWorkload-labeled
		// and every such row was dropped at COPY.
		"ExposedToInternetK8sWorkload",
		// GKE Workload Identity: k8s ServiceAccount → cloud role, split out of
		// FederatedAccess (Repo→IamRole) because k8s_service_account is
		// K8sWorkload-labeled and every such row was dropped at COPY.
		"FederatedAccessK8sWorkload",
		"Accesses", "AccessesK8sWorkload", "ContainsData",
		// SSO graph
		"AssignedTo", "GrantsAccessTo", "GrantsAdmin",
		// IaC ownership
		"DefinedInK8sWorkload", "DefinedInAsset",
		// IaC ownership: IAM role declared in a repo
		"DefinedInIamRole",
		// k8s RBAC: ServiceAccount→ClusterRoleBinding, split out of Binds because
		// k8s_service_account is K8sWorkload-labeled and Binds is Asset→Asset,
		// so every SA-subject row was silently dropped at COPY.
		"BindsK8sWorkload",
		// RunsImage: the pod→container_image hop, loaded so the supply-chain
		// chain package ← RunsPackage ← container_image ← RunsImage ← k8s_pod is
		// traversable in Ladybug. Its DDL endpoints moved Asset→Asset ⇒ K8sWorkload→Asset
		// in the same version (its only producer emits k8s_pod sources).
		// RunsImageAsset: the same hop from the Asset-labelled ECS / Cloud
		// Run services, which RunsImage's K8sWorkload source would drop at COPY.
		"RunsImageAsset",
		"RunsImage",
		// The identity graph. FederatedAccessAsset reroutes the label-promotion
		// class (human_identity carries the catch-all Asset label against a
		// Repo→IamRole table). MemberOf/MemberOfGroup are the human→group→group chain that puts
		// a person on the other end of the SSO nodes. ExecutesAsK8sServiceAccount is
		// the pod→ServiceAccount hop that had no rel table at all.
		"FederatedAccessAsset", "MemberOf", "MemberOfGroup", "ExecutesAsK8sServiceAccount",
	}
	assert.ElementsMatch(t, []string{"runs_package", "depends_on"}, graphschema.OnDemandEdgeTypes())
	var gotLoaded []string
	for rel := range ladybugRelSpec {
		gotLoaded = append(gotLoaded, rel)
	}
	assert.ElementsMatch(t, wantLoaded, gotLoaded, "ladybugRelSpec (loaded set) drifted")

	// routes_to + targets added: the internet→ingress→service→pod
	// exposure chain is now attacker-movement, so the internet-hops BFS crosses it.
	assert.Equal(t, map[string]bool{
		"executes_as": true, "has_role": true, "can_assume": true,
		"can_escalate_to": true, "accesses_secret": true,
		"routes_to": true, "targets": true,
		// binds (k8s RBAC): the middle of workload→SA→binding→ClusterRole, the only
		// path connecting an exposed workload to the RBAC privileges it holds.
		"binds": true,
		// grants_admin: admin access to an account is attacker movement
		// for the internet-hops BFS, same class as can_assume/can_escalate_to.
		"grants_admin": true,
	}, reachEdgeTypes, "reach edge set drifted")

	// PeeredWith removed from the expand view: it is not loaded into
	// Ladybug, so its branch always returned zero rows — pure dead traversal.
	wantExpand := []string{
		"ExposedToInternet", "ExposedToInternetK8sWorkload", "AllowsFrom", "ProtectedBy",
		"DnsPointsTo", "Accesses", "AccessesK8sWorkload", "HasRole", "ExecutesAs", "CanAssume", "CanEscalateTo",
		// SSO graph
		"AssignedTo", "GrantsAccessTo", "GrantsAdmin",
		// IaC ownership
		"DefinedInK8sWorkload", "DefinedInAsset",
		// IaC ownership: IAM role declared in a repo
		"DefinedInIamRole",
		// k8s RBAC: ServiceAccount→ClusterRoleBinding, split out of Binds because
		// k8s_service_account is K8sWorkload-labeled and Binds is Asset→Asset,
		// so every SA-subject row was silently dropped at COPY.
		"Binds", "BindsK8sWorkload",
		// Runtime image and deployment branches stay resident; package
		// memberships are served from inventory on demand.
		"RunsImage", "DeploysTo", "DeploysToService",
		// RunsImageAsset: expanding an ECS / Cloud Run image reaches the
		// service running it, exactly as RunsImage does for a pod.
		"RunsImageAsset",
		// ExecutesAsK8sWorkload: ExecutesAs (the Asset-sourced half of the same edge
		// type) is in the expand view; without this half, expanding an EC2 instance
		// shows its IAM role and expanding a pod shows nothing.
		"ExecutesAsK8sWorkload",
		// The identity chain (MemberOf/MemberOfGroup) and the pod→ServiceAccount
		// hop. FederatedAccessAsset is deliberately NOT here — neither FederatedAccess
		// nor FederatedAccessK8sWorkload is in the expand view, and adding only the
		// new split would recreate the ExecutesAs/ExecutesAsK8sWorkload asymmetry.
		// All three go in together or none do.
		"MemberOf", "MemberOfGroup", "ExecutesAsK8sServiceAccount",
	}
	var gotExpand []string
	for _, rs := range neighborRels {
		gotExpand = append(gotExpand, rs.label)
	}
	// Set equality: each expand rel is an independent per-rel query branch in
	// neighbors(), so branch order is irrelevant to results.
	assert.ElementsMatch(t, wantExpand, gotExpand, "expand view (neighborRels) drifted")
}

// TestFederatedAccessCoversRepoToGCPServiceAccount pins the invariant the
// CI-workflow→federated_access rule depends on: a GCP service account is
// NOT a separate Ladybug node type — assetTypeToNode maps "gcp_service_account"
// to the same IamRole node table as "iam_role"/"iam_user" — and the existing
// Repo→IamRole FederatedAccess rel is already loaded. So a correlate rule that
// emits a federated_access edge from a github_repo to a gcp_service_account
// lands on this same rel table (as k8s_service_account→gcp_service_account
// already does in gcp_wif.go, and as the gcp_oidc_federation named query
// already assumes). No new Rel, no SchemaVersion bump, no Ladybug DDL change is
// needed for that endpoint pair.
func TestFederatedAccessCoversRepoToGCPServiceAccount(t *testing.T) {
	require.Equal(t, NodeIamRole, assetTypeToNode["gcp_service_account"],
		"gcp_service_account must map to the IamRole node table for Repo->gcp_service_account federated_access edges to land on the existing Repo->IamRole rel")

	var found bool
	for _, r := range graphschema.Rels {
		if r.Name == "FederatedAccess" && r.From == NodeRepo && r.To == NodeIamRole {
			found = true
			assert.True(t, r.Loaded, "Repo->IamRole FederatedAccess must be loaded")
		}
	}
	assert.True(t, found, "Repo->gcp_service_account (IamRole) FederatedAccess rel must exist and be loaded")
}

// TestLadybugRelSpecMatchesDDL pins every loaded rel's endpoints AND property
// column names to its CREATE REL TABLE statement. A wrong From/To here would
// silently drop every row at the COPY endpoint pre-filter; a wrong prop column
// aborts the COPY. This closes the gap TestNeighborRelsMatchSchema only covered
// for the expand subset.
func TestLadybugRelSpecMatchesDDL(t *testing.T) {
	for rel, spec := range ladybugRelSpec {
		// quoteLabel backtick-escapes "Group": Ladybug's Cypher parser
		// rejects the keyword bare anywhere it appears as an identifier, so
		// schemaDDL's actual CREATE REL TABLE text carries the escaped form.
		decl := fmt.Sprintf("CREATE REL TABLE IF NOT EXISTS %s(FROM %s TO %s", rel, quoteLabel(spec.from), quoteLabel(spec.to))
		start := strings.Index(schemaDDL, decl)
		require.GreaterOrEqual(t, start, 0,
			"loaded rel %q (%s→%s) has no matching CREATE REL TABLE in schemaDDL: want %q",
			rel, spec.from, spec.to, decl)
		line := schemaDDL[start:]
		line = line[:strings.Index(line, ";")]
		for _, p := range spec.prop {
			assert.Contains(t, line, p.col+" STRING",
				"loaded rel %q: prop column %q not in its DDL declaration", rel, p.col)
		}
	}
	// Every prop override must target a loaded rel — a stale key here means the
	// registry dropped a rel but copy_load kept its column spec.
	for rel := range ladybugRelProps {
		_, ok := ladybugRelSpec[rel]
		assert.True(t, ok, "ladybugRelProps has entry for %q which is not a loaded rel", rel)
	}
}
