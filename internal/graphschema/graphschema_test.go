package graphschema

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capabilityReachTypes are the Reach edge types whose risk propagates AGAINST
// the direction of attack, because what they record is a capability the
// source holds rather than a path by which something arrives at it. A
// capability edge must never be DirForward: forward credits only the far end
// of the chain and leaves the principal a remediation would actually touch
// unelevated.
//
// Deliberately closed and kept in the test rather than the registry: nothing
// derives from it, and the test asserts membership in BOTH directions, so a
// capability edge declared forward fails, and a Reach edge declared reverse
// without being listed here fails too.
var capabilityReachTypes = map[string]bool{
	// A can assume B: A inherits B's privilege, B inherits A's exposure. DirBoth.
	"can_assume": true,
	// The CIEM privesc edge, same shape as can_assume. DirBoth.
	"can_escalate_to": true,
	// A principal that can read a high-value secret is a higher-value target. The
	// secret inheriting the principal's exposure buys nothing, so DirReverse.
	"accesses_secret": true,
}

// TestRegistryConsistency is the gate the old hand-maintained lists never had:
// every synced edge type must either land in a Loaded rel table or carry an
// explicit DropReason on its rel — a silent drop becomes a declared,
// reviewable decision. It also catches structural drift inside the registry.
func TestRegistryConsistency(t *testing.T) {
	relByName := map[string]Rel{}
	for _, r := range Rels {
		_, dup := relByName[r.Name]
		require.False(t, dup, "duplicate rel %q", r.Name)
		require.NotEmpty(t, r.From, "rel %q missing From", r.Name)
		require.NotEmpty(t, r.To, "rel %q missing To", r.Name)
		require.NotEmpty(t, r.Doc, "rel %q missing Doc", r.Name)
		relByName[r.Name] = r
	}

	seenType := map[string]bool{}
	for _, e := range EdgeTypes {
		require.False(t, seenType[e.Type], "duplicate edge type %q", e.Type)
		seenType[e.Type] = true
		require.NotEmpty(t, e.Doc, "edge type %q missing Doc", e.Type)
		assert.Greater(t, e.Weight, 0.0, "edge type %q weight must be positive", e.Type)
		assert.LessOrEqual(t, e.Weight, 1.0, "edge type %q weight above 1.0", e.Type)

		// Every entry declares a risk direction, including the unsynced ones: the
		// BFS indexed every edge in BOTH directions until it was fixed, so an
		// undeclared direction is not a neutral omission — it is the old defect,
		// where an asset inherited risk from principals that cannot reach it.
		// DirectionFor's fail-open default covers an unknown edge type from a new
		// producer; it must not become the answer for a registered one.
		assert.Contains(t, []Direction{DirForward, DirReverse, DirBoth}, e.Dir,
			"edge type %q declares no valid Dir — the BFS would fall back to indexing it in both "+
				"directions, which is the undirected-risk defect", e.Type)

		// A Reach type is one an attacker moves along src→dst (graphstore/reach.go).
		// Risk propagation is a DIFFERENT quantity and may run the other way, so
		// there is no blanket Reach ⇒ forward rule — there was one until
		// a later fix, and it was wrong for exactly the capability edges pinned in
		// capabilityReachTypes below.
		//
		// There is deliberately NO Inherit ⇒ forward rule either. runs_package is
		// Reach-adjacent containment: Inherit (the package takes the image's hop
		// count, so reachability flows INTO the container) and DirReverse (the image
		// takes the package's CVE severity, so risk flows OUT of it). The two
		// quantities travel in opposite directions across a containment edge and
		// constraining them together would force one of them to be wrong.
		// What IS pinned: a Reach type must be forward UNLESS it is a declared
		// capability edge, and a capability edge must never be forward.
		if capabilityReachTypes[e.Type] {
			assert.Contains(t, []Direction{DirReverse, DirBoth}, e.Dir,
				"edge type %q is a capability edge but propagates risk %q. Risk score is blast radius, "+
					"so the principal must inherit the risk of what it can reach; forward credits the far "+
					"end of the chain and leaves the role a remediation would actually touch unelevated",
				e.Type, e.Dir)
		} else if e.Reach {
			assert.Contains(t, []Direction{DirForward, DirBoth}, e.Dir,
				"edge type %q is Reach (attacker movement src→dst per reach.go) and is not a declared "+
					"capability edge, but propagates risk %q — either it is an exposure edge and must be "+
					"forward, or it is a capability edge and belongs in capabilityReachTypes", e.Type, e.Dir)
		}

		for _, r := range e.Reroutes {
			_, ok := relByName[r]
			assert.True(t, ok, "edge type %q reroutes to unknown rel %q", e.Type, r)
			assert.NotEqual(t, e.Rel, r, "edge type %q lists its default rel %q as a reroute", e.Type, r)
		}

		if e.Rel == "" {
			assert.Equal(t, TierUnsynced, e.Tier,
				"edge type %q has no rel mapping but is in a sync tier — it would be fetched then dropped to the generic Edge table", e.Type)
			continue
		}
		rel, ok := relByName[e.Rel]
		require.True(t, ok, "edge type %q maps to unknown rel %q", e.Type, e.Rel)

		// THE gate: synced + mapped but not loaded ⇒ must say why.
		if e.Tier != TierUnsynced && !rel.Loaded {
			assert.NotEmpty(t, rel.DropReason,
				"edge type %q (tier %s) feeds rel %q which is NOT loaded into Ladybug and has no DropReason — "+
					"this is exactly the silent-empty-query drift; either load it or declare why not", e.Type, e.Tier, e.Rel)
		}
	}

	// Loaded rels must not carry a DropReason; unloaded rels fed by nothing are dead DDL.
	fedRels := map[string]bool{}
	for _, e := range EdgeTypes {
		if e.Rel != "" && e.Tier != TierUnsynced {
			fedRels[e.Rel] = true
		}
	}
	// Conditional reroutes in graphstore.buildEdgeRows feed these rels from an
	// edge type whose DEFAULT rel is another table (runs_in/package→RunsIn,
	// executes_as/k8s→ExecutesAsK8sWorkload, federated_access/k8s→
	// FederatedAccessK8sWorkload, …). Derived from the registry's Reroutes field,
	// not hand-listed — the hand-listed version drifted from buildEdgeRows twice.
	for rerouted := range RerouteRels() {
		fedRels[rerouted] = true
	}
	for _, r := range Rels {
		if r.Loaded {
			assert.Empty(t, r.DropReason, "rel %q is Loaded but has a DropReason", r.Name)
			assert.True(t, fedRels[r.Name], "rel %q is Loaded but no synced edge type feeds it — dead table", r.Name)
		}
		if r.Expand {
			// The expand view emits literal Cypher per rel — an unloaded rel there
			// returns zero rows silently (how PeeredWith sat dead in neighborRels).
			assert.True(t, r.Loaded, "rel %q is Expand but not Loaded — its expand branch always returns zero rows", r.Name)
		}
	}
}

// TestReachAndInheritTypesAreCritical is the invariant that keeps the bulk
// tier's shared row cap from breaking reachability. The bulk query orders by
// edge_type before applying one combined row LIMIT, so once total bulk volume
// exceeds the cap, alphabetically-late types get ZERO rows silently, every
// build. Inheritance is reachability: anything the internet-hops computation
// consumes must live in the uncapped critical tier, or it can go silently
// empty and disable the "contained" demotion path platform-wide.
func TestReachAndInheritTypesAreCritical(t *testing.T) {
	for _, e := range EdgeTypes {
		if !e.Reach && !e.Inherit && !e.InheritReverse {
			continue
		}
		assert.Equal(t, TierCritical, e.Tier,
			"edge type %q is Reach=%v Inherit=%v InheritReverse=%v and MUST be in the critical "+
				"(uncapped) tier: the bulk tier's shared cap starves alphabetically-late types to "+
				"zero rows, which reads downstream as 'no attack path' rather than 'no data'",
			e.Type, e.Reach, e.Inherit, e.InheritReverse)
		assert.False(t, e.Inherit && e.InheritReverse,
			"edge type %q declares both Inherit and InheritReverse: internetHops would add it to "+
				"the containment adjacency in both directions, collapsing src and dst to a single "+
				"hop count and making containment symmetric, which it is not", e.Type)
	}

	// All three sets must be non-empty, or the loop above proves nothing.
	require.NotEmpty(t, ReachEdgeTypes(), "reach edge set is empty")
	require.NotEmpty(t, InheritEdgeTypes(), "inherit edge set is empty")
	require.NotEmpty(t, InheritReverseEdgeTypes(), "inherit-reverse edge set is empty")
}

// TestReachRelsIncludeRerouteTargets pins that ReachRels includes reroute
// targets, not just each edge type's default Rel — the K8s reroute targets
// carry the entire k8s half of the reach graph, and a rel absent from the set
// can lose all its rows with no alarm.
func TestReachRelsIncludeRerouteTargets(t *testing.T) {
	rr := ReachRels()
	for _, name := range []string{"ExecutesAsK8sWorkload", "AccessesK8sWorkload", "BindsK8sWorkload"} {
		assert.True(t, rr[name], "reach rel set is missing reroute target %q", name)
	}
}

// TestFederatedAccessK8sWorkloadRegisteredAndLoaded pins the GKE Workload
// Identity split: a federated_access edge sourced from a k8s_service_account is
// K8sWorkload-labeled, but the default FederatedAccess table is Repo→IamRole,
// so such rows need this dedicated rel or they are dropped at COPY.
func TestFederatedAccessK8sWorkloadRegisteredAndLoaded(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	r, ok := rels["FederatedAccessK8sWorkload"]
	require.True(t, ok, "rel FederatedAccessK8sWorkload missing")
	require.True(t, r.Loaded, "rel FederatedAccessK8sWorkload must be Loaded")
	require.Equal(t, NodeK8sWorkload, r.From)
	require.Equal(t, NodeIamRole, r.To)
	require.True(t, RerouteRels()["FederatedAccessK8sWorkload"],
		"FederatedAccessK8sWorkload must be declared as a reroute of federated_access")
}

// TestIdentityGraphRelsRegisteredAndLoaded pins the identity rels' endpoint
// types the way TestFederatedAccessK8sWorkloadRegisteredAndLoaded pins its
// own: TestRegistryConsistency proves a rel is Loaded and fed, but it cannot
// catch a backwards or wrong From/To.
func TestIdentityGraphRelsRegisteredAndLoaded(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	for name, want := range map[string][2]string{
		// The eighth label-promotion instance: human_identity has no node label, so
		// it is :Asset, and the default FederatedAccess table is Repo→IamRole.
		"FederatedAccessAsset": {NodeAsset, NodeIamRole},
		// The identity chain. Person → IdP group → Identity Center group, which is
		// what finally attaches the existing Group/PermissionSet nodes to a human.
		"MemberOf":      {NodeAsset, NodeSSOGroup},
		"MemberOfGroup": {NodeSSOGroup, NodeSSOGroup},
		// pod → in-cluster ServiceAccount: BOTH endpoints promote to K8sWorkload, so
		// neither ExecutesAs (Asset→IamRole) nor ExecutesAsK8sWorkload
		// (K8sWorkload→IamRole) can hold these rows.
		"ExecutesAsK8sServiceAccount": {NodeK8sWorkload, NodeK8sWorkload},
	} {
		r, ok := rels[name]
		require.True(t, ok, "rel %s missing from registry", name)
		require.True(t, r.Loaded, "rel %s must be Loaded (traversable)", name)
		require.Equal(t, want[0], r.From, "rel %s From", name)
		require.Equal(t, want[1], r.To, "rel %s To", name)
	}

	require.True(t, RerouteRels()["FederatedAccessAsset"],
		"FederatedAccessAsset must be declared as a reroute of federated_access")
	require.True(t, RerouteRels()["MemberOfGroup"],
		"MemberOfGroup must be declared as a reroute of member_of")
	require.True(t, RerouteRels()["ExecutesAsK8sServiceAccount"],
		"ExecutesAsK8sServiceAccount must be declared as a reroute of executes_as")

	// member_of must stay OUT of the capped bulk tier. At zero rows — which is what
	// the bulk cap deterministically gives alphabetically-late types — the identity
	// half of the SSO graph vanishes while every group node still looks healthy.
	require.Equal(t, TierCritical, TierOf("member_of"),
		"member_of is not survivable at zero rows and must not sit under the bulk cap")

	// The pod→SA hop inherits Reach from executes_as. That is the point of routing
	// it through executes_as at all: an exposed pod reaches the ServiceAccount's
	// RBAC (via binds) and its federated cloud role.
	require.True(t, ReachRels()["ExecutesAsK8sServiceAccount"],
		"the pod→ServiceAccount hop must be a reach rel")
}

// TestSSOEdgesRegisteredAndLoaded pins the SSO edge slice: the Identity
// Center collector emits assigned_to/grants_access_to/grants_admin verbatim,
// and the Ladybug DDL wires the loaded rels these map to.
func TestSSOEdgesRegisteredAndLoaded(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	for _, name := range []string{"AssignedTo", "GrantsAccessTo", "GrantsAdmin"} {
		r, ok := rels[name]
		require.True(t, ok, "rel %s missing from registry", name)
		require.True(t, r.Loaded, "rel %s must be Loaded (traversable)", name)
	}

	byType := EdgeTypeToRel()
	require.Equal(t, "AssignedTo", byType["assigned_to"])
	require.Equal(t, "GrantsAccessTo", byType["grants_access_to"])
	require.Equal(t, "GrantsAdmin", byType["grants_admin"])
}

// TestDefinedInAssetRelsRegisteredAndLoaded pins the IaC-ownership rel tables:
// correlate rules emit defined_in edges from k8s-workload and Asset-labelled
// sources, and graphstore routes each to the rel typed for its source label.
func TestDefinedInAssetRelsRegisteredAndLoaded(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	for name, wantFrom := range map[string]string{
		"DefinedInK8sWorkload": NodeK8sWorkload,
		"DefinedInAsset":       NodeAsset,
	} {
		r, ok := rels[name]
		require.True(t, ok, "rel %s missing", name)
		require.True(t, r.Loaded, "rel %s must be Loaded", name)
		require.Equal(t, wantFrom, r.From)
		require.Equal(t, NodeRepo, r.To)
	}
}

// TestDefinedInIamRoleRelRegisteredAndLoaded pins the IAM-role ownership rel
// table: a defined_in edge sourced from an IamRole routes to
// this typed rel instead of the DefinedInAsset default, mirroring
// TestDefinedInAssetRelsRegisteredAndLoaded above for the K8s ownership rels.
func TestDefinedInIamRoleRelRegisteredAndLoaded(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	r, ok := rels["DefinedInIamRole"]
	require.True(t, ok, "rel DefinedInIamRole missing")
	require.True(t, r.Loaded, "rel DefinedInIamRole must be Loaded")
	require.Equal(t, NodeIamRole, r.From)
	require.Equal(t, NodeRepo, r.To)
}

// TestAccessesK8sWorkloadRegisteredAndLoaded pins the k8s service→workload
// selector-match rel table: a targets edge whose destination is K8sWorkload-
// labeled routes here instead of the generic Accesses (Asset→Asset) table,
// which would silently drop it. TestRegistryConsistency only proves this rel
// is Loaded and fed — it can't catch a backwards From/To, which is what this
// pins.
func TestAccessesK8sWorkloadRegisteredAndLoaded(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	r, ok := rels["AccessesK8sWorkload"]
	require.True(t, ok, "rel AccessesK8sWorkload missing")
	require.True(t, r.Loaded, "rel AccessesK8sWorkload must be Loaded")
	require.Equal(t, NodeAsset, r.From)
	require.Equal(t, NodeK8sWorkload, r.To)
}

// TestBindsDanglingBudgetReflectsKnownStaleRBAC pins the binds override for a
// known persistent dangling population (stale RBAC bindings
// referencing ServiceAccounts that no longer exist — real hygiene debt, not
// attrition). If this regresses toward the default, either the stale bindings
// were cleaned up (tighten the override back down) or someone reset it
// without re-deriving the baseline — this test forces that choice to be
// conscious rather than silent.
func TestBindsDanglingBudgetReflectsKnownStaleRBAC(t *testing.T) {
	budgets := DanglingBudgets()
	require.InDelta(t, 0.25, budgets["binds"], 1e-9,
		"binds' dangling budget must stay above the stale-RBAC baseline "+
			"(see the DanglingBudget doc comment on the binds EdgeType)")
}

// TestOwnsAssetRegistered pins the OwnsAsset registry-correctness fix:
// correlate/human_identity.go emits human_identity -[owns]-> github_repo, and
// human_identity carries the catch-all :Asset label while the default Owns
// rel is declared From:CloudAccount — a mismatch harmless only because Owns
// has never been promoted to Loaded. OwnsAsset gives that producer its own
// correctly-typed table so a future promotion doesn't silently drop these
// rows. Unlike TestFederatedAccessK8sWorkloadRegisteredAndLoaded, this does
// NOT assert Loaded — Owns/OwnsAsset are deliberately bfs_only.
func TestOwnsAssetRegistered(t *testing.T) {
	rels := map[string]Rel{}
	for _, r := range Rels {
		rels[r.Name] = r
	}
	owns, ok := rels["Owns"]
	require.True(t, ok, "rel Owns missing")
	require.Equal(t, NodeCloudAccount, owns.From,
		"Owns must stay CloudAccount-sourced: it is fed by collect/aws/aws.go's real cloud_account->ec2_instance producer")
	require.Equal(t, NodeAsset, owns.To)
	require.NotEmpty(t, owns.DropReason, "Owns must stay bfs_only until a promotion is a deliberate, reviewed change")

	r, ok := rels["OwnsAsset"]
	require.True(t, ok, "rel OwnsAsset missing")
	require.Equal(t, NodeAsset, r.From, "OwnsAsset must be Asset-sourced: human_identity has no dedicated node label")
	require.Equal(t, NodeRepo, r.To, "OwnsAsset's only producer (correlate/human_identity.go) targets github_repo")
	require.NotEmpty(t, r.DropReason, "OwnsAsset must stay bfs_only, matching Owns")

	require.True(t, RerouteRels()["OwnsAsset"], "OwnsAsset must be declared as a reroute of owns")
}

// TestExportJSONIsFresh fails when frontend/src/generated/graph-schema.json is
// stale relative to the registry. Regenerate with `go run ./cmd/graphschema-gen`.
func TestExportJSONIsFresh(t *testing.T) {
	want, err := ExportJSON()
	require.NoError(t, err)
	got, err := os.ReadFile("../../frontend/src/generated/graph-schema.json")
	require.NoError(t, err, "generated file missing — run `go run ./cmd/graphschema-gen`")
	require.Equal(t, string(want), string(got),
		"frontend/src/generated/graph-schema.json is stale — run `go run ./cmd/graphschema-gen`")
}
