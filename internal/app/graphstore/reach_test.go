package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func edge(src, typ, dst string) asset.Edge {
	return asset.Edge{SrcID: src, EdgeType: typ, DstID: dst}
}

func TestInternetHops(t *testing.T) {
	t.Run("direct + transitive chain", func(t *testing.T) {
		// internet → ec2 (exposed) → executes_as → role → can_assume → admin
		edges := []asset.Edge{
			edge("ec2", "exposed_to_internet", InternetNodeID),
			edge("ec2", "executes_as", "role"),
			edge("role", "can_assume", "admin"),
			edge("admin", "accesses_secret", "secret"),
		}
		hops, _ := internetHops(edges)
		want := map[string]int{"ec2": 0, "role": 1, "admin": 2, "secret": 3}
		for id, w := range want {
			if hops[id] != w {
				t.Errorf("hops[%s] = %d, want %d", id, hops[id], w)
			}
		}
	})

	t.Run("depth cap excludes beyond maxReachDepth", func(t *testing.T) {
		edges := []asset.Edge{
			edge("a", "exposed_to_internet", InternetNodeID),
			edge("a", "can_assume", "b"), // 1
			edge("b", "can_assume", "c"), // 2
			edge("c", "can_assume", "d"), // 3
			edge("d", "can_assume", "e"), // 4 — beyond cap
		}
		hops, _ := internetHops(edges)
		if _, ok := hops["e"]; ok {
			t.Errorf("node e should be beyond depth cap, got %d", hops["e"])
		}
		if hops["d"] != 3 {
			t.Errorf("hops[d] = %d, want 3", hops["d"])
		}
	})

	t.Run("unreachable island absent from map", func(t *testing.T) {
		edges := []asset.Edge{
			edge("x", "exposed_to_internet", InternetNodeID),
			edge("iso1", "can_assume", "iso2"), // no path from any exposed seed
		}
		hops, _ := internetHops(edges)
		if _, ok := hops["iso2"]; ok {
			t.Error("isolated node must not be reachable")
		}
	})

	t.Run("federated_access is NOT traversed (SSO-only role stays unreachable)", func(t *testing.T) {
		// The Okta case: a human/IdP federates into an admin role, but no internet-
		// exposed compute reaches it. It must be unreachable.
		edges := []asset.Edge{
			edge("okta", "federated_access", "admin_role"),
		}
		hops, _ := internetHops(edges)
		if _, ok := hops["admin_role"]; ok {
			t.Error("federated_access must not make a role internet-reachable")
		}
	})

	t.Run("k8s exposure chain: ingress→service→pod is reachable", func(t *testing.T) {
		// internet → ingress (exposed) → routes_to → service → targets → pod.
		// The pod's owning deployment is also targeted (K8sServiceTargets mirrors
		// the pod edge onto the owner) so the aggregated workload finding resolves.
		edges := []asset.Edge{
			edge("ingress", "exposed_to_internet", InternetNodeID),
			edge("ingress", "routes_to", "service"),
			edge("service", "targets", "pod"),
			edge("service", "targets", "deployment"),
		}
		hops, _ := internetHops(edges)
		want := map[string]int{"ingress": 0, "service": 1, "pod": 2, "deployment": 2}
		for id, w := range want {
			if hops[id] != w {
				t.Errorf("hops[%s] = %d, want %d", id, hops[id], w)
			}
		}
	})

	t.Run("cycle is safe", func(t *testing.T) {
		edges := []asset.Edge{
			edge("a", "exposed_to_internet", InternetNodeID),
			edge("a", "can_assume", "b"),
			edge("b", "can_assume", "a"), // back-edge
		}
		hops, _ := internetHops(edges)
		if hops["a"] != 0 || hops["b"] != 1 {
			t.Errorf("cycle handling: a=%d b=%d, want 0/1", hops["a"], hops["b"])
		}
	})

	// INV-1: an identity (IAM user/role, service account) is a principal, never a
	// node on the internet. An exposed_to_internet edge whose source is an identity
	// is a data error and MUST be dropped, not treated as a 0-hop seed — this is the
	// structural guard against the cache-poisoning bug that made non-exposed IAM
	// principals score as "directly reachable from the internet (0-hop)".
	t.Run("identity seed is dropped, not a 0-hop entry point", func(t *testing.T) {
		edges := []asset.Edge{
			// A bogus identity internet seed plus a real transitive edge off it.
			{SrcID: "admin-role", SrcType: "iam_role", EdgeType: "exposed_to_internet", DstID: InternetNodeID},
			edge("admin-role", "can_assume", "downstream"),
			// sso_permission_set: a grant object, not a principal, but the same
			// category error applies — it is not network-located, so it must be
			// dropped exactly like a principal, not treated as a 0-hop seed.
			{SrcID: "perm-set", SrcType: "sso_permission_set", EdgeType: "exposed_to_internet", DstID: InternetNodeID},
			// A legitimate compute seed, for contrast.
			{SrcID: "ec2", SrcType: "ec2_instance", EdgeType: "exposed_to_internet", DstID: InternetNodeID},
		}
		hops, dropped := internetHops(edges)
		if dropped != 2 {
			t.Errorf("expected 2 dropped identity/grant seeds, got %d", dropped)
		}
		if _, ok := hops["perm-set"]; ok {
			t.Error("sso_permission_set must not be a 0-hop internet seed")
		}
		if _, ok := hops["admin-role"]; ok {
			t.Errorf("identity must not be a 0-hop internet seed, got hops[admin-role]=%d", hops["admin-role"])
		}
		if _, ok := hops["downstream"]; ok {
			t.Error("nodes reached only via a dropped identity seed must not be internet-reachable")
		}
		if hops["ec2"] != 0 {
			t.Errorf("a real compute seed is still 0-hop, got %d", hops["ec2"])
		}
	})

	// Containment inheritance: what is INSIDE a reached workload is reachable at
	// that workload's distance, not further away. This is what lets an image CVE
	// reach must_fix — before it, package nodes got no hop count at all and
	// critical image CVEs sat in monitor with a blank must_fix_class.
	t.Run("package inherits the pod's hop count across containment", func(t *testing.T) {
		// internet → ingress(0) → service(1) → pod(2) → image → package.
		// The full chain is 5 edges deep; under plain BFS the package would land at
		// depth 4 and be cut off by maxReachDepth=3 even if containment were traversed.
		edges := []asset.Edge{
			edge("ingress", "exposed_to_internet", InternetNodeID),
			edge("ingress", "routes_to", "service"),
			edge("service", "targets", "pod"),
			edge("pod", "runs_image", "image"),
			edge("image", "runs_package", "pkg:apk/openssl@3.1.4-r5"),
		}
		hops, _ := internetHops(edges)
		want := map[string]int{
			"ingress": 0, "service": 1, "pod": 2,
			"image":                    2, // inherited, not 3
			"pkg:apk/openssl@3.1.4-r5": 2, // inherited, not 4 (which the cap would drop)
		}
		for id, w := range want {
			if hops[id] != w {
				t.Errorf("hops[%s] = %d, want %d", id, hops[id], w)
			}
		}
		if hops["pkg:apk/openssl@3.1.4-r5"] > maxMustFixHopsForTest {
			t.Errorf("package must land within the must-fix hop budget, got %d",
				hops["pkg:apk/openssl@3.1.4-r5"])
		}
	})

	t.Run("ECS service behind an internet-facing load balancer passes reach to its image", func(t *testing.T) {
		// collect/aws/ecs.go: load_balancer -routes_to-> ecs_service -runs_image-> image.
		edges := []asset.Edge{
			edge("alb", "exposed_to_internet", InternetNodeID),
			edge("alb", "routes_to", "ecs-svc"),
			edge("ecs-svc", "runs_image", "image"),
			edge("image", "runs_package", "pkg:deb/openssl@3.0.11"),
		}
		hops, _ := internetHops(edges)
		for id, w := range map[string]int{"alb": 0, "ecs-svc": 1, "image": 1, "pkg:deb/openssl@3.0.11": 1} {
			if got, ok := hops[id]; !ok || got != w {
				t.Errorf("hops[%s] = %d (reached=%t), want %d", id, got, ok, w)
			}
		}
	})

	t.Run("containment through a container node also inherits", func(t *testing.T) {
		edges := []asset.Edge{
			edge("pod", "exposed_to_internet", InternetNodeID),
			edge("pod", "runs_container", "container"),
			edge("container", "runs_image", "image"),
			edge("image", "runs_package", "pkg"),
		}
		hops, _ := internetHops(edges)
		for _, id := range []string{"container", "image", "pkg"} {
			if hops[id] != 0 {
				t.Errorf("hops[%s] = %d, want 0 (inherited from a directly exposed pod)", id, hops[id])
			}
		}
	})

	t.Run("containment does not manufacture reach for an unreachable pod", func(t *testing.T) {
		// No seed anywhere: inheritance must propagate nothing, not default to 0.
		edges := []asset.Edge{
			edge("pod", "runs_image", "image"),
			edge("image", "runs_package", "pkg"),
		}
		hops, _ := internetHops(edges)
		for _, id := range []string{"pod", "image", "pkg"} {
			if _, ok := hops[id]; ok {
				t.Errorf("%s must stay unreachable, got hops=%d", id, hops[id])
			}
		}
	})

	t.Run("attacker-movement distance wins over an inherited one", func(t *testing.T) {
		// An image shared by a 0-hop pod and a 2-hop pod takes the shorter distance.
		edges := []asset.Edge{
			edge("near", "exposed_to_internet", InternetNodeID),
			edge("ingress", "exposed_to_internet", InternetNodeID),
			edge("ingress", "routes_to", "service"),
			edge("service", "targets", "far"),
			edge("near", "runs_image", "image"),
			edge("far", "runs_image", "image"),
		}
		hops, _ := internetHops(edges)
		if hops["image"] != 0 {
			t.Errorf("hops[image] = %d, want 0 (shortest of its two runners)", hops["image"])
		}
	})

	t.Run("containment cycle terminates", func(t *testing.T) {
		edges := []asset.Edge{
			edge("pod", "exposed_to_internet", InternetNodeID),
			edge("pod", "runs_image", "image"),
			edge("image", "runs_package", "pkg"),
			edge("pkg", "runs_package", "image"), // bogus back-edge in containment data
		}
		hops, _ := internetHops(edges) // must not hang
		if hops["pkg"] != 0 {
			t.Errorf("hops[pkg] = %d, want 0", hops["pkg"])
		}
	})
}

// maxMustFixHopsForTest mirrors enrich.maxMustFixHops. Duplicated rather than
// imported because graphstore must not depend on enrich; if the two ever diverge,
// the containment test above is the thing that should fail.
const maxMustFixHopsForTest = 3

// INV-6: any InternetHops outside the valid domain {-2,-1,0..maxReachHops}
// collapses to ReachUnknown (fail-open) — a corrupt or unexpected value must never
// be trusted as a concrete reach distance.
func TestClampInternetHops(t *testing.T) {
	cases := []struct {
		in      int
		want    int
		wantBad bool
	}{
		{ReachUnknown, ReachUnknown, false},
		{ReachNone, ReachNone, false},
		{0, 0, false},
		{maxReachHops, maxReachHops, false},
		{maxReachHops + 1, ReachUnknown, true}, // beyond the BFS depth → invalid
		{-3, ReachUnknown, true},               // below the sentinels → invalid
		{99, ReachUnknown, true},
	}
	for _, c := range cases {
		got, bad := clampInternetHops(c.in)
		if got != c.want || bad != c.wantBad {
			t.Errorf("clampInternetHops(%d) = (%d,%t), want (%d,%t)", c.in, got, bad, c.want, c.wantBad)
		}
	}
}

// NewNodeSignals must default InternetHops to ReachUnknown, never the Go zero
// value 0 (= directly internet-exposed) — the structural guard behind the
// build-site fixes.
func TestNewNodeSignals_DefaultsReachUnknown(t *testing.T) {
	if h := NewNodeSignals().InternetHops; h != ReachUnknown {
		t.Errorf("NewNodeSignals().InternetHops = %d, want ReachUnknown(%d)", h, ReachUnknown)
	}
}

// TestPrewarmSignalCache_OverlaysReach is the regression guard for the reach-cache
// poisoning bug: SignalsByResource never sets InternetHops, so the rollup structs
// carry the zero value 0 — which is the "internet seed" value, not "unknown". The
// pre-warm must overlay the real BFS hops (or a not-reached sentinel), never cache
// a bare 0 that makes every finding-bearing principal look internet-exposed.
func TestPrewarmSignalCache_OverlaysReach(t *testing.T) {
	s := &Service{}
	// Only "ec2" is an internet seed (0-hop); "role" is 1 hop; "user" is unreachable.
	edges := []asset.Edge{
		edge("ec2", "exposed_to_internet", InternetNodeID),
		edge("ec2", "executes_as", "role"),
	}
	s.setLastHops(newReachOverlay(edges), true, nil)

	// The signal rollup carries InternetHops=0 (zero value) for every resource —
	// exactly the poison the fix must overwrite.
	sig := map[string]NodeSignals{
		"ec2":  {PrivescCount: 0},
		"role": {PrivescCount: 1},
		"user": {PrivescCount: 3}, // has a privesc finding but no reach path
	}
	s.prewarmSignalCache(sig)

	get := func(id string) int {
		v, ok := s.nodeSignalsCache.Load(id)
		if !ok {
			t.Fatalf("%s not cached", id)
		}
		return v.(NodeSignals).InternetHops
	}
	if h := get("ec2"); h != 0 {
		t.Errorf("ec2 is an internet seed → 0-hop, got %d", h)
	}
	if h := get("role"); h != 1 {
		t.Errorf("role is 1 hop from the seed, got %d", h)
	}
	// The unreachable user must NOT be cached as 0-hop (the bug). It must be the
	// not-reached sentinel, so InternetReach applies the unreachable penalty, not
	// a false "directly reachable from the internet".
	if h := get("user"); h != ReachNone {
		t.Errorf("unreachable user must be ReachNone(%d), got %d — the poisoning bug", ReachNone, h)
	}
}

// TestPrewarmSignalCache_UnknownWhenReachIncomplete: when the edge set was
// truncated, a not-reached node is ReachUnknown (fail-open), never a false 0.
func TestPrewarmSignalCache_UnknownWhenReachIncomplete(t *testing.T) {
	s := &Service{}
	s.setLastHops(reachOverlay{hops: map[string]int{}, exposed: map[string]bool{}}, false, nil) // reach incomplete, nothing reachable
	s.prewarmSignalCache(map[string]NodeSignals{"user": {PrivescCount: 3}})
	v, _ := s.nodeSignalsCache.Load("user")
	if h := v.(NodeSignals).InternetHops; h != ReachUnknown {
		t.Errorf("incomplete reach → ReachUnknown(%d), got %d", ReachUnknown, h)
	}
}

// TestInternetHopsInheritanceIsDeterministic pins the fix for a genuinely
// nondeterministic result. A container image shared by a directly-exposed pod and
// a distant one used to take whichever runner the closure walked first, and the
// walk order came from iterating a map — so the same topology yielded hops=0 or
// hops=2 for the same image across runs, flapping the must_fix classification of
// that image and every package inside it. Repeated because a single pass could
// pass by luck.
func TestInternetHopsInheritanceIsDeterministic(t *testing.T) {
	edges := []asset.Edge{
		edge("near", "exposed_to_internet", InternetNodeID),
		edge("ingress", "exposed_to_internet", InternetNodeID),
		edge("ingress", "routes_to", "service"),
		edge("service", "targets", "far"),
		edge("near", "runs_image", "image"),
		edge("far", "runs_image", "image"),
		edge("image", "runs_package", "pkg"),
	}
	for i := 0; i < 200; i++ {
		hops, _ := internetHops(edges)
		if hops["image"] != 0 {
			t.Fatalf("run %d: hops[image] = %d, want 0 (the shorter of its two runners)", i, hops["image"])
		}
		if hops["pkg"] != 0 {
			t.Fatalf("run %d: hops[pkg] = %d, want 0 (inherited through the image)", i, hops["pkg"])
		}
	}
}

// The reverse order must give the same answer: a node reached far-first is still
// relaxed down when a nearer runner is found.
func TestInternetHopsInheritanceRelaxesDownward(t *testing.T) {
	edges := []asset.Edge{
		edge("ingress", "exposed_to_internet", InternetNodeID),
		edge("ingress", "routes_to", "service"),
		edge("service", "targets", "far"),
		edge("far", "runs_image", "image"),
		// The nearer runner is declared last on purpose.
		edge("near", "exposed_to_internet", InternetNodeID),
		edge("near", "runs_image", "image"),
	}
	hops, _ := internetHops(edges)
	if hops["image"] != 0 {
		t.Errorf("hops[image] = %d, want 0 — a later-discovered nearer runner must lower the distance", hops["image"])
	}
}

// exposureEdge builds an exposed_to_internet edge carrying a public_access tier.
func exposureEdge(src, tier string) asset.Edge {
	e := edge(src, "exposed_to_internet", InternetNodeID)
	e.Properties = map[string]string{asset.EdgePropPublicAccess: tier}
	return e
}

// TestInternetHopsSeedTier pins the tier→distance contract.
// The possible tier exists so a serverless entry point the collector cannot
// prove unauthenticated is REACHABLE-BUT-FURTHER rather than infinitely far;
// getting this wrong in either direction is a scoring outage:
//   - seeding it at 0 hands every `possible` cloud function the same +18 direct
//     exposure weight as an observed open path;
//   - not seeding it at all is the defect this replaced.
func TestInternetHopsSeedTier(t *testing.T) {
	t.Run("possible seeds one hop in and shifts its subtree", func(t *testing.T) {
		edges := []asset.Edge{
			exposureEdge("fn", asset.PublicAccessPossible),
			edge("fn", "executes_as", "role"),
			edge("role", "can_assume", "admin"),
			edge("admin", "accesses_secret", "secret"), // would be 3 from a confirmed seed
		}
		hops, _ := internetHops(edges)
		want := map[string]int{"fn": 1, "role": 2, "admin": 3}
		for id, w := range want {
			if hops[id] != w {
				t.Errorf("hops[%s] = %d, want %d", id, hops[id], w)
			}
		}
		if _, ok := hops["secret"]; ok {
			t.Errorf("the tail of a possible-seeded chain must truncate at maxReachDepth, got %d", hops["secret"])
		}
	})

	t.Run("confirmed and an absent tier both seed at zero", func(t *testing.T) {
		edges := []asset.Edge{
			exposureEdge("graded", asset.PublicAccessConfirmed),
			edge("ungraded", "exposed_to_internet", InternetNodeID), // legacy ungraded shape
		}
		hops, _ := internetHops(edges)
		if hops["graded"] != 0 || hops["ungraded"] != 0 {
			t.Errorf("hops = %d/%d, want 0/0 — an absent tier must never demote a legacy edge", hops["graded"], hops["ungraded"])
		}
	})

	t.Run("the strongest evidence wins when both tiers name one asset", func(t *testing.T) {
		hops, _ := internetHops([]asset.Edge{
			exposureEdge("api", asset.PublicAccessPossible),
			exposureEdge("api", asset.PublicAccessConfirmed),
		})
		if hops["api"] != 0 {
			t.Errorf("hops[api] = %d, want 0 — one confirmed witness outranks any number of possible ones", hops["api"])
		}
	})

	t.Run("a possible seed already reached sooner keeps the shorter distance", func(t *testing.T) {
		hops, _ := internetHops([]asset.Edge{
			exposureEdge("ec2", asset.PublicAccessConfirmed),
			edge("ec2", "executes_as", "role"),
			exposureEdge("role", asset.PublicAccessPossible), // also 1 via BFS
		})
		if hops["role"] != 1 {
			t.Errorf("hops[role] = %d, want 1", hops["role"])
		}
	})

	t.Run("an identity is never a seed at either tier", func(t *testing.T) {
		e := exposureEdge("arn:aws:iam::1:role/r", asset.PublicAccessPossible)
		e.SrcType = "iam_role"
		hops, dropped := internetHops([]asset.Edge{e})
		if dropped != 1 {
			t.Errorf("identitySeedsDropped = %d, want 1", dropped)
		}
		if _, ok := hops["arn:aws:iam::1:role/r"]; ok {
			t.Error("INV-1: a principal must never be an internet seed, tier notwithstanding")
		}
	})
}

// TestInternetHopsReverseInheritance covers the repo-reachability closure added
// later. github_repo was the source of no reach, inherit or seed edge, so
// internetHops could not assign a repo ANY hop count — the reason many open
// repo-sourced findings (code scanning, secrets, IaC, tfstate, CI federation)
// carried no reachability signal at all.
//
// Both directions are asserted together on purpose: deploys_to must flow
// BACKWARDS (repo takes the workload's distance) and defined_in FORWARDS (the
// rel already points resource → repo), and a regression that treats them alike
// silently produces the same shape of wrong answer the flag exists to fix.
func TestInternetHopsReverseInheritance(t *testing.T) {
	edges := []asset.Edge{
		edge("ingress", "exposed_to_internet", InternetNodeID),
		edge("ingress", "routes_to", "service"),
		edge("service", "targets", "pod"),
		// Causal direction: repo → workload. Containment runs the other way.
		edge("app-repo", "deploys_to", "pod"),
		// Containment direction already: resource → repo.
		edge("pod", "defined_in", "infra-repo"),
		// A repo that deploys nowhere reachable must stay unreached, or the fix
		// would just mark every repo exposed.
		edge("orphan-repo", "deploys_to", "unreached-pod"),
	}
	hops, _ := internetHops(edges)

	assert.Equal(t, 2, hops["pod"], "pod is internet → ingress → service → pod")
	assert.Equal(t, 2, hops["app-repo"],
		"a repo inherits the distance of the workload it deploys to, without costing a hop — "+
			"deploys_to is containment recorded backwards, not attacker movement")
	assert.Equal(t, 2, hops["infra-repo"],
		"a repo inherits the distance of the resource it declares (IaC ownership)")
	_, reached := hops["orphan-repo"]
	assert.False(t, reached,
		"a repo whose only deploy target is unreachable must have NO hop count — "+
			"reverse inheritance must not seed repos, only propagate to them")
}

// A repo deploying to several workloads takes the closest one: if any target is
// internet-facing, the code in that repo is exploitable at that distance.
func TestInternetHopsReverseInheritanceTakesMinimum(t *testing.T) {
	edges := []asset.Edge{
		edge("ingress", "exposed_to_internet", InternetNodeID),
		edge("ingress", "routes_to", "far-pod"),
		edge("near-pod", "exposed_to_internet", InternetNodeID),
		edge("monorepo", "deploys_to", "far-pod"),
		edge("monorepo", "deploys_to", "near-pod"),
	}
	hops, _ := internetHops(edges)
	assert.Equal(t, 0, hops["monorepo"],
		"a repo deploying to both a 1-hop and a 0-hop workload takes the shorter distance")
}

// A security group is a firewall RULE, not a network-reachable endpoint —
// nobody "reaches" a security group, so connected_via_sg must never seed the
// BFS or cost a hop. But the SG's OWN open-rule findings (aws-sg-open-all-ports
// etc.) are attached to the SG resource, and its real exposure is exactly the
// exposure of whatever uses it. Before this, security_group had zero graph
// presence for its own findings: never a source of a Reach/Inherit/seed edge.
func TestInternetHopsSecurityGroupInheritsFromItsMembers(t *testing.T) {
	edges := []asset.Edge{
		edge("ingress", "exposed_to_internet", InternetNodeID),
		edge("ingress", "routes_to", "public-instance"),
		// public-instance is a member of both sg-open and sg-shared.
		edge("public-instance", "connected_via_sg", "sg-open"),
		edge("public-instance", "connected_via_sg", "sg-shared"),
		// private-instance is ALSO a member of sg-shared, but never reached.
		edge("private-instance", "connected_via_sg", "sg-shared"),
		// sg-orphan has no members at all — must stay unreached, not seeded.
	}
	hops, _ := internetHops(edges)

	assert.Equal(t, 1, hops["public-instance"], "internet → ingress(0) → routes_to → public-instance(1)")
	assert.Equal(t, 1, hops["sg-open"],
		"an SG used only by an internet-reachable instance takes that instance's hop count")
	assert.Equal(t, 1, hops["sg-shared"],
		"an SG shared by a reachable and an unreachable instance takes the MINIMUM — the reachable one's distance")
	_, reached := hops["sg-orphan"]
	assert.False(t, reached, "an SG with no members must not be seeded or reached from nothing")
	_, privateReached := hops["private-instance"]
	assert.False(t, privateReached,
		"connected_via_sg must never flow backwards — a private instance sharing an SG with a public one stays unreached")
}

// TestPrewarmSignalCache_CoversAllLoadedNodes is the full-coverage guard: every
// loaded node gets a nodeSignalsCache entry after a prewarm, not only the
// finding-bearing ones sigByResource carries. Before this, NodeSignals/
// TryNodeSignals fell through to Ladybug for any loaded node with zero findings —
// most of the graph (asset_filter.go's alwaysKeepTypes/hasSecurityEdge nodes are
// routinely score-0 and finding-free).
func TestPrewarmSignalCache_CoversAllLoadedNodes(t *testing.T) {
	s := &Service{}
	edges := []asset.Edge{
		edge("ec2", "exposed_to_internet", InternetNodeID),
	}
	// "quiet" is a loaded node (e.g. an alwaysKeepTypes IAM role, or one retained by
	// a security edge) that carries no finding at all — absent from sigByResource.
	s.setLastHops(newReachOverlay(edges), true, []string{"ec2", "quiet"})

	sig := map[string]NodeSignals{
		"ec2": {PrivescCount: 1},
	}
	s.prewarmSignalCache(sig)

	// The finding-bearing node keeps its real rollup values, overlaid with reach.
	v, ok := s.nodeSignalsCache.Load("ec2")
	if !ok {
		t.Fatal("ec2 not cached")
	}
	ec2 := v.(NodeSignals)
	assert.Equal(t, 1, ec2.PrivescCount)
	assert.Equal(t, 0, ec2.InternetHops, "ec2 is the internet seed — 0 hop")

	// "quiet" has no finding, but IS a loaded node — it must still be cached rather
	// than left for a Ladybug round trip on first lookup.
	v, ok = s.nodeSignalsCache.Load("quiet")
	if !ok {
		t.Fatal("quiet is a loaded node with no findings — it must still be pre-warmed")
	}
	quiet := v.(NodeSignals)
	assert.Equal(t, ReachNone, quiet.InternetHops,
		"quiet has no reach path — ReachNone, never the poisoned zero-value 0-hop")
	assert.False(t, quiet.Exposed)
	assert.False(t, quiet.ToxicCombo)
	assert.Equal(t, 0, quiet.PrivescCount)
	assert.Equal(t, 0, quiet.MaxScore)
	assert.Equal(t, "", quiet.CveID)
}

// TestPrewarmSignalCache_SignalOnlyRefreshStillCoversAllNodes proves the second
// call path: a signal-only refresh (no fresh topology, no fresh node list of its
// own) still gets full coverage by reusing the node list setLastHops stashed at
// the last topology build — the same pairing lastOverlay already relied on.
func TestPrewarmSignalCache_SignalOnlyRefreshStillCoversAllNodes(t *testing.T) {
	s := &Service{}
	edges := []asset.Edge{
		edge("ec2", "exposed_to_internet", InternetNodeID),
	}
	s.setLastHops(newReachOverlay(edges), true, []string{"ec2", "quiet"})
	s.prewarmSignalCache(map[string]NodeSignals{"ec2": {PrivescCount: 1}})

	// A later signal-only refresh (RefreshSignals/applySignals shape): a NEW rollup,
	// no setLastHops call in between — must still cover "quiet".
	s.prewarmSignalCache(map[string]NodeSignals{"ec2": {PrivescCount: 2}})

	v, ok := s.nodeSignalsCache.Load("quiet")
	if !ok {
		t.Fatal("quiet dropped out of the cache after a signal-only refresh")
	}
	assert.Equal(t, ReachNone, v.(NodeSignals).InternetHops)
}

// TestSyncFromSources_PrewarmsFindingFreeNode is the end-to-end guard: a real
// SyncFromSources build must cache a finding-free asset too, not only the one
// carrying a finding.
func TestSyncFromSources_PrewarmsFindingFreeNode(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer svc.Close()

	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws"},
		// iam_role is in alwaysKeepTypes, so it survives filterLadybugAssets even with
		// RiskScore 0 and no findings — exactly the "quiet" case this test targets.
		{ID: "role-1", Name: "role", Type: "iam_role", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{}},
	}
	sigs := map[string]NodeSignals{"lb-1": {HasKEV: true, MaxScore: 90, PrivescCount: 2}}
	if err := svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}); err != nil {
		t.Fatalf("SyncFromSources: %v", err)
	}

	if _, ok := svc.nodeSignalsCache.Load("lb-1"); !ok {
		t.Fatal("lb-1 (finding-bearing) not cached")
	}
	v, ok := svc.nodeSignalsCache.Load("role-1")
	if !ok {
		t.Fatal("role-1 is a loaded, finding-free node — it must be pre-warmed, not left for a Ladybug fallback")
	}
	role := v.(NodeSignals)
	assert.Equal(t, ReachNone, role.InternetHops)
	assert.False(t, role.Exposed)
	assert.Equal(t, 0, role.PrivescCount)
}
