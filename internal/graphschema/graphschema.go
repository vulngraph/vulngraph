// Package graphschema is the single source of truth for the graph edge
// pipeline: which edge_type values exist in ClickHouse graph_edges, which sync
// tier fetches them, which Ladybug rel table they map to, which rel tables are
// actually loaded (traversable), which feed the structured expand view, which
// count as attacker-movement for reachability, and what BFS weight they carry.
//
// Every consumer DERIVES its list from this package instead of hand-maintaining
// its own copy: asset (sync tiers), graphstore (edgeTypeToRel, ladybugRelSpec
// endpoints, neighborRels, reach set, BFS weights), reason (NL prompt edge
// blocks), explore (PascalCase↔snake_case translation for the ClickHouse
// fallback), and the frontend (generated graph-schema.json, pinned by a vitest).
// Hand-maintained copies of these facts drift apart silently, and a query
// referencing an unloaded rel returns zero rows with no error.
//
// graphschema is a dependency-free leaf (like internal/graphquery): it imports
// nothing and may be imported from any layer, including domain.go files.
package graphschema

// OnDemandEdgeTypes are inventory relationships excluded from the resident
// graph and available through bounded exploration.
func OnDemandEdgeTypes() []string {
	var out []string
	for _, e := range EdgeTypes {
		if e.OnDemand {
			out = append(out, e.Type)
		}
	}
	return out
}
func IsOnDemandEdge(typ string) bool {
	return onDemandEdges[typ]
}

var onDemandEdges = func() map[string]bool {
	out := map[string]bool{}
	for _, typ := range OnDemandEdgeTypes() {
		out[typ] = true
	}
	return out
}()

// Node label constants — the Ladybug node table names. graphstore's DDL is the
// structural source; TestLadybugRelSpecMatchesDDL (graphstore) pins every
// loaded rel's FROM/TO label to it.
//
// Every asset type shares the Asset label unless it has its own dedicated
// label below (e.g. IamRole, K8sWorkload). Promoting a type off Asset onto its
// own label silently drops any rel table typed FROM/TO Asset that the type
// feeds (see SchemaVersion in graphstore/domain.go) — EC2 instances and
// security groups stay on Asset for that reason, discriminated by Asset.type.
const (
	NodeAsset        = "Asset"
	NodePackage      = "Package"
	NodeRepo         = "Repo"
	NodeIamRole      = "IamRole"
	NodeK8sWorkload  = "K8sWorkload"
	NodeSubnet       = "Subnet"
	NodeCloudAccount = "CloudAccount"
	NodeElasticIP    = "ElasticIP"
	NodeDNSZone      = "DNSZone"
	NodeIamPolicy    = "IamPolicy"
	NodeDataClass    = "DataClass"
	NodeSSOGroup     = "Group"
	NodeSSOPermSet   = "PermissionSet"
)

// Tier is the ClickHouse fetch tier for an edge type during Ladybug bulk sync.
type Tier string

const (
	// TierCritical edges are fetched with NO row limit — attack-path edges that
	// must always appear in the graph regardless of bulk volume.
	TierCritical Tier = "critical"
	// TierBulk edges are high-volume context fetched under a row cap; their
	// absence must never break an attack-path query.
	TierBulk Tier = "bulk"
	// TierUnsynced edges are written to graph_edges by some producer but never
	// fetched into Ladybug. Each entry documents WHY in Doc — an unsynced type with
	// no rationale is drift, and TestRegistryConsistency fails on it.
	TierUnsynced Tier = "unsynced"
)

// Direction is the direction RISK propagates along an edge type in the BFS risk
// propagation (graphstore/bfs.go). It is a claim about causation, not about how
// the edge is stored: an edge_type is stored src→dst by its producer, and for
// half of them the thing that puts the other end at risk is the DESTINATION.
//
// graphstore.buildAdjIndex indexes an edge under the node that should RECEIVE
// the other end's score, because computeBFSBoost(X) walks adj[X] and adds each
// visited neighbour's score into X's own boost. So DirForward — risk flows
// src→dst — is indexed as idx[dst] → src.
type Direction string

const (
	// DirForward: a compromised or risky SRC puts DST at risk. Most movement
	// edges an attacker follows (executes_as, routes_to, binds, has_role) are
	// forward; exposure edges whose destination is the origin of the danger
	// (exposed_to_internet, sg_allows_from) are DirReverse. The attacker's
	// direction on any edge is AttackDirection, not this field.
	DirForward Direction = "forward"
	// DirReverse: risk flows dst→src. Three shapes:
	//
	//   - the destination is the origin of the danger (exposed_to_internet points
	//     at the internet sentinel; sg_allows_from records "src permits ingress
	//     FROM dst");
	//   - the destination is CONTENTS of the source (runs_image/runs_package/
	//     depends_on — a vulnerable package raises the thing shipping it);
	//   - the destination is a CAPABILITY of the source (accesses_secret,
	//     has_policy, allows_action — what a principal can reach is what makes the
	//     principal worth attacking).
	//
	// The capability shape is the one that reads as backwards and is not. Risk
	// score answers "how bad is it if this is compromised", which is blast
	// radius — and blast radius runs AGAINST the direction of attack. A role that
	// can read five wildcard secrets is the thing to remediate; the secret at the
	// far end is the consequence, not the fix.
	//
	// Where a capability edge joins two nodes of the SAME kind (can_assume,
	// can_escalate_to: iam_role→iam_role) neither single direction is right and
	// the answer is DirBoth — see that constant and can_assume's entry.
	DirReverse Direction = "reverse"
	// DirBoth indexes both ends. It is the fail-open answer for an UNRECOGNISED
	// edge type, so a new producer's edge over-propagates rather than silently
	// losing a direction — and it is the DELIBERATE answer in two cases:
	// genuinely symmetric adjacency (peered_with is emitted twice by its
	// producer; connected_via_sg is a spoke-hub joining an SG's members), and a
	// capability edge between two nodes of the same kind
	// (can_assume, can_escalate_to: iam_role→iam_role) where the source inherits
	// the destination's privilege AND the destination inherits the source's
	// exposure.
	//
	// Because it is also the default, a DELIBERATE DirBoth must say so in a
	// comment on its registry entry — otherwise it is indistinguishable from a
	// direction nobody thought about, which is the state this field exists to end.
	DirBoth Direction = "both"
)

// EdgeType describes one edge_type value in ClickHouse graph_edges.
type EdgeType struct {
	Type     string    // snake_case edge_type column value
	Rel      string    // default Ladybug rel table ("" = no mapping, generic Edge fallback)
	Tier     Tier      // fetch tier
	OnDemand bool      // inventory traversal is served by bounded ClickHouse reads
	Reach    bool      // attacker-movement edge for the internet_hops BFS
	Inherit  bool      // containment edge: dst inherits src's hop count at no extra depth
	Weight   float64   // BFS risk-propagation weight (bfs.go), keyed on THIS snake value
	Dir      Direction // direction risk propagates in the BFS — see Direction
	Doc      string    // one-line meaning; unsynced types must explain why they are unsynced
	// InheritReverse is containment recorded in the opposite direction: SRC
	// inherits DST's hop count. Needed when the producer emits the edge along the
	// direction of causation (a repo DEPLOYS TO a workload) while containment runs
	// the other way (the workload CONTAINS the repo's code). Modelling it by
	// flipping the edge at emit time would be worse — deploys_to is also an expand
	// edge and a Repo→K8sWorkload rel table, and "what does this repo deploy to?"
	// must keep answering in the direction a human asks it.
	InheritReverse bool
	// DanglingBudget is the share of this edge type's FETCHED rows that may be
	// dropped at load because an endpoint is GENUINELY not in the inventory,
	// before the build calls it a regression. Zero means DefaultDanglingBudget.
	//
	// A dangling endpoint is not uniformly "expected attrition" — for can_assume
	// it's an AWS cross-account principal that will never be an asset, while for
	// another type it can mean the platform is silently excluding real assets from
	// the graph. Same counter, opposite verdicts, so each type must declare what it
	// expects. Raise an entry only WITH the measurement and the reason; a new edge
	// type gets the strict default and must earn its slack.
	DanglingBudget float64
	// Reroutes are the ADDITIONAL rel tables graphstore.buildEdgeRows can route
	// this edge type to, chosen by endpoint label. Rel is only the DEFAULT: a
	// derivation that reads Rel alone omits every rerouted table, so
	// ExecutesAsK8sWorkload/AccessesK8sWorkload/BindsK8sWorkload would drop out
	// of ReachRels and their load-time row losses would go unreported.
	Reroutes []string
	// ExpiredShareStepBudget is the maximum ABSOLUTE change, build to build, in
	// this edge type's endpoint_expired share of fetched rows before the worker
	// flags it. Zero means DefaultExpiredShareStepBudget.
	//
	// EndpointExpired has no dangling-style ceiling — for executes_as/deploys_to/
	// targets it is legitimately 100% of the drop, because ephemeral endpoints
	// departing is the entire content of the bucket. A ceiling on the SHARE would
	// either never fire or always fire; a ceiling on the STEP stays quiet while a
	// type sits at its ordinary churn rate and moves the moment that rate itself
	// moves — the shape a load-set regression or a collector bug would produce.
	// See EdgeTypeParityStat.ExpiredShareStepChange.
	ExpiredShareStepBudget float64
}

// Rel describes one Ladybug rel table.
type Rel struct {
	Name       string // PascalCase rel table name
	From, To   string // typed endpoint node labels (must match schemaDDL)
	Loaded     bool   // present in ladybugRelSpec — actually traversable in Ladybug
	Expand     bool   // part of the structured expand view (neighborRels)
	DropReason string // required when a synced edge type feeds it but Loaded=false
	Doc        string // one-line description used by the NL prompts and frontend
}

// defaultWeight is the BFS propagation weight for edges with no specific entry.
const defaultWeight = 0.5

// BlastDepth is how deep a blast-radius walk goes when sizing a finding's
// reach — both the respond.Decide walk (full breakdown, feeds the autonomy
// gate) and the enrich must-fix/scoring walk (plain count) must use the
// SAME depth, or the two can silently drift apart on how far "reachable"
// extends. Declared once here rather than as an independent constant in
// each package — "declare once, derive everywhere," the same rule this
// registry already applies to BFS edge weights and sync tiers.
const BlastDepth = 2

// MaxReachDepth bounds the attacker-movement BFS (graphstore's internet-hops
// reach walk): a resource reachable only via a path longer than this counts
// as unreachable for must-fix/reachability purposes. Declared here rather than
// as graphstore's own private constant so a display label elsewhere (e.g.
// enrichcache.ReachBucketFor's "1-N" fingerprint bucket) can derive its text
// from the same number instead of hand-copying it as a bare literal that a
// depth change would silently leave wrong — the same "declare once, derive
// everywhere" rule BlastDepth above exists for.
const MaxReachDepth = 3

// DefaultDanglingBudget is the DanglingBudget for an edge type that declares
// none: 5% of fetched rows may point at something outside the inventory.
//
// Deliberately strict. Edge types with genuinely dangling endpoints are
// expected to sit well under it, while an edge type the graph is quietly
// losing most of sits far above it — so 5% separates the two populations
// with room to spare in both directions.
const DefaultDanglingBudget = 0.05

// DanglingBudgetMinRows is the fetched-row floor below which the budget is not
// evaluated. Small denominators make a share meaningless: for an edge type with a few
// dozen rows, two dangling ones already read as several percent and would page
// forever on noise that a single new cross-account grant creates.
const DanglingBudgetMinRows = 100

// DanglingBudgets returns each edge type's declared dangling budget, with the
// default filled in. Derived, never hand-maintained.
func DanglingBudgets() map[string]float64 {
	out := make(map[string]float64, len(EdgeTypes))
	for _, e := range EdgeTypes {
		b := e.DanglingBudget
		if b == 0 {
			b = DefaultDanglingBudget
		}
		out[e.Type] = b
	}
	return out
}

// DefaultExpiredShareStepBudget is the ExpiredShareStepBudget for an edge type
// that declares none: its endpoint_expired share of fetched rows may move by up
// to 15 percentage points between consecutive builds before the worker flags it.
//
// Looser than DefaultDanglingBudget on purpose — expiry share tracks real
// operational churn (a rolling deploy, an autoscaling event, a node pool
// upgrade cycling every pod on it), and a tight ceiling would page on ordinary
// cluster activity while still needing to catch the shape a load-set
// regression or verification-query defect would produce: a move across the
// WHOLE population, not a slice of it.
const DefaultExpiredShareStepBudget = 0.15

// ExpiredShareStepBudgetMinRows is the fetched-row floor below which the step
// budget is not evaluated, mirroring DanglingBudgetMinRows for the same reason:
// a share computed over a small denominator swings on a handful of rows and
// would page on noise rather than a real shift in population.
const ExpiredShareStepBudgetMinRows = DanglingBudgetMinRows

// ExpiredShareStepBudgets returns each edge type's declared expired-share step
// budget, with the default filled in. Derived, never hand-maintained.
func ExpiredShareStepBudgets() map[string]float64 {
	out := make(map[string]float64, len(EdgeTypes))
	for _, e := range EdgeTypes {
		b := e.ExpiredShareStepBudget
		if b == 0 {
			b = DefaultExpiredShareStepBudget
		}
		out[e.Type] = b
	}
	return out
}

// EdgeFreshnessCond is the SQL condition EVERY graph_edges reader must apply
// (except deliberately-historical queries like asset drift). graph_edges is
// ReplacingMergeTree with no delete path: an edge that disappears from reality
// is never removed, only its synced_at stops advancing. Producers re-stamp all
// live edges each sweep (correlate every 30min; connector sync re-stamps edges
// even on no-change sweeps), so an edge not re-stamped within 48h (24x the
// default 2h SYNC_INTERVAL) is treated as gone. Without this filter, stale
// edges stay traversable until the table TTL.
//
// Known gap: the cutoff is wall-clock, not anchored to each connector's last
// successful sync the way asset freshness uses a per-provider high-water mark.
// A connector that has not synced for more than 48h (expired credentials, for
// example) loses its sync-written edges from traversal, which reads as "no
// path" rather than "unknown". Correlate-derived edges over its assets keep
// being re-stamped, because correlate's load applies no wall-clock freshness
// gate to asset rows. The exception is the full-sweep load, which applies
// asset.EphemeralLivenessCond: it drops k8s_pod/container/k8s_job rows more
// than 72h older than the newest k8s_pod row, so edges over those types stop
// being re-stamped (a partial correlate's by-ID load applies no such gate).
const EdgeFreshnessCond = "synced_at > now() - INTERVAL 48 HOUR"

// EdgeTypes is the registry of every edge_type any producer writes.
// Order is meaningful: derived slices (sync tiers → SQL IN lists) keep it.
var EdgeTypes = []EdgeType{
	// ── Critical tier: fetched uncapped ─────────────────────────────────────
	// DirReverse — the internet is the origin of risk, not a recipient of it —
	// but the BFS effect is nil either way: the `internet` dst is a sentinel
	// seeded directly into Ladybug, never an asset, so it is absent from the score
	// map and contributes 0. The direction is declared because the BFS must not
	// be the one place in the pipeline that treats exposure as symmetric.
	{Type: "exposed_to_internet", Rel: "ExposedToInternet", Tier: TierCritical, Weight: 1.0, Dir: DirReverse,
		Reroutes: []string{"ExposedToInternetK8sWorkload"},
		Doc:      "internet-reachable asset (computed by the reachability rule; dst is the internet sentinel). K8sWorkload-labeled src (k8s_pod/k8s_deployment/…) reroutes to ExposedToInternetK8sWorkload in buildEdgeRows — the default table is Asset→Asset and silently dropped every directly-exposed workload."},
	// DirBoth, and unlike the fail-open default this one is measured. Both ends of
	// a role→role capability edge legitimately inform the other: A inherits B's
	// PRIVILEGE (A can assume B, so owning A gets you B — A is the remediation
	// target), and B inherits A's EXPOSURE (whatever can reach A can reach B).
	// Reach stays src→dst regardless, because attacker movement really is A→B.
	//
	// Declaring either single direction loses one of the two, and because both
	// endpoints are iam_roles in a high-scoring neighbourhood, either choice drops
	// a similar-sized set of identities out of the score>=60 band — a DIFFERENT
	// set each way, with only partial overlap (measured with a BFS diff
	// over a replayed graph). DirBoth crosses the band zero times in
	// either direction while still sharply cutting the boosted-node count,
	// because the reduction that mattered came from the OTHER edge types.
	{Type: "can_assume", Rel: "CanAssume", Tier: TierCritical, Reach: true, Weight: 0.8, Dir: DirBoth,
		Doc: "IAM role A can assume role B"},
	{Type: "executes_as", Rel: "ExecutesAs", Tier: TierCritical, Reach: true, Weight: 0.6, Dir: DirForward,
		Reroutes: []string{"ExecutesAsK8sWorkload", "ExecutesAsK8sServiceAccount"},
		Doc:      "workload runs under this IAM identity — or, for a k8s pod, under the in-cluster ServiceAccount that fronts it (K8sWorkload→K8sWorkload, rerouted to ExecutesAsK8sServiceAccount)"},
	{Type: "federated_access", Rel: "FederatedAccess", Tier: TierCritical, Weight: defaultWeight, Dir: DirForward,
		Reroutes: []string{"FederatedAccessK8sWorkload", "FederatedAccessAsset"},
		Doc:      "GitHub OIDC / IRSA / WIF trust into a cloud role (not Reach: gated by the IdP). K8sWorkload-labeled src (k8s_service_account) reroutes to FederatedAccessK8sWorkload in buildEdgeRows — the default table is Repo→IamRole and silently dropped every GKE Workload-Identity edge. Asset-labeled src (human_identity, from the Okta/Google connectors via correlate/human_identity.go) reroutes to FederatedAccessAsset for the same reason."},
	// DirBoth for the same reason as can_assume above — role→role capability, both
	// ends informative. This is the CIEM privesc edge, so the cost of getting it
	// wrong is concentrated: declaring it forward credits the role at the END of an
	// escalation chain and leaves the weakly-held role at the start, the one a
	// remediation would actually touch, unelevated.
	{Type: "can_escalate_to", Rel: "CanEscalateTo", Tier: TierCritical, Reach: true, Weight: 0.8, Dir: DirBoth,
		Doc: "CIEM privilege-escalation path between roles"},
	// InheritReverse, not Reach: deployment is not attacker movement — nobody
	// pivots from a repo into a cluster along a CI/CD pipeline, and treating it as
	// a hop would make every repo an entry point. It is containment recorded
	// backwards. The code in the repo IS what runs in the workload, so a repo's
	// code-scanning finding is exploitable at exactly the workload's distance from
	// the internet.
	//
	// Without this flag github_repo is the source of no Reach, Inherit or seed
	// edge whatsoever, so internetHops cannot assign a repo ANY hop count — not
	// "unreachable", structurally unassignable. Every repo-sourced finding (code
	// scanning, secrets, IaC, unreadable tfstate, CI federation) would then reach
	// must_fix classification with no reachability signal at all, so none of
	// them could ever reach the page band.
	//
	// Over-approximating on purpose. A monorepo deploying to one exposed service
	// hands every finding in it that service's hop count, including code on no
	// deployed path. Reach is an "can an attacker plausibly get here" bound
	// everywhere else in this file, and the alternative on offer is not a tighter
	// answer, it is no answer.
	//
	// Dir: DirForward even though the containment flag is InheritReverse, and by
	// the same rule the runs_* types follow: the CONTAINING thing takes the
	// contained thing's score. Here the repo is the contents (its code is what
	// runs) and the workload is the container, and the repo is the src — the
	// mirror image of runs_image, where the container is the src and the direction
	// is therefore reverse.
	{Type: "deploys_to", Rel: "DeploysTo", Tier: TierCritical, InheritReverse: true, Weight: defaultWeight, Dir: DirForward,
		Reroutes: []string{"DeploysToService"},
		Doc:      "CI/CD deploys repo to k8s workload (non-k8s dst reroutes to DeploysToService in buildEdgeRows). InheritReverse: the repo takes the hop count of what it deploys to."},
	// DirReverse is read straight off the producers: correlate/secgroups.go emits
	// src=the SG that permits and dst=the SG named in its ingress rule (src=dst
	// when the SG admits its own members), and correlate/gcp_firewall.go
	// annotates its pair "governed instance permits ingress… from the
	// source-tagged instance". The attacker moves dst→src.
	{Type: "sg_allows_from", Rel: "AllowsFrom", Tier: TierCritical, Weight: defaultWeight, Dir: DirReverse,
		Doc: "firewall/SG rule: A allows ingress from B (a self-loop when an SG admits its own members)"},
	// DirReverse — capability: a principal that can read a high-value secret is
	// itself a higher-value target. Forward would give the elevation to the
	// secret, which is not a thing anyone remediates.
	{Type: "accesses_secret", Rel: "AccessesSecret", Tier: TierCritical, Reach: true, Weight: defaultWeight, Dir: DirReverse,
		Doc: "IAM role can read this secret"},
	// DirReverse: every producer (collect/aws/elb.go, collect/aws/instances.go,
	// collect/azure/vms.go) emits src=the protected resource, dst=the control, so
	// reverse is "a permissive control raises what it guards". The forward reading
	// — the SG accumulating its members' risk — is what connected_via_sg already
	// carries, and duplicating it here would double-count the same membership.
	{Type: "protected_by", Rel: "ProtectedBy", Tier: TierCritical, Weight: defaultWeight, Dir: DirReverse,
		Doc: "instance or load balancer is protected by this security group or NSG"},
	// binds is a Reach edge: it is the middle of the only path that connects an
	// internet-exposed workload to the RBAC privileges it actually holds —
	// workload -[executes_as]-> ServiceAccount -[binds]-> ClusterRoleBinding
	// -[binds]-> ClusterRole. Without Reach the chain breaks at the first binds
	// hop, so a dangerous ClusterRole never receives an InternetHops value and the
	// must-fix demotion logic treats it as unreachable and suppresses it — exactly
	// inverted for a real, live path.
	{Type: "binds", Rel: "Binds", Tier: TierCritical, Reach: true, Weight: defaultWeight, Dir: DirForward,
		Reroutes: []string{"BindsK8sWorkload"},
		// DanglingBudget 0.25, not the 0.05 default: clusters commonly carry a
		// persistent population of stale RoleBindings/ClusterRoleBindings that
		// reference ServiceAccounts which no longer exist — real RBAC hygiene
		// debt, not attrition or a collection bug. 0.25 tolerates that with
		// headroom while still catching a genuine regression. Tighten toward the
		// default for clusters whose bindings are kept clean.
		DanglingBudget: 0.25,
		Doc:            "k8s RBAC binding (ServiceAccount→ClusterRoleBinding→ClusterRole) — Reach: carries RBAC privilege back to the workload that holds it"},
	// owns has two producers with different endpoint labels: collect/aws/aws.go
	// emits cloud_account -[owns]-> ec2_instance (CloudAccount→Asset, the
	// default Owns table), and correlate/human_identity.go emits
	// human_identity -[owns]-> github_repo — human_identity carries the
	// catch-all Asset label and github_repo maps to NodeRepo, neither matching
	// Owns' declared CloudAccount→Asset. OwnsAsset gives the human_identity
	// producer its own correctly-typed table instead of leaving the default
	// table's declared FROM wrong for it.
	{Type: "owns", Rel: "Owns", Tier: TierCritical, Weight: 0.6, Dir: DirForward,
		Reroutes: []string{"OwnsAsset"},
		Doc:      "cloud account owns asset (aws.go); Asset-labeled src (human_identity, from correlate/human_identity.go) reroutes to OwnsAsset in buildEdgeRows"},
	// Both are principal→policy (collect/aws/iam.go, correlate/iam_permissions.go),
	// so DirReverse is "the policy's danger raises the principal holding it". The
	// forward reading makes a widely-attached policy — AdministratorAccess — a hub
	// that accumulates every attached principal's score, which is a fan-in artefact
	// rather than a fact about the policy.
	{Type: "has_policy", Rel: "HasPolicy", Tier: TierCritical, Weight: defaultWeight, Dir: DirReverse,
		Doc: "IAM role/user has this policy attached"},
	{Type: "allows_action", Rel: "AllowsAction", Tier: TierCritical, Weight: defaultWeight, Dir: DirReverse,
		Doc: "policy grants a dangerous permission category"},
	// Inherit, not Reach: a security group is a firewall RULE, not a
	// network-reachable endpoint — nobody "reaches" a security group, so it must
	// never cost a hop or seed the BFS on its own. But an SG's own open-rule
	// findings are attached to the SG resource itself, and the SG's actual
	// exposure IS the exposure of whatever uses it. src is the member asset, dst
	// is the SG (spoke-hub, see SharedSecurityGroup.Correlate), so the dst
	// inherits the member's hop count, taking the MINIMUM across every member —
	// the same relax-to-minimum closure runs_image uses for a shared
	// container image.
	//
	// Dir: DirBoth: an SG's risk raises its members and a member's the SG.
	// Membership is not a network path (that is sg_allows_from between two
	// memberships), so it is not Reach.
	{Type: "connected_via_sg", Rel: "ConnectedViaSG", Tier: TierCritical, Inherit: true, Weight: 0.9, Dir: DirBoth,
		Doc: "asset is a member of this security group (spoke-hub). Membership alone is not a network path. Inherit: the SG takes the member's hop count, never the other way — the SG is not itself reachable."},
	// has_role is a Reach edge: truncating it silently breaks the
	// internet_hops BFS and demotes real must-fix findings to "contained". It
	// lives in the critical tier because the bulk total can exceed the bulk cap,
	// and every reach edge type must be fetched uncapped.
	{Type: "has_role", Rel: "HasRole", Tier: TierCritical, Reach: true, Weight: 0.6, Dir: DirForward,
		Doc: "IAM role attached to asset (instance profile)"},
	// The k8s internet-exposure chain. Both are Reach edges, so the
	// invariant (TestRegistryConsistency) forces them into the uncapped
	// critical tier: a capped reach edge truncates silently, the internet-hops
	// BFS then misses the ingress→service→pod path, and an internet-facing
	// workload's finding demotes to "contained".
	{Type: "routes_to", Rel: "Accesses", Tier: TierCritical, Reach: true, Weight: 0.7, Dir: DirForward,
		Doc: "k8s ingress routes to service, or an AWS load balancer forwards to an ECS service through a target group — Reach: first hop of the ingress→service→pod (and LB→ecs_service) exposure chain"},
	{Type: "targets", Rel: "Accesses", Tier: TierCritical, Reach: true, Weight: 0.7, Dir: DirForward,
		Reroutes: []string{"AccessesK8sWorkload"},
		Doc:      "k8s service targets workload — Reach: last hop of the internet→ingress→service→pod exposure chain. K8sWorkload-labeled dst (k8s_deployment/k8s_pod/etc.) reroutes to AccessesK8sWorkload in buildEdgeRows — the default Accesses table is Asset→Asset and would silently drop these."},

	// ── Critical tier, containment (Inherit) ─────────────────────────────────
	//
	// The three Inherit types are uncapped for the SAME reason the Reach types
	// are, and TestReachAndInheritTypesAreCritical enforces it: reachability
	// propagates across containment without costing a hop, so a truncated
	// runs_image hides a real path exactly like a truncated can_assume would —
	// the bulk tier's shared row cap starves alphabetically-late types to zero,
	// which silently disables the "contained" demotion path platform-wide.
	//
	// All three carry Inherit (reach flows src→dst: the contents take the
	// container's hop count) and Dir: DirReverse (risk flows dst→src: the
	// container takes the contents' score). That is not a contradiction, it is the
	// two quantities being different — reachability flows INTO containment,
	// severity flows OUT of it. A pod is more dangerous because its image ships a
	// critical CVE; the CVE is not more dangerous because a pod exists.
	{Type: "runs_package", Rel: "RunsPackage", Tier: TierUnsynced, OnDemand: true, Weight: defaultWeight, Dir: DirReverse,
		Doc: "runtime package inventory; queried on demand from ClickHouse, with reach evaluated on its running workload"},
	{Type: "runs_image", Rel: "RunsImage", Tier: TierCritical, Inherit: true, Weight: defaultWeight, Dir: DirReverse,
		Reroutes: []string{"RunsImageAsset"},
		Doc:      "workload (k8s pod, ECS service, Cloud Run service) runs this container image (Inherit: the image's contents are the workload's own attack surface, not a hop away from it). Loaded and expand-traversable: it is the ONLY link from a container_image back to a running workload, so it is what answers \"which workloads run the image that contains package X\". Asset-labelled sources (ecs_service, cloudrun_service) reroute to RunsImageAsset in buildEdgeRows."},
	// Inherit in the FORWARD direction, unlike deploys_to above: every defined_in
	// rel is <resource> → Repo, so the repo is already the destination and takes
	// the declared resource's hop count directly. This is the IaC-ownership half
	// of repo reachability — a Terraform file that declares an internet-facing
	// bucket is as reachable as the bucket it creates. Critical tier, not bulk,
	// for the same row-cap-starvation reason as the block above.
	{Type: "defined_in", Rel: "DefinedInAsset", Tier: TierCritical, Inherit: true, Weight: defaultWeight, Dir: DirForward,
		Reroutes: []string{"DefinedInK8sWorkload", "DefinedInIamRole"},
		Doc:      "resource is declared in this repo — IaC ownership. Inherit: the declaring repo takes the declared resource's hop count."},
	{Type: "runs_container", Rel: "RunsContainer", Tier: TierCritical, Inherit: true, Weight: defaultWeight, Dir: DirReverse,
		Doc: "ecs_service/k8s_pod runs this container (container asset promoted from spec.containers[]/task-def container definitions; Inherit: same containment rationale as runs_image)"},

	// ── Bulk tier: fetched under the bulk row cap ────────────────────────────
	// dns_points_to keeps the fail-open DirBoth: its producer (correlate/rules.go)
	// establishes only that src is a dns_record and dst is infrastructure, and
	// nothing in the tree settles which end raises the other. The two readings —
	// "the name of a risky asset is risky" and "a dangling record is a takeover of
	// the asset" — point opposite ways, and it carries no Reach or Inherit flag to
	// break the tie. Settle it with the dns_record score distribution: if those
	// nodes are score-0 (they are not scored by any check today) the forward half
	// is inert and the reverse half is the only one that ever moved a number.
	{Type: "dns_points_to", Rel: "DnsPointsTo", Tier: TierBulk, Weight: defaultWeight, Dir: DirBoth,
		Doc: "DNS record resolves to this asset"},
	{Type: "depends_on", Rel: "DependsOn", Tier: TierUnsynced, OnDemand: true, Weight: defaultWeight, Dir: DirReverse,
		Doc: "SBOM dependencies queried on demand from ClickHouse"},
	// DirBoth is what the producer already asserts: collect/aws emits the pair of
	// rows (requester→accepter AND accepter→requester) for every peering, so a
	// one-directional index here would be undone by the data anyway.
	{Type: "peered_with", Rel: "PeeredWith", Tier: TierBulk, Weight: defaultWeight, Dir: DirBoth,
		Doc: "VPC peering connection"},
	// DirReverse is inert in the BFS and declared for consistency with the other
	// containment types: the DataClass endpoints are sentinels MERGE'd into Ladybug by
	// graphstore.seedSentinels, never assets, so they are absent from the score map
	// the BFS reads and contribute 0 in either direction. exposed_to_internet's
	// `internet` sentinel is inert for the same reason.
	{Type: "contains_data", Rel: "ContainsData", Tier: TierBulk, Weight: defaultWeight, Dir: DirReverse,
		Doc: "DSPM classification: asset contains this data class (pii/financial/…)"},

	// ── Unsynced: written to graph_edges but never fetched into Ladybug ─────────
	//
	// Their Dir is latent: an unsynced type never enters the edge slice the BFS
	// builds its adjacency from, so nothing below changes a score today. It is
	// declared because TestRegistryConsistency requires it on every entry, and
	// because re-syncing a type must not also be a silent decision about risk
	// direction. runs_in/in_vpc/in_subnet/member_of_zone are hub-shaped containment
	// (pod→namespace, asset→vpc, record→zone) where DirForward is what stops the hub
	// from accumulating every member's score. applies_to is gcp_firewall→gce_instance,
	// the mirror of protected_by, so DirForward is the same "the control raises what
	// it governs" claim read off the opposite src/dst order.
	{Type: "applies_to", Rel: "ProtectedBy", Tier: TierUnsynced, Weight: defaultWeight, Dir: DirForward,
		Doc: "gcp firewall applies to instance; unsynced ON PURPOSE — the src asset type (gcp_firewall) is in NeverSyncTypes, so its node never exists in Ladybug and the edge would be endpoint-dropped"},
	// member_of_zone + in_subnet: their rel tables are not Loaded, so every
	// fetched row is discarded again at COPY — pure waste that also starves the
	// alphabetically-later bulk types out of the shared fetch budget.
	// runs_in: unlike the two above, its rel (Accesses) IS loaded, which makes it
	// actively harmful rather than merely wasteful — its dominant source label
	// (k8s_pod, :K8sWorkload) doesn't match Accesses' Asset→Asset typing and its
	// dominant destination type (k8s_namespace) can never be a Ladybug node, so every
	// row arrives at the loader as a label mismatch, firing the security-edge WARN
	// on every build. A reroute is the wrong fix here: the destination type is
	// excluded from the graph by design, so a reroute would just convert the
	// mismatch into an endpoint-absent drop and load nothing. runs_in is neither
	// Reach nor Inherit and nothing else traverses it, so leaving it unsynced
	// changes no answer and removes the false alarm at the source.
	{Type: "runs_in", Rel: "Accesses", Tier: TierUnsynced, Weight: 0.7, Dir: DirForward,
		Reroutes: []string{"RunsIn"},
		Doc:      "containment topology (pod→namespace, GCE→VPC); unsynced ON PURPOSE — most rows point at k8s_namespace, which is in NeverSyncTypes and can never be a Ladybug node, and the k8s_pod source is K8sWorkload-labelled against an Asset→Asset rel, so every row was a label mismatch on a reach rel"},
	// in_vpc: every destination type (vpc, azure_vnet) is in NeverSyncTypes, so
	// the InVPC rel table can never hold a row regardless of source label —
	// declaring it Loaded would assert a traversability that can never hold.
	// Nothing queries it either (no `[:InVPC]` anywhere in named_queries.go, the
	// expand view, or a frontend template), so leaving it unsynced costs nothing.
	{Type: "in_vpc", Rel: "InVPC", Tier: TierUnsynced, Weight: defaultWeight, Dir: DirForward,
		Doc: "subnet/EC2/SG lives inside this VPC; unsynced ON PURPOSE — every destination type (vpc, azure_vnet via azure_subnet) is in NeverSyncTypes, so all fetched rows were discarded at COPY on every build, and no query, expand branch or frontend template traverses InVPC"},
	{Type: "member_of_zone", Rel: "MemberOfZone", Tier: TierUnsynced, Weight: defaultWeight, Dir: DirForward,
		Doc: "DNS record belongs to this zone; unsynced ON PURPOSE — MemberOfZone is not Loaded, so the rows were fetched and then dropped, and they were the single biggest consumer of the bulk fetch budget"},
	{Type: "in_subnet", Rel: "InSubnet", Tier: TierUnsynced, Weight: defaultWeight, Dir: DirForward,
		Doc: "asset lives inside this subnet; unsynced ON PURPOSE — same as member_of_zone: InSubnet is not Loaded, so every fetched row was discarded at COPY"},
	// member_of is the only edge that puts a person on the other end of the SSO
	// access graph — the sso_group and sso_permission_set nodes already in Ladybug
	// are assigned permission sets that grant admin on accounts, and without this
	// edge nothing says WHO is in those groups. Two shapes (internal/collect/okta):
	//
	//	human_identity → sso_group(okta)   MemberOf       (Asset→Group)
	//	sso_group(okta) → sso_group(aws)   MemberOfGroup  (Group→Group, SCIM name match)
	//
	// Critical, not bulk, despite carrying no Reach flag: the bulk tier's shared
	// cap starves alphabetically-late types to zero rows, and zero rows here does
	// not thin the identity graph, it deletes it silently while every group and
	// permission-set node stays present and looks healthy.
	{Type: "member_of", Rel: "MemberOf", Tier: TierCritical, Weight: defaultWeight, Dir: DirForward,
		Reroutes: []string{"MemberOfGroup"},
		Doc:      "identity group membership: human_identity → Okta group, and Okta group → the AWS Identity Center group of the same name (Group-labeled src reroutes to MemberOfGroup in buildEdgeRows)"},

	// ── SSO tier: emitted by the AWS Identity Center collector from the
	// provisioned assignments ────────────────────────────────────
	{Type: "assigned_to", Rel: "AssignedTo", Tier: TierBulk, Weight: defaultWeight, Dir: DirForward,
		Doc: "SSO group is assigned this permission set"},
	{Type: "grants_access_to", Rel: "GrantsAccessTo", Tier: TierBulk, Weight: defaultWeight, Dir: DirForward,
		Doc: "permission set is provisioned to this account"},
	{Type: "grants_admin", Rel: "GrantsAdmin", Tier: TierCritical, Reach: true, Weight: 0.8, Dir: DirForward,
		Doc: "permission set confers admin on this account"},
}

// Rels is the registry of every Ladybug rel table reachable from the edge
// pipeline (edgeUnwindQ keys). Order is kept in derived slices.
var Rels = []Rel{
	{Name: "ExposedToInternet", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "internet-reachable asset"},
	{Name: "ExposedToInternetK8sWorkload", From: NodeK8sWorkload, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "internet-reachable k8s workload — src is :K8sWorkload, not :Asset. Split of `exposed_to_internet`, which defaults to ExposedToInternet (Asset→Asset); buildEdgeRows reroutes here when the source is K8sWorkload-labeled. A missing split shows up as label_mismatch on graph_ladybug_edge_type_rows{edge_type=\"exposed_to_internet\"}; neither the reach-rel WARN (exposed_to_internet is the BFS SEED, not a Reach movement edge) nor the loaded=0 alert (Asset-labelled rows keep the table non-empty) would catch it."},
	{Name: "DnsPointsTo", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "DNS record resolves to this asset"},
	{Name: "ConnectedViaSG", From: NodeAsset, To: NodeAsset, Loaded: true,
		Doc: "SG membership, asset→security_group. Sharing an SG is NOT a network path; for SG reachability walk AllowsFrom between memberships: (a)-[:ConnectedViaSG]->(s:Asset), (t:Asset)-[:AllowsFrom]->(s), (b)-[:ConnectedViaSG]->(t) — a reaches b (t = s when the SG admits its own members)"},
	{Name: "AllowsFrom", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "firewall/SG rule: A allows ingress from B, so B can reach A (attacker movement runs dst→src). AWS: security_group→security_group, a self-loop when an SG admits its own members; GCP: gce_instance→gce_instance"},
	{Name: "PeeredWith", From: NodeAsset, To: NodeAsset,
		DropReason: "bfs_only: VPC peering is context topology — kept in the Go edge slice for BFS risk propagation, not query-traversable",
		Doc:        "VPC peering connection"},
	// ProtectedBy's rows are (instance|load_balancer)-[:ProtectedBy]->(security_group)
	// in every producer. It sits inside NOT EXISTS clauses in
	// unprotected_internet_facing_lbs and zombie_lbs, where an always-absent edge
	// does not merely return empty — it stops those clauses from excluding anything.
	{Name: "ProtectedBy", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "(instance|load_balancer)-[:ProtectedBy]->(security_group) — the protected resource is the source node"},
	{Name: "HasRole", From: NodeAsset, To: NodeIamRole, Loaded: true, Expand: true,
		Doc: "IAM role attached to asset"},
	{Name: "ExecutesAs", From: NodeAsset, To: NodeIamRole, Loaded: true, Expand: true,
		Doc: "workload uses this IAM identity"},
	{Name: "ExecutesAsK8sWorkload", From: NodeK8sWorkload, To: NodeIamRole, Loaded: true, Expand: true,
		Doc: "k8s pod/deployment → cloud IAM role. Expand-traversable like ExecutesAs (the Asset-sourced half of the same edge type), so expanding a pod shows its IAM role just as expanding an EC2 instance does."},
	// ExecutesAsK8sServiceAccount is the pod→ServiceAccount hop: every k8s_pod
	// asset carries the ServiceAccount it runs under in
	// Metadata["service_account"] (collect/kubernetes/kubernetes.go). Without
	// this edge the pod could never reach the RBAC privileges and cloud identity
	// hanging off that ServiceAccount:
	//
	//	pod -[this edge]-> ServiceAccount -[binds]-> RoleBinding -[binds]-> ClusterRole
	//	pod -[this edge]-> ServiceAccount -[executes_as]-> cloud role (IRSA/WIF)
	//
	// Reach follows from executes_as being Reach: an exposed pod reaches the RBAC
	// privileges and cloud identity it actually holds. The SA→cloud-role hop must
	// be executes_as (ExecutesAs rule for the IRSA annotation, GCPWorkloadIdentity
	// for the GKE one) — the parallel federated_access edge is not Reach.
	{Name: "ExecutesAsK8sServiceAccount", From: NodeK8sWorkload, To: NodeK8sWorkload, Loaded: true, Expand: true,
		Doc: "k8s pod runs under this in-cluster ServiceAccount — both endpoints are :K8sWorkload (k8s_pod and k8s_service_account both promote to that label), so neither the default ExecutesAs (Asset→IamRole) nor ExecutesAsK8sWorkload (K8sWorkload→IamRole) can hold these rows"},
	{Name: "AccessesK8sWorkload", From: NodeAsset, To: NodeK8sWorkload, Loaded: true, Expand: true,
		Doc: "k8s service targets workload (selector match, last hop) — dst is :K8sWorkload, not :Asset. Split of `targets`, which defaults to Accesses (Asset→Asset) in the EdgeTypes table; buildEdgeRows reroutes here when the destination is K8sWorkload-labeled."},
	{Name: "CanAssume", From: NodeIamRole, To: NodeIamRole, Loaded: true, Expand: true,
		Doc: "role A can assume role B"},
	{Name: "CanEscalateTo", From: NodeIamRole, To: NodeIamRole, Loaded: true, Expand: true,
		Doc: "CIEM privilege escalation path"},
	{Name: "DeploysTo", From: NodeRepo, To: NodeK8sWorkload, Loaded: true, Expand: true,
		Doc: "CI/CD deploys to this k8s pod/deployment (dst is :K8sWorkload, NOT :Asset)"},
	{Name: "DeploysToService", From: NodeRepo, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "CI/CD deploys to a non-k8s service (ECS/Lambda/Cloud Run/load balancer)"},
	{Name: "DependsOn", From: NodeRepo, To: NodePackage,
		DropReason: "on_demand: package inventory is queried from ClickHouse",
		Doc:        "SBOM repo dependency"},
	{Name: "InVPC", From: NodeAsset, To: NodeAsset,
		DropReason: "unfed: in_vpc is TierUnsynced, so nothing reaches this table — and nothing ever did, because every in_vpc destination type is in NeverSyncTypes (fetched but never loaded). The DDL stays because dropping a rel table is a checksum change with no benefit",
		Doc:        "asset lives in this VPC"},
	{Name: "Binds", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "k8s RBAC binding (ClusterRoleBinding→ClusterRole)"},
	{Name: "BindsK8sWorkload", From: NodeK8sWorkload, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "k8s ServiceAccount → ClusterRoleBinding — src is :K8sWorkload, not :Asset. Split of `binds`, which defaults to Binds (Asset→Asset); buildEdgeRows reroutes here when the source is K8sWorkload-labeled. Without this split every SA→binding row would be discarded at COPY (k8s_service_account is K8sWorkload-labeled), so no query could reach a ClusterRole from the identity that holds it."},
	{Name: "AccessesSecret", From: NodeIamRole, To: NodeAsset, Loaded: true,
		Doc: "IAM role can read this GCP secret"},
	{Name: "FederatedAccess", From: NodeRepo, To: NodeIamRole, Loaded: true,
		Doc: "GitHub Actions OIDC → cloud role"},
	{Name: "FederatedAccessK8sWorkload", From: NodeK8sWorkload, To: NodeIamRole, Loaded: true,
		Doc: "GKE Workload Identity / IRSA: k8s ServiceAccount → cloud role — src is :K8sWorkload, not :Repo. Split of `federated_access`, which defaults to FederatedAccess (Repo→IamRole); buildEdgeRows reroutes here when the source is K8sWorkload-labeled. Without the split every k8s_service_account→gcp_service_account edge would be discarded at COPY while the github_repo-sourced edges load fine — a label mismatch the drop detector cannot see, because it only reports rel tables that lose SOME rows, not ALL of one producer's."},
	// FederatedAccessAsset: correlate/human_identity.go emits
	// human_identity -[federated_access]-> iam_role; human_identity is absent
	// from graphstore.assetTypeToNode, so it falls back to :Asset, while the
	// default FederatedAccess table is Repo→IamRole. Without this table those
	// rows would be discarded at COPY with no error or metric — federated_access
	// is not a Reach type, so the usual detectors never fire on it.
	//
	// A reroute rather than a dedicated human_identity node label: promoting a
	// type off Asset is what causes the mismatch class in the first place (see
	// NodeAsset above), and a human identity carries nothing the Asset columns
	// can't hold. Typed on the Asset LABEL, not the human_identity type, so any
	// future Asset-labelled federated_access producer lands here too.
	{Name: "FederatedAccessAsset", From: NodeAsset, To: NodeIamRole, Loaded: true,
		Doc: "a human identity (Okta/Google) federates into this cloud role — src is :Asset, not :Repo. Split of `federated_access`, which defaults to FederatedAccess (Repo→IamRole); buildEdgeRows reroutes here when the source carries the catch-all Asset label."},
	// The identity chain (see the member_of entry in EdgeTypes for why it is
	// critical-tier). Both are Expand: a group node whose only inbound edge is
	// invisible to the expand view can't answer "who is in this group?".
	{Name: "MemberOf", From: NodeAsset, To: NodeSSOGroup, Loaded: true, Expand: true,
		Doc: "human identity is a member of this identity-provider group (src is :Asset — human_identity has no dedicated node label)"},
	{Name: "MemberOfGroup", From: NodeSSOGroup, To: NodeSSOGroup, Loaded: true, Expand: true,
		Doc: "Okta group maps to the AWS Identity Center group of the same name (SCIM display-name match) — the join that connects a person to a permission set"},
	{Name: "RunsPackage", From: NodeAsset, To: NodePackage,
		DropReason: "on_demand: runtime package inventory is queried from ClickHouse",
		Doc:        "asset runs this package; available through bounded inventory exploration"},
	{Name: "RunsIn", From: NodePackage, To: NodeAsset,
		DropReason: "bfs_only: package→asset placement from scanner feeds — no named query traverses it; kept for BFS",
		Doc:        "package runs in this asset"},
	{Name: "Accesses", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "generic containment/topology (runs_in, targets, routes_to). targets reroutes to AccessesK8sWorkload when its dst is K8sWorkload-labeled — routes_to never has a K8sWorkload dst (its only emitter, k8s ingress collection, always targets a k8s_service, which stays generic Asset) so it never needs the reroute."},
	// RunsImage is Loaded, with endpoints declared K8sWorkload→Asset rather than
	// generic Asset→Asset. It is the only edge from a container_image back to a
	// running workload, and RunsPackage is the only edge from an image to a
	// package — without RunsImage loaded, the chain
	// package ← container_image ← k8s_pod dead-ends at the image, so "which pods
	// run the image containing package X" has no answer in Ladybug.
	//
	// The default table keeps its K8sWorkload source (the k8s collector is the
	// bulk producer); the ECS and Cloud Run collectors emit the same edge from
	// Asset-labelled services, which RunsImageAsset holds.
	{Name: "RunsImage", From: NodeK8sWorkload, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "k8s pod runs this container image — the image side of the supply-chain chain (pod →RunsImage→ container_image →RunsPackage→ package)"},
	{Name: "RunsImageAsset", From: NodeAsset, To: NodeAsset, Loaded: true, Expand: true,
		Doc: "ECS service / Cloud Run service runs this container image — src is :Asset, not :K8sWorkload. Split of `runs_image`, which defaults to RunsImage (K8sWorkload→Asset); buildEdgeRows reroutes here when the source is not K8sWorkload-labeled, or every non-k8s workload→image row would be discarded at COPY."},
	// RunsContainer stays unloaded: `container` is a large asset population that
	// always scores 0 and carries no open findings (image vulnerabilities key on
	// `package` instead), so retaining it would blow the node budget to add nodes
	// nothing scores, queries, or reports on. The edge is fetched only for the
	// containment closure.
	{Name: "RunsContainer", From: NodeAsset, To: NodeAsset,
		DropReason: "inherit_only: workload→container containment — consumed by the internetHops closure, never traversed. Unlike RunsImage (loaded) there is nothing at the far end to traverse TO: its destination type `container` is deliberately not retained in Ladybug (a very large asset population, all score 0, zero findings), and the package inventory hangs off container_image, not off `container`",
		Doc:        "ecs_service/k8s_pod runs this container"},
	{Name: "Owns", From: NodeCloudAccount, To: NodeAsset,
		DropReason: "bfs_only: account ownership is inventory context, not an attack edge; kept for BFS",
		Doc:        "cloud account owns asset (collect/aws/aws.go: cloud_account -> ec2_instance)"},
	// OwnsAsset is the human_identity-sourced half of `owns`: it emits
	// human_identity -[owns]-> github_repo, and human_identity carries the
	// catch-all Asset label while github_repo maps to NodeRepo — neither
	// endpoint matches the default Owns table (CloudAccount→Asset). It is
	// registry correctness, not a promotion to Loaded: it exists so that if
	// Owns or OwnsAsset is ever promoted, the human_identity producer already has
	// a correctly-typed table to land in instead of silently violating Owns'
	// declared FROM.
	{Name: "OwnsAsset", From: NodeAsset, To: NodeRepo,
		DropReason: "bfs_only: same reasoning as Owns — account/identity ownership is inventory context, not an attack edge; kept for BFS",
		Doc:        "human identity owns this github repo (src is :Asset — human_identity has no dedicated node label; correlate/human_identity.go). Split of `owns`, which defaults to Owns (CloudAccount→Asset); buildEdgeRows reroutes here when the source carries the catch-all Asset label."},
	{Name: "HasPolicy", From: NodeIamRole, To: NodeIamPolicy,
		DropReason: "bfs_only: policy attachment detail — CIEM queries use CanAssume/CanEscalateTo instead; kept for BFS",
		Doc:        "role/user has policy attached"},
	{Name: "AllowsAction", From: NodeIamRole, To: NodeIamPolicy,
		DropReason: "bfs_only: permission-category detail — surfaced through findings, not graph traversal; kept for BFS",
		Doc:        "policy grants dangerous permission"},
	{Name: "InSubnet", From: NodeAsset, To: NodeSubnet,
		DropReason: "unfed: in_subnet is TierUnsynced, so nothing reaches this table — the DDL stays only because Subnet is still a node label",
		Doc:        "asset lives inside this subnet"},
	{Name: "MemberOfZone", From: NodeAsset, To: NodeDNSZone,
		DropReason: "unfed: member_of_zone is TierUnsynced, so nothing reaches this table — the DDL stays only because DNSZone is still a node label",
		Doc:        "DNS record belongs to this zone"},
	{Name: "ContainsData", From: NodeAsset, To: NodeDataClass, Loaded: true,
		Doc: "storage asset holds this data classification (DSPM). DataClass(id, classification); ids: dataclass:pii|financial|credentials|health|pci|internal"},
	{Name: "AssignedTo", From: NodeSSOGroup, To: NodeSSOPermSet, Loaded: true, Expand: true,
		Doc: "SSO group → permission set"},
	{Name: "GrantsAccessTo", From: NodeSSOPermSet, To: NodeCloudAccount, Loaded: true, Expand: true,
		Doc: "permission set → account it is provisioned to"},
	{Name: "GrantsAdmin", From: NodeSSOPermSet, To: NodeCloudAccount, Loaded: true, Expand: true,
		Doc: "permission set → account it grants admin on"},
	{Name: "DefinedInK8sWorkload", From: NodeK8sWorkload, To: NodeRepo, Loaded: true, Expand: true,
		Doc: "live k8s workload (pod/deployment/statefulset/daemonset/job) is declared in this repo — IaC ownership from a parsed manifest"},
	{Name: "DefinedInAsset", From: NodeAsset, To: NodeRepo, Loaded: true, Expand: true,
		Doc: "live asset (k8s_service, container_image, Terraform-declared resources) is declared in this repo — IaC ownership"},
	{Name: "DefinedInIamRole", From: NodeIamRole, To: NodeRepo, Loaded: true, Expand: true,
		Doc: "IAM role is declared in this repo — IAM-role ownership (Terraform state, identifier harvest)"},
}

// ── Derivations ──────────────────────────────────────────────────────────────

// TierEdgeTypes returns the edge_type values in the given tier, in registry order.
func TierEdgeTypes(t Tier) []string {
	var out []string
	for _, e := range EdgeTypes {
		if e.Tier == t {
			out = append(out, e.Type)
		}
	}
	return out
}

// EdgeTypeToRel returns the edge_type → rel table map (types with no rel are absent).
func EdgeTypeToRel() map[string]string {
	out := make(map[string]string, len(EdgeTypes))
	for _, e := range EdgeTypes {
		if e.Rel != "" {
			out[e.Type] = e.Rel
		}
	}
	return out
}

// RelByName returns the rel entry for a rel table name.
func RelByName(name string) (Rel, bool) {
	for _, r := range Rels {
		if r.Name == name {
			return r, true
		}
	}
	return Rel{}, false
}

// LoadedRels returns the rel tables loaded into Ladybug (traversable), in registry order.
func LoadedRels() []Rel {
	var out []Rel
	for _, r := range Rels {
		if r.Loaded {
			out = append(out, r)
		}
	}
	return out
}

// ExpandRels returns the rel tables in the structured expand view, in registry order.
func ExpandRels() []Rel {
	var out []Rel
	for _, r := range Rels {
		if r.Expand {
			out = append(out, r)
		}
	}
	return out
}

// TierOf returns the fetch tier for an edge_type (TierUnsynced if unknown).
func TierOf(edgeType string) Tier {
	for _, e := range EdgeTypes {
		if e.Type == edgeType {
			return e.Tier
		}
	}
	return TierUnsynced
}

// ReachEdgeTypes returns the attacker-movement edge_type set for the
// internet_hops BFS.
func ReachEdgeTypes() map[string]bool {
	out := map[string]bool{}
	for _, e := range EdgeTypes {
		if e.Reach {
			out[e.Type] = true
		}
	}
	return out
}

// InheritEdgeTypes returns the containment edge_type set across which internet
// reachability is inherited rather than traversed.
//
// These are NOT attacker movement — nothing is exploited by "running" an
// image — which is why they are deliberately absent from ReachEdgeTypes. But
// they are also not mere adjacency: what is inside a workload you have
// already reached is part of that workload's attack surface, exploitable at
// the workload's distance, not extra hops away. Modelling that as inheritance
// rather than extra BFS depth keeps it correct without loosening every other
// identity chain the way raising maxReachDepth globally would.
func InheritEdgeTypes() map[string]bool {
	out := map[string]bool{}
	for _, e := range EdgeTypes {
		if e.Inherit {
			out[e.Type] = true
		}
	}
	return out
}

// InheritReverseEdgeTypes returns the containment edge_type set whose SOURCE
// inherits its destination's hop count — the mirror of InheritEdgeTypes.
//
// Kept as a separate set rather than a direction field on Inherit so that every
// consumer has to decide which one it means. internetHops reads both and appends
// to the same adjacency in opposite directions; ReachComplete and the
// tier guard read the union, because a truncated reverse-containment edge hides
// a real path exactly as well as a truncated forward one.
func InheritReverseEdgeTypes() map[string]bool {
	out := map[string]bool{}
	for _, e := range EdgeTypes {
		if e.InheritReverse {
			out[e.Type] = true
		}
	}
	return out
}

// WeightFor returns the BFS risk-propagation weight for a snake_case edge_type.
func WeightFor(edgeType string) float64 {
	for _, e := range EdgeTypes {
		if e.Type == edgeType {
			return e.Weight
		}
	}
	return defaultWeight
}

// DirectionFor returns the risk-propagation direction for a snake_case
// edge_type. An unregistered type — or a registered one that forgot to declare
// a direction, which TestRegistryConsistency rejects — answers DirBoth, the
// fail-open direction: a new producer's edge over-propagates instead of
// silently losing one direction of risk.
func DirectionFor(edgeType string) Direction {
	for _, e := range EdgeTypes {
		if e.Type != edgeType {
			continue
		}
		switch e.Dir {
		case DirForward, DirReverse, DirBoth:
			return e.Dir
		}
		return DirBoth
	}
	return DirBoth
}

// EdgeTypesForRel returns the snake_case edge_type values that feed a
// PascalCase rel table — the translation the ClickHouse fallback needs to
// filter graph_edges (which stores snake_case) by rel-table names.
func EdgeTypesForRel(rel string) []string {
	var out []string
	for _, e := range EdgeTypes {
		if e.Rel == rel {
			out = append(out, e.Type)
		}
	}
	return out
}

// ReachRels are the rel table names carrying at least one Reach edge type — the
// tables whose rows the internet-hops BFS depends on. Losing rows from one of
// these does not merely thin the graph: it makes assets look UNREACHABLE, which
// downstream reads as the positive assertion "no internet-reachable attack path"
// and demotes real findings to contained. Callers use this to decide whether a
// load-time row loss invalidates the reach signal.
//
// Reroute targets count too — Rel is only the DEFAULT table, so a rel reachable
// only through a reroute (e.g. ExecutesAsK8sWorkload) must still be included or
// its load-time losses go unreported.
func ReachRels() map[string]bool {
	out := map[string]bool{}
	for _, e := range EdgeTypes {
		if !e.Reach {
			continue
		}
		if e.Rel != "" {
			out[e.Rel] = true
		}
		for _, r := range e.Reroutes {
			out[r] = true
		}
	}
	return out
}

// RerouteRels are the rel tables reachable ONLY through a conditional reroute in
// graphstore.buildEdgeRows (endpoint-label-dependent routing), never through an
// edge type's default Rel. Consumers that ask "is this rel fed by anything?" must
// consult it or they will report a live table as dead.
func RerouteRels() map[string]bool {
	out := map[string]bool{}
	for _, e := range EdgeTypes {
		for _, r := range e.Reroutes {
			out[r] = true
		}
	}
	return out
}

// IdentityAssetTypes are the principal (identity) asset types — an IAM user/role,
// a GCP service account, an Azure service principal/managed identity. An identity
// is NEVER itself a node on the internet: "internet-exposed" (direct network
// reachability) is a category error for these, so an identity can never be a seed
// of the internet-hops BFS. Declared here as the single source of truth so both
// the reach seed filter (internal/app/graphstore) and enrich.IsIdentityResource
// derive from one list rather than duplicating it across the layering boundary
// (the layering rules forbid a graphstore↔enrich import).
var IdentityAssetTypes = []string{
	"iam_user",
	"iam_role",
	"gcp_service_account",
	"azure_service_principal",
	"azure_managed_identity",
	// sso_permission_set is a grant object, not a principal — nothing "acts as"
	// a permission set — but the same category error applies: it is not
	// network-located, so "no internet-reachable path" is the wrong question,
	// not evidence of safety. It is the SOURCE of grants_admin (Reach) but never
	// the destination of anything Reach/Inherit, so it can never receive a hop
	// count under any topology. This is a defensive guard against a future edge
	// that accidentally seeds it.
	//
	// Not folded into K8sRBACAssetTypes' dedicated classifier below: that path
	// exists because RBAC findings key on WHO HOLDS the grant (subjects/binds
	// edges), a question this check does not ask — it fires on the grant's
	// CONTENT (AdministratorAccess / Action "*").
	"sso_permission_set",
}

// DependentEdgeTypes are the inbound edges that mean "something relies on this
// asset" and could break if it changed — the inverse of the attack blast radius:
// not "what can this reach if popped" but "what would break if a fix changed it".
// EdgesIntoTypes(resourceID, DependentEdgeTypes) is the one question, and the
// count of DISTINCT source assets it returns is the one answer.
//
// Declared here, not in a domain, because two domains ask it (enrich's
// safety_class worklist, respond's impact assessment fed to the remediation
// reasoner) and must not disagree — the layering rules forbid them importing
// each other, so a shared fact has to live under them. Same shape as
// IdentityAssetTypes below, for the same reason.
//
// Each entry, with what it means when it points AT the judged resource:
//
//   - dns_points_to    a DNS record resolves here
//   - executes_as      a workload runs as this identity
//   - federated_access an external IdP federates into this identity
//   - can_assume       a principal assumes this role
//   - has_role         an instance profile grants it to a workload
//   - binds            a RoleBinding references this Role
//   - targets          a Service routes here — the Kubernetes analogue of
//     dns_points_to
//   - accesses_secret  an iam_role or service account reads this secret; deleting
//     or rotating it breaks that workload
//   - depends_on / runs_package  the SBOM and image edges into a package
//
// Deliberately excluded: deploys_to (the deploying repo is the fix OWNER, not a
// runtime dependent) and owns (account ownership, not dependency — counting it
// would make every AWS resource permanently "risky"). See enrich/safety.go for
// the measured per-type evidence and for the resource types whose dependents
// count is not answerable at all.
var DependentEdgeTypes = []string{
	"dns_points_to", "executes_as", "federated_access",
	"can_assume", "has_role", "binds", "targets", "accesses_secret",
	"depends_on", "runs_package",
}

// K8sRBACBindingTypes are the Kubernetes RBAC GRANT objects — the ones that
// name subjects. Split from K8sRBACRoleTypes because the two answer "who holds
// this?" differently: a binding carries its subjects directly, a role only via
// the bindings that reference it.
var K8sRBACBindingTypes = []string{
	"k8s_role_binding",
	"k8s_cluster_role_binding",
}

// K8sRBACRoleTypes are the Kubernetes RBAC PERMISSION SET objects.
var K8sRBACRoleTypes = []string{
	"k8s_role",
	"k8s_cluster_role",
}

// K8sRBACAssetTypes is every Kubernetes RBAC object — permission sets and the
// grants that hand them out. Declared here, not in enrich, so the must-fix
// classifier and any future graph loader derive one list rather than drifting
// apart ("declare once, derive everywhere"), exactly as
// IdentityAssetTypes does for cloud principals.
//
// These are deliberately NOT in IdentityAssetTypes. An RBAC object is not a
// principal: a Role is a set of permissions and a RoleBinding is a grant, and
// neither is something an attacker "is". The identity carve-out in
// enrich.classifyMustFix exists to stop network-unreachability demoting a
// principal; these types never reach that gate at all, because they are not
// graph nodes and so never produce an internet-hops answer.
var K8sRBACAssetTypes = append(append([]string{}, K8sRBACRoleTypes...), K8sRBACBindingTypes...)

var k8sRBACTypeSet = sliceToSet(K8sRBACAssetTypes)

var k8sRBACBindingTypeSet = sliceToSet(K8sRBACBindingTypes)

// IsK8sRBACType reports whether an asset type is a Kubernetes RBAC object.
func IsK8sRBACType(assetType string) bool { return k8sRBACTypeSet[assetType] }

// IsK8sRBACBindingType reports whether an asset type is a Kubernetes RBAC grant
// (RoleBinding / ClusterRoleBinding) rather than a permission set.
func IsK8sRBACBindingType(assetType string) bool { return k8sRBACBindingTypeSet[assetType] }

// sliceToSet is the O(1) lookup form of a type list.
func sliceToSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// identityTypeSet is the O(1) lookup form of IdentityAssetTypes.
var identityTypeSet = func() map[string]bool {
	m := make(map[string]bool, len(IdentityAssetTypes))
	for _, t := range IdentityAssetTypes {
		m[t] = true
	}
	return m
}()

// IsIdentityType reports whether an asset type is a principal (identity) rather
// than a network-addressable resource. See IdentityAssetTypes.
func IsIdentityType(assetType string) bool {
	return identityTypeSet[assetType]
}
