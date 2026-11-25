package enrich

import (
	"context"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// Advisory "safe to fix" classes — the inverse of the attack blast radius: not
// "what can this reach if popped" but "what would break if a fix changed it",
// combined with whether the resource is even used. Computed at enrich time from
// graph structure alone (no LLM), on EVERY finding, so a freshly-onboarded
// environment has an actionable "start here" worklist the moment its first sync
// completes — rather than waiting for the per-finding reasoning backlog to reach
// each one. The reasoncache safety_band (respond.SafetyBandFor) folds in the
// chosen action class and supersedes this once a finding is reasoned; the class
// names deliberately match it so the UI renders one vocabulary.
const (
	SafetySafe    = "safe"    // conservative: nothing depends on it AND it looks unused
	SafetyCaution = "caution" // usage unconfirmed — verify before acting
	SafetyRisky   = "risky"   // depended-on, production, or internet-facing — a fix could disrupt
)

// safetyFreshWindow: an asset seen within this window is "present" — a live target
// worth fixing. Beyond it the asset is stale (rotated away / decommissioned / gone),
// and its finding is moot, not a safe quick-win — treating stale-as-safe would
// flood the worklist with dead resources (ephemeral k8s pods/jobs, churned
// compute). Mirrors respond.staleAssetAge.
const safetyFreshWindow = 7 * 24 * time.Hour

// dependentEdgeTypes are the inbound edges that mean "something relies on this
// asset" and could break if it changed.
//
// A narrow set here makes "safe" a claim about the edge set rather than about
// the resource: an IAM role that many instances run with, a Role bindings
// reference, a pod a Service routes to — anything not in this list scores
// dependents = 0 and, if present, gets declared safe. safety_class drives the
// Start-here worklist, so an incomplete set here recommends deleting
// load-bearing resources.
//
//   - dns_points_to    a DNS record resolves here
//   - executes_as      a workload runs as this identity
//   - federated_access an external IdP federates into this identity
//   - can_assume       a principal assumes this role
//   - has_role         an instance profile grants it to a workload
//   - binds            a RoleBinding references this Role
//   - targets          a Service routes here — the Kubernetes analogue of
//     dns_points_to
//   - accesses_secret  an iam_role or service account reads this secret;
//     deleting or rotating it breaks that workload
//   - depends_on / runs_package  the SBOM and image edges into a package. Their
//     only destination type is `package`, which safetyUnassessableTypes currently
//     excludes from classification — so they change nothing today. They are kept
//     rather than dropped because they are the CORRECT dependents for a package:
//     if that exclusion is ever lifted, the count is right instead of zero.
//
// Deliberately excluded, each for its own reason:
//
//   - deploys_to  the deploying repo is the fix OWNER, not a runtime dependent. It
//     feeds fixTargetOf below, not the dependents count.
//   - owns        (cloud_account → ec2_instance) is account ownership, not
//     dependency. Deleting an instance does not break the account, and counting
//     it would make every single AWS resource permanently "risky" — the same
//     degeneracy documented for packages above, in the other direction.
//   - attached_to  does not exist anywhere in this platform: ebs_volume is in
//     asset.NeverSyncTypes and has zero inbound edges of ANY type. That is a
//     graph-coverage gap, handled honestly by safetyUnassessableTypes rather
//     than by a phantom entry here that would look like a fix.
//
// Shared with respond, which asks the identical question for the remediation
// reasoner's impact assessment. The list is DECLARED ONCE in graphschema and both
// domains derive from it — two different answers to "what depends on this?"
// is a defect: the domain that mutates cloud state must never be told a
// different dependent count than the one enrich shows on the finding. Add types
// to graphschema.DependentEdgeTypes, never to a local copy here.
var dependentEdgeTypes = graphschema.DependentEdgeTypes

// safetyUnassessableTypes are resource types for which this model cannot produce
// an honest safety class, so it produces NONE — SafetyClass stays empty, exactly
// like a not-yet-enriched finding, and the resource appears in neither the
// Start-here worklist nor the risky list.
//
// This is a deliberate third answer alongside safe/caution/risky. The alternative
// — forcing every resource into one of the three — fails in both directions:
//
//   - package. Adding depends_on to the dependents count would flip every package
//     to risky: a `package` asset only exists in the graph BECAUSE something
//     depends on it, so the dependents count is >= 1 by construction and has zero
//     discriminating power. The deeper mismatch is that the model asks "what
//     breaks if this is removed" while the action for a package finding is
//     `upgrade`, not `delete` — the question does not apply. The real
//     supply-chain urgency signal already exists and is computed separately
//     (assessSupplyChainMustFix).
//   - ebs_volume. Excluded from the graph entirely (asset.NeverSyncTypes), so its
//     dependents count is 0 for a reason that has nothing to do with the volume.
//     An attached, in-use volume and a detached one are indistinguishable here.
//
// Add a type here only when the dependents model cannot answer for it — never to
// silence a type whose edges merely have not been mapped yet. The fix for missing
// coverage is coverage.
var safetyUnassessableTypes = map[string]bool{
	"package":    true,
	"ebs_volume": true,
}

// FixSafetyProvider supplies the graph-structural inputs for the advisory
// safe-to-fix signal. asset.Service implements it (Get, EdgesIntoTypes,
// IsExposedEdge). Optional on the enrich Service (see WithSafetyProvider): a nil
// provider leaves SafetyClass empty, exactly like a not-yet-enriched finding.
type FixSafetyProvider interface {
	Get(ctx context.Context, id string) (asset.Asset, error)
	EdgesIntoTypes(ctx context.Context, dstID string, edgeTypes []string) ([]asset.Edge, error)
	EdgesOut(ctx context.Context, srcID, edgeType string) ([]asset.Edge, error)
	IsExposedEdge(ctx context.Context, id string) (bool, error)
}

// fixSafety is the structural safety signal enrich persists onto a finding.
// Unused here is the strong "present but idle" signal (an inactive IAM principal),
// shown as evidence — distinct from stale/gone, which disqualifies "safe".
type fixSafety struct {
	Dependents int
	Unused     bool
	Class      string
	FixTarget  string
}

// assessSafety computes the structural safety signal for a finding from the graph.
// Best-effort and fail-open: a nil provider, a finding with no resource, or a read
// error yields a zero signal (Class "") rather than an error — enrichment must
// still produce a score. seed is the finding's asset, fetched once by the caller
// and shared with assessMustFix (a zero asset means not-yet-correlated). now is
// the clock for the staleness heuristic.
func assessSafety(ctx context.Context, p FixSafetyProvider, f finding.Finding, seed asset.Asset, now time.Time) fixSafety {
	if p == nil || f.ResourceID == "" {
		return fixSafety{}
	}
	deps, err := p.EdgesIntoTypes(ctx, f.ResourceID, dependentEdgeTypes)
	if err != nil {
		// Can't size dependents → don't guess a band; leave it unknown so a graph
		// hiccup never mislabels something "safe".
		return fixSafety{}
	}
	seen := map[string]bool{}
	for _, e := range deps {
		if e.SrcID != "" {
			seen[e.SrcID] = true
		}
	}
	dependents := len(seen)

	// Same fail-open discipline as the deps read above: an exposed-edge lookup
	// error must never silently default to exposed=false, which classifySafety
	// would then read as a confirmed "not internet-facing" and could promote
	// an actually-exposed resource to SafetySafe.
	exposed, err := p.IsExposedEdge(ctx, f.ResourceID)
	if err != nil {
		return fixSafety{}
	}
	present := isPresent(seed, now)
	// Advisory band, so only a POSITIVE production classification marks the
	// resource risky. Unknown stays its own state rather than becoming prod:
	// most estates tag a minority of resources, and reading untagged as prod
	// would empty the Start-here worklist on exactly the freshly-onboarded
	// estates it exists for. Nothing here gates a mutation — respond's CoVe and
	// safety band read the same classification fail-closed (TreatAsProd).
	prod := asset.ClassifyEnvironment(seed).Env == asset.EnvProd

	sig := fixSafety{
		Dependents: dependents,
		Unused:     isInactive(seed),
		Class:      classifySafety(dependents, present, prod, exposed),
		FixTarget:  fixTargetOf(ctx, p, f, seed),
	}
	// Only the CLASS is withheld for an unassessable type. Dependents, Unused and
	// FixTarget are measurements and stay — they are still the evidence an operator
	// reads on the finding, and FixTarget drives the triage list's "where to fix"
	// hint regardless of whether a safety verdict is possible.
	// The same holds for an asset whose collector could not read its dependents:
	// the count is a lower bound, and a lower bound of 0 must not grade it safe.
	if safetyUnassessableTypes[f.ResourceType] || asset.DependentsUnread(seed) {
		sig.Class = ""
	}
	return sig
}

// classifySafety is the conservative, action-independent band (see the class
// consts). Pure — exhaustively table-tested. "safe" = "present and unreferenced":
// the asset is still live (present), nothing routes to or runs as it (0
// dependents), and it is neither production nor internet-facing. Gating on presence (not staleness) is what keeps the worklist to
// genuinely actionable resources instead of dead/rotated ones whose finding is moot.
func classifySafety(dependents int, present, prod, internetFacing bool) string {
	if dependents > 0 || prod || internetFacing {
		return SafetyRisky
	}
	if present {
		return SafetySafe
	}
	// Not present (stale/gone/uncorrelated): can't confirm it's a live safe target,
	// so verify rather than promote — never "safe" on the strength of an absence.
	return SafetyCaution
}

// isPresent reports whether the asset is live — seen within the freshness window.
// A stale asset (past it) is treated as gone: its finding is moot, so it is never
// classed safe.
func isPresent(a asset.Asset, now time.Time) bool {
	return !a.LastSeen.IsZero() && now.Sub(a.LastSeen) <= safetyFreshWindow
}

// isInactive is the strong "present but idle" signal (an inactive IAM principal:
// no console access, no active keys), shown as evidence beside a safe finding.
func isInactive(a asset.Asset) bool {
	return a.Metadata["inactive"] == "true"
}

// clampU16 narrows a dependents count into the finding's UInt16 column, saturating
// rather than wrapping — a resource with 65k+ dependents is "very depended on" all
// the same, and the exact count past that is immaterial to the safe/risky call.
func clampU16(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 65535 {
		return 65535
	}
	return uint16(n)
}

// fixTargetOf resolves a compact "where to fix" hint the triage list can render
// without a per-row detail fetch. Preference order, strongest evidence first:
// the repo that DECLARES the resource (defined_in), then the repo that ships a
// workload onto it (deploys_to), then the cloud console. The finding-detail view
// computes a richer FixLocation live (findingctx), so this is only the
// at-a-glance hint.
//
// defined_in is checked first and is a different, stronger claim than
// deploys_to: it means this exact resource is IaC-declared in that repo
// (internal/collect/iac harvests the identifiers), so editing the console is the
// wrong move — the next apply reverts it.
//
// Direction matters and is the reason this needs EdgesOut rather than the
// EdgesIntoTypes call below: defined_in points FROM the resource TO the repo
// (gcp_service_account → github_repo), the opposite of deploys_to
// (github_repo → k8s_pod).
func fixTargetOf(ctx context.Context, p FixSafetyProvider, f finding.Finding, seed asset.Asset) string {
	// The same defined_in pick ownership resolution makes (asset.ResolveOwnership),
	// so the fix hint and the finding's owner never name different repos.
	if edges, err := p.EdgesOut(ctx, f.ResourceID, asset.EdgeTypeDefinedIn); err == nil {
		if e, ok := asset.BestDefiningEdge(edges); ok {
			return "repo:" + e.DstID
		}
	}
	if edges, err := p.EdgesIntoTypes(ctx, f.ResourceID, []string{"deploys_to"}); err == nil && len(edges) > 0 {
		best := edges[0]
		for _, e := range edges {
			if e.Properties["confidence"] == "high" {
				best = e
				break
			}
		}
		if best.SrcID != "" {
			return "repo:" + best.SrcID
		}
	}
	if seed.AccountID != "" {
		if seed.Region != "" {
			return "console:" + seed.AccountID + ":" + seed.Region
		}
		return "console:" + seed.AccountID
	}
	return ""
}
