package respond

import (
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// SafetyBand rates how likely applying the proposed action is to break something.
// It is the inverse of the attack blast radius: not "what can this reach if
// popped" but "what depends on this that a fix could disrupt", combined with
// whether the resource is even used. Advisory only for now — surfaced to humans
// to sort quick wins; a future change may feed it into the policy gate.
const (
	SafetySafe    = "safe"    // nothing depends on it / it looks unused / observe-only
	SafetyCaution = "caution" // active resource or unknown dependents — verify first
	SafetyRisky   = "risky"   // destructive action on a depended-on, prod, or exposed asset
)

// FixLocationKind is where a remediation should be applied.
const (
	FixSourceRepo   = "source_repo"   // change the config in the deploying repo and redeploy
	FixCloudConsole = "cloud_console" // no IaC owner — apply directly in the cloud account
	FixUnknown      = "unknown"       // no seed asset / nothing to point at
)

// dependentEdgeTypes are the inbound edges that mean "something relies on this
// asset". DECLARED ONCE in graphschema and shared with enrich, which asks the
// same question for safety_class. Do not re-localize this list; add types to
// graphschema.DependentEdgeTypes so both sides move together.
var dependentEdgeTypes = graphschema.DependentEdgeTypes

// ImpactAssessment is the action-independent "safe to fix" context for a finding:
// what depends on the resource (would break if it changed), whether it looks
// unused, and where a fix should be applied. Structural — it does not know the
// chosen action class, so it is computed while the context pack is assembled and
// fed to the reasoner. The SafetyBand (which folds in the action) is computed
// after the plan by safetyBand().
type ImpactAssessment struct {
	Dependents int // count of distinct assets that depend on this one (inbound edges)
	// DependentsKnown is false when the dependents read failed or could not run
	// (no lineage seam, no resource), or the collector could not read the
	// resource's inbound edges (asset.DependentsUnread). Dependents is then NOT a
	// measurement: nothing may read it as "nothing relies on this".
	DependentsKnown bool
	Unused          bool
	// Signals are human-readable evidence lines — the "what to look for before you
	// action this" shown in the UI and injected into the reasoner prompt.
	Signals     []string
	FixLocation FixLocation
}

// FixLocation is where the remediation lands: the deploying repo (change + redeploy)
// or, absent an IaC owner, the cloud account/region to apply it directly.
type FixLocation struct {
	Kind       string // source_repo | cloud_console | unknown
	Repo       string // org/repo, when Kind == source_repo
	Confidence string // deploys_to edge confidence, when Kind == source_repo
	Account    string // when Kind == cloud_console
	Region     string // when Kind == cloud_console
	Hint       string // one-line human instruction
}

// assessImpact builds the structural impact context from data already in the
// pack plus the inbound dependent edges. Pure — no I/O, exhaustively table-tested.
// seed is the depth-0 blast asset (zero value when the resource was not found),
// carrying the metadata (last_seen, IAM inactivity) the liveness heuristic reads.
// dependentsKnown is whether dependents was actually read (see dependentsOf);
// a seed whose collector could not read its inbound edges is unknown either way.
func assessImpact(pack ContextPack, seed asset.Asset, dependents []asset.Edge, dependentsKnown bool) ImpactAssessment {
	imp := ImpactAssessment{
		FixLocation:     fixLocationOf(pack.Provenance),
		DependentsKnown: dependentsKnown && !asset.DependentsUnread(seed),
	}

	// Dependents: distinct source assets across the inbound dependent edges.
	seen := map[string]bool{}
	for _, e := range dependents {
		if e.SrcID != "" && !seen[e.SrcID] {
			seen[e.SrcID] = true
		}
	}
	imp.Dependents = len(seen)

	// Liveness: stale (stopped appearing in syncs) or an inactive IAM principal
	// are the two "this isn't even used" signals we can read from existing data.
	if pack.Provenance.AgeBucket == "stale" {
		imp.Unused = true
		imp.Signals = append(imp.Signals, "not seen in recent syncs (stale) — may already be decommissioned")
	}
	if seed.Metadata["inactive"] == "true" {
		imp.Unused = true
		imp.Signals = append(imp.Signals, "IAM principal is inactive: no console access and no active access keys")
	}
	switch plu := seed.Metadata["password_last_used_days"]; plu {
	case "", "0":
		// unknown / just used — no signal.
	case "-1":
		imp.Signals = append(imp.Signals, "console password has never been used")
	default:
		imp.Signals = append(imp.Signals, fmt.Sprintf("console password last used %s day(s) ago", plu))
	}

	// Dependents evidence — the core "will this break anything" line.
	switch {
	case !imp.DependentsKnown:
		imp.Signals = append(imp.Signals, "dependents unknown — what relies on this resource could not be read in full; verify before changing it")
	case imp.Dependents == 0:
		imp.Signals = append(imp.Signals, "nothing routes to or runs as this resource — removing it should not break other assets")
		// A workload with no deploying repo is worth flagging, but a MISSING
		// deploys_to edge means "we didn't correlate a repo", not "nothing deploys
		// it" — the edge is best-effort (name/image match). So surface it as
		// evidence to check, but do NOT promote it to Unused (which would flip the
		// band to "safe" on the strength of a correlation gap).
		if isWorkload(seed.Type) && pack.Provenance.SourceRepo == "" {
			imp.Signals = append(imp.Signals, "no repo deploys to this workload — no IaC owner correlated (verify it is really unused)")
		}
	default:
		imp.Signals = append(imp.Signals, fmt.Sprintf("%d asset(s) depend on this (DNS, execution identity, or OIDC access) — confirm before changing it", imp.Dependents))
	}

	return imp
}

// fixLocationOf resolves where a fix should be applied. A resolved source repo
// (from a deploys_to edge) means "change it there and redeploy"; otherwise, if we
// know the cloud account, point at the console; else unknown.
func fixLocationOf(p Provenance) FixLocation {
	if p.SourceRepo != "" {
		hint := fmt.Sprintf("Change the configuration in %s and redeploy", p.SourceRepo)
		if p.SourceConfidence == "medium" {
			hint += " (link is a medium-confidence name match — verify it is the right repo)"
		}
		return FixLocation{Kind: FixSourceRepo, Repo: p.SourceRepo, Confidence: p.SourceConfidence, Hint: hint}
	}
	if p.AccountID != "" {
		hint := "No IaC owner found — apply directly"
		if p.Connector != "" {
			hint += " in the " + p.Connector + " console"
		}
		hint += fmt.Sprintf(" (account %s", p.AccountID)
		if p.Region != "" {
			hint += ", " + p.Region
		}
		hint += ")"
		return FixLocation{Kind: FixCloudConsole, Account: p.AccountID, Region: p.Region, Hint: hint}
	}
	return FixLocation{Kind: FixUnknown}
}

// PromptLines renders the impact context for the reasoner prompt: dependents,
// liveness, and where a fix lands. Injected before the plan is chosen so the
// model can pick the least-invasive action with the impact in view.
func (imp ImpactAssessment) PromptLines() []string {
	lines := []string{"dependents=unknown (not read in full — treat it as possibly depended on)"}
	if imp.DependentsKnown {
		lines[0] = fmt.Sprintf("dependents=%d (assets that rely on this and could break if it changes)", imp.Dependents)
	}
	if imp.Unused {
		lines = append(lines, "usage=appears unused (stale / orphaned / inactive)")
	}
	for _, s := range imp.Signals {
		lines = append(lines, "note: "+s)
	}
	if imp.FixLocation.Hint != "" {
		lines = append(lines, "fix location: "+imp.FixLocation.Hint)
	}
	return lines
}

// safetyBand folds the chosen action class into the structural impact to rate how
// risky applying the fix is. Boring, explicit rules, on purpose:
//   - observe never changes anything → always safe.
//   - a destructive action (isolate/destroy) on something depended-on (or with
//     unknown dependents), in prod (or of unknown environment — both
//     fail-closed), or internet-facing → risky.
//   - a non-destructive action on an unused resource MEASURED to have no
//     dependents → safe. Unknown dependents never reach safe.
//   - everything else → caution (verify before acting).
func safetyBand(action ActionClass, imp ImpactAssessment, exp ExposureFlags, prov Provenance) string {
	if action == ClassObserve {
		return SafetySafe
	}
	destructive := action == ClassIsolate || action == ClassDestroy
	if destructive && (!imp.DependentsKnown || imp.Dependents > 0 || prov.Env.Env.TreatAsProd() || exp.InternetFacing) {
		return SafetyRisky
	}
	if imp.DependentsKnown && imp.Dependents == 0 && imp.Unused {
		return SafetySafe
	}
	return SafetyCaution
}

// SafetyBandFor computes the safety band live from a context pack and an action
// class. The read/detail path (findingctx) uses it so the band always reflects
// the same live impact the UI shows, rather than a band cached at the last Decide
// (which can lag a dependents/usage change until the next reasoning sweep).
func SafetyBandFor(action ActionClass, pack ContextPack) string {
	return safetyBand(action, pack.Impact, pack.Exposure, pack.Provenance)
}

// WorstSafetyBand returns the most cautious of two bands (risky > caution > safe),
// used by govern to fold a cluster of decisions into one queue card. An empty
// band is treated as unknown and does not override a known one.
func WorstSafetyBand(a, b string) string {
	if safetyRank(b) > safetyRank(a) {
		return b
	}
	return a
}

func safetyRank(band string) int {
	switch band {
	case SafetyRisky:
		return 3
	case SafetyCaution:
		return 2
	case SafetySafe:
		return 1
	default:
		return 0
	}
}

// fixLocationJSON is the compact fix-location shape written to the audit trail so
// the Decisions list can render "fix in <repo>" without a per-row detail fetch.
func (fl FixLocation) fixLocationJSON() map[string]any {
	if fl.Kind == "" || fl.Kind == FixUnknown {
		return nil
	}
	m := map[string]any{"kind": fl.Kind}
	if fl.Repo != "" {
		m["repo"] = fl.Repo
	}
	if fl.Confidence != "" {
		m["confidence"] = fl.Confidence
	}
	if fl.Account != "" {
		m["account"] = fl.Account
	}
	if fl.Region != "" {
		m["region"] = fl.Region
	}
	if fl.Hint != "" {
		m["hint"] = fl.Hint
	}
	return m
}

// impactDepsFingerprint is the dependents part of the reason fingerprint.
// Unknown is its own value, never "deps=0".
func impactDepsFingerprint(imp ImpactAssessment) string {
	if !imp.DependentsKnown {
		return "impact:deps=unknown"
	}
	return fmt.Sprintf("impact:deps=%d", imp.Dependents)
}
