// Package forget decides — and, for now, only ever RECORDS — which stored
// assets a proven-complete enumeration says are gone.
//
// Within a live connector, nothing here removes a cloud instance its connector
// stops listing: stored ec2_instance and gce_instance ids that their own
// connector no longer lists stay, and attack paths are computed over them,
// until the assets table's TTL (last_seen + 180 days) drops the rows or an
// admin-confirmed account purge (asset.PurgeAccount) deletes them. The
// staleness sweep never touches cloud types.
//
// The reason it cannot forget is not laziness, it is that "absent from a
// listing" and "deleted" are the same observation until something proves the
// listing was complete. collect.Result.CompletedEnumerations (observe
// only) is that proof, declared only next to error handling that makes it true.
// This package consumes it, applies the refusals collect.Result.MarkComplete
// sketches, and writes down what it WOULD forget.
//
// Nothing here deletes a row, resolves a finding, or removes an edge. In
// ModeEnforce it writes a tombstone — "believed gone at T" — and that is all.
// The consumer of that tombstone is deliberately a separate decision, outside
// this package.
package forget

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrUnknownMode is returned by ParseMode for a value that is neither shadow
// nor enforce. A typo in a deployment env var must not silently choose a mode.
var ErrUnknownMode = errors.New("forget: unknown mode")

// Mode is how far the evaluation is allowed to go.
type Mode string

const (
	// ModeShadow computes and records the decision. Nothing else. This is the
	// default.
	ModeShadow Mode = "shadow"
	// ModeEnforce additionally writes a tombstone row per forgettable asset.
	// It still deletes nothing — see the tombstone-versus-delete distinction above.
	ModeEnforce Mode = "enforce"
)

// ParseMode maps the FORGET_MODE env value to a Mode. Empty means shadow, so an
// unset variable is the safe mode rather than an error.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.TrimSpace(strings.ToLower(s))) {
	case "", ModeShadow:
		return ModeShadow, nil
	case ModeEnforce:
		return ModeEnforce, nil
	default:
		return ModeShadow, fmt.Errorf("%w: %q", ErrUnknownMode, s)
	}
}

// ErrNotTombstoneEligible is returned by ParseEnforceTypes for a type that is
// not on TombstoneEligibleTypes.
var ErrNotTombstoneEligible = errors.New("forget: asset type may not be enforced")

// tombstoneEligible is the set of asset types enforcement may tombstone (ADR
// 081): security_group and vpc, whose deletions can be confirmed without
// EnumerationShrinkFraction. Every other audited type stays shadow-only until
// that guard is calibrated for it; widening this set is a code change.
var tombstoneEligible = map[string]bool{"security_group": true, "vpc": true}

// TombstoneEligibleTypes returns the asset types FORGET_ENFORCE_TYPES may
// name, sorted.
func TombstoneEligibleTypes() []string {
	out := make([]string, 0, len(tombstoneEligible))
	for t := range tombstoneEligible {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ParseEnforceTypes maps the FORGET_ENFORCE_TYPES env value (comma-separated
// asset types, e.g. "security_group,vpc") to the allow-list Service checks
// before writing a tombstone under ModeEnforce.
//
// An empty or all-blank value returns a nil map: the zero value, whose lookups
// are always false, so FORGET_MODE=enforce with FORGET_ENFORCE_TYPES unset
// enforces nothing (CLAUDE.md: the safe value is the zero value). The map is
// only consulted under ModeEnforce.
//
// A type not on TombstoneEligibleTypes (a typo, an unaudited type, or an
// audited type not cleared for enforcement such as ec2_instance) is an error
// wrapping ErrNotTombstoneEligible, so the worker refuses to start rather than
// run with a list that does not mean what it says.
func ParseEnforceTypes(s string) (map[string]bool, error) {
	var out map[string]bool
	for _, part := range strings.Split(s, ",") {
		t := strings.TrimSpace(part)
		if t == "" {
			continue
		}
		if !tombstoneEligible[t] {
			return nil, fmt.Errorf("%w: %q (allowed: %s)", ErrNotTombstoneEligible, t, strings.Join(TombstoneEligibleTypes(), ", "))
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[t] = true
	}
	return out, nil
}

// ── Thresholds ──────────────────────────────────────────────────────────────
//
// Every constant below records the design assumption behind it. Where an
// assumption says the threshold cannot separate the two cases it exists to
// separate, that is recorded here too, because it is a property of the
// workload, not a tuning parameter.
const (
	// RelativeRefusalFraction refuses a scope whose confirmed-absent count
	// exceeds this fraction of the scope's own stored population. "A cloud
	// account does not lose a third of a region in one sweep."
	//
	// IT CAN: spot/autoscaled fleets may turn over their entire population
	// inside a day, so hourly disappearances per (connector, region) scope can
	// have a heavy tail that exceeds 1.0 of the scope's population (more
	// instances gone in an hour than the scope holds at any one time).
	//
	// So 1/3 can sit BELOW legitimate churn on the instance types, and no value
	// above it distinguishes anything — a threshold that has to clear a ratio
	// above 1.0 permits a listing returning nothing. It is kept at 1/3 anyway:
	// the failure mode of a too-tight relative cap is refusing to forget, which
	// is the status quo, and the failure mode of a loose one is mass deletion.
	// The real separator is EnumerationShrinkFraction below, and it is not yet
	// calibrated.
	RelativeRefusalFraction = 1.0 / 3.0

	// MinScopePopulation is the floor beneath which the relative test is noise:
	// a scope holding 3 instances legitimately goes to 1, which is 67% and means
	// nothing. Many (connector, region) scopes are expected to hold fewer than
	// 10 instances while holding only a small fraction of the instance total —
	// this floor governs many scopes by count and very little by volume, which
	// is exactly the trade it is for.
	MinScopePopulation = 10

	// MaxForgetPerSweep bounds the blast radius of one wrong decision to
	// something a human can actually review. Legitimate hourly disappearances
	// in a single scope are expected to stay in the hundreds at most, so a
	// scope asking to forget more than this is already out of family — and 500
	// ids is a reviewable list, where the full corpus is not.
	MaxForgetPerSweep = 500

	// ConfirmWindow is how long an asset must have been absent, and how far back
	// the scope's PREVIOUS complete enumeration must sit, before absence counts.
	// The designed sweep interval is on the order of tens of minutes on both
	// AWS and GCP, so two hours spans at least three completed enumerations on
	// the slower of the two. One complete listing is a claim about one API call;
	// three spaced across two hours remove every single-sweep anomaly, at a cost
	// of two hours of latency on a mechanism whose current latency is infinite.
	ConfirmWindow = 2 * time.Hour

	// EnumerationShrinkFraction refuses a scope whose current enumerated count
	// has fallen below this fraction of its own recent high-water. This is the
	// test that CAN separate "10 instances were terminated" from "the
	// enumeration silently returned half the fleet": churn moves the population
	// but not its size, because births balance deaths, while a truncated or
	// permission-clipped listing moves the size and nothing else.
	//
	// NOT CALIBRATED, and deliberately shipped saying so. The series it needs is
	// one enumerated count per scope per sweep over weeks;
	// graph_sync_scope_enumerated_assets publishes it but is process-lifetime
	// (the worker restarts on every deploy), and `assets` cannot reconstruct it because
	// ReplacingMergeTree merges collapse the per-sweep rows. forget_scope_state exists to
	// accumulate it. 0.5 is a placeholder bound, not a measurement.
	EnumerationShrinkFraction = 0.5

	// HighWaterTTL is how long an enumerated high-water stays authoritative. A
	// scope that legitimately shrank — a decommissioned account, a region
	// emptied on purpose — must not be refused forever by its own former size,
	// and a week is comfortably longer than the confirmation window while short
	// enough that a real shrink drains promptly.
	HighWaterTTL = 7 * 24 * time.Hour
)

// Refusal names why a scope was refused. The empty string means "not refused".
// These are stored and published, so the spellings are part of the contract.
const (
	RefusalNone = ""
	// RefusalNotEnforceable — the scope's family is not on the audited list.
	RefusalNotEnforceable = "not_enforceable"
	// RefusalUnconfirmed — the scope has no previous complete enumeration older
	// than ConfirmWindow, so absence has been observed at most once.
	RefusalUnconfirmed = "unconfirmed"
	// RefusalTooSmall — the scope's population is below MinScopePopulation.
	RefusalTooSmall = "population_too_small"
	// RefusalRelativeCap — see RelativeRefusalFraction.
	RefusalRelativeCap = "relative_cap"
	// RefusalAbsoluteCap — see MaxForgetPerSweep.
	RefusalAbsoluteCap = "absolute_cap"
	// RefusalEnumerationShrank — see EnumerationShrinkFraction.
	RefusalEnumerationShrank = "enumeration_shrank"
	// RefusalEdgeTruncated — an edge type hit its fetch cap, so the topology any
	// node decision would be taken against is known-partial.
	RefusalEdgeTruncated = "edge_truncated"
	// RefusalEdgeHealthUnknown — nothing could report edge-fetch health, so the
	// above cannot be ruled out. Fail closed.
	RefusalEdgeHealthUnknown = "edge_health_unknown"
)

// Family is the API surface half of a scope key — the part after the "/" in
// "eu-west-1/ec2:instances".
type Family struct {
	// Types are the asset types this family enumerates, and MUST match what the
	// collector passes to MarkComplete for it.
	Types []string
	// RegionScoped says the scope key's first component is the region the stored
	// assets carry, so a scope's population can be selected exactly. When false
	// the scope covers every region for its types (GCP's aggregatedList).
	RegionScoped bool
}

// enforceableFamilies is the audited allow-list: a family here has had its
// pagination and error handling read end to end, and its scope key checked
// against the region string the stored assets actually carry.
//
// This is deliberately a SECOND gate in front of the collector's completeness
// claim, not a restatement of it. A collector that starts declaring a new scope
// tomorrow — correctly or not — gains no deletion authority until someone adds
// it here, which is the audit that "declaring completeness without auditing the
// pagination loop" would otherwise skip.
//
// Not here, on purpose:
//   - families that declare completeness but are not audited yet (Azure,
//     GitHub, whose listRepos pages out early by design, and Kubernetes, where
//     RBAC Forbidden on some lists is expected) and the ~30 unaudited AWS/GCP
//     families. Auditing those loops is separate work.
//
// ec2:subnets is enforceable only because a subnet's stored `region` is its
// region, not its AVAILABILITY ZONE ("eu-west-1b"):
// internal/collect/aws/network.go's collectSubnets keeps the AZ in
// Metadata["availability_zone"]. A region-scoped family's population must be
// selectable exactly by its scope key — prefix-matching an AZ onto a region is
// precisely the kind of guess this mechanism must not make.
var enforceableFamilies = map[string]Family{
	"ec2:instances":       {Types: []string{"ec2_instance"}, RegionScoped: true},
	"ec2:security-groups": {Types: []string{"security_group"}, RegionScoped: true},
	"ec2:vpcs":            {Types: []string{"vpc"}, RegionScoped: true},
	"ec2:addresses":       {Types: []string{"elastic_ip"}, RegionScoped: true},
	"ec2:subnets":         {Types: []string{"subnet"}, RegionScoped: true},
	"compute.instances":   {Types: []string{"gce_instance"}, RegionScoped: false},
}

// ScopeKey identifies one evaluated unit: a declared scope narrowed to one of
// the asset types it enumerates. A type is the granularity a deletion decision
// is taken at, and a scope that enumerates two types can be complete for both
// while their populations behave completely differently.
type ScopeKey struct {
	Scope     string
	AssetType string
}

// Scope is one collector scope key split into the two parts the population
// query needs.
type Scope struct {
	// Key is the full scope key exactly as the collector declared it — the
	// identity every stored row and gauge series is keyed on.
	Key string
	// Region is the key's first component, empty when the family is not
	// region-scoped.
	Region string
	Family Family
}

// ParseScope splits a declared scope key and reports whether its family is
// enforceable. A key that is not "<region>/<family>" is never enforceable:
// the region component is half of how a population is selected.
func ParseScope(key string) (Scope, bool) {
	region, family, ok := strings.Cut(key, "/")
	if !ok || region == "" || family == "" {
		return Scope{Key: key}, false
	}
	f, ok := enforceableFamilies[family]
	if !ok {
		return Scope{Key: key}, false
	}
	s := Scope{Key: key, Family: f}
	if f.RegionScoped {
		s.Region = region
	}
	return s, true
}

// EnforceableTypes returns every asset type any enforceable family enumerates.
// It is the type filter of the population read — the read must never look at a
// type no audited scope can account for.
func EnforceableTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range enforceableFamilies {
		for _, t := range f.Types {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Population is what storage holds for one (scope, type) pair, as counted
// against this sweep's own clock rather than wall-clock.
type Population struct {
	// Stored is every row attributable to the scope, live or not.
	Stored int
	// Absent did not have last_seen refreshed by this enumeration.
	Absent int
	// Confirmed has been absent for longer than ConfirmWindow.
	Confirmed int
}

// Input is everything one (scope, type) decision is taken on. Assembled by the
// service; Evaluate is pure so the thresholds are testable without a database.
type Input struct {
	Scope      Scope
	AssetType  string
	Enumerated int
	Population Population
	// PrevCompleteAt is when this scope last proved complete BEFORE this sweep,
	// zero if never.
	PrevCompleteAt time.Time
	// HighWater is the enumerated high-water still in force, and HighWaterAt
	// when it was set. A HighWaterAt older than HighWaterTTL retires it.
	HighWater   int
	HighWaterAt time.Time
	// TruncatedEdgeTypes is what the graph's last edge fetch could not read in
	// full, and EdgeHealthKnown is false when nothing could report it.
	TruncatedEdgeTypes []string
	EdgeHealthKnown    bool
	Now                time.Time
}

// Verdict is the recorded decision for one (scope, type).
type Verdict struct {
	Scope     string
	AssetType string
	// Forgettable is how many assets every refusal permits forgetting. It is 0
	// whenever Refusal is set — there is no "refused but partially acted on".
	Forgettable int
	Refusal     string
	// HighWater is the high-water to store after this evaluation, and
	// HighWaterAt its timestamp: either the retained one or this sweep's count.
	HighWater   int
	HighWaterAt time.Time
	// NextConfirmAnchor is the confirm-window anchor to persist for the NEXT
	// sweep's Input.PrevCompleteAt — see nextConfirmAnchor's doc comment. It is
	// NOT simply this sweep's own completion time: the anchor must stay sticky
	// across many sweeps until it has actually aged ConfirmWindow, or the window
	// never elapses at the collector's sync cadence.
	NextConfirmAnchor time.Time
}

// Decide applies every refusal in collect.Result.MarkComplete's design, in
// the order that keeps the cheapest and most categorical first, and returns
// what may be forgotten.
//
// It is total: every path either sets a Refusal or returns a Forgettable count,
// so there is no way to reach the caller without a decision. The order matters
// for the RECORD rather than the outcome — the stored refusal names the first
// reason, which is the one a human should read first.
func Decide(in Input) Verdict {
	v := Verdict{Scope: in.Scope.Key, AssetType: in.AssetType}
	v.HighWater, v.HighWaterAt = nextHighWater(in)
	v.NextConfirmAnchor = nextConfirmAnchor(in)

	refuse := func(reason string) Verdict {
		v.Refusal = reason
		v.Forgettable = 0
		return v
	}

	// Re-derived from the key rather than trusted from in.Scope: ParseScope is
	// the ONE predicate for "may this scope forget anything", and a caller that
	// hand-built a Scope (or parsed a key one test away from an audited one)
	// must not be able to hand Decide a family the parser would have rejected.
	// A malformed key without a region component reaches here with an audited
	// family attached, which a check on the family alone would let through.
	if _, ok := ParseScope(in.Scope.Key); !ok {
		return refuse(RefusalNotEnforceable)
	}
	// There is deliberately no connector-wide "some OTHER family in this sweep
	// failed" refusal here (collect.Result.Partial): it would refuse every
	// audited scope's decision on the strength of a sibling family's unrelated
	// failure, poisoning scopes that individually proved their OWN enumeration
	// complete (collect.Result.MarkComplete's contract). The caller
	// (jobs.evaluateForget) instead cross-checks each scope's declared count
	// against what actually reached collect.Result.Assets — catching a
	// collector goroutine that declares a scope complete and then panics
	// before its assets are appended — at the scope it actually concerns,
	// rather than treating every scope in the connector as suspect.
	if !in.EdgeHealthKnown {
		return refuse(RefusalEdgeHealthUnknown)
	}
	if len(in.TruncatedEdgeTypes) > 0 {
		return refuse(RefusalEdgeTruncated)
	}
	// Consecutive-sweep confirmation. Both halves are required: the scope must
	// have completed before, far enough back, AND the candidates must have been
	// absent that whole time. Either alone is a single observation.
	if in.PrevCompleteAt.IsZero() || in.Now.Sub(in.PrevCompleteAt) < ConfirmWindow {
		return refuse(RefusalUnconfirmed)
	}
	if in.Population.Stored < MinScopePopulation {
		return refuse(RefusalTooSmall)
	}
	// Enumeration shrink, before the candidate tests: a listing that returned
	// half of what this scope has recently held is not evidence about anything,
	// however few candidates it happens to produce.
	if v.HighWater > 0 && float64(in.Enumerated) < EnumerationShrinkFraction*float64(v.HighWater) {
		return refuse(RefusalEnumerationShrank)
	}
	confirmed := in.Population.Confirmed
	if confirmed <= 0 {
		return v // nothing to forget, and nothing refused
	}
	if float64(confirmed) > RelativeRefusalFraction*float64(in.Population.Stored) {
		return refuse(RefusalRelativeCap)
	}
	if confirmed > MaxForgetPerSweep {
		return refuse(RefusalAbsoluteCap)
	}
	v.Forgettable = confirmed
	return v
}

// nextHighWater returns the enumerated high-water to carry forward. It rises
// immediately and falls only after HighWaterTTL, so a scope that genuinely
// shrank stops being refused by its own history within a week while a scope
// that momentarily under-enumerates does not lower the bar it is judged by.
func nextHighWater(in Input) (int, time.Time) {
	switch {
	case in.Enumerated >= in.HighWater:
		return in.Enumerated, in.Now
	case in.HighWaterAt.IsZero(), in.Now.Sub(in.HighWaterAt) > HighWaterTTL:
		return in.Enumerated, in.Now
	default:
		return in.HighWater, in.HighWaterAt
	}
}

// nextConfirmAnchor computes the confirm-window anchor to persist for the NEXT
// sweep's Input.PrevCompleteAt.
//
// The anchor must not be the PREVIOUS sweep's own completion time: sliding
// forward every cycle, that is NEVER more than one sync interval old, so under
// the designed sync cadence (tens of minutes) against a 2-hour window
// `Now - PrevCompleteAt < ConfirmWindow` would hold on every evaluation after
// the first and RefusalUnconfirmed would never clear.
//
// The anchor is instead STICKY: it stays fixed across many sweeps — each one
// correctly still refusing on RefusalUnconfirmed, because not enough real time has
// passed — until it has aged past ConfirmWindow, at which point Decide finally
// evaluates the population checks and this function rolls the anchor forward to
// start a fresh confirmation window. Rolling forward on every sweep regardless
// would never let the window elapse at all; rolling it forward only
// when it matures is what makes "the scope must have completed before, far enough
// back" (Decide's own comment) an achievable condition rather than a permanent
// refusal.
func nextConfirmAnchor(in Input) time.Time {
	switch {
	case in.PrevCompleteAt.IsZero():
		// First completion ever recorded for this scope: seed the anchor at
		// this sweep. The confirm-window check still refuses THIS evaluation
		// (Now - Now < ConfirmWindow), correctly — one listing is one API call.
		return in.Now
	case in.Now.Sub(in.PrevCompleteAt) >= ConfirmWindow:
		// The anchor just matured and was consumed by this decision (whichever
		// way it went) — start a fresh window from here.
		return in.Now
	default:
		// Not yet matured: keep the same anchor so the window keeps accumulating
		// real elapsed time instead of resetting on every sweep.
		return in.PrevCompleteAt
	}
}
