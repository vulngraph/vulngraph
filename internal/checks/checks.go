// Package checks is the CSPM check framework. A Check is data plus a
// predicate; the Registry runs every applicable check over collected assets and
// emits a finding per violation. The catalogue grows by adding Checks.
package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// source is stamped on every finding these checks produce.
const source = "cspm"

// Check is a single posture rule. It applies to one provider and (optionally)
// one asset type; Violates reports whether a given asset breaches the rule.
type Check struct {
	ID          string // stable CIS-style id, e.g. "aws-ec2-public-ip"
	Title       string
	Description string
	Remediation string
	Type        string // category, e.g. "exposure"
	Severity    finding.Severity
	Provider    asset.Provider
	AssetType   string // "" matches any asset type for the provider
	Violates    func(asset.Asset) bool
	// SeverityFor optionally overrides Severity per asset — e.g. an exposure check
	// that fires on any public resource but grades confirmed-unauthenticated access
	// higher than a merely-reachable, still-auth-gated one. Nil → fixed Severity.
	SeverityFor func(asset.Asset) finding.Severity
	// TitleFor optionally overrides Title per asset, for the same reason SeverityFor
	// exists: a check that fires on two materially different conditions cannot
	// describe both in one absolute sentence (e.g. a confirmed-public bucket vs.
	// a merely-missing Block-Public-Access setting). The Title is what a responder
	// and every export actually reads, so it must match the graded severity. Nil →
	// fixed Title.
	//
	// Safe to vary per asset: the finding id is DeterministicID(check id, asset id)
	// and does not include the title, so changing it rewrites the same row rather
	// than forking a duplicate finding.
	TitleFor func(asset.Asset) string
	// EvidenceFor optionally supplies the per-asset facts that made this check
	// fire, copied onto Finding.Metadata. Without it a check can only state its
	// static Description, so a responder learns THAT a resource is dangerous but
	// not WHY. Keys are merged into the finding's metadata; nil or empty is fine.
	EvidenceFor func(asset.Asset) map[string]string
	// RequiredKeys are the asset metadata keys Violates reads. NOT hand-written:
	// Register stamps it from derivedRequiredKeys, which cmd/checkkeys-gen derives
	// from this package's AST. The key names are fully derived; the probe values
	// are not (see TableProbes).
	//
	// It lets the lifecycle reconcile ask "did the collector actually observe this
	// resource's posture?" separately from "is the resource still in violation?" —
	// a check that goes silent because required keys are missing must not have its
	// silence read as remediation and close the finding as fixed.
	RequiredKeys []string
	// ProbeValues are the candidate values tried for an absent RequiredKey when
	// deciding whether this predicate's silence actually depended on the missing
	// data. Derived with RequiredKeys; see Evaluable.
	ProbeValues []string
	// TableProbes are extra probe values the derivation cannot see: it harvests
	// only literals in this package's source, so a value from a lookup table or
	// an imported constant (asset.PublicAccessConfirmed) is never a probe, and
	// without these an absent key would read as "evaluated, clean" and close the
	// finding as fixed. Register appends them to the derived ProbeValues.
	// TestUnresolvedComparandsHaveTableProbes enforces them for an imported
	// constant compared directly with ==, != or a switch case
	// (keyscan.importedComparands); one passed as a function argument (e.g. to
	// strings.EqualFold) and values from lookup tables rely on the author.
	TableProbes []string
	// TimeDependent marks a check whose predicate reads the wall clock (an
	// end-of-life date compared to today): its answer on an asset that never
	// changes still flips on the day the date passes, so the changed-asset
	// cadence would never deliver it. Like RequiredKeys it is stamped by
	// Register from the generated derivation, never hand-set, so a predicate
	// that starts reading the clock cannot forget to say so.
	TimeDependent bool
	// logic is the generated digest of this check's source (derivedLogicDigests),
	// folded into Registry.Fingerprint.
	logic string
}

// probeCombinationCap bounds the substitution search in Evaluable at
// len(ProbeValues)^len(absent) predicate calls; past it the check is treated as
// not evaluable, which withholds a resolution rather than inventing one. Wide
// probe sets (20+ values) cross it at three absent keys.
const probeCombinationCap = 4096

// Evaluable reports whether this check's "no violation" answer for a was an
// observation or an accident of missing data.
//
// Presence-of-every-key is the wrong test: some checks read a key only to
// SUPPRESS themselves under a specific condition, where absent correctly means
// the condition doesn't apply, and a plain presence test would keep those
// findings open forever. So the question asked here is semantic: could ANY
// value of the absent keys have made this predicate fire? If yes, the silence
// proves nothing and the finding must not be closed as fixed; if no, the check
// genuinely observed a clean resource. Candidate values come from the
// predicate's own source (ProbeValues) and are a deliberate superset — a
// useless probe costs a comparison, a missing one costs a live finding closed
// as remediated.
//
// A check with no required keys (a predicate on structural asset fields) is
// always evaluable, as is one whose predicate could not be analysed statically.
// A required key that is present but unreadable (malformed JSON rules) is no
// better than an absent one: the predicate never saw the data.
func (c Check) Evaluable(a asset.Asset) bool {
	a = gcpIAMObservedMetadata(a)
	a = awsIAMObservedMetadata(a)
	if structuredMetadataUnreadable(a, c.RequiredKeys) {
		return false
	}
	var absent []string
	for _, k := range c.RequiredKeys {
		if _, ok := a.Metadata[k]; !ok {
			absent = append(absent, k)
		}
	}
	if len(absent) == 0 {
		return true
	}
	if c.Violates == nil || len(c.ProbeValues) == 0 {
		return false
	}
	combos := 1
	for range absent {
		combos *= len(c.ProbeValues)
		if combos > probeCombinationCap {
			return false
		}
	}
	probe := a
	probe.Metadata = make(map[string]string, len(a.Metadata))
	for k, v := range a.Metadata {
		probe.Metadata[k] = v
	}
	for i := 0; i < combos; i++ {
		n := i
		for _, k := range absent {
			probe.Metadata[k] = c.ProbeValues[n%len(c.ProbeValues)]
			n /= len(c.ProbeValues)
		}
		if c.Violates(probe) {
			return false // some value of the missing data would have fired
		}
	}
	return true
}

// AppliesTo reports whether this check should run against a given asset. The
// lifecycle reconcile needs it to tell "this check ran on this resource and
// stayed silent" from "this check never looked at this resource at all" — the
// latter says nothing either way, and only the former can mean fixed.
func (c Check) AppliesTo(a asset.Asset) bool {
	return c.Provider == a.Provider && (c.AssetType == "" || c.AssetType == a.Type)
}

// applies reports whether this check should run against a given asset.
func (c Check) applies(a asset.Asset) bool { return c.AppliesTo(a) }

// eval returns a finding if the asset violates the check.
func (c Check) eval(a asset.Asset, now time.Time) (finding.Finding, bool) {
	if !c.Violates(a) {
		return finding.Finding{}, false
	}
	severity := c.Severity
	if c.SeverityFor != nil {
		severity = c.SeverityFor(a)
	}
	title := c.Title
	if c.TitleFor != nil {
		title = c.TitleFor(a)
	}
	var evidence map[string]string
	if c.EvidenceFor != nil {
		if ev := c.EvidenceFor(a); len(ev) > 0 {
			evidence = ev
		}
	}
	return finding.Finding{
		// Deterministic: re-scans upsert the same row (ReplacingMergeTree).
		ID:           dbutil.DeterministicID(c.ID, a.ID),
		Metadata:     evidence,
		Source:       source,
		Type:         c.Type,
		Severity:     severity,
		Title:        title,
		Description:  c.Description,
		ResourceType: a.Type,
		ResourceID:   a.ID,
		ResourceName: a.Name,
		Region:       a.Region,
		CheckID:      c.ID,
		Remediation:  c.Remediation,
		DetectedAt:   now,
	}, true
}

// observedNone reports whether the collector recorded key with an EMPTY value —
// an observed "this resource has none of it" — as distinct from the key being
// missing entirely, which means the collector couldn't read the setting at all.
// A check must never turn absent data into a finding: an expired credential or
// a throttled API call would then manufacture violations across a whole estate.
// String counterpart of the explicit-"false" test the boolean checks use.
func observedNone(a asset.Asset, key string) bool {
	v, ok := a.Metadata[key]
	return ok && v == ""
}

// tieredExposureSeverity grades an exposure finding by the collector's
// public_access tier (asset.PublicAccessConfirmed/Possible): confirmed
// unauthenticated access gets the `confirmed` band; a merely-reachable or
// permitted-but-unproven resource — public IP on an auth-gated database, an
// unlocked-but-not-actually-public bucket — gets the lower `possible` band.
// It's still worth surfacing that a resource is public; it just isn't as severe
// when credentials or IAM still stand in the way.
func tieredExposureSeverity(confirmed, possible finding.Severity) func(asset.Asset) finding.Severity {
	return func(a asset.Asset) finding.Severity {
		if a.Metadata["public_access"] == asset.PublicAccessConfirmed {
			return confirmed
		}
		return possible
	}
}

// tieredExposureTitle is tieredExposureSeverity's counterpart for the Title, keyed
// on the same public_access tier: grading severity down isn't enough if the title
// still flatly states the resource is public, since a responder reads the title,
// not the description. Every tiered exposure check should pass one.
func tieredExposureTitle(confirmed, possible string) func(asset.Asset) string {
	return func(a asset.Asset) string {
		if a.Metadata["public_access"] == asset.PublicAccessConfirmed {
			return confirmed
		}
		return possible
	}
}

// Registry holds the registered checks.
type Registry struct {
	checks []Check
	byID   map[string]int // check ID → index into checks, for ByID
}

func NewRegistry() *Registry { return &Registry{byID: map[string]int{}} }

// Register adds checks, stamping each with the metadata keys its predicate
// reads (derivedRequiredKeys, generated from this package's source by
// cmd/checkkeys-gen) and the probe values derived with them plus TableProbes.
// The key list is never hand-written, so a predicate edit cannot leave it
// stale once the generator is re-run (TestRequiredKeysGeneratedIsCurrent).
func (r *Registry) Register(checks ...Check) {
	for _, c := range checks {
		if !dynamicPredicateChecks[c.ID] {
			c.RequiredKeys = derivedRequiredKeys[c.ID]
			c.ProbeValues = append(append([]string(nil), derivedProbeValues[c.ID]...), c.TableProbes...)
		}
		c.TimeDependent = derivedTimeDependent[c.ID]
		c.logic = derivedLogicDigests[c.ID]
		if r.byID == nil {
			r.byID = map[string]int{}
		}
		r.byID[c.ID] = len(r.checks)
		r.checks = append(r.checks, c)
	}
}

// ByID returns the registered check with the given ID. The lifecycle reconcile
// uses it to ask a stored finding's originating check whether it could evaluate
// the resource at all before treating its silence as a fix.
func (r *Registry) ByID(id string) (Check, bool) {
	i, ok := r.byID[id]
	if !ok {
		return Check{}, false
	}
	return r.checks[i], true
}

// Len reports how many checks are registered.
func (r *Registry) Len() int { return len(r.checks) }

// IDs returns every registered check's ID as a set, for tests that check
// catalogue consistency. Do not use it to auto-resolve findings whose check_id
// is not in the registry: CIEM rule IDs are never registry checks, and a
// misconfigured registry would mass-resolve the estate.
func (r *Registry) IDs() map[string]bool {
	out := make(map[string]bool, len(r.checks))
	for _, c := range r.checks {
		out[c.ID] = true
	}
	return out
}

// Evaluability is one check's ability to see the estate it grades: how many
// assets it applies to, and how many of those it could actually evaluate (see
// Check.Evaluable).
type Evaluability struct {
	CheckID    string
	Applicable int
	Evaluable  int
}

// Ratio is the fraction of applicable assets the check could actually evaluate.
// 1 when nothing applies — a check with no assets is not blind, it is idle, and
// reporting 0 there would bury the checks that really are blind under noise.
func (e Evaluability) Ratio() float64 {
	if e.Applicable == 0 {
		return 1
	}
	return float64(e.Evaluable) / float64(e.Applicable)
}

// Evaluability reports, per check, how much of its applicable asset population
// it could evaluate. Without this measurement, a check that silently stops
// emitting looks identical to a fixed estate and the lifecycle closes the
// difference as remediation.
//
// Called with a connector's full collected asset set (not the changed-asset
// subset), so the ratio describes the estate rather than the sweep.
func (r *Registry) Evaluability(assets []asset.Asset) []Evaluability {
	out := make([]Evaluability, len(r.checks))
	for i, c := range r.checks {
		out[i] = Evaluability{CheckID: c.ID}
	}
	for _, a := range assets {
		for i, c := range r.checks {
			if !c.applies(a) {
				continue
			}
			out[i].Applicable++
			if c.Evaluable(a) {
				out[i].Evaluable++
			}
		}
	}
	return out
}

// Fingerprint identifies the registered check set and each check's logic (a
// hash over sorted "id + logic digest" entries). The sync worker stores it per
// connector alongside the asset fingerprint, so a deploy that adds, removes OR
// edits a check forces one full-asset check backfill per connector: a new check
// fires on existing, unchanged assets, and an edited predicate (a CIEM rule, a
// severity grade, a step-aside) re-grades them, instead of either waiting for
// the assets to change naturally.
func (r *Registry) Fingerprint() string {
	entries := make([]string, len(r.checks))
	for i, c := range r.checks {
		entries[i] = c.ID + "\x01" + c.logic
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// TimeDependent returns a registry of only the checks that read the wall clock,
// for the sync worker's daily re-evaluation over every applicable asset.
func (r *Registry) TimeDependent() *Registry {
	out := NewRegistry()
	for _, c := range r.checks {
		if c.TimeDependent {
			out.Register(c)
		}
	}
	return out
}

// Run evaluates every applicable check against every asset and returns all
// findings. Each asset is matched only against checks for its provider/type.
// Findings on Kubernetes pods that carry owner workload metadata collapse to
// one finding per (workload, check): pods are replicas of one template, so
// per-pod findings would only multiply the same misconfiguration by the
// replica count. Mirrors the GuardDuty (resource, type) collapse.
func (r *Registry) Run(assets []asset.Asset, now time.Time) []finding.Finding {
	var out []finding.Finding
	agg := newWorkloadAggregator()
	for _, a := range assets {
		for _, c := range r.checks {
			if !c.applies(a) {
				continue
			}
			f, ok := c.eval(a, now)
			if !ok {
				continue
			}
			if agg.absorb(a, f) {
				continue
			}
			out = append(out, f)
		}
	}
	return append(out, agg.findings()...)
}

// workloadAggregator groups pod findings by (owner workload, check). The
// representative finding is re-addressed to the workload — a stable resource
// ID like "<cluster>/deployment/<ns>/<name>" that matches the collected
// k8s_deployment asset ID — so re-sweeps upsert one row per workload.
type workloadAggregator struct {
	grouped map[string]*finding.Finding
	counts  map[string]int
	order   []string
}

func newWorkloadAggregator() *workloadAggregator {
	return &workloadAggregator{grouped: map[string]*finding.Finding{}, counts: map[string]int{}}
}

// aggregatableOwnerKinds are the pod-owner kinds collected as first-class k8s
// workload assets (kubernetes.go: deploymentAsset, statefulSetAsset,
// daemonSetAsset, jobAsset). A bare-ReplicaSet owner has no asset and is
// excluded on purpose.
var aggregatableOwnerKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true,
}

// WorkloadOwnerID returns the asset ID of the workload a pod's findings are
// rolled up under, and false for an asset whose findings stay per-pod (not a
// pod, no owner, or an owner kind not collected as an asset).
func WorkloadOwnerID(a asset.Asset) (string, bool) {
	kind, name := a.Metadata["owner_kind"], a.Metadata["owner_name"]
	if a.Type != "k8s_pod" || name == "" || !aggregatableOwnerKinds[kind] {
		return "", false
	}
	return fmt.Sprintf("%s/%s/%s/%s", a.Region, strings.ToLower(kind), a.Metadata["namespace"], name), true
}

// absorb takes ownership of a finding when its asset is a pod owned by a
// workload kind collected as an asset; it reports false for everything else
// (finding stays per-pod).
//
// Restricted to aggregatableOwnerKinds deliberately: only those kinds are
// collected as k8s_<kind> assets, so the aggregated finding's ResourceID
// resolves to a real asset that UI drill-down, enrich, and the lifecycle
// reconcile (which only sees collected asset IDs) can all resolve. A
// bare-ReplicaSet owner has no asset, so an aggregated finding there would be
// an unresolvable zombie; those stay per-pod.
func (w *workloadAggregator) absorb(a asset.Asset, f finding.Finding) bool {
	ownerID, ok := WorkloadOwnerID(a)
	if !ok {
		return false
	}
	kind, name := a.Metadata["owner_kind"], a.Metadata["owner_name"]
	key := f.CheckID + "\x00" + ownerID
	if g, ok := w.grouped[key]; ok {
		w.counts[key]++
		if severityRank(f.Severity) > severityRank(g.Severity) {
			// The most severe replica speaks for the workload: its grade together
			// with the title and evidence that justify it, so the three never
			// disagree. Only the identity stays the workload's.
			id, rid, rtype, rname := g.ID, g.ResourceID, g.ResourceType, g.ResourceName
			*g = f
			g.ID, g.ResourceID, g.ResourceType, g.ResourceName = id, rid, rtype, rname
		}
		return true
	}
	f.ID = dbutil.DeterministicID(f.CheckID, ownerID)
	f.ResourceID = ownerID
	f.ResourceType = "k8s_" + strings.ToLower(kind)
	f.ResourceName = name
	w.grouped[key] = &f
	w.counts[key] = 1
	w.order = append(w.order, key)
	return true
}

// findings returns one finding per (workload, check), annotated with the
// affected pod count when more than one replica violated.
func (w *workloadAggregator) findings() []finding.Finding {
	out := make([]finding.Finding, 0, len(w.order))
	for _, key := range w.order {
		g := w.grouped[key]
		if n := w.counts[key]; n > 1 {
			if g.Metadata == nil {
				g.Metadata = map[string]string{}
			}
			g.Metadata["occurrences"] = strconv.Itoa(n)
			g.Title = fmt.Sprintf("%s (×%d pods)", g.Title, n)
		}
		out = append(out, *g)
	}
	return out
}

// severityRank orders severities so the workload collapse keeps the most severe.
func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	default:
		return 0
	}
}

// All returns the registered checks. Read-only view for callers that need to
// enumerate the catalogue (tooling, evaluability reporting).
func (r *Registry) All() []Check { return append([]Check(nil), r.checks...) }
