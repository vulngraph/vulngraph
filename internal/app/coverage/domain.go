// Package coverage answers "are we covered?" as a query rather than an audit.
//
// Every detection gap this platform has hit fails on exactly one of four axes,
// and from the outside all four look identical — silence. The map of which
// axis each finding category fails on is never a hand-typed snapshot: a
// snapshot is wrong three weeks later and nobody notices (a stale comment
// read as fact). Everything here is DERIVED: from the checks registry
// (checks.Default(), including the AST-derived Check.RequiredKeys), from the
// edge registry (internal/graphschema), and from live ClickHouse
// counts. cmd/coverage-gen renders it to docs/COVERAGE.md.
package coverage

import (
	"errors"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ErrNoLiveData is returned by accessors for a section that needs a ClickHouse
// connection the generator did not have. The generator degrades to offline mode
// rather than failing: CI has no ClickHouse connection, and a tool that only
// runs from a laptop rots.
var ErrNoLiveData = errors.New("coverage: no live data (offline mode)")

// Axis is one of the four ways detection goes silent. They are ordered as a
// pipeline — you cannot have evidence you did not collect, cannot assert on
// evidence you do not have, cannot score a finding that never fired — and the
// axis derivation takes the FIRST one that fails, because fixing a later axis
// while an earlier one is broken changes nothing.
type Axis string

const (
	// AxisCollected — the asset type has no rows at all.
	AxisCollected Axis = "collected"
	// AxisEvidence — assets exist but the metadata key a check reads does not.
	AxisEvidence Axis = "evidence"
	// AxisCheck — the data is collected and nothing reads it.
	AxisCheck Axis = "check"
	// AxisGraph — the finding exists but the edge does not, so scoring cannot
	// reach it.
	AxisGraph Axis = "graph"
	// AxisCovered — none of the four fail.
	AxisCovered Axis = "covered"
)

// AxisDef documents one axis and, crucially, the MECHANICAL rule that assigns
// it. The rule is what makes this document regenerable: no judgement is applied
// per category, so a category that changes axis between two runs changed in the
// data, not in someone's opinion.
type AxisDef struct {
	Axis    Axis
	Symptom string
	Rule    string
}

// Axes is the ordered pipeline. Order is load-bearing: DeriveAxis returns the
// first failing axis in this order.
var Axes = []AxisDef{
	{
		Axis:    AxisCollected,
		Symptom: "the asset type has no rows",
		Rule:    "every resource type carrying this category's open findings has zero fresh assets — or the source is declared in the code and has produced nothing at all",
	},
	{
		Axis:    AxisEvidence,
		Symptom: "assets exist but the metadata key does not",
		Rule:    "some registered check that ACTUALLY PRODUCES this category's open findings — joined by `check_id`, not by sharing an asset type — has an evidence-bearing RequiredKey present on fewer than all of its fresh applicable assets. Suppressor keys are excluded: a key whose absence cannot prevent the predicate concluding is not missing data",
	},
	{
		Axis:    AxisCheck,
		Symptom: "data is collected and nothing reads it",
		Rule:    "this category's resource types carry observed metadata keys that no registered check for that provider+type declares in RequiredKeys",
	},
	{
		Axis:    AxisGraph,
		Symptom: "the finding exists but the edge does not, so scoring cannot reach it",
		Rule:    "this category's resource types are the source of zero fresh edges of any reach-set or internet-seed type, so the internet-hops BFS can never assign them a hop count",
	},
}

// ProviderScope records whether a provider's numbers are weighted in
// prioritisation or merely reported. This is the ONE place a scope decision is
// declared rather than derived — it is a product decision, not a fact about the
// data — and TestProviderScopeCoversEveryDeclaredProvider fails when
// asset.Provider gains a constant that nobody classified here.
type ProviderScope struct {
	Provider string
	Weighted bool
	Reason   string
}

// ProviderScopes classifies every asset.Provider constant.
var ProviderScopes = []ProviderScope{
	{Provider: "aws", Weighted: true, Reason: "core cloud provider"},
	{Provider: "gcp", Weighted: true, Reason: "core cloud provider"},
	{Provider: "kubernetes", Weighted: true, Reason: "the workload layer where services run"},
	{Provider: "github", Weighted: true, Reason: "the source of the supply-chain lineage"},
	{Provider: "azure", Weighted: false, Reason: "collector coverage is narrower; treating it as a gap would distort priority lists, so it is reported and not weighted"},
}

// StageKind is how a lineage stage counts.
type StageKind string

const (
	// StageAssets counts fresh assets of the named types.
	StageAssets StageKind = "assets"
	// StageEdgeSrc counts distinct sources of a fresh edge type.
	StageEdgeSrc StageKind = "edge_src"
	// StageEdgeDst counts distinct destinations of a fresh edge type.
	StageEdgeDst StageKind = "edge_dst"
	// StageAssetMeta counts fresh assets of the named types whose metadata
	// MetaKey holds one of MetaValues — a known-ness stamp, where an edge count
	// cannot tell "observed nothing" from "never looked".
	StageAssetMeta StageKind = "asset_meta"
)

// LineageStage is one link in the chain "repo → asset → exposed → which
// packages, from where". The chain is the headline of this document because it
// breaks in the MIDDLE, not at the ends: both endpoints are well populated and
// every join between them loses an order of magnitude.
//
// Declared here as data — TestLineageStagesReferenceTheRegistries fails when a
// stage names an edge type absent from graphschema.EdgeTypes or an asset type
// no registered check applies to, which is what turns a rename into a red test
// instead of a silently-zero row in a trusted document.
type LineageStage struct {
	Name string
	Kind StageKind
	// EdgeType for StageEdgeSrc/StageEdgeDst.
	EdgeType string
	// Types filters: asset types for StageAssets, endpoint types for the edge
	// kinds. Empty means no filter.
	Types []string
	// Question is what a zero here would mean.
	Question string
	// OfStage is the stage name this one is expressed as a percentage of.
	// Empty means it stands alone.
	OfStage string
	// MetaKey / MetaValues for StageAssetMeta.
	MetaKey    string
	MetaValues []string
}

// LineageStages is the chain, in order.
var LineageStages = []LineageStage{
	{
		Name: "repos", Kind: StageAssets, Types: []string{"github_repo"},
		Question: "how many repositories exist at all",
	},
	{
		Name: "repos with an SBOM", Kind: StageEdgeSrc, EdgeType: "depends_on", Types: []string{"github_repo"},
		Question: "do we know what a repo depends on", OfStage: "repos",
	},
	{
		Name: "repos linked to a runtime", Kind: StageEdgeSrc, EdgeType: "deploys_to", Types: []string{"github_repo"},
		Question: "do we know where a repo's code actually runs", OfStage: "repos",
	},
	{
		Name: "repos owning an asset", Kind: StageEdgeDst, EdgeType: "defined_in", Types: []string{"github_repo"},
		Question: "do we know which repo declares a cloud resource", OfStage: "repos",
	},
	{
		Name: "assets exposed to the internet", Kind: StageEdgeSrc, EdgeType: "exposed_to_internet",
		Question: "which assets are the attacker's entry points",
	},
	{
		Name: "things with a package inventory", Kind: StageEdgeSrc, EdgeType: "runs_package",
		Question: "for how many things do we know the installed packages",
	},
	{
		Name: "VMs with a package inventory", Kind: StageEdgeSrc, EdgeType: "runs_package",
		Types:    []string{"ec2_instance", "gce_instance", "azure_vm"},
		Question: "do we know what is installed on a virtual machine", OfStage: "VMs",
	},
	{
		Name: "VMs with a known package inventory", Kind: StageAssetMeta,
		Types:   []string{"ec2_instance", "gce_instance", "azure_vm"},
		MetaKey: asset.MetaPackageInventory, MetaValues: []string{asset.PackageInventorySSM, asset.PackageInventoryOSConfig, asset.PackageInventoryDisk, asset.PackageInventoryBYOA},
		Question: "is a VM without CVE findings observed clean, or unobserved (no SSM agent / OS Config / disk scan)", OfStage: "VMs",
	},
	{
		Name: "VMs with a CVE-matchable inventory", Kind: StageAssetMeta,
		Types:   []string{"ec2_instance", "gce_instance", "azure_vm"},
		MetaKey: asset.MetaPackageCVEMatchable, MetaValues: []string{"true"},
		Question: "can an advisory source match the VM's OS packages in full (see VM OS advisory coverage for why not)", OfStage: "VMs",
	},
	{
		Name: "VMs", Kind: StageAssets, Types: []string{"ec2_instance", "gce_instance", "azure_vm"},
		Question: "how many virtual machines exist at all",
	},
}

// CheckFact is one registered check plus, when live, the evidence its predicate
// depends on.
type CheckFact struct {
	ID        string
	Title     string
	Provider  string
	AssetType string
	Type      string
	Severity  string
	// RequiredKeys is Check.RequiredKeys — AST-derived, never hand-written.
	RequiredKeys []string
	// EvidenceKeys are the RequiredKeys whose ABSENCE can hide a violation, and
	// SuppressorKeys the rest — keys the predicate reads only to exempt itself,
	// whose absence never prevented it concluding. Derived by evidenceKeys()
	// from Check.Evaluable, never declared. Only EvidenceKeys can constitute an
	// evidence gap: advising a collector to emit a suppressor would turn the
	// check OFF where it fires today.
	EvidenceKeys   []string
	SuppressorKeys []string
	// Live fields below; EvidenceKnown is false in offline mode.
	EvidenceKnown bool
	// Applicable is the number of fresh assets this check runs against.
	Applicable uint64
	// WorstKey is the EVIDENCE key present on the fewest applicable assets, and
	// WorstKeyPresent is that count. A check's evidence coverage cannot exceed
	// WorstKeyPresent/Applicable — per-key presence is measured independently,
	// so this is an upper bound on "assets carrying ALL required keys", stated
	// as a bound rather than dressed up as an exact figure.
	WorstKey        string
	WorstKeyPresent uint64
	OpenFindings    uint64
}

// StructuralOnly reports whether this check reads no asset metadata at all — it
// decides on structural asset fields, so the evidence axis cannot apply to it.
func (c CheckFact) StructuralOnly() bool { return len(c.RequiredKeys) == 0 }

// EvidenceBlind reports whether the evidence axis cannot apply to this check:
// it reads no metadata at all, or reads only suppressor keys, whose absence
// cannot prevent it concluding. EvidenceKeys is only populated when live, so
// offline this collapses to StructuralOnly.
func (c CheckFact) EvidenceBlind() bool {
	if c.StructuralOnly() {
		return true
	}
	return c.EvidenceKnown && len(c.EvidenceKeys) == 0
}

// EvidenceBound is the upper bound on the fraction of applicable fresh assets
// carrying every evidence-bearing RequiredKey, in [0,1]. Checks the evidence
// axis cannot apply to return 1; checks with no applicable assets return 0.
func (c CheckFact) EvidenceBound() float64 {
	if c.EvidenceBlind() {
		return 1
	}
	if c.Applicable == 0 {
		return 0
	}
	return float64(c.WorstKeyPresent) / float64(c.Applicable)
}

// CategoryFact is one finding category (source × type) with its band split and
// the axis it fails on.
type CategoryFact struct {
	Source string
	Type   string
	Open   uint64
	// Blank counts open findings with an empty must_fix_class — enrich reached no
	// verdict at all: it has not run on them, or failed open on missing evidence,
	// not that it weighed them and found nothing.
	Blank uint64
	// Routine counts open findings the classifier weighed and found no urgency
	// evidence for: the population a fully-covered category's remaining question
	// is about.
	Routine uint64
	Page    uint64
	High    uint64
	// ResourceTypes are the resource types carrying this category's open
	// findings, most-common first (capped at resourceTypeSample).
	ResourceTypes []string
	Axis          Axis
	// Because is the derived one-line justification for Axis, naming the
	// concrete measurement that triggered the rule.
	Because string
	// Target is the condition that would close this category.
	Target string
	// NeedsDecision marks a target that is a product decision, not engineering.
	NeedsDecision bool
}

// BlankPct, PagePct and HighPct are percentages of Open.
func (c CategoryFact) BlankPct() float64 { return pct(c.Blank, c.Open) }

// PagePct is the share of this category's open findings in the page band.
func (c CategoryFact) PagePct() float64 { return pct(c.Page, c.Open) }

// HighPct is the share of this category's open findings in the high band.
func (c CategoryFact) HighPct() float64 { return pct(c.High, c.Open) }

func pct(n, of uint64) float64 {
	if of == 0 {
		return 0
	}
	return 100 * float64(n) / float64(of)
}

// SourceFact is one finding source's liveness. Declared is true when the source
// string appears in a finding.Finding composite literal (or the external-import
// allowlist) somewhere in the tree — i.e. the code CAN produce it. A declared
// source with zero findings never fired; that is the loudest possible silence
// and nothing in this platform measured it before.
type SourceFact struct {
	Source       string
	Declared     bool
	Total        uint64
	Open         uint64
	LastDetected time.Time
}

// StaleDays is whole days since this source last produced a finding, or -1 when
// it never has.
func (s SourceFact) StaleDays(now time.Time) int {
	if s.LastDetected.IsZero() {
		return -1
	}
	return int(now.Sub(s.LastDetected).Hours() / 24)
}

// UnreadKey is a metadata key a collector writes that no registered check for
// that provider+type reads — the `check` axis, measured.
//
// The population is deliberately narrowed to keys the registry reads SOMEWHERE:
// a key that no check anywhere declares is descriptive metadata (an ARN, a
// creation timestamp) and listing it would bury the signal under hundreds of
// rows. A key the platform has already decided is assertable, present on this
// type and asserted on for a different one, is a real gap — `public_access` on
// one bucket type and not the other is precisely the shape this axis exists to
// catch.
type UnreadKey struct {
	Provider  string
	AssetType string
	Key       string
	Assets    uint64
	// ReadBy are the check IDs that DO read this key, for other provider/type
	// pairs — the evidence that the key is assertable.
	ReadBy []string
}

// ScoringSeedEdgeTypes are the edge types that SEED the internet-hops BFS
// rather than move along it. graphschema marks movement edges with Reach, but a
// seed is not a movement edge and carries no flag of its own, so it is declared
// here — the one derived-from-judgement value in this package.
// TestScoringSeedsAreRegisteredNonReachTypes fails if a named seed leaves the
// registry or gains Reach, which would mean it is no longer a seed.
var ScoringSeedEdgeTypes = []string{"exposed_to_internet"}

// EdgeFact is one edge type from the graphschema registry, plus its live fresh
// volume. The `graph` axis is a property of this table: an edge type that is
// unsynced, or feeds an unloaded rel, cannot carry a hop count no matter how
// many rows ClickHouse holds.
type EdgeFact struct {
	Type       string
	Rel        string
	Tier       string
	Reach      bool
	Inherit    bool
	Loaded     bool
	Expand     bool
	DropReason string
	Doc        string
	// Live fields; LiveKnown is false offline.
	LiveKnown   bool
	Rows        uint64
	DistinctSrc uint64
}

// StageFact is a measured lineage stage.
type StageFact struct {
	LineageStage
	Count uint64
	// OfCount is the count of OfStage, 0 when OfStage is empty.
	OfCount uint64
}

// Pct is this stage as a percentage of its OfStage.
func (s StageFact) Pct() float64 { return pct(s.Count, s.OfCount) }

// TypeCount is a fresh-asset count for one provider/type pair.
type TypeCount struct {
	Provider  string
	AssetType string
	Count     uint64
}

// KeyPresence is how many fresh assets of one provider/type carry one metadata
// key. Both the evidence axis (is a check's RequiredKey there?) and the check
// axis (does anything read this key?) are computed from this one measurement.
type KeyPresence struct {
	Provider  string
	AssetType string
	Key       string
	Assets    uint64
}

// BandSplit is one finding category's open count and band split.
type BandSplit struct {
	Source  string
	Type    string
	Open    uint64
	Blank   uint64
	Routine uint64
	Page    uint64
	High    uint64
}

// ResourceTypeCount is how many open findings of one category sit on one
// resource type.
type ResourceTypeCount struct {
	Source       string
	Type         string
	ResourceType string
	Open         uint64
}

// CategoryCheck is how many of one category's open findings a single check_id
// produced. It is the join that makes the evidence axis answer for the checks
// that ACTUALLY emit a category's findings rather than for any check that
// happens to share an asset type — six categories carry `github_repo` among
// their resource types, and without this join all six would be told to go fix
// branch protection.
//
// CheckID is whatever the producer stamped: some sources (nuclei, supply_chain)
// carry IDs that are not registry checks, so the service resolves each against
// the registry rather than assuming.
type CategoryCheck struct {
	Source  string
	Type    string
	CheckID string
	Open    uint64
}

// EdgeEndpointCount is the deduped fresh volume of one edge type at one
// endpoint type. Direction is carried by which slice it lands in.
type EdgeEndpointCount struct {
	EdgeType     string
	EndpointType string
	Rows         uint64
	Distinct     uint64
}

// MetaValueCount is how many fresh assets of one type hold one value of one
// metadata key ("" = key absent).
type MetaValueCount struct {
	AssetType string
	Key       string
	Value     string
	Count     uint64
}

// LiveFacts is everything the ClickHouse repository measures, in domain terms.
// The service turns it into a Report; the repository never decides anything.
type LiveFacts struct {
	Assets    []TypeCount
	Keys      []KeyPresence
	Bands     []BandSplit
	Resources []ResourceTypeCount
	Sources   []SourceFact
	CheckOpen map[string]uint64
	// CategoryChecks is which check_ids produced each category's open findings.
	CategoryChecks []CategoryCheck
	EdgesBySrc     []EdgeEndpointCount
	EdgesByDst     []EdgeEndpointCount
	EdgeTotals     map[string]uint64
	// MetaValues is the value split of every StageAssetMeta key.
	MetaValues []MetaValueCount
	MeasuredAt time.Time
	// Failed names the measurements that did not complete, and QueryErrors the
	// reasons. A section built on a failed measurement must say so rather than
	// render zeros: "unknown" and "none" look identical in a table, and telling
	// them apart is the whole job of this document.
	Failed      []string
	QueryErrors []string
}

// Report is the whole generated document as data. Render turns it into
// markdown; nothing in it is typed by hand.
type Report struct {
	GeneratedAt time.Time
	// Live is false when no ClickHouse connection was available. Offline reports
	// carry the registry-derived half and say which sections are missing.
	Live bool
	// LiveErr records why live data was unavailable, for the reader.
	LiveErr string

	Checks     []CheckFact
	Edges      []EdgeFact
	Categories []CategoryFact
	Sources    []SourceFact
	UnreadKeys []UnreadKey
	Stages     []StageFact
	// Advisory and AdvisoryGaps are the VM OS advisory coverage (live only).
	Advisory     []AdvisoryRow
	AdvisoryGaps []GapRow

	// FreshAssets is fresh asset count per provider (live only).
	FreshAssets map[string]uint64
	// EmptyAssetTypes are asset types some registered check targets that hold
	// zero fresh assets — the `collected` axis at check granularity.
	EmptyAssetTypes []string
	// UnreadKeyTotal is the full count before the rendering cap.
	UnreadKeyTotal int
	// FailedSteps names the live measurements that did not complete.
	FailedSteps []string
}
