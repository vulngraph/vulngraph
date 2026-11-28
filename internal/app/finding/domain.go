// Package finding owns security findings — the output of CSPM checks (and
// later the scanner and supply-chain feeds). Findings are stored in ClickHouse
// and are the input to scoring and reasoning.
package finding

import (
	"errors"
	"time"
)

// Severity is the raw severity assigned by whatever produced the finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is one detected issue against one resource. ID is deterministic
// (derived from source + check + resource) so re-scans upsert the same row via
// ClickHouse ReplacingMergeTree instead of duplicating.
//
// Severity is the raw scanner input. Score is the contextual risk assessment
// produced by enrichment (internal/app/enrich) — it is the value the product
// surfaces and sorts on; severity is only an input to it. Score/ScoreBand/
// EnrichedAt are zero until a finding has been enriched.
type Finding struct {
	ID           string
	Source       string // cspm, nuclei, supply_chain, ...
	Type         string // category, e.g. "exposure", "misconfiguration"
	Severity     Severity
	Title        string
	Description  string
	ResourceType string
	ResourceID   string
	ResourceName string
	Region       string
	CheckID      string
	Remediation  string
	// DetectedAt is the MOST RECENT emission's timestamp, not the first. Every
	// producer stamps `now` on every re-emission and nothing carries the old
	// value forward, so this is "last detected". It is the list sort key and the
	// TTL anchor — read FirstDetectedAt for anything that means age.
	DetectedAt time.Time
	// FirstDetectedAt is the first observation of this finding, immutable under
	// re-observation: Service.RecordObserved pins it to the stored value for any
	// id that already exists, and the repo reads it as min-over-nonzero across
	// surviving row versions so a stray producer write cannot move it forward.
	// This is the ONLY age input any scoring source may read (the
	// FindingAge). Zero means "never established" — treat as unknown and do not
	// demote (absence of evidence never demotes).
	FirstDetectedAt time.Time
	// Metadata holds scanner-native context with no dedicated column — e.g. a
	// nuclei finding's matched_url, evidence, and references. Persisted in the
	// findings `tags` Map column. Nil/empty for sources that don't set it.
	Metadata map[string]string

	// Enrichment outputs -- the ten fields live in their own table
	// (finding_enrichment), written ONLY by enrich/KEV via Service.RecordEnrichment
	// and read back via a LEFT JOIN on every finding reader (Get/ByIDs/
	// ByResourceIDs/List/Summary/Clusters/the risk rollups). No producer or
	// lifecycle write touches `findings`' own copies of these columns, so a
	// producer re-observation can never reset them to zero on the next Upsert.
	// Tag any new enrichment output here AND in Enrichment/EnrichmentOf
	// (domain.go) -- there is no test deriving one list from the other, so
	// both must be updated by hand.
	Score      uint8  // contextual risk score 0–100 (0 = not yet enriched)
	ScoreBand  string // enrich.Band classification of Score
	EnrichedAt time.Time
	// KnownExploited is set by the KEV refresh job when CheckID is a CISA-KEV CVE;
	// the enrichment KEV source reads it (no second catalog lifecycle).
	KnownExploited bool

	// Structural "safe to fix" signal, computed at enrich time from graph
	// structure alone (no LLM) — the "will fixing this break anything?" axis, the
	// inverse of attack blast radius (see internal/app/enrich/safety.go). Unlike
	// the reasoncache safety_band (populated only once a finding is reasoned),
	// these are set on every enriched finding, so a freshly-onboarded environment
	// has an actionable "start here" worklist immediately.
	Dependents  uint16 // distinct assets that depend on this resource (would break if it changed)
	Unused      bool   // resource looks decommissioned (stale / inactive / orphaned)
	SafetyClass string // advisory: "safe" | "caution" | "risky" | "" (unknown/unenriched)
	FixTarget   string // compact fix location, e.g. "repo:org/name" | "console:aws:eu-west-1" | ""

	// Evidence-backed urgency tier, computed at enrich from real
	// reachability + exploitability + blast + compensating controls — NOT the score.
	// "must_fix" | "elevated" | "contained" | "controlled" | "routine" | ""
	// (unenriched). "routine" is the classifier's fall-through — weighed, no urgency
	// evidence — and is the MAJORITY verdict; it ranks below "contained".
	MustFixClass  string
	MustFixReason string // compact evidence, e.g. "internet-reachable (2 hops) · KEV · blast 42"

	// Routing context, stamped by enrich from the finding's asset
	// (asset.ResolveOwnership, asset.ClassifyEnvironment) into finding_enrichment
	// beside the outputs above, so the list can filter and facet on it without a
	// query-time join to `assets` (ADR 089). OwnerSource "" means resolution has
	// not run on this finding yet or could not complete — NEVER "unowned", which
	// is OwnerSource "none". Environment "" likewise means not yet stamped;
	// "unknown" is the classifier's real answer.
	OwnerTeam       string
	OwnerSource     string // tag | codeowners | iac | none | ""
	OwnerConfidence string // high | medium | low | ""
	Environment     string // prod | staging | dev | unknown | ""

	// Lifecycle. LastObservedAt is stamped each time the emitting
	// check/collector re-observes the finding at sync. ResolvedAt is set by the
	// sync-time reconcile when the checks ran on this finding's resource and did
	// NOT re-emit it (fixed), or the resource was deleted; cleared on reappearance
	// (regression). Zero ResolvedAt = open. Readers exclude resolved by default.
	LastObservedAt time.Time
	ResolvedAt     time.Time
	// ResolutionReason records WHY it resolved (see resolution.go). Empty on an
	// open finding, and on rows resolved before the column existed.
	ResolutionReason ResolutionReason
}

// ProvenanceConnectorKey is the Metadata key naming the listing whose sweep
// last emitted a provider-native finding: the connector id for a connector
// sweep (the same key the sync worker stamps on assets), or the fetcher's scope
// for a feed with no connector — "gcp_scc:organizations/<id>" for the SCC
// worker. Findings have no account or connector column, and a provider-native
// feed's absence can only be judged against the listing that produced it, so
// this tag is what scopes that judgement to one listing.
const ProvenanceConnectorKey = "prov_connector_id"

// SecretValidityKey is the Metadata key carrying GitHub's own check of whether a
// leaked secret still works (the secret-scanning alert's `validity`): one of the
// SecretValidity* values below, or absent when GitHub reported none (validity
// checks are off, or the provider is not one GitHub can check). Absent means
// unknown, never "not live".
const SecretValidityKey = "secret_validity"

// The validity values GitHub reports on a secret-scanning alert.
const (
	SecretValidityActive   = "active"   // the provider accepted the credential
	SecretValidityInactive = "inactive" // the provider rejected it: revoked or expired
	SecretValidityUnknown  = "unknown"  // GitHub could not tell
)

// OpenKey is the narrow identity of an open finding: enough for a caller to
// decide whether it is a resolution candidate without hydrating the full row.
type OpenKey struct {
	ID     string
	Region string
	Type   string
}

// Resolved reports whether the finding has been auto-resolved (no longer
// observed by its emitting check, or its resource was deleted).
func (f Finding) Resolved() bool { return !f.ResolvedAt.IsZero() && f.ResolvedAt.Year() > 2000 }

// Enrichment is the write model for the ten enrichment-output fields on
// Finding, targeting the finding_enrichment table instead of the
// full findings row. Written ONLY by enrich/KEV (Service.RecordEnrichment) —
// no producer or lifecycle path writes this table, which is the whole point:
// a producer re-observation's full-row Upsert on `findings` has no shared row
// to lose an enrichment update on, and no shared
// COLUMN either -- insertFindings writes none of these ten.
type Enrichment struct {
	ID             string
	Score          uint8
	ScoreBand      string
	KnownExploited bool
	Dependents     uint16
	Unused         bool
	SafetyClass    string
	FixTarget      string
	MustFixClass   string
	MustFixReason  string
	EnrichedAt     time.Time
	// Routing context (see Finding). Carried through EnrichmentOf like the
	// outputs above, so a KEV write built from a ByIDs re-read keeps it.
	OwnerTeam       string
	OwnerSource     string
	OwnerConfidence string
	Environment     string
}

// EnrichmentOf extracts f's Enrichment view — the ten enrichment-output
// fields, keyed by id. Exported so score-writers (enrich, the KEV refresh) can
// build their RecordEnrichment argument from a Finding instead of re-deriving
// the field list at each call site.
// There is no reflection or struct tag tying this list to Finding's own
// enrichment fields -- both this function and Finding's doc comment above
// must be updated by hand when a new enrichment output is added.
func EnrichmentOf(f Finding) Enrichment {
	return Enrichment{
		ID:             f.ID,
		Score:          f.Score,
		ScoreBand:      f.ScoreBand,
		KnownExploited: f.KnownExploited,
		Dependents:     f.Dependents,
		Unused:         f.Unused,
		SafetyClass:    f.SafetyClass,
		FixTarget:      f.FixTarget,
		MustFixClass:   f.MustFixClass,
		MustFixReason:  f.MustFixReason,
		EnrichedAt:     f.EnrichedAt,

		OwnerTeam:       f.OwnerTeam,
		OwnerSource:     f.OwnerSource,
		OwnerConfidence: f.OwnerConfidence,
		Environment:     f.Environment,
	}
}

// OwnerUnowned is the Filter.Owner value selecting findings whose owner
// resolved to nobody (OwnerSource "none").
const OwnerUnowned = "unowned"

// Unowned reports whether routing should treat f as nobody's: resolved to no
// owner, or not resolved at all. The second case is deliberate — an alert for a
// finding whose owner we could not establish must still reach someone, so it
// goes wherever unowned findings go rather than nowhere.
func (f Finding) Unowned() bool { return f.OwnerSource == "" || f.OwnerSource == "none" }

// EnrichmentState is how far enrichment has got on a finding. It exists because
// every enrichment output uses "" / 0 for BOTH "the pipeline has not run" and
// "the pipeline ran and the answer is genuinely nothing" — an ambiguity that
// misleads audits and, worse, is what the UI ends up rendering. safety_class,
// score and score_band all carry that double meaning, so callers must be able
// to tell "the pipeline has not run" from "it ran and found nothing", which is what
// this closed enum is for — never an empty string on the wire.
//
// must_fix_class names "weighed, no urgency evidence" as a verdict of its own
// (MustFixRoutine), so a blank there never means "weighed and found nothing":
// it means enrichment has not run, or the classifier failed open on missing
// evidence (for example no resource, unknown repo visibility, a truncated
// supply-chain walk, a package or code-scanning alert with no deployment lineage,
// or no RBAC subject evidence). enrichment_state is the authority on whether the pipeline
// ran, which is why the frontend keeps its fallback.
type EnrichmentState string

const (
	// StateNeverEnriched: no enrichment has ever run. Every enrichment output on
	// this finding is a zero value carrying no information.
	StateNeverEnriched EnrichmentState = "never_enriched"
	// StateStale: enriched, but longer ago than StaleEnrichmentAfter — the outputs
	// reflect a prior state of the graph, and possibly a prior version of the
	// scoring logic.
	StateStale EnrichmentState = "stale"
	// StateEnriched: enriched recently. A zero-valued output here is a real answer.
	StateEnriched EnrichmentState = "enriched"
)

// StaleEnrichmentAfter is when an enriched finding's outputs stop being
// trustworthy. Twice the enrich freshness backstop (jobs.defaultEnrichMaxAge,
// 24h): one missed backstop is ordinary sweep lag, two means this finding is
// not being reached.
const StaleEnrichmentAfter = 48 * time.Hour

// EnrichmentStateAt reports how far enrichment has got, as of now. Pure: the
// caller supplies the clock so handlers and tests agree.
func (f Finding) EnrichmentStateAt(now time.Time) EnrichmentState {
	// Same sentinel convention as Resolved(): ClickHouse DateTime has no NULL, so
	// an unset timestamp reads back as the 1970 epoch, not the Go zero time.
	if f.EnrichedAt.IsZero() || f.EnrichedAt.Year() <= 2000 {
		return StateNeverEnriched
	}
	if now.Sub(f.EnrichedAt) > StaleEnrichmentAfter {
		return StateStale
	}
	return StateEnriched
}

// Filter narrows a ListFindings query. Zero values mean "no filter".
type Filter struct {
	Source      string
	Severity    Severity
	ResourceID  string // only findings on this resource (for graph-aware enrichment)
	CheckID     string // only findings from this check (drill-down from a cluster)
	MinScore    uint8  // exclude findings below this enriched score
	SortByScore bool   // sort by enriched score desc instead of detected_at desc
	SafeOnly    bool   // only findings classed structurally safe to fix (safety_class = 'safe')
	MustFixOnly bool   // only findings classed evidence-backed must-fix (must_fix_class = 'must_fix')
	Unenriched  bool   // only never-enriched findings (enriched_at unset) — the score-0 backlog
	// Owner narrows to one owner team (as stored: asset.NormalizeOwner form), or
	// OwnerUnowned for findings whose owner resolved to nobody. Environment
	// narrows to one classified environment (prod|staging|dev|unknown). Both read
	// finding_enrichment, so a finding enrich has not reached yet matches neither.
	Owner       string
	Environment string
	// StaleFirst sorts already-enriched findings by enriched_at ascending (oldest first)
	// instead of detected_at descending, and excludes the never-enriched (Unenriched
	// already owns those). The enrich drift-pass sweep uses this: without it, a filter
	// with no ordering hook restarts from the newest-detected finding every tick, so a
	// corpus bigger than one tick's budget never has its tail re-enriched — a finding
	// scored before a new enrich feature (e.g. must_fix_class) shipped stays on
	// that stale classification indefinitely. Cache hits do not change enriched_at,
	// so bounded sweeps must persist their enumeration cursor across ticks.
	StaleFirst bool
	// EnrichedBefore freezes an enrichment-time pass boundary. Rows rescored after
	// the boundary are excluded from that pass, even when their sort keys move.
	EnrichedBefore time.Time
	// OldestFirst sorts by detected_at ASCENDING instead of the default descending.
	// A sweep with a per-tick scan ceiling and a cursor that resets each tick can
	// only ever see the newest N findings; if the backlog it exists to drain is
	// OLDER than that window, it re-examines the same live rows forever and
	// resolves nothing. Ordering oldest-first puts the backlog directly under the
	// ceiling. Pairs naturally with DetectedBefore to bound the candidate set.
	OldestFirst     bool
	IncludeResolved bool      // include auto-resolved findings (resolved_at set); default false hides them
	DetectedAfter   time.Time // for scan run findings: only findings after this time
	DetectedBefore  time.Time // for scan run findings: only findings before this time
	Limit           int
	Cursor          string // keyset pagination cursor (opaque; see cursor.go)
	// CVEIn restricts to findings whose check_id IS a CVE in this list, OR whose
	// tags["cve"] metadata is — mirroring kev.findingCVE's own two-lineage match
	// (scanner/OSV findings key check_id on the CVE directly; nuclei findings key
	// on a template slug and carry the CVE in metadata instead). Matched
	// case-insensitively (upper() both sides in SQL), matching kev.Catalog's own
	// upper-casing. Pushed into the pre-aggregation WHERE (repo.go), not a Go-side
	// filter: check_id (like source/resource_id) is baked into the finding's
	// deterministic ID, so it is identical across every ReplacingMergeTree version
	// and safe to filter before GROUP BY — without it, the KEV refresh job
	// re-aggregates the entire per-source subset on every pagination page (the
	// GROUP BY runs before ORDER BY/LIMIT, so a smaller page doesn't reduce the
	// aggregation cost, only how many times it repeats it), which can hit
	// ClickHouse's per-query timeout on a large catalog. Mutually exclusive with
	// CheckID in practice (CheckID is a single exact drill-down value; CVEIn is
	// this multi-value need) — nothing enforces that, so a caller combining both
	// gets their AND, which is likely not what either meant, but is not a
	// data-safety issue either way.
	CVEIn []string
}

// EnrichmentPage carries IDs and the original selection seek key. It is not a
// hydrated finding page; its length and cursor come from one source statement.
type EnrichmentPage struct {
	IDs    []string
	Cursor string
}

var ErrNotFound = errors.New("finding: not found")

// ErrNeedsPerson: an API-key request to resolve a finding that only a person
// on a signed-in session may close (Service.ResolveManually).
var ErrNeedsPerson = errors.New("finding: this finding can only be resolved from a signed-in session")

// NeedsPersonError is ErrNeedsPerson with the agent guard's reason.
type NeedsPersonError struct{ Reason string }

func (e *NeedsPersonError) Error() string { return ErrNeedsPerson.Error() + " (" + e.Reason + ")" }

func (e *NeedsPersonError) Unwrap() error { return ErrNeedsPerson }

// ErrInvalidResolution is returned when a resolution carries no valid reason.
// Resolving without saying why is what made check quality unmeasurable, so it is
// an error rather than a defaulted empty string (see resolution.go).
var ErrInvalidResolution = errors.New("finding: invalid resolution reason")

// ErrResultTooLarge is returned when a batch read's result exceeds its OOM guard.
// Callers MUST treat it as a skipped read (fail-closed), never as an empty or
// partial result: on the lifecycle paths a partial finding set that looks complete
// silently under-resolves.
var ErrResultTooLarge = errors.New("finding: result too large")
