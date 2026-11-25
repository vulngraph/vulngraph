// Package collect defines the Collector contract that each provider implements
// and the registry the sync job uses to find the right collector for a
// connector. Collectors are pure producers: given a decrypted config they
// return assets and edges, and never touch storage themselves.
package collect

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// ErrPermanent marks a collect failure that retrying cannot fix — e.g. the hub
// identity is not trusted by the account's role, so every attempt fails
// identically. The sync worker cancels such a job instead of retrying it, so
// one unreachable connector never starves the shared worker pool.
var ErrPermanent = errors.New("collect: permanent failure")

// Result is what a collector discovered in one run. Findings carries provider-
// native findings (e.g. AWS GuardDuty, GCP SCC) that the provider already
// computed — distinct from the CSPM findings the sync worker derives from
// Assets via the check registry. The sync worker records both.
type Result struct {
	Assets   []asset.Asset
	Edges    []asset.Edge
	Findings []finding.Finding

	// Partial reports that collection was incomplete this sweep — a best-effort
	// collector was skipped on error, or a paginated listing returned early.
	// When true, absence of an asset from Assets does NOT mean it was deleted,
	// so the sync worker skips deletion reconciliation (hash pruning and finding
	// auto-resolution): otherwise a transient API error would wrongly resolve
	// live findings and churn asset hashes.
	//
	// Partial is a single aggregate boolean per connector and remains the outer
	// gate: one flaky best-effort family still blocks deletion reconciliation
	// for the whole connector. CompletedEnumerations does not lift that gate;
	// inside a non-partial sweep it narrows deletion to the (region, type)
	// pairs a scope proved complete.
	Partial bool

	// CompletedEnumerations lists the scopes whose enumeration this sweep can
	// PROVE was complete: every page was read and no error was swallowed, so
	// absence of a resource of one of those types from that scope is evidence
	// of deletion rather than of a listing that stopped early.
	//
	// A scope MUST be declared here only next to the error handling that makes
	// the claim true (aws.complete beside aws.skip, gcp.noteComplete beside
	// gcp.bestEffort). It is consumed by sync deletion reconciliation
	// (internal/jobs findDeletedAssets → applyDeletions, which prunes hashes,
	// records asset_deletions and resolves findings as resource-gone) and by
	// GuardDuty finding closure (reconcileGuardDutyFindings). For asset
	// deletion it only narrows what a non-partial sweep may delete and never
	// grants deletion on its own. GuardDuty closure runs on any sweep without
	// an error, partial or not, and there a completed region scope alone
	// authorizes closing that region's unreturned findings.
	CompletedEnumerations []ScopeEnumeration

	// ProvenCapabilities lists capabilities THIS sweep proved by a successful
	// privileged call — e.g. AWS Identity Center's "sso_admin", proven the
	// moment ListPermissionSets succeeds (internal/collect/aws/identitycenter.go).
	// A plain string, not internal/app/connector.ProvenCapability: the collect
	// package must stay decoupled from app domains; internal/jobs/sync.go is
	// the seam that converts between the two and persists proof into
	// connector_proven_capabilities, where it is monotonic —
	// nothing here un-proves a capability once it reaches storage.
	ProvenCapabilities []string

	// ClosedFindings are provider-native findings the provider itself reports
	// closed this sweep (a GHAS alert fixed, dismissed or resolved on GitHub).
	// Unlike absence from a listing, each one is positive evidence about one
	// finding, so it needs no completeness claim: the sync worker resolves the
	// matching stored finding with the closure's reason
	// (internal/jobs/sync_provider.go reconcileProviderClosures).
	ClosedFindings []FindingClosure
}

// FindingClosure is a provider's report that one of its findings is closed.
// ID is the finding id the open alert was recorded under; Reason maps the
// provider's state onto the resolution taxonomy; Note is the provider's own
// words for it ("dismissed on GitHub: false positive"), recorded beside the
// coarse reason so a human can see why.
type FindingClosure struct {
	ID     string
	Source string
	Reason finding.ResolutionReason
	Note   string
}

// ProvenCapabilitiesConfigKey is the cfg key internal/jobs/sync.go populates
// before calling Collector.Collect, carrying the comma-separated set of
// capabilities already proven for this connector in a PRIOR sweep (from
// connector_proven_capabilities). A collector consults it instead of
// re-deriving proof from data this sweep may not have collected, so a
// transient gap in this sweep's own evidence can't cost a connector its
// already-earned proof.
const ProvenCapabilitiesConfigKey = "proven_capabilities"

// ScopeEnumeration is one proven-complete listing: the collector read every
// page of Types within Scope and swallowed no error, and Count is what it
// found.
//
// Scope is a stable per-collector key naming the API surface the listing came
// from — "eu-west-1/ec2:instances", "global/compute.instances" — so the same
// scope means the same thing across sweeps and can be compared over time. It
// is NOT a display string: a watermark gauge is keyed on it, so renaming a
// scope silently starts a new series and loses the history that says a scope
// has not completed in weeks.
//
// Types are asset.Asset.Type values, because that is the granularity a
// deletion decision is made at. A scope that enumerates several types (one
// DescribeX call producing two asset types) lists all of them; a type
// enumerated by several scopes (EC2 instances, one scope per region) needs
// EVERY such scope complete before the type as a whole is fully enumerated.
type ScopeEnumeration struct {
	Scope string
	Types []string
	Count int
}

// GuardDutyFindingsFamily is the scope family ("<region>/guardduty:findings")
// an AWS sweep declares complete when it listed every ACTIVE GuardDuty finding
// in a region; GuardDutyFindingType is its type label. A finding listing, not
// an asset enumeration — forget never treats it as enforceable — and the sync
// worker reads it to close stored GuardDuty findings the provider no longer
// lists (internal/jobs/sync_provider.go). Exported because the collector and
// the sync worker must agree on it and neither imports the other.
const (
	GuardDutyFindingsFamily = "guardduty:findings"
	GuardDutyFindingType    = "guardduty_finding"
)

// MarkComplete records a proven-complete enumeration. It is the ONLY writer of
// Result.CompletedEnumerations — a hand-rolled append bypasses the validation
// below, and an invalid completeness claim is the single input the deletion
// reconciliation acts on to delete real inventory. Enforced by
// TestCompletedEnumerationsHaveASingleWriter.
//
// A claim with no scope, no types, or a negative count is dropped rather than
// recorded: it cannot be attributed to anything, and an unattributable claim
// must not read as coverage.
//
// CompletedEnumerations is consumed today by sync deletion reconciliation
// (internal/jobs/sync.go → findDeletedAssets/applyDeletions, which prune
// hashes, record asset_deletions and resolve findings as resource-gone) and by
// GuardDuty finding closure (sync_provider.go reconcileGuardDutyFindings).
// That path enforces only the absolute per-sweep cap (sync_deletion_scope.go
// deletionCap). The relative cap, consecutive-sweep confirmation and
// enumeration-shrink refusals live in forget.Decide but do not gate it.
func (r *Result) MarkComplete(scope string, types []string, n int) {
	if scope == "" || len(types) == 0 || n < 0 {
		return
	}
	for _, t := range types {
		if t == "" {
			return
		}
	}
	r.CompletedEnumerations = append(r.CompletedEnumerations, ScopeEnumeration{
		Scope: scope, Types: types, Count: n,
	})
}

// MarkCapabilityProven records that this sweep proved capability by a
// successful privileged call (mirrors MarkComplete's shape for
// CompletedEnumerations). It is a per-sweep claim only — internal/jobs/sync.go
// is what persists it into connector_proven_capabilities, where it becomes
// permanent (proof is monotonic). Calling this more than
// once with the same capability is harmless: the caller dedupes, and the
// persistence layer's ON CONFLICT DO NOTHING would anyway.
//
// An empty capability is dropped rather than recorded, same reasoning as
// MarkComplete's empty-scope guard: it cannot be attributed to anything.
func (r *Result) MarkCapabilityProven(capability string) {
	if capability == "" {
		return
	}
	for _, c := range r.ProvenCapabilities {
		if c == capability {
			return
		}
	}
	r.ProvenCapabilities = append(r.ProvenCapabilities, capability)
}

// Collector pulls the current inventory for one connector. cfg is the
// connector's decrypted config (provider-specific keys).
type Collector interface {
	Collect(ctx context.Context, cfg map[string]string) (Result, error)
}

// Registry maps a connector type to its collector. A type with no registered
// collector cannot sync yet — the sync job reports that explicitly rather than
// failing silently.
type Registry struct {
	byType map[connector.Type]Collector
}

func NewRegistry() *Registry {
	return &Registry{byType: map[connector.Type]Collector{}}
}

func (r *Registry) Register(t connector.Type, c Collector) {
	r.byType[t] = c
}

// For returns the collector for a connector type, or an error naming the type
// if none is registered.
func (r *Registry) For(t connector.Type) (Collector, error) {
	c, ok := r.byType[t]
	if !ok {
		return nil, fmt.Errorf("collect: no collector registered for type %q", t)
	}
	return c, nil
}
