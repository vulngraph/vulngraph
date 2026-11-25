// Package jobs — the lifecycle edge for provider-native findings.
//
// A provider-native feed computes its findings itself, so no check of ours can
// re-run and fall silent. Two kinds of evidence close one: the provider saying
// so (GHAS reports an alert fixed, dismissed or resolved —
// reconcileProviderClosures), or the provider no longer listing it, which counts
// only where the listing is proven complete (GuardDuty,
// collect.Result.MarkComplete — reconcileGuardDutyFindings), and only for the
// findings that listing could have returned. SCC's org-wide feed closes its own
// the second way in SCCWorker (scc.go).
package jobs

import (
	"context"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// guardDutySource is the finding source the AWS collector records GuardDuty
// findings under.
const guardDutySource = "aws_guardduty"

// guardDutyThreatType is the type of a finding mapped from the GuardDuty
// listing itself. The collector also emits "coverage" findings under the same
// source (an EKS cluster GuardDuty names but inventory lacks); those are derived
// from the EKS listing as well, so a complete GuardDuty listing alone cannot
// prove one gone and they are never closed here.
const guardDutyThreatType = "threat"

// providerFindingReconciler is the slice of finding.Service the provider-native
// reconcile needs.
type providerFindingReconciler interface {
	OpenKeysByConnector(ctx context.Context, source, connectorID string) ([]finding.OpenKey, error)
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	Resolve(ctx context.Context, findings []finding.Finding, reason finding.ResolutionReason) error
}

// stampFindingProvenance tags every provider-native finding with the listing
// that emitted it (a connector id, or a connector-less feed's scope such as
// SCC's) — the findings counterpart of stampProvenance. Findings carry no
// account or connector column, and the reconcile below may only judge a finding
// against the listing that produced it.
func stampFindingProvenance(findings []finding.Finding, connectorID string) {
	for i := range findings {
		if findings[i].Metadata == nil {
			findings[i].Metadata = map[string]string{}
		}
		findings[i].Metadata[finding.ProvenanceConnectorKey] = connectorID
	}
}

// completedGuardDutyRegions returns the regions whose GuardDuty listing this
// sweep proved complete.
func completedGuardDutyRegions(completed []collect.ScopeEnumeration) map[string]bool {
	out := map[string]bool{}
	for _, se := range completed {
		region, family, ok := strings.Cut(se.Scope, "/")
		if ok && region != "" && family == collect.GuardDutyFindingsFamily {
			out[region] = true
		}
	}
	return out
}

// reconcileGuardDutyFindings closes stored GuardDuty threat findings that a
// complete listing stopped returning — archived by an operator, matched by a
// suppression rule, or aged out of the listing window. Only open findings this
// connector last emitted, in a region whose listing was proven complete this
// sweep, and whose id this sweep did not emit in ANY region: the collector's id
// is per (resource, type) without the region, so one id can be live in a region
// other than the one its stored row names.
//
// Resolved as ReasonProviderClosed, never ReasonFixed: GuardDuty dropping a
// finding says nobody needs to look at it any more, not that the threat was
// remediated.
//
// Best-effort like every lifecycle edge: any read or write error resolves
// nothing this sweep and the next sweep retries.
func reconcileGuardDutyFindings(ctx context.Context, svc providerFindingReconciler, connectorID string, completed []collect.ScopeEnumeration, emitted []finding.Finding) {
	regions := completedGuardDutyRegions(completed)
	if len(regions) == 0 {
		return
	}
	closeUnlistedFindings(ctx, svc, unlistedFeed{
		name: "guardduty", source: guardDutySource, typ: guardDutyThreatType, provenance: connectorID,
		inScope: func(region string) bool { return regions[region] },
	}, emitted)
}

// unlistedFeed names one provider listing proven complete: the open findings
// of source and typ last emitted under provenance (finding.ProvenanceConnectorKey),
// in a region inScope accepts, are exactly what it could have returned.
type unlistedFeed struct {
	name       string // for logs
	source     string
	typ        string
	provenance string
	inScope    func(region string) bool
}

// closeUnlistedFindings resolves, as ReasonProviderClosed, every stored open
// finding of feed that its complete listing did not return (emitted). The
// listing is matched by id alone: a provider id can be live in a region other
// than the one its stored row names. Any read or write error resolves nothing.
func closeUnlistedFindings(ctx context.Context, svc providerFindingReconciler, feed unlistedFeed, emitted []finding.Finding) {
	if feed.provenance == "" {
		return
	}
	logger := log.FromContext(ctx).With().Str("feed", feed.name).Str("provenance", feed.provenance).Logger()
	emittedIDs := make(map[string]bool, len(emitted))
	for _, f := range emitted {
		emittedIDs[f.ID] = true
	}

	keys, err := svc.OpenKeysByConnector(ctx, feed.source, feed.provenance)
	if err != nil {
		logger.Warn().Err(err).Msg("provider reconcile read failed (nothing resolved)")
		return
	}
	var ids []string
	for _, k := range keys {
		if feed.inScope(k.Region) && k.Type == feed.typ && !emittedIDs[k.ID] {
			ids = append(ids, k.ID)
		}
	}

	var toResolve []finding.Finding
	for start := 0; start < len(ids); start += reconcileBatch {
		end := min(start+reconcileBatch, len(ids))
		stored, err := svc.ByIDs(ctx, ids[start:end])
		if err != nil {
			logger.Warn().Err(err).Msg("provider reconcile hydrate failed (nothing resolved)")
			return
		}
		// Re-checked on the hydrated row: a concurrent write between the key read
		// and this one (another sweep re-observing it) must win over a stale key.
		for _, f := range stored {
			if f.Source == feed.source && f.Type == feed.typ && !f.Resolved() &&
				feed.inScope(f.Region) && f.Metadata[finding.ProvenanceConnectorKey] == feed.provenance {
				toResolve = append(toResolve, f)
			}
		}
	}
	if len(toResolve) == 0 {
		return
	}
	if err := svc.Resolve(ctx, toResolve, finding.ReasonProviderClosed); err != nil {
		logger.Warn().Err(err).Int("findings", len(toResolve)).Msg("provider reconcile resolve failed")
		return
	}
	logger.Info().Int("findings", len(toResolve)).
		Msg("provider findings resolved (no longer listed as active by their provider)")
}

// reconcileProviderClosures resolves the stored findings a provider itself
// reported closed this sweep (collect.Result.ClosedFindings: a GHAS alert fixed,
// dismissed or resolved on GitHub), each with the reason the provider's state
// maps to and the provider's own words as resolved_reason. A closure is positive
// evidence about one alert, so unlike reconcileGuardDutyFindings it needs no
// completeness claim — but it closes only an open finding of the closure's
// source that this connector last emitted, and never one this sweep's open
// listing returned (the alert was reopened between the two listings).
//
// Best-effort like every lifecycle edge: a read or write error resolves nothing
// for that batch, and the next sweep reads the closure again (the collector
// re-reads closures inside its lookback window).
func reconcileProviderClosures(ctx context.Context, svc providerFindingReconciler, connectorID string, closures []collect.FindingClosure, emitted []finding.Finding) {
	if len(closures) == 0 || connectorID == "" {
		return
	}
	logger := log.FromContext(ctx)
	emittedIDs := make(map[string]bool, len(emitted))
	for _, f := range emitted {
		emittedIDs[f.ID] = true
	}
	byID := make(map[string]collect.FindingClosure, len(closures))
	var ids []string
	for _, c := range closures {
		if c.ID == "" || !c.Reason.Valid() || emittedIDs[c.ID] {
			continue
		}
		if _, dup := byID[c.ID]; !dup {
			ids = append(ids, c.ID)
			byID[c.ID] = c
		}
	}

	toResolve := map[finding.ResolutionReason][]finding.Finding{}
	for start := 0; start < len(ids); start += reconcileBatch {
		end := min(start+reconcileBatch, len(ids))
		stored, err := svc.ByIDs(ctx, ids[start:end])
		if err != nil {
			logger.Warn().Err(err).Str("connector_id", connectorID).
				Msg("sync: provider closure hydrate failed (batch not resolved)")
			continue
		}
		for _, f := range stored {
			c := byID[f.ID]
			if f.Source != c.Source || f.Resolved() || f.Metadata[finding.ProvenanceConnectorKey] != connectorID {
				continue
			}
			if f.Metadata == nil {
				f.Metadata = map[string]string{}
			}
			f.Metadata["resolved_reason"] = c.Note
			f.Metadata["resolved_by"] = c.Source
			toResolve[c.Reason] = append(toResolve[c.Reason], f)
		}
	}
	for reason, fs := range toResolve {
		if err := svc.Resolve(ctx, fs, reason); err != nil {
			logger.Warn().Err(err).Str("connector_id", connectorID).Str("reason", string(reason)).
				Int("findings", len(fs)).Msg("sync: provider closure resolve failed")
			continue
		}
		logger.Info().Str("connector_id", connectorID).Str("reason", string(reason)).Int("findings", len(fs)).
			Msg("sync: findings resolved (closed by their provider)")
	}
}
