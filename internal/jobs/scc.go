package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SCCFetcher pulls active threat findings from GCP Security Command Center.
// *scc.Fetcher implements it; tests fake it. A nil-error Fetch is the complete
// listing: every page was read. Scope names that listing (the organization) —
// stable across fetches, and distinct for a different organization.
type SCCFetcher interface {
	Fetch(ctx context.Context) ([]finding.Finding, error)
	Scope() string
}

// sccSource and sccThreatType are what internal/intel/scc records its findings
// under.
const (
	sccSource     = "gcp_scc"
	sccThreatType = "threat"
)

// GCEInstanceLister lists gce_instance assets. asset.Service implements it.
type GCEInstanceLister interface {
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
}

// gceInstanceListLimit bounds the resolver's live listing. Well above any
// real estate, with the same margin ssoPermSetListLimit uses for its own type.
const gceInstanceListLimit = 20000

// gceIDResolver resolves an SCC finding's numeric-instance-ID resource_id
// (project/numeric_id — the shape Security Command Center's resourceName
// actually carries for a compute instance) to the asset ID our GCE collector
// builds it under (project/name). Without this join, a finding on gce_instance
// can never match its own asset: internetHops, blast-radius and every other
// reach-based lookup key on the asset ID, so must_fix_class could never
// resolve for it regardless of how exposed the real instance was.
//
// A short process-cached TTL, same shape as AssetSSOResolver
// (enrich/sources_sso.go): GCE instances number in the thousands and churn
// slowly enough that a per-finding ClickHouse round trip would be wasteful,
// but stale for more than a few minutes risks missing a freshly-created
// instance's malware finding.
type gceIDResolver struct {
	Lister GCEInstanceLister

	byNumericID map[string]string // key: "project/numericID", value: real asset ID
	loadedAt    time.Time
	now         func() time.Time
}

func newGCEIDResolver(lister GCEInstanceLister) *gceIDResolver {
	return &gceIDResolver{Lister: lister, now: time.Now}
}

// resolve returns the real gce_instance asset ID for a "project/numeric_id"
// resource_id, or ("", false) if no matching instance is currently collected —
// deliberately not a guess: a finding that fails to resolve keeps its original
// (unjoinable) resource_id rather than being pointed at the wrong instance.
func (r *gceIDResolver) resolve(ctx context.Context, resourceID string) (string, bool) {
	const ttl = 10 * time.Minute
	if r.byNumericID == nil || r.now().Sub(r.loadedAt) > ttl {
		instances, err := r.Lister.ListByType(ctx, "gce_instance", gceInstanceListLimit)
		if err != nil {
			// Keep any prior cache on a transient error; if none, report unresolved
			// rather than block the whole SCC sweep on one failed lookup.
			if r.byNumericID == nil {
				return "", false
			}
		} else {
			m := make(map[string]string, len(instances))
			for _, a := range instances {
				project, _, ok := strings.Cut(a.ID, "/")
				if !ok {
					continue
				}
				if numID := a.Metadata["gcp_instance_id"]; numID != "" {
					m[project+"/"+numID] = a.ID
				}
			}
			r.byNumericID = m
			r.loadedAt = r.now()
		}
	}
	realID, ok := r.byNumericID[resourceID]
	return realID, ok
}

// RefreshSCCArgs pulls the org's active SCC THREAT findings and records them.
type RefreshSCCArgs struct{}

func (RefreshSCCArgs) Kind() string { return "refresh_scc" }

// InsertOpts: singleton with 3 attempts (periodicSingletonOpts).
func (RefreshSCCArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, 3)
}

// SCCWorker fetches SCC threat findings and records them — a provider-native
// findings feed (like KEV/OSV), since SCC is org-scoped rather than per-asset.
type SCCWorker struct {
	river.WorkerDefaults[RefreshSCCArgs]
	fetcher  SCCFetcher
	findings FindingStore
	// gceResolver rewrites a gce_instance finding's numeric-ID resource_id to
	// the real asset ID before it is ever persisted, so every downstream
	// resource-ID lookup (reach, blast radius, enrich) just works — nil disables
	// resolution (existing tests construct SCCWorker directly without it).
	gceResolver *gceIDResolver
	// closer resolves the stored threat findings a complete fetch no longer
	// lists (closeUnlistedFindings); nil disables it.
	closer providerFindingReconciler
}

// Timeout overrides River's default 1-minute timeout. SCC org-scoped fetches
// can pull thousands of findings across many pages; 5 minutes gives ample headroom.
func (SCCWorker) Timeout(_ *river.Job[RefreshSCCArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *SCCWorker) Work(ctx context.Context, _ *river.Job[RefreshSCCArgs]) error {
	found, err := w.fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("Work: fetch scc: %w", err)
	}
	unresolved := 0
	if w.gceResolver != nil {
		for i := range found {
			if found[i].ResourceType != "gce_instance" {
				continue
			}
			if realID, ok := w.gceResolver.resolve(ctx, found[i].ResourceID); ok {
				found[i].ResourceID = realID
			} else {
				unresolved++
			}
		}
	}
	if unresolved > 0 {
		log.FromContext(ctx).Warn().Int("unresolved", unresolved).
			Msg("scc: some gce_instance findings could not be matched to a collected instance; resource_id left as SCC's numeric ID")
	}
	// The fetch is SCC's whole ACTIVE THREAT listing for the organization, so
	// a stored finding it no longer returns went inactive in SCC (or stopped
	// being a threat): it is closed as provider_closed below, only after this
	// fetch's findings are stored open, and only for findings this listing
	// produced (their provenance is the fetcher's scope).
	scope := w.fetcher.Scope()
	stampFindingProvenance(found, scope)
	if len(found) > 0 {
		if err := w.findings.RecordObserved(ctx, found); err != nil {
			return fmt.Errorf("Work: record scc findings: %w", err)
		}
		enqueueEnrich(ctx, found)
	}
	if w.closer != nil {
		closeUnlistedFindings(ctx, w.closer, unlistedFeed{
			name: "scc", source: sccSource, typ: sccThreatType, provenance: scope,
			inScope: func(string) bool { return true },
		}, found)
	}
	log.FromContext(ctx).Info().Int("findings", len(found)).Msg("scc threat findings refreshed")
	return nil
}
