package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeSCCFetcher struct {
	found []finding.Finding
	err   error
}

func (f fakeSCCFetcher) Fetch(context.Context) ([]finding.Finding, error) {
	return f.found, f.err
}

func (fakeSCCFetcher) Scope() string { return "gcp_scc:organizations/1" }

type fakeGCEInstanceLister struct {
	instances []asset.Asset
	err       error
}

func (f fakeGCEInstanceLister) ListByType(context.Context, string, int) ([]asset.Asset, error) {
	return f.instances, f.err
}

func gceAsset(project, name, numericID string) asset.Asset {
	return asset.Asset{
		ID: project + "/" + name, Type: "gce_instance",
		Metadata: map[string]string{"gcp_instance_id": numericID},
	}
}

// The core case: SCC's resourceName carries the compute instance's NUMERIC id,
// while our asset ID is built from its NAME. Without the resolver bridging the
// two, a "Malware: Malicious file on disk (YARA)" finding is unresolvable to any
// asset, so must_fix_class could never resolve regardless of how exposed the
// real instance was.
func TestSCCWorker_ResolvesGCEInstanceNumericID(t *testing.T) {
	lister := fakeGCEInstanceLister{instances: []asset.Asset{
		gceAsset("proj-1", "db-example-1", "5001234567890123456"),
	}}
	fetcher := fakeSCCFetcher{found: []finding.Finding{
		{ID: "f1", Source: "gcp_scc", ResourceType: "gce_instance", ResourceID: "proj-1/5001234567890123456"},
	}}
	store := &fakeFindingStore{}
	w := &SCCWorker{fetcher: fetcher, findings: store, gceResolver: newGCEIDResolver(lister)}

	require.NoError(t, w.Work(context.Background(), nil))
	require.Len(t, store.recorded, 1)
	require.Equal(t, "proj-1/db-example-1", store.recorded[0].ResourceID,
		"the finding must be rewritten to the REAL asset ID before it is ever persisted")
}

// A numeric ID with no matching collected instance must NOT be guessed at —
// the finding is still recorded (never dropped), with its original,
// unjoinable resource_id left as-is.
func TestSCCWorker_UnresolvedInstanceKeepsOriginalResourceID(t *testing.T) {
	lister := fakeGCEInstanceLister{instances: []asset.Asset{
		gceAsset("proj-1", "db-example-1", "111"),
	}}
	fetcher := fakeSCCFetcher{found: []finding.Finding{
		{ID: "f1", Source: "gcp_scc", ResourceType: "gce_instance", ResourceID: "proj-1/999-not-collected"},
	}}
	store := &fakeFindingStore{}
	w := &SCCWorker{fetcher: fetcher, findings: store, gceResolver: newGCEIDResolver(lister)}

	require.NoError(t, w.Work(context.Background(), nil))
	require.Len(t, store.recorded, 1)
	require.Equal(t, "proj-1/999-not-collected", store.recorded[0].ResourceID)
}

// Findings on other resource types must not be touched by the resolver at all.
func TestSCCWorker_NonGCEInstanceFindingsUntouched(t *testing.T) {
	lister := fakeGCEInstanceLister{}
	fetcher := fakeSCCFetcher{found: []finding.Finding{
		{ID: "f1", Source: "gcp_scc", ResourceType: "gcs_bucket", ResourceID: "proj-1/my-bucket"},
	}}
	store := &fakeFindingStore{}
	w := &SCCWorker{fetcher: fetcher, findings: store, gceResolver: newGCEIDResolver(lister)}

	require.NoError(t, w.Work(context.Background(), nil))
	require.Equal(t, "proj-1/my-bucket", store.recorded[0].ResourceID)
}

// A nil resolver (the shape every pre-existing test in this file used) must
// leave Work fully functional — resolution is an enhancement, not a
// precondition for the SCC feed to work at all.
func TestSCCWorker_NilResolverSkipsResolution(t *testing.T) {
	fetcher := fakeSCCFetcher{found: []finding.Finding{
		{ID: "f1", Source: "gcp_scc", ResourceType: "gce_instance", ResourceID: "proj-1/123"},
	}}
	store := &fakeFindingStore{}
	w := &SCCWorker{fetcher: fetcher, findings: store}

	require.NoError(t, w.Work(context.Background(), nil))
	require.Equal(t, "proj-1/123", store.recorded[0].ResourceID)
}

// The resolver's cache must key on the exact "project/numericID" join, not
// silently match across projects that happen to reuse the same numeric ID.
func TestGCEIDResolver_ScopedToProject(t *testing.T) {
	lister := fakeGCEInstanceLister{instances: []asset.Asset{
		gceAsset("proj-a", "instance-a", "42"),
		gceAsset("proj-b", "instance-b", "42"),
	}}
	r := newGCEIDResolver(lister)

	got, ok := r.resolve(context.Background(), "proj-a/42")
	require.True(t, ok)
	require.Equal(t, "proj-a/instance-a", got)

	got, ok = r.resolve(context.Background(), "proj-b/42")
	require.True(t, ok)
	require.Equal(t, "proj-b/instance-b", got)
}

// A Lister error with no prior cache must report unresolved rather than
// panic or fabricate a match.
func TestGCEIDResolver_ListerErrorWithNoCacheIsUnresolved(t *testing.T) {
	r := newGCEIDResolver(fakeGCEInstanceLister{err: context.DeadlineExceeded})
	_, ok := r.resolve(context.Background(), "proj-1/123")
	require.False(t, ok)
}

// SCC's fetch is the organization's whole ACTIVE THREAT listing, so a stored
// threat it no longer returns went inactive in SCC: it is closed as
// provider_closed. Only findings this organization's listing produced are
// candidates, and a fetch error closes nothing.
func TestSCCWorker_ClosesFindingsTheListingNoLongerReturns(t *testing.T) {
	const scope = "gcp_scc:organizations/1"
	stored := func(id, provenance string) finding.Finding {
		return finding.Finding{ID: id, Source: "gcp_scc", Type: "threat",
			Metadata: map[string]string{finding.ProvenanceConnectorKey: provenance}}
	}
	closer := &fakeProviderReconciler{stored: []finding.Finding{
		stored("still-active", scope),
		stored("went-inactive", scope),
		stored("other-org", "gcp_scc:organizations/2"),
	}}
	fetcher := fakeSCCFetcher{found: []finding.Finding{{ID: "still-active", Source: "gcp_scc", Type: "threat"}}}
	store := &fakeFindingStore{}
	w := &SCCWorker{fetcher: fetcher, findings: store, closer: closer}

	require.NoError(t, w.Work(context.Background(), nil))
	require.Equal(t, scope, store.recorded[0].Metadata[finding.ProvenanceConnectorKey],
		"recorded findings carry the listing's scope, or no later fetch could close them")
	require.Equal(t, []string{"went-inactive"}, resolvedIDs(closer.resolved))
	require.Equal(t, []finding.ResolutionReason{finding.ReasonProviderClosed}, closer.reasons)

	failing := &fakeProviderReconciler{stored: []finding.Finding{stored("went-inactive", scope)}}
	w = &SCCWorker{fetcher: fakeSCCFetcher{err: errors.New("permission denied")}, findings: &fakeFindingStore{}, closer: failing}
	require.Error(t, w.Work(context.Background(), nil))
	require.Empty(t, failing.resolved, "a failed fetch is not an empty listing")
}
