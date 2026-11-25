package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeAssetExposer records the limit invalidateExposedFindings asked for, so a
// regression that silently reintroduces a caller-side hardcoded limit (the
// exact bug fixed previously — asset.Service.ListExternalIDs used to hardcode
// a smaller limit, overriding this package's own maxExposedAssets before it ever saw
// a count to compare against) fails loudly instead of by coincidence.
type fakeAssetExposer struct {
	gotLimit int
	ids      []string
	err      error
}

func (f *fakeAssetExposer) ListExternalIDs(_ context.Context, limit int) ([]string, error) {
	f.gotLimit = limit
	if f.err != nil {
		return nil, f.err
	}
	if limit < len(f.ids) {
		return f.ids[:limit], nil
	}
	return f.ids, nil
}

type fakeFindingsByResource struct {
	byResource map[string][]finding.Finding
}

func (f *fakeFindingsByResource) ByResourceIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, id := range ids {
		out = append(out, f.byResource[id]...)
	}
	return out, nil
}

type fakeEnrichCacheInvalidator struct {
	invalidatedIDs []string
}

func (f *fakeEnrichCacheInvalidator) InvalidateFingerprints(_ context.Context, findingIDs []string) error {
	f.invalidatedIDs = append(f.invalidatedIDs, findingIDs...)
	return nil
}

// The regression this pins: ListExternalIDs must be asked for maxExposedAssets,
// not some smaller value baked into the asset-side implementation.
// Before the fix, asset.Service.ListExternalIDs hardcoded a much smaller limit
// and took no parameter at all, so this package's own
// len(assetIDs) > maxExposedAssets cap could never fire — a documented, larger
// cap silently governed by an unrelated hardcoded limit several times smaller
// (maxExposedAssets was itself then corrected down to match CHRepo.ListExternal's own
// defaultExternalLimit ceiling, see asset.clampExternalLimit).
func TestInvalidateExposedFindings_RequestsTheDocumentedCap(t *testing.T) {
	assets := &fakeAssetExposer{ids: []string{"a-1", "a-2"}}
	findings := &fakeFindingsByResource{byResource: map[string][]finding.Finding{
		"a-1": {{ID: "f-1", ResourceID: "a-1"}},
	}}
	cache := &fakeEnrichCacheInvalidator{}

	invalidateExposedFindings(context.Background(), assets, findings, cache)

	require.Equal(t, maxExposedAssets, assets.gotLimit,
		"invalidateExposedFindings must pass its own cap to ListExternalIDs, not rely on the callee's own limit")
	require.Equal(t, []string{"f-1"}, cache.invalidatedIDs)
}

// A resolved finding on an exposed asset is never invalidated or re-enqueued:
// re-enriching it every sweep is what re-sent "New finding" for fixed CVEs.
func TestInvalidateExposedFindings_SkipsResolved(t *testing.T) {
	assets := &fakeAssetExposer{ids: []string{"a-1"}}
	findings := &fakeFindingsByResource{byResource: map[string][]finding.Finding{
		"a-1": {
			{ID: "open", ResourceID: "a-1"},
			{ID: "fixed", ResourceID: "a-1", ResolvedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
		},
	}}
	cache := &fakeEnrichCacheInvalidator{}

	invalidateExposedFindings(context.Background(), assets, findings, cache)

	require.Equal(t, []string{"open"}, cache.invalidatedIDs)
}

func TestInvalidateExposedFindings_NoExposedAssets(t *testing.T) {
	assets := &fakeAssetExposer{}
	findings := &fakeFindingsByResource{byResource: map[string][]finding.Finding{}}
	cache := &fakeEnrichCacheInvalidator{}

	invalidateExposedFindings(context.Background(), assets, findings, cache)

	require.Empty(t, cache.invalidatedIDs)
}

// Batches larger than batchSize (500) are processed in more than one
// ByResourceIDs/InvalidateFingerprints round, so a slow ClickHouse query on one
// batch can't force loading every affected finding in memory at once.
func TestInvalidateExposedFindings_BatchesLargeAssetLists(t *testing.T) {
	ids := make([]string, 0, 750)
	byResource := map[string][]finding.Finding{}
	for i := 0; i < 750; i++ {
		id := "a-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		ids = append(ids, id)
		byResource[id] = []finding.Finding{{ID: id + "-f", ResourceID: id}}
	}
	assets := &fakeAssetExposer{ids: ids}
	findings := &fakeFindingsByResource{byResource: byResource}
	cache := &fakeEnrichCacheInvalidator{}

	invalidateExposedFindings(context.Background(), assets, findings, cache)

	require.Len(t, cache.invalidatedIDs, 750, "every asset's finding must still be reached across batches")
}
