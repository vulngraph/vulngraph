package jobs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestDriftTriggerAssets_OnlyExternalChangedAssets pins the filter: an asset
// must be BOTH in changedAssetIDs and externally reachable (public IP or
// domain) to be a drift-scan candidate.
func TestDriftTriggerAssets_OnlyExternalChangedAssets(t *testing.T) {
	changed := map[string]bool{"ext-changed": true, "internal-changed": true}
	toIngest := []asset.Asset{
		{ID: "ext-changed", PublicIP: "1.2.3.4"},
		{ID: "internal-changed"},                       // changed, but not externally reachable
		{ID: "ext-unchanged", Domain: "x.example.com"}, // externally reachable, but not changed
	}

	got := driftTriggerAssets(toIngest, changed)
	require.Equal(t, []string{"ext-changed"}, got)
}

// TestDriftTriggerAssets_DedupesRepeatedAssetIDs is the regression test for a
// batch-rejection bug: EnqueueDriftScans' InsertMany builds one row per
// (asset, profile) via a single INSERT ... ON CONFLICT DO UPDATE statement,
// and Postgres rejects that statement outright if it would touch the same
// conflict target twice ("ON CONFLICT DO UPDATE command cannot affect row a
// second time") — so a duplicate asset ID reaching EnqueueDriftScans fails
// the WHOLE batch, silently losing every drift trigger for the sweep, not
// just the duplicate one. toIngest has no ID-dedup guarantee upstream.
func TestDriftTriggerAssets_DedupesRepeatedAssetIDs(t *testing.T) {
	changed := map[string]bool{"ext-1": true}
	toIngest := []asset.Asset{
		{ID: "ext-1", PublicIP: "1.2.3.4"},
		{ID: "ext-1", PublicIP: "1.2.3.4"}, // same asset appended twice
	}

	got := driftTriggerAssets(toIngest, changed)
	require.Equal(t, []string{"ext-1"}, got, "a repeated asset ID must appear at most once")
}

// TestDriftTriggerAssets_UnaffectedByPartialCorrelateSizeCap guards against
// coupling drift scanning to the partial-correlate size cap: the
// drift-scan trigger used to live INSIDE the `len(changedAssetIDs) <=
// maxPartialCorrelateIDs` block, so the exact sync that changes so many
// assets it falls back to a full correlate sweep also silently skipped drift
// scanning for those same assets. driftTriggerAssets takes no size cap at
// all, which is the fix — this test proves it by exceeding the cap.
func TestDriftTriggerAssets_UnaffectedByPartialCorrelateSizeCap(t *testing.T) {
	n := maxPartialCorrelateIDs + 1
	changed := make(map[string]bool, n)
	toIngest := make([]asset.Asset, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ext-%d", i)
		changed[id] = true
		toIngest = append(toIngest, asset.Asset{ID: id, PublicIP: "10.0.0.1"})
	}

	got := driftTriggerAssets(toIngest, changed)
	require.Len(t, got, n, "every changed external asset must be a drift candidate regardless of maxPartialCorrelateIDs")
}
