package asset

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mergeDriftEvents is what stops the two-query (new + changed) merge in
// DriftEvents/PGDriftEvents from returning up to 2x the requested limit,
// ordered as "all new-asset events, then all changed/exposure events"
// instead of one true newest-first feed.
func TestMergeDriftEvents(t *testing.T) {
	now := time.Now()
	at := func(minutesAgo int) time.Time { return now.Add(-time.Duration(minutesAgo) * time.Minute) }

	t.Run("interleaves two kind-sorted blocks into one newest-first feed", func(t *testing.T) {
		// As returned by the two source queries today: each block newest-first
		// on its own, but concatenated rather than merged.
		events := []DriftEvent{
			{AssetID: "new-old", Kind: DriftKindNewAsset, DetectedAt: at(60)},
			{AssetID: "new-recent", Kind: DriftKindNewAsset, DetectedAt: at(5)},
			{AssetID: "changed-newest", Kind: DriftKindChanged, DetectedAt: at(1)},
			{AssetID: "changed-old", Kind: DriftKindChanged, DetectedAt: at(45)},
		}
		got := mergeDriftEvents(events, 10)
		var order []string
		for _, e := range got {
			order = append(order, e.AssetID)
		}
		require.Equal(t, []string{"changed-newest", "new-recent", "changed-old", "new-old"}, order)
	})

	t.Run("truncates to limit instead of returning up to 2x", func(t *testing.T) {
		events := []DriftEvent{
			{AssetID: "a", DetectedAt: at(3)},
			{AssetID: "b", DetectedAt: at(1)},
			{AssetID: "c", DetectedAt: at(2)},
		}
		got := mergeDriftEvents(events, 2)
		require.Len(t, got, 2)
		require.Equal(t, "b", got[0].AssetID)
		require.Equal(t, "c", got[1].AssetID)
	})

	t.Run("limit<=0 means no truncation", func(t *testing.T) {
		events := []DriftEvent{{AssetID: "a", DetectedAt: at(1)}, {AssetID: "b", DetectedAt: at(2)}}
		got := mergeDriftEvents(events, 0)
		require.Len(t, got, 2)
	})

	t.Run("empty input", func(t *testing.T) {
		require.Empty(t, mergeDriftEvents(nil, 10))
	})
}

func TestClassifyHashChange(t *testing.T) {
	for _, tc := range []struct {
		name               string
		curName, curIP     string
		prevName, prevIP   string
		wantKind           DriftKind
		wantField          string
		wantOld, wantNewer string
	}{
		{name: "rename only", curName: "b", prevName: "a", curIP: "1.1.1.1", prevIP: "1.1.1.1",
			wantKind: DriftKindChanged, wantField: "name", wantOld: "a", wantNewer: "b"},
		{name: "ip reassigned", curName: "a", prevName: "a", curIP: "2.2.2.2", prevIP: "1.1.1.1",
			wantKind: DriftKindChanged, wantField: "public_ip", wantOld: "1.1.1.1", wantNewer: "2.2.2.2"},
		{name: "gains public ip", curName: "a", prevName: "a", curIP: "1.1.1.1",
			wantKind: DriftKindNewExposure, wantField: "public_ip", wantOld: "", wantNewer: "1.1.1.1"},
		{name: "loses public ip", curName: "a", prevName: "a", prevIP: "1.1.1.1",
			wantKind: DriftKindRemovedExposure, wantField: "public_ip", wantOld: "1.1.1.1", wantNewer: ""},
		{name: "gains public ip and renamed in the same sync", curName: "b", prevName: "a", curIP: "1.1.1.1",
			wantKind: DriftKindNewExposure, wantField: "public_ip,name", wantOld: " / a", wantNewer: "1.1.1.1 / b"},
		{name: "loses public ip and renamed in the same sync", curName: "b", prevName: "a", prevIP: "1.1.1.1",
			wantKind: DriftKindRemovedExposure, wantField: "public_ip,name", wantOld: "1.1.1.1 / a", wantNewer: " / b"},
		{name: "ip reassigned and renamed", curName: "b", prevName: "a", curIP: "2.2.2.2", prevIP: "1.1.1.1",
			wantKind: DriftKindChanged, wantField: "public_ip,name", wantOld: "1.1.1.1 / a", wantNewer: "2.2.2.2 / b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := DriftEvent{AssetID: "id-1", AssetName: tc.curName, PublicIP: tc.curIP}
			classifyHashChange(&ev, tc.prevName, tc.prevIP)
			require.Equal(t, tc.wantKind, ev.Kind)
			require.Equal(t, tc.wantField, ev.Field)
			require.Equal(t, tc.wantOld, ev.OldValue)
			require.Equal(t, tc.wantNewer, ev.NewValue)
		})
	}
}

func TestWhyDriftEvent_ExposureWithRename(t *testing.T) {
	ev := DriftEvent{AssetName: "b", PublicIP: "1.1.1.1"}
	classifyHashChange(&ev, "a", "")
	why := whyDriftEvent(ev)
	require.Contains(t, why, "internet-reachable")
	require.Contains(t, why, "renamed")
}

// TestFindingsForAssetsQuery_OpenOnly pins that the drift rollup counts only
// open findings: the latest version's resolved_at must be the zero DateTime.
func TestFindingsForAssetsQuery_OpenOnly(t *testing.T) {
	require.Contains(t, findingsForAssets, "HAVING argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')")
}

// TestDriftNewAssetsQuery_FiltersOnFirstDiscoveredAt pins the exact
// fix by content: the pre-aggregation WHERE must reference first_discovered_at
// (immutable, pinned by Service.pinFirstDiscoveredAt), never the raw
// discovered_at column a collector re-stamps to `now` on every sweep — that
// exact regression previously matched every asset as "new" on any 24h
// lookback. A future edit to this
// query reverting the WHERE clause fails this test instead of silently
// reintroducing the bug.
func TestDriftNewAssetsQuery_FiltersOnFirstDiscoveredAt(t *testing.T) {
	require.Contains(t, driftNewAssets, "WHERE first_discovered_at >= now() - INTERVAL ? SECOND")
	require.NotContains(t, driftNewAssets, "WHERE discovered_at >= now() - INTERVAL ? SECOND")
	require.Contains(t, driftNewAssets, firstDiscoveredAtAgg,
		"the read side must use the same minIf-over-nonzero aggregate finding/repo.go uses for first_detected_at")
}

// A failed findings lookup must not read as "no findings": the events keep
// zero counts, but FindingsKnown stays false so the UI shows unknown.
func TestApplyDriftFindings(t *testing.T) {
	t.Run("lookup failed: findings unknown, explanation still set", func(t *testing.T) {
		got := applyDriftFindings([]DriftEvent{{Kind: DriftKindNewAsset, AssetID: "a"}}, nil, false)
		require.False(t, got[0].FindingsKnown)
		require.Zero(t, got[0].FindingsCount)
		require.NotEmpty(t, got[0].Why)
	})
	t.Run("lookup succeeded: counts known, absent asset is a real zero", func(t *testing.T) {
		rows := []driftFindingRow{{id: "a", cnt: 3, score: 80}}
		got := applyDriftFindings([]DriftEvent{{AssetID: "a"}, {AssetID: "b"}}, rows, true)
		require.True(t, got[0].FindingsKnown)
		require.Equal(t, 3, got[0].FindingsCount)
		require.Equal(t, 80, got[0].MaxScore)
		require.True(t, got[1].FindingsKnown)
		require.Zero(t, got[1].FindingsCount)
	})
}

// The Postgres-backed feed drops events whose asset is not inventory and keeps
// events with no ClickHouse context: absent context is not evidence the asset
// is dead.
func TestApplyAssetContext(t *testing.T) {
	events := []DriftEvent{{AssetID: "live"}, {AssetID: "dead-pod"}, {AssetID: "no-ctx"}}
	got := applyAssetContext(events, map[string]assetCtx{
		"live":     {inventory: 1, assetType: "ec2_instance", provider: "aws"},
		"dead-pod": {inventory: 0, assetType: "k8s_pod"},
	})
	require.Len(t, got, 2)
	require.Equal(t, "live", got[0].AssetID)
	require.Equal(t, "ec2_instance", got[0].AssetType)
	require.Equal(t, "aws", got[0].Provider)
	require.Equal(t, "no-ctx", got[1].AssetID)
	require.Empty(t, got[1].AssetType)
}

// Both ClickHouse drift readers and the Postgres feed's context fetch carry the
// inventory gate.
func TestDriftQueriesApplyInventoryGate(t *testing.T) {
	for name, q := range map[string]string{
		"driftNewAssets":    driftNewAssets,
		"driftNewExposures": driftNewExposures,
		"pgAssetContext":    pgAssetContext,
	} {
		require.Contains(t, q, inventoryReadCond, name)
	}
}

// TestDriftEvents_SinceErrorNamesAParseableExample pins that the 400 for a bad
// `since` only suggests values time.ParseDuration accepts: it used to suggest
// "7d", which is itself rejected with this same error.
func TestDriftEvents_SinceErrorNamesAParseableExample(t *testing.T) {
	h := NewDriftHandlerWithPool(nil, nil)
	rec := httptest.NewRecorder()
	h.Events(rec, httptest.NewRequest(http.MethodGet, "/api/drift/events?since=7d", nil))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "168h")
	for _, example := range []string{"24h", "168h"} {
		_, err := time.ParseDuration(example)
		require.NoError(t, err, "every suggested example must parse")
	}
}
