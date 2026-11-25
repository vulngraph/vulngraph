package pkginv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

func goodSubmission(t *testing.T) Submission {
	t.Helper()
	s, err := Validate(goodRequest(), clock)
	require.NoError(t, err)
	return s
}

func TestEvaluate_KnownOnlyWhenEverythingHolds(t *testing.T) {
	on := distro.Sources{distro.SourceOSV: true}
	v := Evaluate(goodSubmission(t), clock, on)
	require.True(t, v.InventoryKnown)
	require.True(t, v.CVEMatchableKnown)
	require.Empty(t, v.Gap)
	require.Equal(t, "Ubuntu:22.04:LTS", v.Ecosystem)
	require.Len(t, v.Packages, 2)

	t.Run("freshness boundary", func(t *testing.T) {
		s := goodSubmission(t)
		s.ObservedAt = clock.Add(-FreshFor)
		require.True(t, Evaluate(s, clock, on).InventoryKnown, "exactly 7 days is still fresh")
		s.ObservedAt = clock.Add(-FreshFor - time.Second)
		v := Evaluate(s, clock, on)
		require.False(t, v.InventoryKnown)
		require.Equal(t, GapStale, v.Gap)
	})
	t.Run("incomplete is checked before anything else", func(t *testing.T) {
		s := goodSubmission(t)
		s.Complete = false
		s.ObservedAt = clock.Add(-30 * 24 * time.Hour)
		require.Equal(t, GapIncomplete, Evaluate(s, clock, on).Gap)
	})
	t.Run("an empty complete list is not clean on an unmatchable os", func(t *testing.T) {
		s := goodSubmission(t)
		s.Packages = nil
		s.OS = OS{ID: "plan9"}
		v := Evaluate(s, clock, on)
		require.False(t, v.InventoryKnown)
		require.Equal(t, asset.CVEGapUnknownRelease, v.Gap)
	})
	t.Run("rpm epoch and release build the EVR", func(t *testing.T) {
		s := Submission{OS: OS{ID: "rhel", VersionID: "9.3"}, Complete: true, ObservedAt: clock,
			Packages: []Package{{Name: "openssl", Version: "3.0.7", Release: "24.el9", Epoch: "1", SourceName: "openssl"}}}
		v := Evaluate(s, clock, distro.Sources{distro.SourceOSV: true})
		require.Len(t, v.Packages, 1)
		require.Equal(t, "1:3.0.7-24.el9", v.Packages[0].Version)
		require.Equal(t, "Red Hat:9", v.Packages[0].Ecosystem)
	})
}

func TestStamp(t *testing.T) {
	known := InventoryRecord{
		Scanner: Scanner{Name: "acme-agent", Version: "1.4.2"}, Ecosystem: "Ubuntu:22.04:LTS",
		ObservedAt: clock, InventoryKnown: true, CVEMatchableKnown: true,
	}
	meta := map[string]string{}
	known.Stamp(meta)
	require.Equal(t, map[string]string{
		"package_inventory":                 "byoa",
		"package_inventory_observed_on":     "2026-11-25",
		"package_ecosystem":                 "Ubuntu:22.04:LTS",
		"package_cve_matchable":             "true",
		"package_inventory_scanner":         "acme-agent",
		"package_inventory_scanner_version": "1.4.2",
	}, meta)

	gap := InventoryRecord{Scanner: Scanner{Name: "acme-agent", Version: "1.4.2"}, Ecosystem: "Ubuntu:22.04:LTS", Gap: GapIncomplete}
	meta = map[string]string{}
	gap.Stamp(meta)
	require.Equal(t, "none", meta["package_inventory"])
	require.Equal(t, GapIncomplete, meta["package_inventory_gap"])
	require.NotContains(t, meta, "package_ecosystem", "a gap must not carry an ecosystem that reads as coverage")
	require.NotContains(t, meta, "package_cve_matchable")

	require.NotPanics(t, func() { known.Stamp(nil) })
}

func TestFreshest(t *testing.T) {
	_, ok := Freshest(nil)
	require.False(t, ok)
	old := InventoryRecord{Source: "a", ObservedAt: clock.Add(-2 * time.Hour), InventoryKnown: true}
	newer := InventoryRecord{Source: "b", ObservedAt: clock.Add(-time.Hour), InventoryKnown: true}
	gap := InventoryRecord{Source: "c", ObservedAt: clock}
	got, _ := Freshest([]InventoryRecord{old, gap, newer})
	require.Equal(t, "b", got.Source)
	got, _ = Freshest([]InventoryRecord{gap, {Source: "d", ObservedAt: clock}})
	require.Equal(t, "c", got.Source, "ties break on source")
}

func TestPrincipalMaySubmit(t *testing.T) {
	require.True(t, Principal{KeyID: "k", Scope: "inventory", OwnerRole: "admin"}.MaySubmit())
	for _, p := range []Principal{
		{}, {KeyID: "k", Scope: "inventory", OwnerRole: "viewer"}, {KeyID: "k", Scope: "write", OwnerRole: "admin"},
		{Scope: "inventory", OwnerRole: "admin"},
	} {
		require.False(t, p.MaySubmit(), "%+v", p)
	}
}
