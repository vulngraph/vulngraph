package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The stored sync_fingerprint carries the check-registry identity per
// connector: a check deployment must force one full-asset backfill sweep on
// EVERY connector, not just the first one a worker process happens to sync
// (an in-memory check count would backfill only the first connector). It also
// carries the day the time-dependent checks last ran on every asset.
func TestSyncFingerprint_CombineSplit(t *testing.T) {
	tests := []struct {
		name         string
		fp           syncFingerprint
		wantCombined string
	}{
		{"normal", syncFingerprint{"abc123", "ck9", "2026-10-09"}, "abc123|checks:ck9|day:2026-10-09"},
		{"empty asset FP never short-circuits", syncFingerprint{"", "ck9", "2026-10-09"}, ""},
		{"empty checks FP still tagged", syncFingerprint{"abc123", "", ""}, "abc123|checks:|day:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			combined := combineSyncFingerprint(tt.fp)
			require.Equal(t, tt.wantCombined, combined)
			if combined == "" {
				return
			}
			require.Equal(t, tt.fp, splitSyncFingerprint(combined))
		})
	}
}

// A fingerprint stored before the checks suffix existed must split with an
// empty checks part, which mismatches any live registry fingerprint — forcing
// exactly one backfill sweep per connector after deploy.
func TestSyncFingerprint_LegacyValueForcesBackfill(t *testing.T) {
	fp := splitSyncFingerprint("legacy-asset-fp-no-suffix")
	require.Equal(t, "legacy-asset-fp-no-suffix", fp.assetFP)
	require.Empty(t, fp.checksFP)
	require.Empty(t, fp.day)
}

// A fingerprint stored before the day suffix keeps its asset and checks parts
// (no spurious full backfill) and reads as "re-check due".
func TestSyncFingerprint_PreDayValueMakesRecheckDue(t *testing.T) {
	fp := splitSyncFingerprint("abc123|checks:ck9")
	require.Equal(t, syncFingerprint{assetFP: "abc123", checksFP: "ck9"}, fp)
	require.NotEqual(t, clockDay(time.Now()), fp.day)
}

func TestClockDay_IsUTC(t *testing.T) {
	late := time.Date(2026, 10, 9, 23, 30, 0, 0, time.FixedZone("x", -5*3600))
	require.Equal(t, "2026-10-10", clockDay(late))
}
