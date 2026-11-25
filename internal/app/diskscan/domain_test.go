package diskscan

import (
	"testing"

	"github.com/stretchr/testify/assert"

	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

func TestZeroValuesAreSafe(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"mode is off", DiskScanMode(""), DiskScanModeOff},
		{"mode off not enabled", DiskScanMode("").Enabled(), false},
		{"mode off valid", DiskScanMode("").Valid(), true},
		{"unknown mode invalid", DiskScanMode("bogus").Valid(), false},
		{"inventory unknown", VolumeResult{}.InventoryKnown, false},
		{"cve matchable unknown", VolumeResult{}.CVEMatchableKnown, false},
		{"source none", VolumeResult{}.SnapshotSource, SourceNone},
		{"encrypted false", VolumeResult{}.Encrypted, false},
		{"run status empty", DiskScanRun{}.Status, RunStatus("")},
		{"existing snapshots enabled", DiskScanModeExistingSnapshots.Enabled(), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, tc.got) })
	}
}

func TestValuesMatchEngine(t *testing.T) {
	pairs := [][2]string{
		{GapNotEnabled, engine.GapNotEnabled},
		{GapNoSnapshotAvailable, engine.GapNoSnapshotAvailable},
		{GapSnapshotPending, engine.GapSnapshotPending},
		{GapEncryptedNoKey, engine.GapEncryptedNoKey},
		{GapUnsupportedFS, engine.GapUnsupportedFS},
		{GapUnsupportedPartition, engine.GapUnsupportedPartition},
		{GapReadError, engine.GapReadError},
		{GapOverCap, engine.GapOverCap},
		{GapPermissionDenied, engine.GapPermissionDenied},
		{GapStale, engine.GapStale},
		{string(DiskScanModeCreateSnapshots), engine.ModeCreateSnapshots},
	}
	for _, p := range pairs {
		assert.Equal(t, p[1], p[0])
	}
}
