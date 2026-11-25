// Package diskscan orchestrates agentless VM disk scanning: it records which
// volumes were read, how, and why a volume has no package inventory. domain.go
// is pure: no infrastructure imports. Gap and mode values repeat those in
// internal/scanner/diskscan and a test pins that they match.
package diskscan

import (
	"errors"
	"time"
)

var (
	ErrNotFound   = errors.New("diskscan: not found")
	ErrNotEnabled = errors.New("diskscan: not enabled for connector")
	ErrInvalid    = errors.New("diskscan: invalid input")

	// The sentinels below are what a connector adapter reports for an opt-in
	// change it refuses; the handler maps them to statuses.
	ErrForbidden    = errors.New("diskscan: only an admin signed in as a person may change disk scanning")
	ErrConfirmation = errors.New("diskscan: the typed confirmation does not match")
	ErrUnsupported  = errors.New("diskscan: not supported for this connector or mode")
	ErrRoleMissing  = errors.New("diskscan: creating snapshots needs the dedicated disk scan role set on the connector")
	ErrRoleShared   = errors.New("diskscan: the disk scan role must differ from the collection, read-only and execute roles")
)

// DiskScanMode is a connector's opt-in level. The zero value is off.
type DiskScanMode string

const (
	DiskScanModeOff               DiskScanMode = ""
	DiskScanModeExistingSnapshots DiskScanMode = "existing_snapshots"
	DiskScanModeCreateSnapshots   DiskScanMode = "create_snapshots"
)

// Valid reports whether m is a known mode; the empty string is off.
func (m DiskScanMode) Valid() bool {
	switch m {
	case DiskScanModeOff, DiskScanModeExistingSnapshots, DiskScanModeCreateSnapshots:
		return true
	}
	return false
}

// Enabled reports whether any disk reading is permitted.
func (m DiskScanMode) Enabled() bool { return m != DiskScanModeOff }

// RunStatus is the state of a DiskScanRun.
type RunStatus string

const (
	StatusQueued     RunStatus = "queued"
	StatusRunning    RunStatus = "running"
	StatusSucceeded  RunStatus = "succeeded"
	StatusPartial    RunStatus = "partial"
	StatusFailed     RunStatus = "failed"
	StatusNotEnabled RunStatus = "not_enabled"
)

// SnapshotSource says where a volume's snapshot came from.
type SnapshotSource string

const (
	SourceNone          SnapshotSource = ""
	SourceReused        SnapshotSource = "reused"
	SourceCreated       SnapshotSource = "created"
	SourceImageBaseline SnapshotSource = "image_baseline"
)

// Gap values: why a volume has no trustworthy package inventory.
const (
	GapNone                 = ""
	GapNotEnabled           = "not_enabled"
	GapNoSnapshotAvailable  = "no_snapshot_available"
	GapSnapshotPending      = "snapshot_pending"
	GapEncryptedNoKey       = "encrypted_no_key"
	GapUnsupportedFS        = "unsupported_fs"
	GapUnsupportedPartition = "unsupported_partition"
	GapReadError            = "read_error"
	GapOverCap              = "over_cap"
	GapPermissionDenied     = "permission_denied"
	GapStale                = "stale"
)

// DiskScanTarget is one volume to scan.
type DiskScanTarget struct {
	ConnectorID string
	AssetID     string
	VolumeRef   string
	Boot        bool
	ImageID     string
}

// RunCounts tallies volume outcomes of a run.
type RunCounts struct {
	Volumes    int
	Scanned    int
	Gaps       int
	NotEnabled int
}

// DiskScanRun is one planning pass over a connector's volumes.
type DiskScanRun struct {
	ID          string
	ConnectorID string
	Status      RunStatus
	StartedAt   time.Time
	FinishedAt  time.Time
	Counts      RunCounts
	Err         string
}

// VolumeResult is the latest outcome for one volume. InventoryKnown and
// CVEMatchableKnown are false unless the scan proved them; a volume with
// InventoryKnown false has Gap set and PackageCount is meaningless.
type VolumeResult struct {
	RunID             string
	AssetID           string
	VolumeRef         string
	SnapshotID        string
	SnapshotSource    SnapshotSource
	Encrypted         bool
	InventoryKnown    bool
	CVEMatchableKnown bool
	Gap               string
	PackageCount      int
	ObservedAt        time.Time
}
