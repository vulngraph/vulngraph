// Package diskscan is the engine that reads a VM disk snapshot and inventories
// its installed packages. It is a leaf: it imports no internal/app package, so
// the app layer's domain types repeat the string values below and a test pins
// that they match.
package diskscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// Gap values: why a disk produced no trustworthy package inventory.
const (
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

// ModeCreateSnapshots is the connector disk-scan mode that permits snapshot
// creation; it equals the app layer's DiskScanModeCreateSnapshots.
const ModeCreateSnapshots = "create_snapshots"

// ModeExistingSnapshots is the connector disk-scan mode that reads snapshots
// that already exist; it equals the app layer's DiskScanModeExistingSnapshots.
const ModeExistingSnapshots = "existing_snapshots"

// TagKey marks every snapshot Vulngraph creates; deletion refuses anything
// without it.
const TagKey = "vulngraph-disk-scan"

var (
	// ErrBlockUnreadable is returned by a BlockSource for a range it cannot read.
	ErrBlockUnreadable = errors.New("diskscan: block unreadable")
	// ErrNoDiff is returned by Provider.Changed when the provider cannot diff.
	ErrNoDiff = errors.New("diskscan: changed-block diff unsupported")
	// ErrNotAuthorized is returned by Authorize when the connector has not opted in.
	ErrNotAuthorized = errors.New("diskscan: snapshot creation not authorized")
)

// BlockSource is a read-only view of a disk. Sparse ranges read as zeros.
type BlockSource interface {
	io.ReaderAt
	Size() int64
	Close() error
}

// VolumeRef names one volume on a provider.
type VolumeRef struct {
	Provider string
	Region   string
	VolumeID string
	Boot     bool
	ImageID  string
}

// Snapshot is a point-in-time copy of a volume. Ephemeral snapshots were
// created by Vulngraph and must be deleted after the scan.
type Snapshot struct {
	ID        string
	Provider  string
	Region    string
	VolumeID  string
	SizeBytes int64
	Encrypted bool
	Ephemeral bool
	CreatedAt time.Time
}

// Extent is a byte range of a disk.
type Extent struct {
	Offset int64
	Length int64
}

// Provider reads existing snapshots. Implementations hold read-only clients.
type Provider interface {
	ListReusable(ctx context.Context, vol VolumeRef) ([]Snapshot, error)
	Open(ctx context.Context, snap Snapshot) (BlockSource, error)
	// Changed returns ErrNoDiff when the provider cannot diff the two snapshots.
	Changed(ctx context.Context, base, next Snapshot) ([]Extent, error)
}

// Snapshotter is the only way to mutate cloud state. Its single implementation
// lives in the snapshotter package, and every call needs an OptIn.
type Snapshotter interface {
	CreateTagged(ctx context.Context, optIn OptIn, vol VolumeRef, runID string) (Snapshot, error)
	DeleteTagged(ctx context.Context, optIn OptIn, snap Snapshot) error
	ListTagged(ctx context.Context, optIn OptIn) ([]Snapshot, error)
}

// ConnectorGrant is what a connector's configuration says about disk scanning.
// OtherRoles are the collection, read-only and execute role identifiers the
// disk-scan role must differ from.
type ConnectorGrant struct {
	Mode         string
	DiskScanRole string
	OtherRoles   []string
}

// OptIn proves a connector authorized snapshot creation. The field is
// unexported and Authorize is the only constructor, so no other package can
// forge one.
type OptIn struct {
	role string
}

// Authorize returns an OptIn only when the mode is create_snapshots and the
// disk-scan role is set and distinct from every other role.
func Authorize(grant ConnectorGrant) (OptIn, error) {
	if grant.Mode != ModeCreateSnapshots {
		return OptIn{}, fmt.Errorf("Authorize: mode %q: %w", grant.Mode, ErrNotAuthorized)
	}
	if grant.DiskScanRole == "" {
		return OptIn{}, fmt.Errorf("Authorize: no disk-scan role: %w", ErrNotAuthorized)
	}
	if slices.Contains(grant.OtherRoles, grant.DiskScanRole) {
		return OptIn{}, fmt.Errorf("Authorize: disk-scan role shared with another role: %w", ErrNotAuthorized)
	}
	return OptIn{role: grant.DiskScanRole}, nil
}

// Role is the principal the snapshotter assumes; empty for a zero OptIn.
func (o OptIn) Role() string { return o.role }

// Valid reports whether the OptIn came from Authorize.
func (o OptIn) Valid() bool { return o.role != "" }

// ReadOptIn proves a connector authorized the read-access grant and revoke pair
// (Azure's beginGetAccess and endGetAccess, a read SAS on a snapshot) and
// nothing else: it never authorizes creating or deleting a snapshot, which
// needs an OptIn. It is valid in both existing_snapshots and create_snapshots
// mode, and only for a connector with a distinct disk-scan principal. The
// field is unexported, so AuthorizeRead is the only constructor.
type ReadOptIn struct {
	principal string
}

// AuthorizeRead returns a ReadOptIn only when the mode is existing_snapshots or
// create_snapshots and the disk-scan principal is set and distinct from every
// other role.
func AuthorizeRead(grant ConnectorGrant) (ReadOptIn, error) {
	if grant.Mode != ModeExistingSnapshots && grant.Mode != ModeCreateSnapshots {
		return ReadOptIn{}, fmt.Errorf("AuthorizeRead: mode %q: %w", grant.Mode, ErrNotAuthorized)
	}
	if grant.DiskScanRole == "" {
		return ReadOptIn{}, fmt.Errorf("AuthorizeRead: no disk-scan principal: %w", ErrNotAuthorized)
	}
	if slices.Contains(grant.OtherRoles, grant.DiskScanRole) {
		return ReadOptIn{}, fmt.Errorf("AuthorizeRead: disk-scan principal shared with another role: %w", ErrNotAuthorized)
	}
	return ReadOptIn{principal: grant.DiskScanRole}, nil
}

// Principal is the identity the read grant is made with; empty for a zero ReadOptIn.
func (o ReadOptIn) Principal() string { return o.principal }

// Valid reports whether the ReadOptIn came from AuthorizeRead.
func (o ReadOptIn) Valid() bool { return o.principal != "" }

// Limits bound one disk read. A zero field means the engine default.
type Limits struct {
	MaxVolumeBytes int64
	MaxBytesRead   int64
	MaxFileBytes   int64
	MaxTotalBytes  int64
}

// DiskResult is the outcome of ScanDisk. Packages is meaningful only when
// InventoryKnown is true; otherwise Gap says why and Packages is nil.
type DiskResult struct {
	Packages       []pkginventory.InstalledPackage
	Ecosystem      string
	Gap            string
	InventoryKnown bool
	LanguageGap    bool
}
