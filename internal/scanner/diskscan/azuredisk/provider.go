// Package azuredisk is the read-only Azure provider for disk scanning. It lists
// existing managed-disk snapshots and reads them over a read SAS URL that the
// snapshotter package produced; it holds no client that can change Azure state.
package azuredisk

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	providerName   = "azure"
	provisionedOK  = "Succeeded"
	requestTimeout = 5 * time.Minute
)

// SnapshotLister is the read side of armcompute.SnapshotsClient.
type SnapshotLister interface {
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.SnapshotsClientListByResourceGroupOptions) *runtime.Pager[armcompute.SnapshotsClientListByResourceGroupResponse]
}

// DiskGetter is the read side of armcompute.DisksClient.
type DiskGetter interface {
	Get(ctx context.Context, resourceGroupName string, diskName string, options *armcompute.DisksClientGetOptions) (armcompute.DisksClientGetResponse, error)
}

// ReadAccess yields a read SAS URL for a snapshot. The snapshotter's grant_read
// operation is the only production source.
type ReadAccess interface {
	ReadURL(ctx context.Context, snap diskscan.Snapshot) (string, error)
}

// ReadAccessFunc adapts a function to ReadAccess.
type ReadAccessFunc func(ctx context.Context, snap diskscan.Snapshot) (string, error)

// ReadURL implements ReadAccess.
func (f ReadAccessFunc) ReadURL(ctx context.Context, snap diskscan.Snapshot) (string, error) {
	return f(ctx, snap)
}

// Config tunes a Provider. Zero values take the defaults.
type Config struct {
	// ResourceGroups holds the groups searched for snapshots; empty means the
	// resource group of the disk itself.
	ResourceGroups []string
	// Access supplies read SAS URLs; Open and Changed fail without it.
	Access ReadAccess
	// HTTP is the client for range reads; nil means safenet.New, which blocks
	// private addresses at dial time.
	HTTP *http.Client
	// BlockSize is the bytes per range request; CacheBlocks bounds the LRU.
	BlockSize   int64
	CacheBlocks int
	// Backoff is the first retry delay for a 5xx, 429 or network failure.
	Backoff time.Duration
}

// Provider implements diskscan.Provider for Azure managed disks.
type Provider struct {
	snapshots SnapshotLister
	disks     DiskGetter
	cfg       Config
	differ    pageDiffer
}

var _ diskscan.Provider = (*Provider)(nil)

// New builds a Provider over read-only clients.
func New(snapshots SnapshotLister, disks DiskGetter, cfg Config) *Provider {
	if cfg.HTTP == nil {
		cfg.HTTP = safenet.New(requestTimeout)
	}
	if cfg.BlockSize <= 0 {
		cfg.BlockSize = defaultBlockSize
	}
	if cfg.CacheBlocks <= 0 {
		cfg.CacheBlocks = defaultCacheBlocks
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	return &Provider{snapshots: snapshots, disks: disks, cfg: cfg, differ: blobDiffer{client: cfg.HTTP}}
}

// ListReusable returns the completed, non-ephemeral snapshots of the managed
// disk vol.VolumeID, newest first.
func (p *Provider) ListReusable(ctx context.Context, vol diskscan.VolumeRef) ([]diskscan.Snapshot, error) {
	disk, err := arm.ParseResourceID(vol.VolumeID)
	if err != nil {
		return nil, fmt.Errorf("ListReusable: volume id %q: %w", vol.VolumeID, err)
	}
	diskEncrypted, err := p.diskUsesADE(ctx, disk)
	if err != nil {
		return nil, fmt.Errorf("ListReusable: %w", err)
	}
	groups := p.cfg.ResourceGroups
	if len(groups) == 0 {
		groups = []string{disk.ResourceGroupName}
	}
	var out []diskscan.Snapshot
	for _, rg := range groups {
		pager := p.snapshots.NewListByResourceGroupPager(rg, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListReusable: list %s: %w", rg, err)
			}
			for _, s := range page.Value {
				if snap, ok := reusable(s, vol.VolumeID, diskEncrypted); ok {
					out = append(out, snap)
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b diskscan.Snapshot) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (p *Provider) diskUsesADE(ctx context.Context, disk *arm.ResourceID) (bool, error) {
	if p.disks == nil {
		return false, nil
	}
	res, err := p.disks.Get(ctx, disk.ResourceGroupName, disk.Name, nil)
	if err != nil {
		return false, fmt.Errorf("read disk %s: %w", disk.Name, err)
	}
	props := res.Properties
	return props != nil && props.EncryptionSettingsCollection != nil &&
		props.EncryptionSettingsCollection.Enabled != nil && *props.EncryptionSettingsCollection.Enabled, nil
}

func reusable(s *armcompute.Snapshot, volumeID string, diskEncrypted bool) (diskscan.Snapshot, bool) {
	if s == nil || s.ID == nil || s.Properties == nil || s.Properties.CreationData == nil {
		return diskscan.Snapshot{}, false
	}
	src := s.Properties.CreationData.SourceResourceID
	if src == nil || !strings.EqualFold(*src, volumeID) {
		return diskscan.Snapshot{}, false
	}
	if _, ours := s.Tags[diskscan.TagKey]; ours {
		return diskscan.Snapshot{}, false
	}
	if s.Properties.ProvisioningState == nil || *s.Properties.ProvisioningState != provisionedOK {
		return diskscan.Snapshot{}, false
	}
	snap := diskscan.Snapshot{ID: *s.ID, Provider: providerName, VolumeID: volumeID, Encrypted: diskEncrypted}
	if s.Location != nil {
		snap.Region = *s.Location
	}
	if s.Properties.DiskSizeBytes != nil {
		snap.SizeBytes = *s.Properties.DiskSizeBytes
	}
	if s.Properties.TimeCreated != nil {
		snap.CreatedAt = *s.Properties.TimeCreated
	}
	if c := s.Properties.EncryptionSettingsCollection; c != nil && c.Enabled != nil && *c.Enabled {
		snap.Encrypted = true
	}
	return snap, true
}

// Open reads snap over a read SAS URL from the configured ReadAccess.
func (p *Provider) Open(ctx context.Context, snap diskscan.Snapshot) (diskscan.BlockSource, error) {
	if snap.SizeBytes <= 0 {
		return nil, fmt.Errorf("Open: snapshot %s has no size", snap.ID)
	}
	sasURL, err := p.readURL(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("Open: %w", err)
	}
	return newRangeSource(ctx, p.cfg.HTTP, sasURL, snap.SizeBytes, p.cfg.BlockSize, p.cfg.CacheBlocks, p.cfg.Backoff), nil
}

// Changed returns the byte ranges that differ between two incremental
// snapshots of the same disk, or ErrNoDiff when the service cannot say.
func (p *Provider) Changed(ctx context.Context, base, next diskscan.Snapshot) ([]diskscan.Extent, error) {
	if base.ID == "" || next.ID == "" || !strings.EqualFold(base.VolumeID, next.VolumeID) || !base.CreatedAt.Before(next.CreatedAt) {
		return nil, fmt.Errorf("Changed: %w", diskscan.ErrNoDiff)
	}
	nextURL, err := p.readURL(ctx, next)
	if err != nil {
		return nil, fmt.Errorf("Changed: %w", err)
	}
	baseURL, err := p.readURL(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("Changed: %w", err)
	}
	extents, err := p.differ.changedRanges(ctx, nextURL, baseURL)
	if err != nil {
		return nil, fmt.Errorf("Changed: %w", err)
	}
	return extents, nil
}

func (p *Provider) readURL(ctx context.Context, snap diskscan.Snapshot) (string, error) {
	if p.cfg.Access == nil {
		return "", fmt.Errorf("no read access configured for %s", snap.ID)
	}
	u, err := p.cfg.Access.ReadURL(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("read access for %s: %w", snap.ID, err)
	}
	if u == "" {
		return "", fmt.Errorf("read access for %s: empty URL", snap.ID)
	}
	return u, nil
}
