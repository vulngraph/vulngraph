package snapshotter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

// Config keys of the Azure disk-scan principal. They are never the collection
// (client_id) or execute (execute_client_id) identity.
const (
	ConfigAzureClientID     = "disk_scan_client_id"
	ConfigAzureClientSecret = "disk_scan_client_secret"
)

const (
	azureCleanupTimeout = 2 * time.Minute
	azurePollFrequency  = 5 * time.Second
	azureDefaultGrant   = int32(3600)
)

// ErrAzureUntagged is returned when a delete targets a snapshot that does not
// carry the vulngraph-disk-scan tag.
var ErrAzureUntagged = errors.New("snapshotter: snapshot lacks the " + diskscan.TagKey + " tag, refusing to delete")

var errAzureNotFound = errors.New("snapshotter: azure snapshot not found")

// AzureConfig locates the resource group the snapshots live in and the
// disk-scan service principal.
type AzureConfig struct {
	SubscriptionID string
	ResourceGroup  string
	TenantID       string
	ClientID       string
	ClientSecret   string
	// GrantSeconds is the lifetime of a read SAS; zero means one hour.
	GrantSeconds int32
}

// azureSnapshotAPI is the four mutating operations (create, delete, grant_read,
// revoke_read) plus the two reads the snapshotter needs. Methods are
// unexported so only this package can call them.
type azureSnapshotAPI interface {
	create(ctx context.Context, rg, name string, snap armcompute.Snapshot) (armcompute.Snapshot, error)
	remove(ctx context.Context, rg, name string) error
	grantRead(ctx context.Context, rg, name string, seconds int32) (string, error)
	revokeRead(ctx context.Context, rg, name string) error
	get(ctx context.Context, rg, name string) (armcompute.Snapshot, error)
	list(ctx context.Context, rg string) ([]*armcompute.Snapshot, error)
}

// Azure creates, reads and deletes ephemeral tagged incremental snapshots. It
// is the only holder of the mutating armcompute client.
type Azure struct {
	// AzureReader promotes GrantRead and RevokeRead, which a ReadOptIn (not the
	// create OptIn) authorizes.
	*AzureReader
	optIn diskscan.OptIn
	rg    string
	api   azureSnapshotAPI
}

var _ diskscan.Snapshotter = (*Azure)(nil)

// NewAzure builds the snapshotter with the disk-scan service principal. The
// OptIn must come from diskscan.Authorize and name the same client id.
func NewAzure(optIn diskscan.OptIn, cfg AzureConfig) (*Azure, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.TenantID == "" {
		return nil, fmt.Errorf("NewAzure: %s, %s and a tenant are required", ConfigAzureClientID, ConfigAzureClientSecret)
	}
	if !optIn.Valid() || optIn.Role() != cfg.ClientID {
		return nil, fmt.Errorf("NewAzure: opt-in does not match the disk-scan principal: %w", diskscan.ErrNotAuthorized)
	}
	cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("NewAzure: credential: %w", err)
	}
	client, err := armcompute.NewSnapshotsClient(cfg.SubscriptionID, cred, &arm.ClientOptions{DisableRPRegistration: true})
	if err != nil {
		return nil, fmt.Errorf("NewAzure: client: %w", err)
	}
	return newAzure(optIn, cfg, &armSnapshots{client: client})
}

func newAzure(optIn diskscan.OptIn, cfg AzureConfig, api azureSnapshotAPI) (*Azure, error) {
	if !optIn.Valid() {
		return nil, fmt.Errorf("newAzure: %w", diskscan.ErrNotAuthorized)
	}
	if cfg.ResourceGroup == "" {
		return nil, errors.New("newAzure: resource group is required")
	}
	grant := cfg.GrantSeconds
	if grant <= 0 {
		grant = azureDefaultGrant
	}
	reader := &AzureReader{principal: optIn.Role(), sub: cfg.SubscriptionID, grant: grant, api: api}
	return &Azure{AzureReader: reader, optIn: optIn, rg: cfg.ResourceGroup, api: api}, nil
}

func (a *Azure) authorize(optIn diskscan.OptIn) error {
	if !optIn.Valid() || optIn.Role() != a.optIn.Role() {
		return fmt.Errorf("snapshotter: opt-in does not match this snapshotter: %w", diskscan.ErrNotAuthorized)
	}
	return nil
}

// azureSnapshotName is deterministic so a retried job finds the snapshot its
// first attempt created instead of making a second one.
func azureSnapshotName(runID, volumeID string) string {
	sum := sha256.Sum256([]byte(runID + "|" + strings.ToLower(volumeID)))
	return "vulngraph-ds-" + hex.EncodeToString(sum[:8])
}

// CreateTagged creates an incremental snapshot of the managed disk vol.VolumeID,
// tagged vulngraph-disk-scan=runID, in the configured resource group.
func (a *Azure) CreateTagged(ctx context.Context, optIn diskscan.OptIn, vol diskscan.VolumeRef, runID string) (snap diskscan.Snapshot, err error) {
	if err := a.authorize(optIn); err != nil {
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %w", err)
	}
	if runID == "" || vol.VolumeID == "" || vol.Region == "" {
		return diskscan.Snapshot{}, errors.New("CreateTagged: run id, volume id and region are required")
	}
	name := azureSnapshotName(runID, vol.VolumeID)

	existing, err := a.api.get(ctx, a.rg, name)
	switch {
	case err == nil:
		if tagValue(existing.Tags) != runID {
			return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %s exists and belongs to another run", name)
		}
		return toSnapshot(existing, vol.VolumeID), nil
	case !errors.Is(err, errAzureNotFound):
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: lookup: %w", err)
	}

	defer func() {
		if err != nil {
			a.cleanup(ctx, name)
		}
	}()
	created, err := a.api.create(ctx, a.rg, name, armcompute.Snapshot{
		Location: &vol.Region,
		Tags:     map[string]*string{diskscan.TagKey: &runID},
		Properties: &armcompute.SnapshotProperties{
			Incremental: new(true),
			CreationData: &armcompute.CreationData{
				CreateOption:     new(armcompute.DiskCreateOptionCopy),
				SourceResourceID: &vol.VolumeID,
			},
		},
	})
	if err != nil {
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %w", err)
	}
	return toSnapshot(created, vol.VolumeID), nil
}

// DeleteTagged revokes any read grant and deletes snap, after re-reading its
// live tags: a snapshot without the vulngraph-disk-scan tag is never deleted.
// The delete runs even when the revoke fails.
func (a *Azure) DeleteTagged(ctx context.Context, optIn diskscan.OptIn, snap diskscan.Snapshot) error {
	if err := a.authorize(optIn); err != nil {
		return fmt.Errorf("DeleteTagged: %w", err)
	}
	rg, name, err := a.locate(snap)
	if err != nil {
		return fmt.Errorf("DeleteTagged: %w", err)
	}
	return a.deleteIfTagged(ctx, rg, name)
}

// ListTagged lists the snapshots carrying the vulngraph-disk-scan tag, however
// old, for the orphan sweeper.
func (a *Azure) ListTagged(ctx context.Context, optIn diskscan.OptIn) ([]diskscan.Snapshot, error) {
	if err := a.authorize(optIn); err != nil {
		return nil, fmt.Errorf("ListTagged: %w", err)
	}
	all, err := a.api.list(ctx, a.rg)
	if err != nil {
		return nil, fmt.Errorf("ListTagged: %w", err)
	}
	var out []diskscan.Snapshot
	for _, s := range all {
		if s == nil || s.ID == nil || tagValue(s.Tags) == "" {
			continue
		}
		volumeID := ""
		if p := s.Properties; p != nil && p.CreationData != nil && p.CreationData.SourceResourceID != nil {
			volumeID = *p.CreationData.SourceResourceID
		}
		out = append(out, toSnapshot(*s, volumeID))
	}
	return out, nil
}

func (a *Azure) deleteIfTagged(ctx context.Context, rg, name string) (err error) {
	live, err := a.api.get(ctx, rg, name)
	if errors.Is(err, errAzureNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("re-read tags: %w", err)
	}
	if _, ok := live.Tags[diskscan.TagKey]; !ok {
		return fmt.Errorf("%s: %w", name, ErrAzureUntagged)
	}
	defer func() {
		if derr := a.api.remove(ctx, rg, name); derr != nil && !errors.Is(derr, errAzureNotFound) {
			err = errors.Join(err, fmt.Errorf("delete: %w", derr))
		}
	}()
	if rerr := a.api.revokeRead(ctx, rg, name); rerr != nil && !errors.Is(rerr, errAzureNotFound) {
		err = fmt.Errorf("revoke: %w", rerr)
	}
	return err
}

// cleanup removes a snapshot a failed create may have left behind, on a fresh
// context because the failure is often the caller's cancellation. The orphan
// sweeper is the backstop when this also fails.
func (a *Azure) cleanup(ctx context.Context, name string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), azureCleanupTimeout)
	defer cancel()
	_ = a.deleteIfTagged(cctx, a.rg, name)
}

// locate resolves a snapshot's resource group and name, refusing anything
// outside the configured resource group.
func (a *Azure) locate(snap diskscan.Snapshot) (rg, name string, err error) {
	id, err := arm.ParseResourceID(snap.ID)
	if err != nil {
		return "", "", fmt.Errorf("snapshot id %q: %w", snap.ID, err)
	}
	if !strings.EqualFold(id.ResourceGroupName, a.rg) {
		return "", "", fmt.Errorf("snapshot %s is outside resource group %s", snap.ID, a.rg)
	}
	return id.ResourceGroupName, id.Name, nil
}

func tagValue(tags map[string]*string) string {
	if v, ok := tags[diskscan.TagKey]; ok && v != nil {
		return *v
	}
	return ""
}

func toSnapshot(s armcompute.Snapshot, volumeID string) diskscan.Snapshot {
	out := diskscan.Snapshot{Provider: "azure", VolumeID: volumeID, Ephemeral: tagValue(s.Tags) != ""}
	if s.ID != nil {
		out.ID = *s.ID
	}
	if s.Location != nil {
		out.Region = *s.Location
	}
	if p := s.Properties; p != nil {
		if p.DiskSizeBytes != nil {
			out.SizeBytes = *p.DiskSizeBytes
		}
		if p.TimeCreated != nil {
			out.CreatedAt = *p.TimeCreated
		}
		if c := p.EncryptionSettingsCollection; c != nil && c.Enabled != nil && *c.Enabled {
			out.Encrypted = true
		}
	}
	return out
}

// armSnapshots is the production azureSnapshotAPI over the ARM client.
type armSnapshots struct{ client *armcompute.SnapshotsClient }

func (c *armSnapshots) create(ctx context.Context, rg, name string, snap armcompute.Snapshot) (armcompute.Snapshot, error) {
	poller, err := c.client.BeginCreateOrUpdate(ctx, rg, name, snap, nil)
	if err != nil {
		return armcompute.Snapshot{}, err
	}
	res, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: azurePollFrequency})
	if err != nil {
		return armcompute.Snapshot{}, err
	}
	return res.Snapshot, nil
}

func (c *armSnapshots) remove(ctx context.Context, rg, name string) error {
	poller, err := c.client.BeginDelete(ctx, rg, name, nil)
	if err != nil {
		return mapNotFound(err)
	}
	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: azurePollFrequency})
	return mapNotFound(err)
}

func (c *armSnapshots) grantRead(ctx context.Context, rg, name string, seconds int32) (string, error) {
	poller, err := c.client.BeginGrantAccess(ctx, rg, name, armcompute.GrantAccessData{
		Access:            new(armcompute.AccessLevelRead),
		DurationInSeconds: &seconds,
	}, nil)
	if err != nil {
		return "", err
	}
	res, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: azurePollFrequency})
	if err != nil {
		return "", err
	}
	if res.AccessSAS == nil {
		return "", nil
	}
	return *res.AccessSAS, nil
}

func (c *armSnapshots) revokeRead(ctx context.Context, rg, name string) error {
	poller, err := c.client.BeginRevokeAccess(ctx, rg, name, nil)
	if err != nil {
		return mapNotFound(err)
	}
	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: azurePollFrequency})
	return mapNotFound(err)
}

func (c *armSnapshots) get(ctx context.Context, rg, name string) (armcompute.Snapshot, error) {
	res, err := c.client.Get(ctx, rg, name, nil)
	if err != nil {
		return armcompute.Snapshot{}, mapNotFound(err)
	}
	return res.Snapshot, nil
}

func (c *armSnapshots) list(ctx context.Context, rg string) ([]*armcompute.Snapshot, error) {
	var out []*armcompute.Snapshot
	pager := c.client.NewListByResourceGroupPager(rg, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func mapNotFound(err error) error {
	if re, ok := errors.AsType[*azcore.ResponseError](err); ok && re.StatusCode == http.StatusNotFound {
		return errAzureNotFound
	}
	return err
}
