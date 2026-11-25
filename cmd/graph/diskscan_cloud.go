package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan/envelope"
	"github.com/vulngraph/vulngraph/internal/jobs"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/azuredisk"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/snapshotter"
)

// configAzureResourceGroup is the resource group disk-scan snapshots live in.
const configAzureResourceGroup = "disk_scan_resource_group"

// diskScanConfigKeys are the only connector config keys a volume job's
// envelope carries, per connector type: the disk-scan principal, the
// collection credentials a read needs, and the location of the account.
var diskScanConfigKeys = map[connector.Type][]string{
	connector.TypeAWS: {
		"region", "regions", "role_arn", "external_id", "hub_role_arn",
		"aws_access_key_id", "aws_secret_access_key", "aws_session_token", connector.ConfigDiskScanRoleARN,
	},
	connector.TypeAzure: {
		"tenant_id", "subscription_id", "client_id", "client_secret",
		connector.ConfigDiskScanClientID, snapshotter.ConfigAzureClientSecret, configAzureResourceGroup,
	},
}

const envelopeLifetimeCap = 24 * time.Hour

// diskClouds implements jobs.DiskScanClouds. connectors is nil on the scanner
// pod, which can only Open.
type diskClouds struct {
	key        envelope.Key
	connectors *connector.Service
}

var _ jobs.DiskScanClouds = (*diskClouds)(nil)

func (d *diskClouds) accessOf(ctx context.Context, connectorID string, expires time.Time) (connector.Connector, envelope.Access, error) {
	if d.connectors == nil {
		return connector.Connector{}, envelope.Access{}, errors.New("accessOf: this pod cannot read connectors")
	}
	c, err := d.connectors.Get(ctx, connectorID)
	if err != nil {
		return connector.Connector{}, envelope.Access{}, fmt.Errorf("accessOf: %w", err)
	}
	keys, ok := diskScanConfigKeys[c.Type]
	if !ok {
		return connector.Connector{}, envelope.Access{}, fmt.Errorf("accessOf: connector type %s has no disk scan support", c.Type)
	}
	cfg := make(map[string]string, len(keys))
	for _, k := range keys {
		if v := c.Config[k]; v != "" {
			cfg[k] = v
		}
	}
	role, others := connector.DiskScanRoles(c.Type, c.Config)
	return c, envelope.Access{
		ConnectorID: c.ID, Type: string(c.Type), Role: role, OtherRoles: others, Config: cfg, ExpiresAt: expires,
	}, nil
}

// Seal packs what one run's volume jobs may use. On AWS that is two short-lived
// STS sessions, so the scanner assumes no role and holds no long-lived key; on
// Azure it is the disk-scan client secret, which is long-lived.
func (d *diskClouds) Seal(ctx context.Context, connectorID, runID string, expiresAt time.Time) ([]byte, error) {
	if limit := time.Now().Add(envelopeLifetimeCap); expiresAt.After(limit) {
		expiresAt = limit
	}
	c, a, err := d.accessOf(ctx, connectorID, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("Seal: %w", err)
	}
	if c.Type == connector.TypeAWS {
		if a, err = sealAWSAccess(ctx, c, a); err != nil {
			return nil, fmt.Errorf("Seal: %w", err)
		}
	}
	sealed, err := envelope.Seal(d.key, runID, a)
	if err != nil {
		return nil, fmt.Errorf("Seal: %w", err)
	}
	return sealed, nil
}

func (d *diskClouds) Open(ctx context.Context, connectorID, runID string, sealed []byte) (jobs.DiskScanAccess, error) {
	a, err := envelope.Open(d.key, runID, connectorID, sealed, time.Now())
	if errors.Is(err, envelope.ErrExpired) {
		return jobs.DiskScanAccess{}, fmt.Errorf("Open: %w: %w", jobs.ErrDiskCredentialsExpired, err)
	}
	if err != nil {
		return jobs.DiskScanAccess{}, fmt.Errorf("Open: %w: %w", jobs.ErrDiskEnvelope, err)
	}
	return d.build(ctx, a, false)
}

func (d *diskClouds) Resolve(ctx context.Context, connectorID string) (jobs.DiskScanAccess, error) {
	_, a, err := d.accessOf(ctx, connectorID, time.Now().Add(time.Hour))
	if err != nil {
		return jobs.DiskScanAccess{}, fmt.Errorf("Resolve: %w", err)
	}
	return d.build(ctx, a, true)
}

// build makes the cloud for an access. sweep asks it to know every region the
// connector may hold snapshots in.
func (d *diskClouds) build(ctx context.Context, a envelope.Access, sweep bool) (jobs.DiskScanAccess, error) {
	var cloud jobs.DiskCloud
	var err error
	switch connector.Type(a.Type) {
	case connector.TypeAWS:
		cloud, err = newAWSCloudFor(ctx, a, sweep)
	case connector.TypeAzure:
		cloud, err = newAzureDiskCloud(a)
	default:
		err = fmt.Errorf("connector type %s has no disk scan support", a.Type)
	}
	if err != nil {
		return jobs.DiskScanAccess{}, fmt.Errorf("build: %w", err)
	}
	return jobs.DiskScanAccess{Role: a.Role, OtherRoles: a.OtherRoles, Cloud: cloud}, nil
}

// mappedProvider turns provider errors into the jobs' own, so the jobs never
// import a provider package to classify one.
type mappedProvider struct {
	engine.Provider
	mapErr func(error) error
}

func (p mappedProvider) ListReusable(ctx context.Context, vol engine.VolumeRef) ([]engine.Snapshot, error) {
	snaps, err := p.Provider.ListReusable(ctx, vol)
	return snaps, p.mapErr(err)
}

func (p mappedProvider) Open(ctx context.Context, snap engine.Snapshot) (engine.BlockSource, error) {
	src, err := p.Provider.Open(ctx, snap)
	return src, p.mapErr(err)
}

func (p mappedProvider) Changed(ctx context.Context, base, next engine.Snapshot) ([]engine.Extent, error) {
	ext, err := p.Provider.Changed(ctx, base, next)
	return ext, p.mapErr(err)
}

// mappedSnapshotter does the same for the snapshotter's errors.
type mappedSnapshotter struct {
	engine.Snapshotter
	mapErr func(error) error
}

func (s mappedSnapshotter) CreateTagged(ctx context.Context, o engine.OptIn, vol engine.VolumeRef, runID string) (engine.Snapshot, error) {
	snap, err := s.Snapshotter.CreateTagged(ctx, o, vol, runID)
	return snap, s.mapErr(err)
}

func (s mappedSnapshotter) DeleteTagged(ctx context.Context, o engine.OptIn, snap engine.Snapshot) error {
	return s.mapErr(s.Snapshotter.DeleteTagged(ctx, o, snap))
}

// azureDiskCloud reads snapshots over read SAS URLs. The grant is authorized by
// a ReadOptIn, valid in existing_snapshots and create_snapshots mode alike,
// and only with a distinct disk-scan principal; create and delete need the
// create OptIn and exist in create_snapshots mode only. Unlike AWS, the Azure
// envelope carries the disk-scan client secret itself, which does not expire.
type azureDiskCloud struct {
	a    envelope.Access
	cred azcore.TokenCredential

	mu sync.Mutex
	sn *snapshotter.Azure
	rd *snapshotter.AzureReader
}

func azureCredential(cfg map[string]string) (azcore.TokenCredential, error) {
	if cfg["client_id"] != "" && cfg["client_secret"] != "" && cfg["tenant_id"] != "" {
		cred, err := azidentity.NewClientSecretCredential(cfg["tenant_id"], cfg["client_id"], cfg["client_secret"], nil)
		if err != nil {
			return nil, fmt.Errorf("azureCredential: %w", err)
		}
		return cred, nil
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azureCredential: %w", err)
	}
	return cred, nil
}

func newAzureDiskCloud(a envelope.Access) (*azureDiskCloud, error) {
	if a.Config["subscription_id"] == "" {
		return nil, errors.New("newAzureDiskCloud: subscription_id is required")
	}
	cred, err := azureCredential(a.Config)
	if err != nil {
		return nil, fmt.Errorf("newAzureDiskCloud: %w", err)
	}
	return &azureDiskCloud{a: a, cred: cred}, nil
}

func mapAzureErr(err error) error {
	var re *azcore.ResponseError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &re) && (re.StatusCode == 401 || re.StatusCode == 403):
		return fmt.Errorf("%w: %w", jobs.ErrDiskPermissionDenied, err)
	}
	return err
}

// azure returns the snapshotter, built once per job.
func (c *azureDiskCloud) azure(optIn engine.OptIn) (*snapshotter.Azure, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sn != nil {
		return c.sn, nil
	}
	sn, err := snapshotter.NewAzure(optIn, snapshotter.AzureConfig{
		SubscriptionID: c.a.Config["subscription_id"],
		ResourceGroup:  c.a.Config[configAzureResourceGroup],
		TenantID:       c.a.Config["tenant_id"],
		ClientID:       c.a.Config[connector.ConfigDiskScanClientID],
		ClientSecret:   c.a.Config[snapshotter.ConfigAzureClientSecret],
	})
	if err != nil {
		return nil, fmt.Errorf("azure: %w", err)
	}
	c.sn = sn
	return sn, nil
}

// reader returns the read-access holder, built once per job.
func (c *azureDiskCloud) reader(readIn engine.ReadOptIn) (*snapshotter.AzureReader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rd != nil {
		return c.rd, nil
	}
	rd, err := snapshotter.NewAzureReader(readIn, snapshotter.AzureConfig{
		SubscriptionID: c.a.Config["subscription_id"],
		TenantID:       c.a.Config["tenant_id"],
		ClientID:       c.a.Config[connector.ConfigDiskScanClientID],
		ClientSecret:   c.a.Config[snapshotter.ConfigAzureClientSecret],
	})
	if err != nil {
		return nil, fmt.Errorf("reader: %w", err)
	}
	c.rd = rd
	return rd, nil
}

func (c *azureDiskCloud) Provider(ins jobs.DiskOptIns) engine.Provider {
	access := azuredisk.ReadAccessFunc(func(ctx context.Context, snap engine.Snapshot) (string, error) {
		if !ins.Read.Valid() {
			return "", fmt.Errorf("reading an Azure snapshot needs the disk-scan principal's read grant: %w", jobs.ErrDiskPermissionDenied)
		}
		rd, err := c.reader(ins.Read)
		if err != nil {
			return "", err
		}
		url, err := rd.GrantRead(ctx, ins.Read, snap)
		return url, mapAzureErr(err)
	})
	p, err := c.readProvider(access)
	if err != nil {
		return failingProvider{err: err}
	}
	return mappedProvider{Provider: p, mapErr: mapAzureErr}
}

// readOnlyDiskARM keeps the ARM pipeline from registering a resource provider,
// which would be a write nobody approved.
var readOnlyDiskARM = &arm.ClientOptions{DisableRPRegistration: true}

func (c *azureDiskCloud) readProvider(access azuredisk.ReadAccess) (*azuredisk.Provider, error) {
	sub := c.a.Config["subscription_id"]
	snaps, err := armcompute.NewSnapshotsClient(sub, c.cred, readOnlyDiskARM)
	if err != nil {
		return nil, fmt.Errorf("readProvider: %w", err)
	}
	disks, err := armcompute.NewDisksClient(sub, c.cred, readOnlyDiskARM)
	if err != nil {
		return nil, fmt.Errorf("readProvider: %w", err)
	}
	return azuredisk.New(snaps, disks, azuredisk.Config{Access: access}), nil
}

func (c *azureDiskCloud) Snapshotter(optIn engine.OptIn) (engine.Snapshotter, error) {
	sn, err := c.azure(optIn)
	if err != nil {
		return nil, fmt.Errorf("Snapshotter: %w", err)
	}
	return mappedSnapshotter{Snapshotter: sn, mapErr: mapAzureErr}, nil
}

// WaitCompleted is a no-op: the snapshotter's create returns when the snapshot
// has been provisioned.
func (c *azureDiskCloud) WaitCompleted(context.Context, engine.Snapshot) error { return nil }

// Release ends the SAS grant taken to read snap.
func (c *azureDiskCloud) Release(ctx context.Context, ins jobs.DiskOptIns, snap engine.Snapshot) error {
	if !ins.Read.Valid() {
		return nil
	}
	rd, err := c.reader(ins.Read)
	if err != nil {
		return fmt.Errorf("Release: %w", err)
	}
	return mapAzureErr(rd.RevokeRead(ctx, ins.Read, snap))
}

// failingProvider reports why a provider could not be built, on first use.
type failingProvider struct{ err error }

func (p failingProvider) ListReusable(context.Context, engine.VolumeRef) ([]engine.Snapshot, error) {
	return nil, p.err
}

func (p failingProvider) Open(context.Context, engine.Snapshot) (engine.BlockSource, error) {
	return nil, p.err
}

func (p failingProvider) Changed(context.Context, engine.Snapshot, engine.Snapshot) ([]engine.Extent, error) {
	return nil, p.err
}
