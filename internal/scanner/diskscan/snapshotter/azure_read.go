package snapshotter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

// azureReadAPI is the read-access pair and nothing else: an AzureReader holds
// no way to create or delete a snapshot.
type azureReadAPI interface {
	grantRead(ctx context.Context, rg, name string, seconds int32) (string, error)
	revokeRead(ctx context.Context, rg, name string) error
}

// AzureReader grants and revokes read SAS access on snapshots, authorized by a
// diskscan.ReadOptIn. Reading a snapshot over HTTPS needs a SAS in every mode,
// including existing_snapshots, where nothing may be created or deleted.
type AzureReader struct {
	principal string
	sub       string
	grant     int32
	api       azureReadAPI
}

// NewAzureReader builds the read-access holder with the disk-scan service
// principal. The ReadOptIn must come from diskscan.AuthorizeRead and name the
// same client id.
func NewAzureReader(readIn diskscan.ReadOptIn, cfg AzureConfig) (*AzureReader, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.TenantID == "" || cfg.SubscriptionID == "" {
		return nil, fmt.Errorf("NewAzureReader: %s, %s, a tenant and a subscription are required", ConfigAzureClientID, ConfigAzureClientSecret)
	}
	if !readIn.Valid() || readIn.Principal() != cfg.ClientID {
		return nil, fmt.Errorf("NewAzureReader: opt-in does not match the disk-scan principal: %w", diskscan.ErrNotAuthorized)
	}
	cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("NewAzureReader: credential: %w", err)
	}
	client, err := armcompute.NewSnapshotsClient(cfg.SubscriptionID, cred, &arm.ClientOptions{DisableRPRegistration: true})
	if err != nil {
		return nil, fmt.Errorf("NewAzureReader: client: %w", err)
	}
	return newAzureReader(readIn, cfg, &armSnapshots{client: client})
}

func newAzureReader(readIn diskscan.ReadOptIn, cfg AzureConfig, api azureReadAPI) (*AzureReader, error) {
	if !readIn.Valid() {
		return nil, fmt.Errorf("newAzureReader: %w", diskscan.ErrNotAuthorized)
	}
	grant := cfg.GrantSeconds
	if grant <= 0 {
		grant = azureDefaultGrant
	}
	return &AzureReader{principal: readIn.Principal(), sub: cfg.SubscriptionID, grant: grant, api: api}, nil
}

func (r *AzureReader) authorizeRead(readIn diskscan.ReadOptIn) error {
	if !readIn.Valid() || readIn.Principal() != r.principal {
		return fmt.Errorf("snapshotter: read opt-in does not match this snapshotter: %w", diskscan.ErrNotAuthorized)
	}
	return nil
}

// locateRead resolves a snapshot's resource group and name. A snapshot may sit
// in any resource group the principal's role covers, but only in the
// connector's own subscription.
func (r *AzureReader) locateRead(snap diskscan.Snapshot) (rg, name string, err error) {
	id, err := arm.ParseResourceID(snap.ID)
	if err != nil {
		return "", "", fmt.Errorf("snapshot id %q: %w", snap.ID, err)
	}
	if r.sub != "" && !strings.EqualFold(id.SubscriptionID, r.sub) {
		return "", "", fmt.Errorf("snapshot %s is outside subscription %s", snap.ID, r.sub)
	}
	return id.ResourceGroupName, id.Name, nil
}

// GrantRead returns a read-only SAS URL for snap. The grant is revoked before
// returning an error, and callers revoke it with RevokeRead (or DeleteTagged)
// when the scan ends.
func (r *AzureReader) GrantRead(ctx context.Context, readIn diskscan.ReadOptIn, snap diskscan.Snapshot) (url string, err error) {
	if err := r.authorizeRead(readIn); err != nil {
		return "", fmt.Errorf("GrantRead: %w", err)
	}
	rg, name, err := r.locateRead(snap)
	if err != nil {
		return "", fmt.Errorf("GrantRead: %w", err)
	}
	defer func() {
		if err != nil {
			r.revokeQuietly(ctx, rg, name)
		}
	}()
	sas, err := r.api.grantRead(ctx, rg, name, r.grant)
	if err != nil {
		return "", fmt.Errorf("GrantRead: %w", err)
	}
	if sas == "" {
		return "", errors.New("GrantRead: service returned no access URL")
	}
	return sas, nil
}

// RevokeRead ends the SAS grant on snap. Revoking a snapshot with no grant, or
// one that is gone, is not an error.
func (r *AzureReader) RevokeRead(ctx context.Context, readIn diskscan.ReadOptIn, snap diskscan.Snapshot) error {
	if err := r.authorizeRead(readIn); err != nil {
		return fmt.Errorf("RevokeRead: %w", err)
	}
	rg, name, err := r.locateRead(snap)
	if err != nil {
		return fmt.Errorf("RevokeRead: %w", err)
	}
	if err := r.api.revokeRead(ctx, rg, name); err != nil && !errors.Is(err, errAzureNotFound) {
		return fmt.Errorf("RevokeRead: %w", err)
	}
	return nil
}

func (r *AzureReader) revokeQuietly(ctx context.Context, rg, name string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), azureCleanupTimeout)
	defer cancel()
	_ = r.api.revokeRead(cctx, rg, name)
}
