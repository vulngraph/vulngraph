package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectDisks pulls managed disks and their network-exposure posture. Azure
// disks are always encrypted at rest, so the security signal is exportability:
// a disk with public network access enabled and an AllowAll network policy can
// be exported (SAS URI) over the internet — a data-exfiltration path. Orphaned
// (Unattached) disks are surfaced as hygiene.
func collectDisks(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, error) {
	client, err := armcompute.NewDisksClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectDisks: client: %w", err)
	}

	var assets []asset.Asset
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectDisks: list: %w", err)
		}
		for _, d := range page.Value {
			if d.ID == nil {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           strVal(d.ID),
				Name:         strVal(d.Name),
				Type:         "azure_disk",
				Provider:     asset.ProviderAzure,
				Region:       strVal(d.Location),
				AccountID:    subscriptionID,
				Metadata:     diskMetadata(d),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

// diskMetadata maps one disk's state and network-exposure posture. A disk
// returned without properties has none observed: its keys are left out and the
// exposure tier is unknown, so internet_exportable cannot read as "false".
func diskMetadata(d *armcompute.Disk) map[string]string {
	p := d.Properties
	if p == nil {
		return map[string]string{"public_access": publicAccessUnknown}
	}
	state, netPolicy, pubAccess, encType := "", "", "", ""
	if p.DiskState != nil {
		state = string(*p.DiskState)
	}
	if p.NetworkAccessPolicy != nil {
		netPolicy = string(*p.NetworkAccessPolicy)
	}
	if p.PublicNetworkAccess != nil {
		pubAccess = string(*p.PublicNetworkAccess)
	}
	if p.Encryption != nil && p.Encryption.Type != nil {
		encType = string(*p.Encryption.Type)
	}
	// Exportable over the internet: public network access enabled AND the
	// network policy permits export from any network.
	exportable := strings.EqualFold(pubAccess, "Enabled") &&
		strings.EqualFold(netPolicy, string(armcompute.NetworkAccessPolicyAllowAll))
	meta := map[string]string{
		"disk_state":            state,
		"network_access_policy": netPolicy,
		"public_network_access": pubAccess,
		"encryption_type":       encType,
		"internet_exportable":   fmt.Sprintf("%t", exportable),
		"unattached":            fmt.Sprintf("%t", strings.EqualFold(state, "Unattached")),
		"vm_attached":           fmt.Sprintf("%t", d.ManagedBy != nil && *d.ManagedBy != "" || len(d.ManagedByExtended) > 0),
	}
	if exportable {
		meta["public_access"] = asset.PublicAccessPossible
	}
	return meta
}
