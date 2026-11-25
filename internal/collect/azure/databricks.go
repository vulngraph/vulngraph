package azure

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectDatabricks lists the subscription's Azure Databricks workspaces
// (CIS Azure 2.1.x).
func collectDatabricks(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time, opts *arm.ClientOptions) ([]asset.Asset, error) {
	client, err := armdatabricks.NewWorkspacesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("collectDatabricks: client: %w", err)
	}
	var assets []asset.Asset
	pager := client.NewListBySubscriptionPager(nil)
	for first := true; pager.More(); first = false {
		page, err := pager.NextPage(ctx)
		if first && isUnregisteredProvider(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("collectDatabricks: list: %w", err)
		}
		for _, w := range page.Value {
			if w == nil || w.ID == nil {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           *w.ID,
				Name:         strVal(w.Name),
				Type:         "azure_databricks_workspace",
				Provider:     asset.ProviderAzure,
				Region:       strVal(w.Location),
				AccountID:    subscriptionID,
				Endpoint:     httpsURL(databricksURL(w)),
				Tags:         azTags(w.Tags),
				Metadata:     databricksMetadata(w),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

func databricksURL(w *armdatabricks.Workspace) string {
	if w.Properties == nil {
		return ""
	}
	return strVal(w.Properties.WorkspaceURL)
}

// databricksMetadata maps one workspace. publicNetworkAccess is Enabled until
// set otherwise. enableNoPublicIp changed its default (true for workspaces
// created on newer API versions), so an unset value stays absent.
func databricksMetadata(w *armdatabricks.Workspace) map[string]string {
	meta := map[string]string{}
	if w.SKU != nil {
		meta["sku"] = strVal(w.SKU.Name)
	}
	p := w.Properties
	if p == nil {
		return meta
	}
	meta["public_network_access"] = string(armdatabricks.PublicNetworkAccessEnabled)
	if p.PublicNetworkAccess != nil {
		meta["public_network_access"] = string(*p.PublicNetworkAccess)
	}
	approved := 0
	for _, pec := range p.PrivateEndpointConnections {
		if pec != nil && pec.Properties != nil && pec.Properties.PrivateLinkServiceConnectionState != nil &&
			pec.Properties.PrivateLinkServiceConnectionState.Status != nil &&
			*pec.Properties.PrivateLinkServiceConnectionState.Status == armdatabricks.PrivateLinkServiceConnectionStatusApproved {
			approved++
		}
	}
	meta["private_endpoint_count"] = strconv.Itoa(approved)
	meta["cmk_encryption"] = strings.Join(databricksCMKEntities(p), ",")
	params := p.Parameters
	if params == nil {
		return meta
	}
	if params.EnableNoPublicIP != nil && params.EnableNoPublicIP.Value != nil {
		meta["no_public_ip"] = boolStr(*params.EnableNoPublicIP.Value)
	}
	// Without a customer VNet the workspace runs in a Databricks-managed VNet
	// whose NSGs Databricks owns.
	meta["custom_vnet_id"] = stringParam(params.CustomVirtualNetworkID)
	if meta["custom_vnet_id"] != "" {
		meta["public_subnet"] = stringParam(params.CustomPublicSubnetName)
		meta["private_subnet"] = stringParam(params.CustomPrivateSubnetName)
	}
	return meta
}

// databricksCMKEntities lists which workspace data is encrypted with a
// customer-managed key: managed services (notebooks, secrets), managed disks,
// and the DBFS root.
func databricksCMKEntities(p *armdatabricks.WorkspaceProperties) []string {
	var out []string
	if p.Encryption != nil && p.Encryption.Entities != nil {
		e := p.Encryption.Entities
		if e.ManagedServices != nil && e.ManagedServices.KeySource != nil &&
			strings.EqualFold(string(*e.ManagedServices.KeySource), string(armdatabricks.EncryptionKeySourceMicrosoftKeyvault)) {
			out = append(out, "managed_services")
		}
		if e.ManagedDisk != nil && e.ManagedDisk.KeySource != nil &&
			strings.EqualFold(string(*e.ManagedDisk.KeySource), string(armdatabricks.EncryptionKeySourceMicrosoftKeyvault)) {
			out = append(out, "managed_disk")
		}
	}
	if params := p.Parameters; params != nil && params.Encryption != nil && params.Encryption.Value != nil &&
		params.Encryption.Value.KeySource != nil &&
		strings.EqualFold(string(*params.Encryption.Value.KeySource), string(armdatabricks.KeySourceMicrosoftKeyvault)) {
		out = append(out, "dbfs_root")
	}
	sort.Strings(out)
	return out
}

func stringParam(p *armdatabricks.WorkspaceCustomStringParameter) string {
	if p == nil {
		return ""
	}
	return strVal(p.Value)
}

// applyDatabricksSubnetNSGs resolves CIS 2.1.2 for VNet-injected workspaces:
// the injected subnets are looked up among this sweep's subnet assets, and
// subnets_without_nsg is written only when both were found with an observed
// NSG association.
func applyDatabricksSubnetNSGs(assets []asset.Asset) {
	nsgOf := map[string]string{}
	for _, a := range assets {
		if a.Provider == asset.ProviderAzure && a.Type == "azure_subnet" {
			if nsg, ok := a.Metadata["nsg_id"]; ok {
				nsgOf[strings.ToLower(a.ID)] = nsg
			}
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Provider != asset.ProviderAzure || a.Type != "azure_databricks_workspace" || a.Metadata["custom_vnet_id"] == "" {
			continue
		}
		var bare []string
		resolved := true
		for _, name := range []string{a.Metadata["public_subnet"], a.Metadata["private_subnet"]} {
			if name == "" {
				resolved = false
				break
			}
			nsg, ok := nsgOf[strings.ToLower(a.Metadata["custom_vnet_id"]+"/subnets/"+name)]
			if !ok {
				resolved = false
				break
			}
			if nsg == "" {
				bare = append(bare, name)
			}
		}
		if resolved {
			a.Metadata["subnets_without_nsg"] = strings.Join(bare, ",")
		}
	}
}
