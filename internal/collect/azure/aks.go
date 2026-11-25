package azure

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v8"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectAKS lists the subscription's AKS managed clusters with the
// control-plane settings CIS AKS section 5 asks about. Node pools are folded
// into the cluster asset (node_pools_<setting> lists the offending pools) so a
// cluster-wide misconfiguration is one finding, as for GKE.
func collectAKS(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time, opts *arm.ClientOptions) ([]asset.Asset, error) {
	client, err := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("collectAKS: client: %w", err)
	}
	var assets []asset.Asset
	pager := client.NewListPager(nil)
	for first := true; pager.More(); first = false {
		page, err := pager.NextPage(ctx)
		if first && isUnregisteredProvider(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("collectAKS: list: %w", err)
		}
		for _, mc := range page.Value {
			if mc == nil || mc.ID == nil {
				continue
			}
			fqdn := ""
			if mc.Properties != nil {
				fqdn = strVal(mc.Properties.Fqdn)
			}
			assets = append(assets, asset.Asset{
				ID:           *mc.ID,
				Name:         strVal(mc.Name),
				Type:         "azure_aks_cluster",
				Provider:     asset.ProviderAzure,
				Region:       strVal(mc.Location),
				AccountID:    subscriptionID,
				Domain:       fqdn,
				Tags:         azTags(mc.Tags),
				Metadata:     aksMetadata(mc),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

// aksMetadata maps one managed cluster. An unset field is written as its
// documented AKS default only where that default never changed (local
// accounts on, Azure RBAC off, no private cluster, no authorized ranges, no
// network policy, Defender/KMS/workload identity/Azure Policy off, upgrade
// channel none). enableRBAC is always returned by ARM, and the node OS upgrade
// channel's default changed with the API version, so those stay absent when
// unset.
func aksMetadata(mc *armcontainerservice.ManagedCluster) map[string]string {
	meta := map[string]string{}
	p := mc.Properties
	if p == nil {
		return meta
	}
	meta["kubernetes_version"] = strVal(p.CurrentKubernetesVersion)
	if p.EnableRBAC != nil {
		meta["rbac_enabled"] = boolStr(*p.EnableRBAC)
	}
	// Managed Entra integration, or the legacy (server app) integration.
	entra := p.AADProfile != nil && ((p.AADProfile.Managed != nil && *p.AADProfile.Managed) || strVal(p.AADProfile.ServerAppID) != "")
	meta["entra_integration"] = boolStr(entra)
	meta["azure_rbac"] = boolStr(entra && p.AADProfile.EnableAzureRBAC != nil && *p.AADProfile.EnableAzureRBAC)
	meta["local_accounts_disabled"] = boolStr(p.DisableLocalAccounts != nil && *p.DisableLocalAccounts)
	aksAPIAccess(p, meta)
	aksNetworkPolicy(p.NetworkProfile, meta)
	aksSecurityProfile(p.SecurityProfile, meta)
	meta["azure_policy_addon"] = boolStr(aksAddonEnabled(p.AddonProfiles, "azurepolicy"))
	meta["upgrade_channel"] = string(armcontainerservice.UpgradeChannelNone)
	if up := p.AutoUpgradeProfile; up != nil {
		if up.UpgradeChannel != nil {
			meta["upgrade_channel"] = string(*up.UpgradeChannel)
		}
		if up.NodeOSUpgradeChannel != nil {
			meta["node_os_upgrade_channel"] = string(*up.NodeOSUpgradeChannel)
		}
	}
	var publicIP []string
	for _, pool := range p.AgentPoolProfiles {
		if pool != nil && pool.EnableNodePublicIP != nil && *pool.EnableNodePublicIP {
			publicIP = append(publicIP, strVal(pool.Name))
		}
	}
	sort.Strings(publicIP)
	meta["node_pools_public_ip"] = strings.Join(publicIP, ",")
	return meta
}

// aksAPIAccess records how the API server is reached. A private cluster, or
// public network access Disabled, has no internet-facing endpoint.
func aksAPIAccess(p *armcontainerservice.ManagedClusterProperties, meta map[string]string) {
	private := false
	var ranges []string
	if ap := p.APIServerAccessProfile; ap != nil {
		private = ap.EnablePrivateCluster != nil && *ap.EnablePrivateCluster
		ranges = nonEmpty(ap.AuthorizedIPRanges)
	}
	if p.PublicNetworkAccess != nil && *p.PublicNetworkAccess == armcontainerservice.PublicNetworkAccessDisabled {
		private = true
	}
	meta["api_public"] = boolStr(!private)
	sort.Strings(ranges)
	meta["authorized_ip_ranges"] = strings.Join(ranges, ",")
}

// aksNetworkPolicy records the NetworkPolicy engine. The Cilium dataplane
// enforces NetworkPolicy itself, whatever networkPolicy says.
func aksNetworkPolicy(np *armcontainerservice.NetworkProfile, meta map[string]string) {
	policy := string(armcontainerservice.NetworkPolicyNone)
	if np != nil {
		if np.NetworkPolicy != nil && *np.NetworkPolicy != "" {
			policy = string(*np.NetworkPolicy)
		}
		if np.NetworkDataplane != nil && *np.NetworkDataplane == armcontainerservice.NetworkDataplaneCilium {
			policy = string(armcontainerservice.NetworkPolicyCilium)
		}
	}
	meta["network_policy"] = policy
}

func aksSecurityProfile(sp *armcontainerservice.ManagedClusterSecurityProfile, meta map[string]string) {
	defender, kms, wi := false, false, false
	if sp != nil {
		defender = sp.Defender != nil && sp.Defender.SecurityMonitoring != nil &&
			sp.Defender.SecurityMonitoring.Enabled != nil && *sp.Defender.SecurityMonitoring.Enabled
		kms = sp.AzureKeyVaultKms != nil && sp.AzureKeyVaultKms.Enabled != nil && *sp.AzureKeyVaultKms.Enabled
		wi = sp.WorkloadIdentity != nil && sp.WorkloadIdentity.Enabled != nil && *sp.WorkloadIdentity.Enabled
	}
	meta["defender"] = boolStr(defender)
	meta["kms_secrets"] = boolStr(kms)
	meta["workload_identity"] = boolStr(wi)
}

// aksAddonEnabled matches an add-on key case-insensitively: ARM has returned
// both "azurepolicy" and "azurePolicy" over API versions.
func aksAddonEnabled(addons map[string]*armcontainerservice.ManagedClusterAddonProfile, name string) bool {
	for k, a := range addons {
		if strings.EqualFold(k, name) && a != nil && a.Enabled != nil && *a.Enabled {
			return true
		}
	}
	return false
}
