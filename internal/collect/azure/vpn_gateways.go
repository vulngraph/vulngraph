package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// vpnGatewayFilter selects virtual network gateways from the generic resource
// listing. The Network API lists gateways only per resource group, so the
// subscription-wide resource listing finds them and each is then read whole.
const vpnGatewayFilter = "resourceType eq 'Microsoft.Network/virtualNetworkGateways'"

// collectVPNGateways reads every VPN-type virtual network gateway (CIS 7.9).
// ExpressRoute gateways carry no point-to-site configuration and are skipped.
func collectVPNGateways(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time, opts *arm.ClientOptions) ([]asset.Asset, error) {
	resources, err := armresources.NewClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("collectVPNGateways: resources client: %w", err)
	}
	gateways, err := armnetwork.NewVirtualNetworkGatewaysClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("collectVPNGateways: gateways client: %w", err)
	}
	filter := vpnGatewayFilter
	var assets []asset.Asset
	pager := resources.NewListPager(&armresources.ClientListOptions{Filter: &filter})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectVPNGateways: list: %w", err)
		}
		for _, r := range page.Value {
			if r == nil || r.ID == nil {
				continue
			}
			resp, err := gateways.Get(ctx, resourceGroup(*r.ID), strVal(r.Name), nil)
			if respErr, ok := errors.AsType[*azcore.ResponseError](err); ok && respErr.StatusCode == http.StatusNotFound {
				continue // deleted between the listing and the read
			}
			if err != nil {
				return nil, fmt.Errorf("collectVPNGateways: get %s: %w", *r.ID, err)
			}
			gw := resp.VirtualNetworkGateway
			if gw.Properties != nil && gw.Properties.GatewayType != nil &&
				*gw.Properties.GatewayType != armnetwork.VirtualNetworkGatewayTypeVPN {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           *r.ID,
				Name:         strVal(r.Name),
				Type:         "azure_vpn_gateway",
				Provider:     asset.ProviderAzure,
				Region:       strVal(gw.Location),
				AccountID:    subscriptionID,
				Tags:         azTags(gw.Tags),
				Metadata:     vpnGatewayMetadata(&gw),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

// vpnGatewayMetadata records whether point-to-site is configured and with
// which authentication types. Older gateways leave vpnAuthenticationTypes
// empty and imply the type from what is configured (an Entra tenant, root
// certificates, a RADIUS server); when nothing implies one the types stay
// absent rather than reading as compliant or not.
func vpnGatewayMetadata(gw *armnetwork.VirtualNetworkGateway) map[string]string {
	meta := map[string]string{}
	if gw.Properties == nil {
		return meta
	}
	cfg := gw.Properties.VPNClientConfiguration
	p2s := cfg != nil && cfg.VPNClientAddressPool != nil && len(nonEmpty(cfg.VPNClientAddressPool.AddressPrefixes)) > 0
	meta["p2s_enabled"] = boolStr(p2s)
	if !p2s {
		return meta
	}
	types := map[string]bool{}
	for _, t := range cfg.VPNAuthenticationTypes {
		if t != nil {
			types[string(*t)] = true
		}
	}
	if len(types) == 0 {
		if strVal(cfg.AADTenant) != "" {
			types[string(armnetwork.VPNAuthenticationTypeAAD)] = true
		}
		if len(cfg.VPNClientRootCertificates) > 0 {
			types[string(armnetwork.VPNAuthenticationTypeCertificate)] = true
		}
		if strVal(cfg.RadiusServerAddress) != "" || len(cfg.RadiusServers) > 0 {
			types[string(armnetwork.VPNAuthenticationTypeRadius)] = true
		}
	}
	if len(types) == 0 {
		return meta
	}
	list := make([]string, 0, len(types))
	for t := range types {
		list = append(list, t)
	}
	sort.Strings(list)
	meta["p2s_auth_types"] = strings.Join(list, ",")
	return meta
}
