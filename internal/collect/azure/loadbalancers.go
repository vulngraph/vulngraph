package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectLoadBalancers pulls Azure Load Balancers and Application Gateways.
// External LBs / App Gateways have a public frontend IP — public=true so
// InternetReachability emits exposed_to_internet edges.
func collectLoadBalancers(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, error) {
	lbClient, err := armnetwork.NewLoadBalancersClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectLoadBalancers: lb client: %w", err)
	}
	agClient, err := armnetwork.NewApplicationGatewaysClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("collectLoadBalancers: ag client: %w", err)
	}

	var assets []asset.Asset

	// Load Balancers
	lbPager := lbClient.NewListAllPager(nil)
	for lbPager.More() {
		page, err := lbPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectLoadBalancers: list lbs: %w", err)
		}
		for _, lb := range page.Value {
			if lb.ID == nil {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           *lb.ID,
				Name:         strVal(lb.Name),
				Type:         "load_balancer",
				Provider:     asset.ProviderAzure,
				Region:       strVal(lb.Location),
				AccountID:    subscriptionID,
				Tags:         azTags(lb.Tags),
				Metadata:     lbMetadata(lb),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}

	// Application Gateways
	agPager := agClient.NewListAllPager(nil)
	for agPager.More() {
		page, err := agPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collectLoadBalancers: list ags: %w", err)
		}
		for _, ag := range page.Value {
			if ag.ID == nil {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           *ag.ID,
				Name:         strVal(ag.Name),
				Type:         "azure_app_gateway",
				Provider:     asset.ProviderAzure,
				Region:       strVal(ag.Location),
				AccountID:    subscriptionID,
				Tags:         azTags(ag.Tags),
				Metadata:     appGatewayMetadata(ag),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}

	return assets, nil
}

// lbMetadata maps one load balancer. "public" is "true" when any frontend has
// a public IP, and "false" only when the properties block and every frontend's
// properties came back: an unread frontend may be the public one, and "false"
// would read as an internal balancer.
func lbMetadata(lb *armnetwork.LoadBalancer) map[string]string {
	meta := map[string]string{"sku": lbSKU(lb)}
	if lb.Properties == nil {
		return meta
	}
	public, complete := false, true
	for _, fe := range lb.Properties.FrontendIPConfigurations {
		switch {
		case fe == nil || fe.Properties == nil:
			complete = false
		case fe.Properties.PublicIPAddress != nil:
			public = true
		}
	}
	if public || complete {
		meta["public"] = boolStr(public)
	}
	return meta
}

// appGatewayMetadata maps one Application Gateway. The posture keys (CIS 7.10,
// 7.12, 7.13) are written only when the properties block came back.
func appGatewayMetadata(ag *armnetwork.ApplicationGateway) map[string]string {
	meta := map[string]string{
		"public": "true", // App Gateways have a public frontend by design
	}
	p := ag.Properties
	if p == nil {
		return meta
	}
	// A WAF is either the legacy inline configuration or an attached WAF policy;
	// neither is ever on by default, so "neither present" is an observation.
	// An attached policy's own state is joined in by applyWAFPolicies.
	inline := p.WebApplicationFirewallConfiguration != nil && p.WebApplicationFirewallConfiguration.Enabled != nil &&
		*p.WebApplicationFirewallConfiguration.Enabled
	meta["waf_inline"] = boolStr(inline)
	policyID := ""
	if p.FirewallPolicy != nil {
		policyID = strVal(p.FirewallPolicy.ID)
	}
	meta["waf_policy_id"] = policyID
	meta["waf_enabled"] = boolStr(inline || policyID != "")
	// HTTP/2 is off until explicitly enabled.
	meta["http2_enabled"] = boolStr(p.EnableHTTP2 != nil && *p.EnableHTTP2)
	tier := ""
	if p.SKU != nil && p.SKU.Tier != nil {
		tier = string(*p.SKU.Tier)
	}
	meta["sku_tier"] = tier
	if v := appGatewayFloorTLS(p, tier); v != "" {
		meta["min_tls_version"] = v
	}
	return meta
}

// appGatewayFloorTLS is the lowest TLS version any listener can negotiate:
// the gateway-wide SSL policy and every SSL profile's policy (the
// listener-specific policies). Where no policy is set (nil, or an object
// naming nothing) the gateway runs its SKU's default: AppGwSslPolicy20220101
// (TLS 1.2) on v2 and Basic gateways since the August 2025 TLS 1.0/1.1
// retirement, but still AppGwSslPolicy20150501 (TLS 1.0) on v1 gateways,
// whose default Microsoft left unchanged. "" when a policy in play, or the
// SKU behind a default, cannot be resolved.
func appGatewayFloorTLS(p *armnetwork.ApplicationGatewayPropertiesFormat, tier string) string {
	floor := appGatewayPolicyTLS(p.SSLPolicy, tier)
	for _, prof := range p.SSLProfiles {
		if prof == nil || prof.Properties == nil || prof.Properties.SSLPolicy == nil {
			continue
		}
		v := appGatewayPolicyTLS(prof.Properties.SSLPolicy, tier)
		if v == "" || floor == "" {
			return ""
		}
		if v < floor {
			floor = v
		}
	}
	return floor
}

// appGatewayPolicyTLS resolves one SSL policy, falling back to the SKU default
// for an unset policy.
func appGatewayPolicyTLS(sp *armnetwork.ApplicationGatewaySSLPolicy, tier string) string {
	if !sslPolicyUnset(sp) {
		return appGatewayMinTLS(sp)
	}
	switch armnetwork.ApplicationGatewayTier(tier) {
	case armnetwork.ApplicationGatewayTierStandardV2, armnetwork.ApplicationGatewayTierWAFV2, armnetwork.ApplicationGatewayTierBasic:
		return "1.2"
	case armnetwork.ApplicationGatewayTierStandard, armnetwork.ApplicationGatewayTierWAF:
		return "1.0"
	}
	return ""
}

// sslPolicyUnset reports a policy that selects nothing, so the default applies.
func sslPolicyUnset(sp *armnetwork.ApplicationGatewaySSLPolicy) bool {
	return sp == nil || (sp.PolicyType == nil && sp.PolicyName == nil && sp.MinProtocolVersion == nil &&
		len(sp.DisabledSSLProtocols) == 0 && len(sp.CipherSuites) == 0)
}

// appGatewayMinTLS resolves the lowest TLS version an SSL policy accepts, as
// "1.0".."1.3". "" when it cannot be told: nil or empty (the SKU default,
// resolved by appGatewayPolicyTLS), an unknown predefined policy, or a custom
// policy that only lists cipher suites.
func appGatewayMinTLS(sp *armnetwork.ApplicationGatewaySSLPolicy) string {
	if sp == nil {
		return ""
	}
	if sp.MinProtocolVersion != nil {
		return sslProtocolVersion(*sp.MinProtocolVersion)
	}
	if sp.PolicyName != nil {
		switch *sp.PolicyName {
		case armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20150501:
			return "1.0"
		case armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20170401:
			return "1.1"
		case armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20170401S,
			armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101,
			armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101S:
			return "1.2"
		}
		return ""
	}
	if len(sp.DisabledSSLProtocols) == 0 {
		return ""
	}
	// Legacy custom policy expressed as a disabled list: the lowest version
	// not disabled is the floor.
	disabled := map[armnetwork.ApplicationGatewaySSLProtocol]bool{}
	for _, d := range sp.DisabledSSLProtocols {
		if d != nil {
			disabled[*d] = true
		}
	}
	for _, v := range []armnetwork.ApplicationGatewaySSLProtocol{
		armnetwork.ApplicationGatewaySSLProtocolTLSv10,
		armnetwork.ApplicationGatewaySSLProtocolTLSv11,
		armnetwork.ApplicationGatewaySSLProtocolTLSv12,
		armnetwork.ApplicationGatewaySSLProtocolTLSv13,
	} {
		if !disabled[v] {
			return sslProtocolVersion(v)
		}
	}
	return ""
}

func sslProtocolVersion(v armnetwork.ApplicationGatewaySSLProtocol) string {
	switch v {
	case armnetwork.ApplicationGatewaySSLProtocolTLSv10:
		return "1.0"
	case armnetwork.ApplicationGatewaySSLProtocolTLSv11:
		return "1.1"
	case armnetwork.ApplicationGatewaySSLProtocolTLSv12:
		return "1.2"
	case armnetwork.ApplicationGatewaySSLProtocolTLSv13:
		return "1.3"
	}
	return ""
}

func lbSKU(lb *armnetwork.LoadBalancer) string {
	if lb.SKU == nil || lb.SKU.Name == nil {
		return ""
	}
	return string(*lb.SKU.Name)
}
