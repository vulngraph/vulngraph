package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// botManagerRuleSet is the managed rule set that gives an Application Gateway
// WAF policy bot protection (CIS 7.15).
const botManagerRuleSet = "Microsoft_BotManagerRuleSet"

// collectWAFPolicies lists the Application Gateway WAF policies (CIS 7.14,
// 7.15; and the policy state behind 7.10).
func collectWAFPolicies(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time, opts *arm.ClientOptions) ([]asset.Asset, error) {
	client, err := armnetwork.NewWebApplicationFirewallPoliciesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("collectWAFPolicies: client: %w", err)
	}
	var assets []asset.Asset
	pager := client.NewListAllPager(nil)
	for first := true; pager.More(); first = false {
		page, err := pager.NextPage(ctx)
		if first && isUnregisteredProvider(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("collectWAFPolicies: list: %w", err)
		}
		for _, p := range page.Value {
			if p == nil || p.ID == nil {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           *p.ID,
				Name:         strVal(p.Name),
				Type:         "azure_waf_policy",
				Provider:     asset.ProviderAzure,
				Region:       strVal(p.Location),
				AccountID:    subscriptionID,
				Tags:         azTags(p.Tags),
				Metadata:     wafPolicyMetadata(p),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

// wafPolicyMetadata maps one WAF policy. Settings ARM left unset stay absent:
// the policy resource does not document a default for state or body
// inspection. The managed rule sets are required on every policy, so the
// absence of the bot rule set is an observation.
func wafPolicyMetadata(p *armnetwork.WebApplicationFirewallPolicy) map[string]string {
	meta := map[string]string{}
	props := p.Properties
	if props == nil {
		return meta
	}
	meta["attached"] = boolStr(len(props.ApplicationGateways) > 0 || len(props.HTTPListeners) > 0 || len(props.PathBasedRules) > 0)
	if s := props.PolicySettings; s != nil {
		if s.State != nil {
			meta["state"] = string(*s.State)
		}
		if s.Mode != nil {
			meta["mode"] = string(*s.Mode)
		}
		if s.RequestBodyCheck != nil {
			meta["request_body_check"] = boolStr(*s.RequestBodyCheck)
		}
	}
	if props.ManagedRules != nil {
		bot := false
		for _, rs := range props.ManagedRules.ManagedRuleSets {
			if rs != nil && strings.EqualFold(strVal(rs.RuleSetType), botManagerRuleSet) {
				bot = true
			}
		}
		meta["bot_protection"] = boolStr(bot)
	}
	return meta
}

// applyWAFPolicies resolves the WAF state of every gateway whose WAF is an
// attached policy (CIS 7.10): a Disabled policy is no WAF. When the policy
// listing failed (policies is empty) or the policy was not in it, the attached
// policy's state is unknown and waf_enabled is withdrawn rather than left
// reading as a working WAF.
func applyWAFPolicies(assets []asset.Asset, policies []asset.Asset) {
	type policyState struct{ state, mode string }
	byID := map[string]policyState{}
	for _, p := range policies {
		byID[strings.ToLower(p.ID)] = policyState{state: p.Metadata["state"], mode: p.Metadata["mode"]}
	}
	for i := range assets {
		a := &assets[i]
		if a.Provider != asset.ProviderAzure || a.Type != "azure_app_gateway" || a.Metadata["waf_inline"] == "true" {
			continue
		}
		key := strings.ToLower(a.Metadata["waf_policy_id"])
		if key == "" {
			continue
		}
		p, ok := byID[key]
		if !ok || p.state == "" {
			delete(a.Metadata, "waf_enabled")
			continue
		}
		a.Metadata["waf_enabled"] = boolStr(p.state == string(armnetwork.WebApplicationFirewallEnabledStateEnabled))
		a.Metadata["waf_mode"] = p.mode
	}
}
