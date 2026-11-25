package azure

import (
	"context"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// collectResourcePosture runs the resource-service reads behind CIS Azure
// Foundations sections 2, 7, 8.4 and 9 and the CIS AKS benchmark, after the
// core collectors so it can annotate the assets they produced.
//
// New resource families (WAF policies, VPN gateways, AKS, Databricks) go
// through appendOrLog: a failure marks the sweep partial and claims nothing.
// The rest only annotate assets already enumerated, so a failure there leaves
// their keys absent (unknown) without touching completeness.
func collectResourcePosture(ctx context.Context, result *collect.Result, cred azcore.TokenCredential, subscriptionID string, now time.Time) {
	logger := log.FromContext(ctx)
	opts := readOnlyARM()

	wafOK, wafPolicies := appendOrLog(ctx, result, "waf-policies", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectWAFPolicies(ctx, cred, subscriptionID, now, opts)
		return assets, nil, err
	})
	if wafOK {
		result.MarkComplete(subscriptionID+"/network:waf-policies", []string{"azure_waf_policy"}, len(wafPolicies))
	}
	applyWAFPolicies(result.Assets, wafPolicies)

	if ok, assets := appendOrLog(ctx, result, "vpn-gateways", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectVPNGateways(ctx, cred, subscriptionID, now, opts)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/network:vpn-gateways", []string{"azure_vpn_gateway"}, len(assets))
	}
	if ok, assets := appendOrLog(ctx, result, "aks", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectAKS(ctx, cred, subscriptionID, now, opts)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/containerservice:managed-clusters", []string{"azure_aks_cluster"}, len(assets))
	}
	if ok, assets := appendOrLog(ctx, result, "databricks", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectDatabricks(ctx, cred, subscriptionID, now, opts)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/databricks:workspaces", []string{"azure_databricks_workspace"}, len(assets))
	}
	applyDatabricksSubnetNSGs(result.Assets)

	if scopes, err := readDeleteLockScopes(ctx, cred, subscriptionID, opts); err != nil {
		logger.Warn().Err(err).Msg("azure management locks unreadable; storage delete-lock posture unknown")
	} else {
		applyStorageLocks(result.Assets, scopes, subscriptionID)
	}

	sub := map[string]string{}
	if nw, err := readNetworkWatchers(ctx, cred, subscriptionID, opts); err != nil {
		logger.Warn().Err(err).Msg("azure network watchers unreadable; flow-log posture unknown")
	} else {
		applyFlowLogs(result.Assets, nw)
		sub["network_watcher_missing_regions"] = watcherMissingRegions(result.Assets, nw)
	}
	if n, err := countBastionHosts(ctx, cred, subscriptionID, opts); err != nil {
		logger.Warn().Err(err).Msg("azure bastion hosts unreadable")
	} else {
		sub["bastion_host_count"] = strconv.Itoa(n)
	}
	// The VM listing is fail-fast (collectAll returns before reaching here on
	// any page error), so this count is a complete enumeration.
	sub["vm_count"] = strconv.Itoa(countTypes(result.Assets, "azure_vm"))
	mergeSubscriptionFacts(result, subscriptionID, sub, now)
}

// mergeSubscriptionFacts adds subscription-wide keys to the subscription's one
// azure_subscription asset, creating it when the identities collector did not
// (its RBAC keys are then absent, which its checks read as unknown). Several
// readers contribute keys, so the asset is extended, never replaced.
func mergeSubscriptionFacts(result *collect.Result, subscriptionID string, kv map[string]string, now time.Time) {
	id := "/subscriptions/" + subscriptionID
	for i := range result.Assets {
		a := &result.Assets[i]
		if a.Provider == asset.ProviderAzure && a.Type == "azure_subscription" && a.ID == id {
			if a.Metadata == nil {
				a.Metadata = map[string]string{}
			}
			for k, v := range kv {
				a.Metadata[k] = v
			}
			return
		}
	}
	meta := make(map[string]string, len(kv))
	for k, v := range kv {
		meta[k] = v
	}
	result.Assets = append(result.Assets, asset.Asset{
		ID:           id,
		Name:         subscriptionID,
		Type:         "azure_subscription",
		Provider:     asset.ProviderAzure,
		AccountID:    subscriptionID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	})
}
