package azure

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// flowLog is one flow log as the CIS 6.1.1.5/6.1.1.6/7.5/7.8 checks read it.
type flowLog struct {
	enabled bool
	// retentionDays is 0 when records are kept indefinitely: no retention
	// policy, a disabled one, or 0 days (Azure's "retain forever").
	retentionDays int32
	analytics     bool
}

// networkWatchers is the subscription's Network Watcher estate: the regions
// that have a watcher and every flow log keyed by its lowercased target
// resource ID (an NSG or a VNet).
type networkWatchers struct {
	regions  map[string]bool
	flowLogs map[string]flowLog
}

// readNetworkWatchers lists every Network Watcher and each watcher's flow
// logs. Any page error fails the whole read: a flow log missed on a short
// page would make its target read as unlogged.
func readNetworkWatchers(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, opts *arm.ClientOptions) (networkWatchers, error) {
	watchers, err := armnetwork.NewWatchersClient(subscriptionID, cred, opts)
	if err != nil {
		return networkWatchers{}, fmt.Errorf("readNetworkWatchers: watchers client: %w", err)
	}
	flowLogs, err := armnetwork.NewFlowLogsClient(subscriptionID, cred, opts)
	if err != nil {
		return networkWatchers{}, fmt.Errorf("readNetworkWatchers: flow logs client: %w", err)
	}
	out := networkWatchers{regions: map[string]bool{}, flowLogs: map[string]flowLog{}}
	pager := watchers.NewListAllPager(nil)
	for first := true; pager.More(); first = false {
		page, err := pager.NextPage(ctx)
		if first && isUnregisteredProvider(err) {
			return out, nil
		}
		if err != nil {
			return networkWatchers{}, fmt.Errorf("readNetworkWatchers: list watchers: %w", err)
		}
		for _, w := range page.Value {
			if w == nil || w.ID == nil {
				continue
			}
			out.regions[normRegion(strVal(w.Location))] = true
			flPager := flowLogs.NewListPager(resourceGroup(*w.ID), strVal(w.Name), nil)
			for flPager.More() {
				flPage, err := flPager.NextPage(ctx)
				if err != nil {
					return networkWatchers{}, fmt.Errorf("readNetworkWatchers: list flow logs of %s: %w", *w.ID, err)
				}
				for _, fl := range flPage.Value {
					out.addFlowLog(fl)
				}
			}
		}
	}
	return out, nil
}

// addFlowLog records one flow log against its target. Azure allows one flow
// log per target; should two appear, an enabled one wins so a stale disabled
// leftover cannot hide a working log.
func (n networkWatchers) addFlowLog(fl *armnetwork.FlowLog) {
	if fl == nil || fl.Properties == nil || fl.Properties.TargetResourceID == nil {
		return
	}
	p := fl.Properties
	f := flowLog{enabled: p.Enabled != nil && *p.Enabled}
	if rp := p.RetentionPolicy; rp != nil && rp.Enabled != nil && *rp.Enabled && rp.Days != nil {
		f.retentionDays = *rp.Days
	}
	if fa := p.FlowAnalyticsConfiguration; fa != nil && fa.NetworkWatcherFlowAnalyticsConfiguration != nil {
		ta := fa.NetworkWatcherFlowAnalyticsConfiguration
		f.analytics = ta.Enabled != nil && *ta.Enabled && strVal(ta.WorkspaceResourceID) != ""
	}
	key := strings.ToLower(*p.TargetResourceID)
	if prev, ok := n.flowLogs[key]; ok && prev.enabled && !f.enabled {
		return
	}
	n.flowLogs[key] = f
}

// applyFlowLogs writes each VNet's and NSG's flow-log posture onto its asset.
// Only called with a complete read, so "no flow log" is an observation.
func applyFlowLogs(assets []asset.Asset, n networkWatchers) {
	for i := range assets {
		a := &assets[i]
		if a.Provider != asset.ProviderAzure || (a.Type != "azure_vnet" && a.Type != "security_group") {
			continue
		}
		if a.Metadata == nil {
			a.Metadata = map[string]string{}
		}
		f, ok := n.flowLogs[strings.ToLower(a.ID)]
		a.Metadata["flow_log_enabled"] = boolStr(ok && f.enabled)
		if !ok || !f.enabled {
			continue
		}
		a.Metadata["flow_log_retention_days"] = strconv.Itoa(int(f.retentionDays))
		a.Metadata["flow_log_traffic_analytics"] = boolStr(f.analytics)
	}
}

// watcherMissingRegions lists the regions holding a VNet but no Network
// Watcher, sorted. VNets are the measure because a watcher observes network
// resources, and every VM, NIC, gateway and private endpoint lives in a VNet.
func watcherMissingRegions(assets []asset.Asset, n networkWatchers) string {
	missing := map[string]bool{}
	for _, a := range assets {
		if a.Provider == asset.ProviderAzure && a.Type == "azure_vnet" {
			if r := normRegion(a.Region); r != "" && !n.regions[r] {
				missing[r] = true
			}
		}
	}
	out := make([]string, 0, len(missing))
	for r := range missing {
		out = append(out, r)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// normRegion folds "East US" and "eastus" together: ARM returns locations in
// the short form, but older resources can carry the display form.
func normRegion(r string) string {
	return strings.ToLower(strings.ReplaceAll(r, " ", ""))
}

// countBastionHosts counts the subscription's Azure Bastion hosts (CIS 8.4.1).
func countBastionHosts(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, opts *arm.ClientOptions) (int, error) {
	client, err := armnetwork.NewBastionHostsClient(subscriptionID, cred, opts)
	if err != nil {
		return 0, fmt.Errorf("countBastionHosts: client: %w", err)
	}
	n := 0
	pager := client.NewListPager(nil)
	for first := true; pager.More(); first = false {
		page, err := pager.NextPage(ctx)
		if first && isUnregisteredProvider(err) {
			return 0, nil
		}
		if err != nil {
			return 0, fmt.Errorf("countBastionHosts: list: %w", err)
		}
		for _, b := range page.Value {
			if b != nil && b.ID != nil {
				n++
			}
		}
	}
	return n, nil
}
