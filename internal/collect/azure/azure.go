// Package azure collects VMs, networking, storage, web apps, SQL, load
// balancers and Key Vaults from an Azure subscription, plus the
// subscription-wide (RBAC, Defender for Cloud, Azure Monitor) and Entra
// tenant-wide settings CSPM checks read. Authentication prefers OIDC:
// Service Principal (client_id + client_secret) for migration from a prior
// static-key credential deployment; DefaultAzureCredential (Workload Identity
// on GKE, Azure CLI in local dev) otherwise.
package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Collector implements collect.Collector for Azure.
type Collector struct{}

func New() *Collector { return &Collector{} }

// Collect runs the full inventory pull for a subscription. An auth failure is
// wrapped as collect.ErrPermanent so the sync worker cancels instead of
// retrying (same pattern as the AWS collector).
func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	res, err := c.collectAll(ctx, cfg)
	if err != nil && isPermanentAzureErr(err) {
		return res, fmt.Errorf("%w: %v", collect.ErrPermanent, err)
	}
	return res, err
}

func (c *Collector) collectAll(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	subscriptionID := cfg["subscription_id"]
	if subscriptionID == "" {
		return collect.Result{}, fmt.Errorf("collectAll: subscription_id is required")
	}

	cred, err := credential(ctx, cfg)
	if err != nil {
		return collect.Result{}, fmt.Errorf("collectAll: %w", err)
	}

	now := time.Now()
	var result collect.Result

	// VMs + NIC-level NSG edges — fail fast: networking topology depends on this.
	//
	// A nil error here means vmClient's pager read every page (collectVMs
	// returns early on any page error) — per-NIC lookups inside are
	// best-effort and only ever omit VM metadata, never a VM itself, so they
	// don't undermine this claim. Scope is subscription-wide, matching the
	// real enumeration unit: unlike AWS, Azure Compute is not region-partitioned
	// API-side (one ListAll call already spans every region).
	vms, vmEdges, err := collectVMs(ctx, cred, subscriptionID, now)
	if err != nil {
		return collect.Result{}, fmt.Errorf("collectAll: %w", err)
	}
	result.Assets = append(result.Assets, vms...)
	result.Edges = append(result.Edges, vmEdges...)
	result.MarkComplete(subscriptionID+"/compute:vms", []string{"azure_vm"}, len(vms))

	// Networking (vNets, subnets, NSGs, public IPs) — fail fast: reachability
	// rules need NSG ingress data to compute exposed_to_internet edges.
	//
	// collectNetworking discards everything and returns an error if ANY of its
	// three pagers fails a page, so a nil error here proves all three
	// listings read every page. They're claimed as separate scopes (matching
	// separate ARM API surfaces, each independently subject to a future
	// permission/feature gap) even though today they succeed or fail together.
	netAssets, netEdges, err := collectNetworking(ctx, cred, subscriptionID, now)
	if err != nil {
		return collect.Result{}, fmt.Errorf("collectAll: %w", err)
	}
	result.Assets = append(result.Assets, netAssets...)
	result.Edges = append(result.Edges, netEdges...)
	result.MarkComplete(subscriptionID+"/network:vnets", []string{"azure_vnet", "azure_subnet"},
		countTypes(netAssets, "azure_vnet", "azure_subnet"))
	result.MarkComplete(subscriptionID+"/network:nsgs", []string{"security_group"},
		countTypes(netAssets, "security_group"))
	result.MarkComplete(subscriptionID+"/network:public-ips", []string{"azure_public_ip"},
		countTypes(netAssets, "azure_public_ip"))

	// Remaining services are best-effort: a permission gap in one must not
	// abort the subscription sync — same pattern as GCP managed collectors.
	// appendOrLog reports whether its listing completed so callers can claim
	// enumeration ONLY on that success path, next to the same error check that
	// already gates result.Partial.
	if ok, assets := appendOrLog(ctx, &result, "loadbalancers", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectLoadBalancers(ctx, cred, subscriptionID, now)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/network:loadbalancers", []string{"load_balancer", "azure_app_gateway"},
			countTypes(assets, "load_balancer", "azure_app_gateway"))
	}
	if ok, assets := appendOrLog(ctx, &result, "webapps", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectWebApps(ctx, cred, subscriptionID, now)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/appservice:webapps", []string{"azure_webapp"}, len(assets))
	}
	if ok, assets := appendOrLog(ctx, &result, "storage", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectStorage(ctx, cred, subscriptionID, now)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/storage:accounts", []string{"azure_storage_account"}, len(assets))
	}
	if ok, assets := appendOrLog(ctx, &result, "sql", func() ([]asset.Asset, []asset.Edge, error) {
		return collectSQL(ctx, cred, subscriptionID, now)
	}); ok {
		// Only azure_sql_server is claimed: the per-server database pager
		// (sql.go) is itself best-effort and silently `break`s on a page
		// error instead of propagating it, so a nil error from collectSQL
		// does NOT prove every server's database list was fully read.
		result.MarkComplete(subscriptionID+"/sql:servers", []string{"azure_sql_server"},
			countTypes(assets, "azure_sql_server"))
	}
	// Managed disks — internet-exportability + orphaned-disk posture.
	if ok, assets := appendOrLog(ctx, &result, "disks", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectDisks(ctx, cred, subscriptionID, now)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/compute:disks", []string{"azure_disk"}, len(assets))
	}
	// Identity / RBAC — best-effort: feeds the CIEM privesc analyzer and lets the
	// ExecutesAs correlator resolve VM→managed-identity. A missing Microsoft.
	// Authorization read permission must not abort the whole subscription sync.
	//
	// execRoleTargets: every "azure_managed_identity:<id>" already written into
	// an exec_role by a collector run above (VMs, web apps) — passed through so
	// a managed identity with zero role assignments still gets an asset (see
	// collectIdentities' doc comment). Collected here, after those collectors
	// ran and before this one, specifically so it reflects everything gathered
	// this sweep, not a stale prior one. It only ever ADDS entries sourced from
	// this same sweep's own in-memory data (never an independent, possibly
	// truncated, external listing), so it cannot undermine the completeness
	// claim below — both role-definition and role-assignment pagers fully
	// read or error out, with no per-page error swallowed.
	var rbac *rbacListing
	if ok, assets := appendOrLog(ctx, &result, "identities", func() ([]asset.Asset, []asset.Edge, error) {
		ids, listing, err := collectIdentities(ctx, cred, subscriptionID, now, execRoleTargets(result.Assets))
		if err == nil {
			rbac = &listing
		}
		return ids, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/authorization:identities", []string{"azure_service_principal"},
			countTypes(assets, "azure_service_principal"))
	}
	if ok, assets := appendOrLog(ctx, &result, "keyvaults", func() ([]asset.Asset, []asset.Edge, error) {
		assets, err := collectKeyVaults(ctx, cred, subscriptionID, now)
		return assets, nil, err
	}); ok {
		result.MarkComplete(subscriptionID+"/keyvault:vaults", []string{keyVaultType}, len(assets))
	}

	// Subscription-wide settings: RBAC facts, Defender for Cloud, Azure
	// Monitor, resource logging, and the Entra joins — one asset, one finding
	// per setting. Each contributing read is best-effort and leaves only its
	// own keys absent when it fails.
	sub := newSettingsAsset()
	if rbac != nil {
		sub.set(subscriptionRBACSettings(*rbac, subscriptionID))
	}
	armc, err := newARMRestClient(cred, readOnlyARM())
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("azure ARM REST client unavailable")
	}
	collectDefender(ctx, cred, armc, subscriptionID, sub)
	collectMonitor(ctx, cred, subscriptionID, sub)
	if completeTypes(result)["azure_webapp"] {
		sub.set(map[string]string{"app_service_count": strconv.Itoa(countTypes(result.Assets, "azure_webapp"))})
	}
	if list, err := armDiagLister(cred); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("azure resource logging rollup skipped; CIS 6.1.4 is unknown")
	} else if kv, err := resourceLoggingSettings(ctx, list, result); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("azure resource logging rollup skipped; CIS 6.1.4 is unknown")
	} else {
		sub.set(kv)
	}
	// Entra tenant settings. The tenant asset is missing only when the tenant
	// ID cannot be resolved, which appendOrLog reports as a partial sweep.
	var facts entraFacts
	appendOrLog(ctx, &result, "entra tenant", func() ([]asset.Asset, []asset.Edge, error) {
		tenant, f, err := collectTenant(ctx, cred, cfg, subscriptionID, now)
		if err != nil {
			return nil, nil, err
		}
		facts = f
		// Lets a purge of this subscription's connector find the tenant asset
		// it shares (internal/app/connector PurgeAndDelete).
		sub.set(map[string]string{tenantSettingsAccountKey: tenant.AccountID})
		return []asset.Asset{tenant}, nil, nil
	})
	sub.set(subscriptionEntraJoins(rbac, facts, assetIDs(result.Assets, "azure_vm"), subscriptionID))
	result.Assets = append(result.Assets, sub.subscriptionAsset(subscriptionID, now))
	// The subscription asset is always emitted, so its enumeration is always
	// complete; an unread setting is an absent key, not a missing asset.
	result.MarkComplete(subscriptionID+"/authorization:subscription", []string{"azure_subscription"}, 1)
	// Resource-service posture (resources_posture.go): WAF policies, VPN
	// gateways, AKS, Databricks, locks, Network Watcher and Bastion.
	collectResourcePosture(ctx, &result, cred, subscriptionID, now)

	return result, nil
}

// assetIDs returns the IDs of assets of type t.
func assetIDs(assets []asset.Asset, t string) []string {
	var out []string
	for _, a := range assets {
		if a.Type == t {
			out = append(out, a.ID)
		}
	}
	return out
}

// execRoleTargets returns the distinct exec_role values already stamped onto
// this sweep's collected assets (VMs, web apps) — the managed identities a
// workload declares it runs as, whether or not anything has been granted to
// them yet. Feeds collectIdentities so a zero-permission identity still gets
// an asset; see that function's doc comment for why.
func execRoleTargets(assets []asset.Asset) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range assets {
		target := a.Metadata["exec_role"]
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

// appendOrLog runs fn, appends its result to result on success, and reports
// whether it succeeded (and the assets it fetched) so a caller can make a
// completeness claim next to the same success check — never separately from
// it, or the claim could drift out of sync with the error handling that makes
// it true.
func appendOrLog(ctx context.Context, result *collect.Result, name string, fn func() ([]asset.Asset, []asset.Edge, error)) (ok bool, assets []asset.Asset) {
	assets, edges, err := fn()
	if err != nil {
		// Partial MUST be set here. SyncWorker treats !res.Partial as proof of a
		// complete enumeration and, on that basis, prunes the connector's asset
		// hashes and RESOLVES THE FINDINGS of every asset the sweep did not return
		// (internal/jobs/sync.go, "absent≠deleted"). Skipping a family without
		// flagging it therefore reports a permission gap or a transient Azure error
		// as "these resources were deleted" and auto-resolves live findings on them.
		//
		// GCP's equivalent (bestEffort) and AWS's (skip) set it the same way.
		result.Partial = true
		log.FromContext(ctx).Warn().Err(err).Str("service", name).Msg("azure collection skipped")
		return false, nil
	}
	result.Assets = append(result.Assets, assets...)
	result.Edges = append(result.Edges, edges...)
	return true, assets
}

// isPermanentAzureErr reports whether err is an Azure auth failure that
// retrying cannot fix (401 Unauthorized, 403 Forbidden).
func isPermanentAzureErr(err error) bool {
	respErr, ok := errors.AsType[*azcore.ResponseError](err)
	if !ok {
		return false
	}
	return respErr.StatusCode == http.StatusUnauthorized ||
		respErr.StatusCode == http.StatusForbidden
}
