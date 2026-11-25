package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// collectTenant assembles the azure_tenant_settings asset (Graph reads plus
// the tenant-level ARM reads: Entra and Intune diagnostic settings, the
// subscription tenant-transfer policy) and returns the per-user Graph facts
// for the subscription joins. It errors only when the tenant or the
// connector's application cannot be resolved — without them there is no
// asset key to attach anything to.
func collectTenant(ctx context.Context, cred azcore.TokenCredential, cfg map[string]string, subscriptionID string, now time.Time) (asset.Asset, entraFacts, error) {
	tenantID, err := resolveTenantID(ctx, cred, cfg, subscriptionID)
	if err != nil {
		return asset.Asset{}, entraFacts{}, fmt.Errorf("collectTenant: %w", err)
	}
	appID, err := resolveAppID(ctx, cred, cfg)
	if err != nil {
		return asset.Asset{}, entraFacts{}, fmt.Errorf("collectTenant: %w", err)
	}
	tenant := newSettingsAsset()
	facts := collectEntra(ctx, newGraphClient(cred, nil), tenant)

	if armc, err := newARMRestClient(cred, readOnlyARM()); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("azure tenant ARM client unavailable")
	} else {
		if kv, err := tenantDiagnosticSettings(ctx, armc, aadDiagnosticSettingsPath, entraDiagSettings); err != nil {
			logGraphSkip(ctx, "Entra diagnostic settings", err)
		} else {
			tenant.set(kv)
		}
		if kv, err := tenantDiagnosticSettings(ctx, armc, intuneDiagnosticSettingsPath, intuneDiagSettings); err != nil {
			logGraphSkip(ctx, "Intune diagnostic settings", err)
		} else {
			tenant.set(kv)
		}
	}
	if kv, err := tenantTransferPolicy(ctx, cred); err != nil {
		logGraphSkip(ctx, "subscription tenant policy", err)
	} else {
		tenant.set(kv)
	}
	return tenant.tenantAsset(tenantSettingsKey(tenantID, appID), tenantID, now), facts, nil
}

// resolveTenantID prefers the connector's configured tenant and falls back to
// the subscription's home tenant (readable with Reader).
func resolveTenantID(ctx context.Context, cred azcore.TokenCredential, cfg map[string]string, subscriptionID string) (string, error) {
	if t := cfg["tenant_id"]; t != "" {
		return t, nil
	}
	c, err := armsubscriptions.NewClient(cred, readOnlyARM())
	if err != nil {
		return "", fmt.Errorf("resolveTenantID: %w", err)
	}
	sub, err := c.Get(ctx, subscriptionID, nil)
	if err != nil {
		return "", fmt.Errorf("resolveTenantID: %w", err)
	}
	if sub.TenantID == nil || *sub.TenantID == "" {
		return "", fmt.Errorf("resolveTenantID: subscription %s has no tenant id", subscriptionID)
	}
	return *sub.TenantID, nil
}

// tenantSettingsKey is the tenant settings asset's ID and account ID: one per
// tenant AND connector application. Connectors sharing an app registration
// see the same Graph permissions, so they write identical keys; keying by
// tenant alone let connectors with different consent overwrite each other's
// view of the tenant every sweep.
func tenantSettingsKey(tenantID, appID string) string {
	return "azure-tenant:" + strings.ToLower(tenantID) + ":" + strings.ToLower(appID)
}

// resolveAppID is the connector's application (client) ID: the configured
// client_id, else the appid/azp claim of the token the credential issues
// (Workload Identity and other ambient credentials configure no client_id).
func resolveAppID(ctx context.Context, cred azcore.TokenCredential, cfg map[string]string) (string, error) {
	if id := cfg["client_id"]; id != "" {
		return id, nil
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: graphScopes})
	if err != nil {
		return "", fmt.Errorf("resolveAppID: %w", err)
	}
	id := tokenAppID(tok.Token)
	if id == "" {
		return "", fmt.Errorf("resolveAppID: token carries no appid/azp claim")
	}
	return id, nil
}

// tokenAppID reads the appid (v1) or azp (v2) claim of a JWT access token the
// credential just issued. The signature is not checked: the token is our own,
// and the claim only names an asset key.
func tokenAppID(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		AppID string `json:"appid"`
		AZP   string `json:"azp"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	if c.AppID != "" {
		return c.AppID
	}
	return c.AZP
}

// Tenant-scope diagnostic settings (no SDK module covers these providers).
const (
	aadDiagnosticSettingsPath    = "/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
	intuneDiagnosticSettingsPath = "/providers/Microsoft.Intune/diagnosticSettings?api-version=2017-04-01-preview"
)

// tenantDiagSetting is one tenant-scope diagnostic setting.
type tenantDiagSetting struct {
	Properties struct {
		WorkspaceID                 string `json:"workspaceId"`
		StorageAccountID            string `json:"storageAccountId"`
		EventHubAuthorizationRuleID string `json:"eventHubAuthorizationRuleId"`
		Logs                        []struct {
			Category string `json:"category"`
			Enabled  bool   `json:"enabled"`
		} `json:"logs"`
	} `json:"properties"`
}

func tenantDiagnosticSettings(ctx context.Context, c *restClient, path string, render func([]tenantDiagSetting) map[string]string) (map[string]string, error) {
	settings, err := listAll[tenantDiagSetting](ctx, c, path, nil)
	if err != nil {
		return nil, fmt.Errorf("tenantDiagnosticSettings: %w", err)
	}
	return render(settings), nil
}

// entraDiagSettings: the Entra log categories exported anywhere (CIS 6.1.1.7,
// 6.1.1.8 accept any destination).
func entraDiagSettings(settings []tenantDiagSetting) map[string]string {
	return map[string]string{"entra_diag_categories": diagCategories(settings, false)}
}

// intuneDiagSettings: the Intune log categories sent to a Log Analytics
// workspace (CIS 6.1.1.9 names Log Analytics as the destination).
func intuneDiagSettings(settings []tenantDiagSetting) map[string]string {
	return map[string]string{"intune_diag_workspace_categories": diagCategories(settings, true)}
}

func diagCategories(settings []tenantDiagSetting, workspaceOnly bool) string {
	cats := set()
	for _, s := range settings {
		p := s.Properties
		if workspaceOnly && p.WorkspaceID == "" {
			continue
		}
		if p.WorkspaceID == "" && p.StorageAccountID == "" && p.EventHubAuthorizationRuleID == "" {
			continue
		}
		for _, l := range p.Logs {
			if l.Enabled && l.Category != "" {
				cats[l.Category] = struct{}{}
			}
		}
	}
	return strings.Join(sortedKeys(cats), ",")
}

// tenantTransferPolicy reads CIS 5.6: may subscriptions leave or enter this
// tenant. An unset flag is the documented default (not blocked).
func tenantTransferPolicy(ctx context.Context, cred azcore.TokenCredential) (map[string]string, error) {
	c, err := armsubscription.NewPolicyClient(cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("tenantTransferPolicy: %w", err)
	}
	resp, err := c.GetPolicyForTenant(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("tenantTransferPolicy: %w", err)
	}
	return tenantPolicySettings(resp.Properties), nil
}

func tenantPolicySettings(p *armsubscription.TenantPolicy) map[string]string {
	if p == nil {
		return nil
	}
	return map[string]string{
		"subscriptions_leaving_tenant_blocked":  strconv.FormatBool(p.BlockSubscriptionsLeavingTenant != nil && *p.BlockSubscriptionsLeavingTenant),
		"subscriptions_entering_tenant_blocked": strconv.FormatBool(p.BlockSubscriptionsIntoTenant != nil && *p.BlockSubscriptionsIntoTenant),
	}
}

// Built-in roles that administer a virtual machine (CIS 3.1.1): full control
// of it, or administrator sign-in to its OS.
var privilegedVMRoleGUIDs = map[string]string{
	ownerRoleGUID:                          "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
	"1c0163c0-47e6-4577-8991-ea5c82e286e4": "Virtual Machine Administrator Login",
}

// subscriptionEntraJoins renders the subscription facts that need both the
// RBAC listing and Entra user data: disabled users still holding a role (CIS
// 5.3.5) and users with a VM-administering role who are not MFA capable (CIS
// 3.1.1). Each key is written only when every input it reads was fully read.
//
// Group assignments are not expanded (membership needs GroupMember.Read.All
// and transitive reads), so a disabled user or a non-MFA user reaching a role
// only through a group is not reported — stated in the matrix reason.
func subscriptionEntraJoins(l *rbacListing, f entraFacts, vmIDs []string, subscriptionID string) map[string]string {
	if l == nil {
		return nil
	}
	out := map[string]string{}
	subScope := "/subscriptions/" + subscriptionID
	if f.disabledUsers != nil {
		held := set()
		for _, ra := range l.assignments {
			if upn, ok := f.disabledUsers[ra.principalID]; ok && ra.principalType == "User" {
				held[labelUser(upn, ra.principalID)+" ("+roleName(l, ra)+")"] = struct{}{}
			}
		}
		out["disabled_users_with_roles_count"] = strconv.Itoa(len(held))
		out["disabled_users_with_roles"] = sample(sortedKeys(held))
	}
	if f.disabledUsers != nil && f.mfa != nil {
		noMFA := set()
		for _, ra := range l.assignments {
			role, privileged := privilegedVMRoleGUIDs[roleGUID(ra.roleDefID)]
			if !privileged || ra.principalType != "User" || !reachesAnyVM(ra.scope, subScope, vmIDs) {
				continue
			}
			if _, disabled := f.disabledUsers[ra.principalID]; disabled {
				continue
			}
			r, known := f.mfa[ra.principalID]
			if !known || r.IsMfaCapable {
				continue // a user missing from the report is unknown, not a gap
			}
			noMFA[labelUser(r.UserPrincipalName, ra.principalID)+" ("+role+")"] = struct{}{}
		}
		out["privileged_vm_users_without_mfa_count"] = strconv.Itoa(len(noMFA))
		out["privileged_vm_users_without_mfa"] = sample(sortedKeys(noMFA))
	}
	return out
}

// reachesAnyVM reports whether an assignment at scope applies to at least one
// collected VM: it is at or above the subscription, or a prefix of a VM's
// resource ID (its resource group or the VM itself).
func reachesAnyVM(scope, subScope string, vmIDs []string) bool {
	if len(vmIDs) == 0 {
		return false
	}
	if coversSubscription(scope, subScope) {
		return true
	}
	s := strings.ToLower(strings.TrimSuffix(scope, "/"))
	for _, id := range vmIDs {
		v := strings.ToLower(id)
		if v == s || strings.HasPrefix(v, s+"/") {
			return true
		}
	}
	return false
}

func labelUser(upn, id string) string {
	if upn != "" {
		return upn
	}
	return id
}

func roleName(l *rbacListing, ra roleAssignment) string {
	if d, ok := l.defs[ra.roleDefID]; ok && d.name != "" {
		return d.name
	}
	return roleGUID(ra.roleDefID)
}
