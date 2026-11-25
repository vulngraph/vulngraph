package ciem

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

const azureReviewSub = "/subscriptions/sub-1"
const azureReviewVM = azureReviewSub + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/critical-vm"
const azureRunCommand = "Microsoft.Compute/virtualMachines/runCommand/action"

func azureEvidenceAsset(t *testing.T, grants ...AzureRoleGrant) asset.Asset {
	t.Helper()
	raw, err := MarshalAzureRoleGrants(grants)
	require.NoError(t, err)
	return asset.Asset{ID: "scope-review", Type: "azure_service_principal", Provider: asset.ProviderAzure, AccountID: "sub-1",
		Metadata: map[string]string{"role_grants": raw}}
}

func TestAzureScope_UnrelatedAuthorityCannotDemoteCandidate(t *testing.T) {
	for _, tc := range []struct {
		name, scope, condition string
		complete               bool
		severity               string
	}{
		{"sibling group", azureReviewSub + "/resourceGroups/dev", "", true, SeverityHigh},
		{"sibling resource", azureReviewSub + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/other-vm", "", true, SeverityHigh},
		{"nested resource", azureReviewVM + "/extensions/agent", "", true, SeverityHigh},
		{"same group is still narrower than subscription", azureReviewSub + "/resourceGroups/prod", "", true, SeverityHigh},
		{"wrong subscription", "/subscriptions/sub-2", "", true, SeverityHigh},
		{"subscription prefix collision", "/subscriptions/sub-10", "", true, SeverityHigh},
		{"management ancestry unknown", "/providers/Microsoft.Management/managementGroups/parent", "", true, SeverityHigh},
		{"missing scope", "", "", true, SeverityHigh},
		{"glob scope is not ARM scope", "*", "", true, SeverityHigh},
		{"legacy condition evidence absent", azureReviewSub, "", false, SeverityHigh},
		{"conditional owner", azureReviewSub, "@Request[roleDefinitionId] ForAnyOfAnyValues:GuidEquals {reader}", true, SeverityHigh},
		{"observed subscription owner", azureReviewSub, "", true, SeverityHigh},
		{"scope casing", strings.ToUpper(azureReviewSub), "", true, SeverityHigh},
		{"trailing slash", azureReviewSub + "/", "", true, SeverityHigh},
		{"known root inheritance", "/", "", true, SeverityHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal := azureEvidenceAsset(t,
				AzureRoleGrant{Role: "VM operator", Scope: azureReviewVM, Actions: []string{azureRunCommand}, EvidenceComplete: true},
				AzureRoleGrant{Role: "Owner", Scope: tc.scope, Actions: []string{"*"}, Condition: tc.condition, EvidenceComplete: tc.complete})
			principal.Metadata["admin"] = "true" // old collector hints cannot override evaluated evidence
			result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
			assertAzureRunSeverity(t, result, tc.severity)
			if tc.severity == SeverityHigh {
				require.NotEqual(t, TierAdmin, result.Tiers[principal.ID].Tier)
			}
		})
	}
}

func TestAzureScope_MixedSubscriptionCandidateStaysHigh(t *testing.T) {
	principal := azureEvidenceAsset(t,
		AzureRoleGrant{Scope: azureReviewSub, Actions: []string{"*"}, EvidenceComplete: true},
		AzureRoleGrant{Scope: "/subscriptions/sub-2/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm", Actions: []string{azureRunCommand}, EvidenceComplete: true})
	result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
	require.NotEqual(t, TierAdmin, result.Tiers[principal.ID].Tier, "allow-only inventory cannot prove current admin")
	assertAzureRunSeverity(t, result, SeverityHigh)
}

func TestAzureScope_SelfGrantNeedsKnownBroadUnconditionalEvidence(t *testing.T) {
	for _, scope := range []string{azureReviewSub, azureReviewSub + "/resourceGroups/dev", "/subscriptions/sub-10", "", "/providers/Microsoft.Management/managementGroups/parent"} {
		for _, complete := range []bool{false, true} {
			for _, condition := range []string{"", "restricted role assignment"} {
				principal := azureEvidenceAsset(t,
					AzureRoleGrant{Scope: azureReviewVM, Actions: []string{azureRunCommand}, EvidenceComplete: true},
					AzureRoleGrant{Scope: scope, Actions: []string{"Microsoft.Authorization/*"}, EvidenceComplete: complete, Condition: condition})
				result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
				assertAzureRunSeverity(t, result, SeverityHigh)
			}
		}
	}
}

func TestAzureScope_ResourceEvidenceAndNotActionsStayLocal(t *testing.T) {
	p := azureEvidenceAsset(t,
		AzureRoleGrant{Role: "restricted", Scope: strings.ToUpper(azureReviewSub), Actions: []string{"*"}, NotActions: []string{azureRunCommand}, EvidenceComplete: true},
		AzureRoleGrant{Role: "operator", Scope: azureReviewVM, Actions: []string{azureRunCommand}, EvidenceComplete: true})
	principal, err := principalFromAsset(p)
	require.NoError(t, err)
	perms := buildAzurePermissions(principal)
	require.Equal(t, []string{strings.ToLower(azureReviewVM)}, AllowedResourceScopes(perms, azureRunCommand))
	require.Equal(t, tierNormal, azurePrincipalTier("sub-1", perms), "uncollected deny assignments prevent authority proof")
	for i := range perms {
		perms[i].Approximate = false // pure helper control: explicitly supplied fully observed permissions
	}
	require.Equal(t, tierSelfGrant, azurePrincipalTier("sub-1", perms), "a narrow grant cannot restore the excluded action across the subscription")
	for _, tc := range []struct {
		parent, child string
		contains      bool
	}{
		{azureReviewSub + "/resourceGroups/dev", azureReviewSub + "/resourceGroups/development", false},
		{azureReviewVM, azureReviewVM + "/extensions/agent", true},
		{strings.ToUpper(azureReviewSub), azureReviewVM, true},
		{azureReviewSub, "/subscriptions/sub-10", false},
		{"/providers/Microsoft.Management/managementGroups/parent", azureReviewSub, false},
		{"", azureReviewSub, false},
		{"/subscriptions/sub-1/../sub-2", azureReviewSub, false},
	} {
		require.Equal(t, tc.contains, azureScopeContains(tc.parent, tc.child), "%s contains %s", tc.parent, tc.child)
	}
}

func TestAzureScope_LegacyFallbackNeverProvesAdmin(t *testing.T) {
	for _, raw := range []string{"", "broken", "null"} {
		principal := asset.Asset{ID: "legacy", Provider: asset.ProviderAzure, Type: "azure_service_principal", AccountID: "sub-1",
			Metadata: map[string]string{"permissions": "*", "role_grants": raw, "roles": "Owner", "admin": "true"}}
		result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
		assertAzureRunSeverity(t, result, SeverityHigh)
		require.NotEqual(t, TierAdmin, result.Tiers[principal.ID].Tier)
	}
}

func TestAzureScope_DataWildcardDoesNotGrantARM(t *testing.T) {
	principal := azureEvidenceAsset(t, AzureRoleGrant{Scope: azureReviewSub, DataActions: []string{"*"}, EvidenceComplete: true})
	principal.Metadata["permissions"] = "*" // stale legacy flattened form must not override valid structured input
	result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
	require.Empty(t, result.Findings)
	require.NotEqual(t, TierAdmin, result.Tiers[principal.ID].Tier)
}

func TestAzureScope_FullyObservedPermissionControls(t *testing.T) {
	for _, tc := range []struct {
		name, scope, action string
		approximate         bool
		want                privilegeTier
	}{
		{"subscription owner", azureReviewSub, "*", false, tierAdmin},
		{"root owner", "/", "*", false, tierAdmin},
		{"case-insensitive ID", strings.ToUpper(azureReviewSub), "*", false, tierAdmin},
		{"subscription self grant", azureReviewSub, "Microsoft.Authorization/*", false, tierSelfGrant},
		{"resource group owner", azureReviewSub + "/resourceGroups/prod", "*", false, tierNormal},
		{"resource group self grant", azureReviewSub + "/resourceGroups/prod", "Microsoft.Authorization/*", false, tierNormal},
		{"unknown management ancestry", "/providers/Microsoft.Management/managementGroups/parent", "*", false, tierNormal},
		{"subscription prefix collision", "/subscriptions/sub-10", "*", false, tierNormal},
		{"unresolved scope", "*", "*", false, tierNormal},
		{"incomplete authority evidence", azureReviewSub, "*", true, tierNormal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			perms := []EffectivePermission{{Action: tc.action, Resource: tc.scope, SourcePolicy: azureRBACSource, Grant: "grant", Approximate: tc.approximate}}
			require.Equal(t, tc.want, azurePrincipalTier("sub-1", perms))
		})
	}
	perms := []EffectivePermission{{Action: "*", Resource: azureReviewSub, SourcePolicy: azureRBACSource, Grant: "owner"}}
	require.True(t, azureTierCoversScopes(tierAdmin, perms, []string{azureReviewVM}))
	require.False(t, azureTierCoversScopes(tierAdmin, perms, []string{azureReviewVM, "/subscriptions/sub-2"}))
	require.False(t, azureTierCoversScopes(tierAdmin, perms, []string{"*"}))
}

func TestAzureScope_LegacyExclusionUnionCannotEraseCandidatesOrCloseFindings(t *testing.T) {
	principal := asset.Asset{ID: "legacy", Provider: asset.ProviderAzure, Type: "azure_service_principal", AccountID: "sub-1",
		Metadata: map[string]string{"permissions": "*,Microsoft.Authorization/*", "not_permissions": "Microsoft.Authorization/*/Write"}}
	result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
	require.Equal(t, TierUnknown, result.Tiers[principal.ID].Tier)
	stamped := []asset.Asset{principal}
	StampTiers(stamped, result.Tiers)
	require.False(t, Graded(stamped[0]), "unresolved cross-role exclusions cannot establish a clean evaluation")
	require.True(t, hasRule(result.Paths, "azure-privesc-01"), "another role may grant what a flattened exclusion removes")
}

func assertAzureRunSeverity(t *testing.T, result AnalysisResult, want string) {
	t.Helper()
	for _, finding := range result.Findings {
		if finding.RuleID == "azure-privesc-03" {
			require.Equal(t, want, finding.Severity, "resources=%v", finding.Resources)
			return
		}
	}
	t.Fatal("VM run-command candidate was lost")
}

func TestAzureScope_LegacyStructuredExclusionsCannotEraseARMActions(t *testing.T) {
	// Old collectors merged NotDataActions into NotActions. This could mean
	// "all ARM actions, no data actions", not "no ARM actions".
	legacy := azureEvidenceAsset(t, AzureRoleGrant{Scope: azureReviewSub, Actions: []string{"*"}, NotActions: []string{"*"}})
	result := AnalyzeIAMAssets(t.Context(), []asset.Asset{legacy})
	assertAzureRunSeverity(t, result, SeverityHigh)
	require.Equal(t, TierUnknown, result.Tiers[legacy.ID].Tier)
	current := azureEvidenceAsset(t, AzureRoleGrant{Scope: azureReviewSub, Actions: []string{"*"}, NotActions: []string{"*"}, EvidenceComplete: true})
	current.Metadata["role_grants_complete"] = "true"
	require.Empty(t, AnalyzeIAMAssets(t.Context(), []asset.Asset{current}).Findings, "a fully observed control-plane exclusion still applies")
}
