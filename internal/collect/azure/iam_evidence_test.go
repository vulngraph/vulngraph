package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

const azureEvidenceSubscription = "/subscriptions/sub-1"
const azureEvidenceVM = azureEvidenceSubscription + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm"
const azureEvidenceRun = "Microsoft.Compute/virtualMachines/runCommand/action"

func TestCollectIdentities_ScopeAndConditionEvidenceReachesCIEM(t *testing.T) {
	for _, tc := range []struct {
		name, ownerScope, condition                    string
		missingExclusions, missingDefinition, dataOnly bool
		wantSeverity                                   string
	}{
		{name: "subscription allow still lacks deny coverage", ownerScope: azureEvidenceSubscription, wantSeverity: ciem.SeverityHigh},
		{name: "sibling group", ownerScope: azureEvidenceSubscription + "/resourceGroups/dev", wantSeverity: ciem.SeverityHigh},
		{name: "conditional owner", ownerScope: azureEvidenceSubscription, condition: "restricted role assignment", wantSeverity: ciem.SeverityHigh},
		{name: "missing exclusions", ownerScope: azureEvidenceSubscription, missingExclusions: true, wantSeverity: ciem.SeverityHigh},
		{name: "unresolved definition", ownerScope: azureEvidenceSubscription, missingDefinition: true, wantSeverity: ciem.SeverityHigh},
		{name: "missing scope", wantSeverity: ciem.SeverityHigh},
		{name: "data wildcard only", ownerScope: azureEvidenceSubscription, dataOnly: true, wantSeverity: ciem.SeverityHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			permission := map[string]any{"actions": []string{"*"}, "notActions": []string{}}
			if tc.missingExclusions {
				delete(permission, "notActions")
			}
			if tc.dataOnly {
				permission["actions"], permission["dataActions"] = []string{}, []string{"*"}
			}
			defs := []any{azureDefinitionWire("operator", []map[string]any{{"actions": []string{azureEvidenceRun}, "notActions": []string{}}})}
			if !tc.missingDefinition {
				defs = append(defs, azureDefinitionWire("owner", []map[string]any{permission}))
			}
			assignments := []any{
				azureAssignmentWire("operator", azureEvidenceVM, ""),
				azureAssignmentWire("OWNER", tc.ownerScope, tc.condition), // role IDs are case-insensitive
			}
			assets, _, err := collectAzureEvidence(t, map[string]fakeResponse{
				azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: azureWireJSON(t, map[string]any{"value": defs})},
				azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: azureWireJSON(t, map[string]any{"value": assignments})},
			})
			require.NoError(t, err)
			require.Len(t, assets, 1)
			var grants []ciem.AzureRoleGrant
			require.NoError(t, json.Unmarshal([]byte(assets[0].Metadata["role_grants"]), &grants))
			if tc.condition != "" {
				require.Contains(t, assets[0].Metadata["role_grants"], tc.condition)
			}
			if tc.missingDefinition || tc.missingExclusions || tc.ownerScope == "" {
				require.Equal(t, "false", assets[0].Metadata["role_grants_complete"])
			}
			if tc.dataOnly {
				require.NotContains(t, strings.Split(assets[0].Metadata["permissions"], ","), "*")
				require.Contains(t, assets[0].Metadata["role_grants"], "data_actions")
			}
			assertAzureCollectorSeverity(t, assets, tc.wantSeverity)
		})
	}
}

func TestCollectIdentities_PartialListingIsAnError(t *testing.T) {
	for _, kind := range []string{"roleDefinitions", "roleAssignments"} {
		responses := map[string]fakeResponse{
			azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: azureWireJSON(t, map[string]any{"value": []any{azureDefinitionWire("owner", []map[string]any{{"actions": []string{"*"}, "notActions": []string{}}})}})},
			azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: azureWireJSON(t, map[string]any{"value": []any{azureAssignmentWire("owner", azureEvidenceSubscription, "")}})},
			"/next": {status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed","message":"denied"}}`},
		}
		responses[azureEvidenceSubscription+"/providers/Microsoft.Authorization/"+kind] = fakeResponse{body: `{"value":[],"nextLink":"https://management.azure.com/next"}`}
		assets, _, err := collectAzureEvidence(t, responses)
		require.Error(t, err)
		require.Empty(t, assets, "a partial page set is never published as complete")
	}
}

func TestCollectIdentities_UnresolvedOnlyDefinitionStaysUnknown(t *testing.T) {
	assets, _, err := collectAzureEvidence(t, map[string]fakeResponse{
		azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: `{"value":[]}`},
		azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: azureWireJSON(t, map[string]any{"value": []any{azureAssignmentWire("missing", azureEvidenceSubscription, "")}})},
	})
	require.NoError(t, err)
	require.Len(t, assets, 1, "an unresolved identity is retained")
	result := ciem.AnalyzeIAMAssets(t.Context(), assets)
	require.Equal(t, ciem.TierUnknown, result.Tiers[assets[0].ID].Tier)
}

func TestCollectIdentities_PermissionBlocksRemainIndependent(t *testing.T) {
	defs := azureDefinitionWire("mixed", []map[string]any{
		{"actions": []string{"*"}, "notActions": []string{azureEvidenceRun}},
		{"actions": []string{azureEvidenceRun}, "notActions": []string{}},
	})
	assets, _, err := collectAzureEvidence(t, map[string]fakeResponse{
		azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: azureWireJSON(t, map[string]any{"value": []any{defs}})},
		azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: azureWireJSON(t, map[string]any{"value": []any{azureAssignmentWire("mixed", azureEvidenceVM, "")}})},
	})
	require.NoError(t, err)
	assertAzureCollectorSeverity(t, assets, ciem.SeverityHigh)
}

func TestCollectIdentities_UnknownPrincipalTypeDoesNotBecomeEmptyGrant(t *testing.T) {
	assignment := azureAssignmentWire("operator", azureEvidenceVM, "")
	delete(assignment["properties"].(map[string]any), "principalType")
	responses := map[string]fakeResponse{
		azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: azureWireJSON(t, map[string]any{"value": []any{azureDefinitionWire("operator", []map[string]any{{"actions": []string{azureEvidenceRun}, "notActions": []string{}}})}})},
		azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: azureWireJSON(t, map[string]any{"value": []any{assignment}})},
	}
	assets, _, err := collectAzureEvidence(t, responses, "azure_managed_identity:sp")
	require.NoError(t, err)
	assertAzureCollectorSeverity(t, assets, ciem.SeverityHigh)
	assets, _, err = collectAzureEvidence(t, responses)
	require.Error(t, err, "an unknown principal class is not an observed empty workload grant")
	require.Empty(t, assets)
	assignment["properties"].(map[string]any)["principalType"] = "User"
	responses[azureEvidenceSubscription+"/providers/Microsoft.Authorization/roleAssignments"] = fakeResponse{body: azureWireJSON(t, map[string]any{"value": []any{assignment}})}
	assets, _, err = collectAzureEvidence(t, responses)
	require.NoError(t, err)
	require.Empty(t, assets, "known users are not manufactured workload identities")
}

func azureDefinitionWire(name string, permissions []map[string]any) map[string]any {
	return map[string]any{"id": "/definitions/" + name, "properties": map[string]any{"roleName": name, "permissions": permissions}}
}

func azureAssignmentWire(role, scope, condition string) map[string]any {
	props := map[string]any{"principalId": "sp", "principalType": "ServicePrincipal", "roleDefinitionId": "/definitions/" + role}
	if scope != "" {
		props["scope"] = scope
	}
	if condition != "" {
		props["condition"], props["conditionVersion"] = condition, "2.0"
	}
	return map[string]any{"properties": props}
}

func azureWireJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return string(raw)
}

func collectAzureEvidence(t *testing.T, responses map[string]fakeResponse, execRefs ...string) ([]asset.Asset, rbacListing, error) {
	t.Helper()
	opts, recorder := fakeOpts(&fakeREST{responses: responses})
	defs, err := armauthorization.NewRoleDefinitionsClient(fakeCred{}, opts)
	require.NoError(t, err)
	assignments, err := armauthorization.NewRoleAssignmentsClient("sub-1", fakeCred{}, opts)
	require.NoError(t, err)
	assets, listing, err := collectIdentitiesWithClients(t.Context(), defs, assignments, "sub-1", time.Now(), execRefs)
	recorder.requireReadOnly(t)
	return assets, listing, err
}

func assertAzureCollectorSeverity(t *testing.T, assets []asset.Asset, want string) {
	t.Helper()
	result := ciem.AnalyzeIAMAssets(t.Context(), assets)
	for _, f := range result.Findings {
		if f.RuleID == "azure-privesc-03" {
			require.Equal(t, want, f.Severity, fmt.Sprint(f.Resources))
			return
		}
	}
	t.Fatal("VM run-command candidate was lost")
}

func TestCollectIdentities_MissingListValueIsNotObservedEmpty(t *testing.T) {
	for _, kind := range []string{"roleDefinitions", "roleAssignments"} {
		responses := map[string]fakeResponse{
			azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: `{"value":[]}`},
			azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: `{"value":[]}`},
		}
		responses[azureEvidenceSubscription+"/providers/Microsoft.Authorization/"+kind] = fakeResponse{body: `{}`}
		assets, _, err := collectAzureEvidence(t, responses, "azure_managed_identity:sp")
		require.Error(t, err)
		require.Empty(t, assets, "an omitted response field cannot clear a known identity's grants")
	}
}
