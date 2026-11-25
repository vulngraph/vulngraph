package azure

import (
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/stretchr/testify/require"
)

func TestCollectIdentities_CaseVariantsJoinWorkloadGrant(t *testing.T) {
	const principal = "aabbccdd-1122-3344-5566-778899aabbcc"
	for _, missingType := range []bool{false, true} {
		assignment := azureAssignmentWire("operator", azureEvidenceVM, "")
		props := assignment["properties"].(map[string]any)
		props["principalId"] = strings.ToUpper(principal)
		if missingType {
			delete(props, "principalType")
		}
		assets, _, err := collectAzureEvidence(t, map[string]fakeResponse{
			azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleDefinitions": {body: azureWireJSON(t, map[string]any{"value": []any{azureDefinitionWire("operator", []map[string]any{{"actions": []string{azureEvidenceRun}, "notActions": []string{}}})}})},
			azureEvidenceSubscription + "/providers/Microsoft.Authorization/roleAssignments": {body: azureWireJSON(t, map[string]any{"value": []any{assignment}})},
		}, "azure_managed_identity:"+principal, "azure_managed_identity:"+strings.ToUpper(principal))
		require.NoError(t, err)
		require.Len(t, assets, 1, "one GUID is one identity; a case alias must not become a graded empty principal")
		require.Equal(t, "azure_managed_identity:"+principal, assets[0].ID)
		assertAzureCollectorSeverity(t, assets, "high")
	}
}

func TestAzureWorkloads_CanonicalIdentityReference(t *testing.T) {
	const principal = "AABBCCDD-1122-3344-5566-778899AABBCC"
	const want = "azure_managed_identity:aabbccdd-1122-3344-5566-778899aabbcc"
	vm := testVM()
	vm.Identity = &armcompute.VirtualMachineIdentity{PrincipalID: to.Ptr(principal)}
	vmAsset, _ := vmAssetWithNICs(t.Context(), vm, "s", time.Now(), nicsByID(nil), noSubnetNSG)
	require.Equal(t, want, vmAsset.Metadata["exec_role"])

	app := site("app")
	app.Identity = &armappservice.ManagedServiceIdentity{PrincipalID: to.Ptr(principal)}
	client := &fakeWebApps{apps: []*armappservice.Site{app}}
	assets, err := collectWebAppsWith(t.Context(), client, client, "s", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, want, assets[0].Metadata["exec_role"])
}
