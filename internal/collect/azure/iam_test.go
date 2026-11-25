package azure

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

func ptr(s string) *string { return &s }

func TestRolePermissionActions_SeparatesControlAndData(t *testing.T) {
	perms := []*armauthorization.Permission{
		{
			Actions:        []*string{ptr("*")},
			NotActions:     []*string{ptr("Microsoft.Authorization/*/Write"), ptr("Microsoft.Authorization/*/Delete")},
			DataActions:    []*string{ptr("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")},
			NotDataActions: nil,
		},
		nil, // must be skipped without panicking
	}
	actions, notActions := rolePermissionActions(perms)
	require.Contains(t, actions, "*")
	require.NotContains(t, actions, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")
	require.ElementsMatch(t, []string{"Microsoft.Authorization/*/Write", "Microsoft.Authorization/*/Delete"}, notActions)
}

func TestBuildIdentityAssets_UnionsAssignedRoles(t *testing.T) {
	now := time.Unix(1720000000, 0).UTC()
	defs := map[string]roleDef{
		"/def/owner":       {name: "Owner", actions: []string{"*"}},
		"/def/reader":      {name: "Reader", actions: []string{"*/read"}},
		"/def/contributor": {name: "Contributor", actions: []string{"*"}, notActions: []string{"Microsoft.Authorization/*/Write"}},
	}
	assignments := []roleAssignment{
		// sp-1 has Owner + Reader across two scopes → union of actions, two roles/scopes.
		{principalID: "sp-1", roleDefID: "/def/owner", scope: "/subscriptions/s"},
		{principalID: "sp-1", roleDefID: "/def/reader", scope: "/subscriptions/s/resourceGroups/rg"},
		// sp-2 has Contributor only → carries NotActions.
		{principalID: "sp-2", roleDefID: "/def/contributor", scope: "/subscriptions/s"},
		// an unresolved role definition remains uncertain evidence.
		{principalID: "sp-2", roleDefID: "/def/missing", scope: "/subscriptions/s"},
	}

	assets, err := buildIdentityAssets(assignments, defs, "sub-123", now, nil)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	// Sorted by ID: "azure_managed_identity:sp-1" < ":sp-2".
	sp1, sp2 := assets[0], assets[1]
	require.Equal(t, "azure_managed_identity:sp-1", sp1.ID)
	require.Equal(t, "azure_service_principal", sp1.Type)
	require.Equal(t, "sub-123", sp1.AccountID)
	require.ElementsMatch(t, []string{"*", "*/read"}, splitCSV(sp1.Metadata["permissions"]))
	require.ElementsMatch(t, []string{"Owner", "Reader"}, splitCSV(sp1.Metadata["roles"]))
	require.Len(t, splitCSV(sp1.Metadata["scopes"]), 2)

	require.Equal(t, "azure_managed_identity:sp-2", sp2.ID)
	require.Equal(t, []string{"Microsoft.Authorization/*/Write"}, splitCSV(sp2.Metadata["not_permissions"]))
	require.Equal(t, []string{"Contributor"}, splitCSV(sp2.Metadata["roles"]))

	// Each assignment must also survive whole, sorted by role then scope: the union
	// above is display data, and on a multi-role principal it is the form that lets
	// one role's NotActions cancel another role's grant.
	var grants []ciem.AzureRoleGrant
	require.NoError(t, json.Unmarshal([]byte(sp1.Metadata["role_grants"]), &grants))
	require.Equal(t, []ciem.AzureRoleGrant{
		{Role: "Owner", Scope: "/subscriptions/s", Actions: []string{"*"}},
		{Role: "Reader", Scope: "/subscriptions/s/resourceGroups/rg", Actions: []string{"*/read"}},
	}, grants)

	var sp2Grants []ciem.AzureRoleGrant
	require.NoError(t, json.Unmarshal([]byte(sp2.Metadata["role_grants"]), &sp2Grants))
	require.Equal(t, []ciem.AzureRoleGrant{{Role: "/def/missing", Scope: "/subscriptions/s"}, {
		Role:       "Contributor",
		Scope:      "/subscriptions/s",
		Actions:    []string{"*"},
		NotActions: []string{"Microsoft.Authorization/*/Write"},
	}}, sp2Grants)
}

// TestBuildIdentityAssets_GrantsAreStable pins the sort: assignments arrive in ARM
// paging order, and an unstable role_grants blob would rewrite the asset's sync
// fingerprint on every sweep.
func TestBuildIdentityAssets_GrantsAreStable(t *testing.T) {
	now := time.Unix(1720000000, 0).UTC()
	defs := map[string]roleDef{
		"/def/a": {name: "Alpha", actions: []string{"a/read"}},
		"/def/z": {name: "Zeta", actions: []string{"z/read"}},
	}
	forward := []roleAssignment{
		{principalID: "sp-1", roleDefID: "/def/a", scope: "/subscriptions/s"},
		{principalID: "sp-1", roleDefID: "/def/z", scope: "/subscriptions/s"},
	}
	reversed := []roleAssignment{forward[1], forward[0]}

	a, err := buildIdentityAssets(forward, defs, "sub-123", now, nil)
	require.NoError(t, err)
	b, err := buildIdentityAssets(reversed, defs, "sub-123", now, nil)
	require.NoError(t, err)
	require.Equal(t, a[0].Metadata["role_grants"], b[0].Metadata["role_grants"])
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// A managed identity referenced by a workload's exec_role but with ZERO role
// assignments must still get an asset — it is a real Entra ID principal
// whether or not anything has been granted to it yet. Before this, ExecutesAs
// had nothing to link the workload to, so no executes_as edge from an Azure
// workload to an Azure identity could exist.
func TestBuildIdentityAssets_ZeroPermissionIdentityStillGetsAnAsset(t *testing.T) {
	now := time.Unix(1720000000, 0).UTC()
	defs := map[string]roleDef{
		"/def/owner": {name: "Owner", actions: []string{"*"}},
	}
	assignments := []roleAssignment{
		{principalID: "sp-1", roleDefID: "/def/owner", scope: "/subscriptions/s"},
	}
	// sp-2 has no role assignment at all, but a webapp's exec_role references it.
	execRoleRefs := []string{
		"azure_managed_identity:sp-1",         // already covered by an assignment — must not duplicate
		"azure_managed_identity:sp-2",         // zero grants — must still produce an asset
		"serviceAccount:not-ours@example.iam", // wrong shape — must never fabricate an asset
	}

	assets, err := buildIdentityAssets(assignments, defs, "sub-123", now, execRoleRefs)
	require.NoError(t, err)
	require.Len(t, assets, 2, "sp-1 (from the assignment) and sp-2 (from exec_role only) — no duplicate, no fabricated third asset")

	byID := map[string]asset.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}
	sp2 := byID["azure_managed_identity:sp-2"]
	require.Equal(t, "azure_service_principal", sp2.Type)
	require.Equal(t, "sub-123", sp2.AccountID)
	require.Empty(t, sp2.Metadata["permissions"], "no role assignment means no permissions — correctly empty, not fabricated")
	require.Empty(t, sp2.Metadata["role_grants"])
}
