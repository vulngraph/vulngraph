package azure

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

func readRoleDefinition(properties *armauthorization.RoleDefinitionProperties) roleDef {
	actions, notActions := rolePermissionActions(properties.Permissions)
	def := roleDef{
		name: strVal(properties.RoleName), roleType: strVal(properties.RoleType),
		assignableScopes: derefAll(properties.AssignableScopes),
		actions:          actions, notActions: notActions, complete: len(properties.Permissions) > 0,
	}
	for _, p := range properties.Permissions {
		if p == nil {
			def.complete = false
			continue
		}
		// A missing exclusion list cannot certify that a wildcard is unrestricted.
		// Data-only definitions may omit Actions, and remain useful stored evidence.
		if p.Actions == nil || p.NotActions == nil || !completeStrings(p.Actions) || !completeStrings(p.NotActions) {
			def.complete = false
		}
		def.permissions = append(def.permissions, ciem.AzureRoleGrant{
			Actions: derefAll(p.Actions), NotActions: derefAll(p.NotActions),
			DataActions: derefAll(p.DataActions), NotDataActions: derefAll(p.NotDataActions),
		})
	}
	return def
}

func completeStrings(values []*string) bool {
	for _, value := range values {
		if value == nil || *value == "" {
			return false
		}
	}
	return true
}

func azureGrantsComplete(grants []ciem.AzureRoleGrant) bool {
	for _, grant := range grants {
		if !grant.EvidenceComplete {
			return false
		}
	}
	return true
}
