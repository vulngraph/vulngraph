package azure

import (
	"strconv"
	"strings"
)

// Built-in role definition GUIDs, identical in every tenant.
const (
	ownerRoleGUID                   = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	userAccessAdministratorRoleGUID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
)

// subscriptionRBACSettings renders the subscription-wide RBAC facts CIS asks
// about (5.3.3, 5.4, 5.7) onto the subscription settings asset. These are
// properties of the subscription, not of any one principal, so they produce one
// finding on the subscription rather than one per assignment.
//
// It is only ever called with a fully read role-definition and role-assignment
// listing (collectIdentities returns an error on any page failure), so a zero
// owner count or an empty list here is an observation. The assignment listing
// is ListForSubscription without a filter, which ARM documents as returning the
// assignments at, above and below the subscription — inherited management-group
// and root ("/") assignments included. The role-definition listing returns every
// definition "applicable at scope and above", so a custom role defined at an
// ancestor management group is in it.
func subscriptionRBACSettings(l rbacListing, subscriptionID string) map[string]string {
	subScope := "/subscriptions/" + subscriptionID
	owners := set()
	rootUAA := set()
	for _, ra := range l.assignments {
		switch roleGUID(ra.roleDefID) {
		case ownerRoleGUID:
			if coversSubscription(ra.scope, subScope) {
				owners[principalLabel(ra)] = struct{}{}
			}
		case userAccessAdministratorRoleGUID:
			// Root scope is "elevated access": UAA over every subscription and
			// management group in the tenant.
			if ra.scope == "/" {
				rootUAA[principalLabel(ra)] = struct{}{}
			}
		}
	}
	customOwners := set()
	customRoles, lockAdminRoles := 0, 0
	for _, def := range l.defs {
		if isCustomOwnerRole(def, subScope) {
			customOwners[def.name] = struct{}{}
		}
		if isCustomRoleAt(def, subScope) {
			customRoles++
			if grantsLockAdministration(def) {
				lockAdminRoles++
			}
		}
	}
	return map[string]string{
		"owner_count":             strconv.Itoa(len(owners)),
		"owners":                  strings.Join(sortedKeys(owners), ","),
		"root_user_access_admins": strings.Join(sortedKeys(rootUAA), ","),
		"custom_owner_roles":      strings.Join(sortedKeys(customOwners), ","),
		"custom_role_count":       strconv.Itoa(customRoles),
		"custom_lock_admin_roles": strconv.Itoa(lockAdminRoles),
	}
}

// isCustomRoleAt reports whether def is a custom role assignable at this
// subscription or above it.
func isCustomRoleAt(def roleDef, subScope string) bool {
	if def.roleType != "CustomRole" {
		return false
	}
	for _, s := range def.assignableScopes {
		if coversSubscription(s, subScope) {
			return true
		}
	}
	return false
}

// grantsLockAdministration reports whether def lists an action under
// Microsoft.Authorization/locks/. A bare "*" or "Microsoft.Authorization/*"
// does not count: the role must name the lock actions.
func grantsLockAdministration(def roleDef) bool {
	for _, a := range def.actions {
		if strings.HasPrefix(strings.ToLower(a), "microsoft.authorization/locks/") {
			return true
		}
	}
	return false
}

// isCustomOwnerRole reports whether def is a custom role granting every action
// ("*") that can be assigned at this subscription or above it — a home-made
// subscription Owner (CIS 5.4).
func isCustomOwnerRole(def roleDef, subScope string) bool {
	if def.roleType != "CustomRole" {
		return false
	}
	wildcard := false
	for _, a := range def.actions {
		if a == "*" {
			wildcard = true
			break
		}
	}
	if !wildcard {
		return false
	}
	for _, s := range def.assignableScopes {
		if coversSubscription(s, subScope) {
			return true
		}
	}
	return false
}

// coversSubscription reports whether an RBAC scope is the subscription itself
// or one of its ancestors (a management group or the tenant root). Resource
// group and resource scopes are below it and do not make anyone a
// subscription owner.
func coversSubscription(scope, subScope string) bool {
	s := strings.ToLower(strings.TrimSuffix(scope, "/"))
	return scope == "/" || s == strings.ToLower(subScope) ||
		strings.HasPrefix(s, "/providers/microsoft.management/managementgroups/")
}

// roleGUID is the trailing GUID of a role definition ID, lowercased — the part
// that is the same whichever scope the definition ID was rendered under.
func roleGUID(roleDefID string) string {
	i := strings.LastIndex(roleDefID, "/")
	return strings.ToLower(roleDefID[i+1:])
}

// principalLabel renders "Type:objectID" so the evidence says whether an owner
// is a user, a group (which may hold many people) or a service principal.
func principalLabel(ra roleAssignment) string {
	t := ra.principalType
	if t == "" {
		t = "Unknown"
	}
	return t + ":" + ra.principalID
}
