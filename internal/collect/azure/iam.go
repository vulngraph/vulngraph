package azure

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// collectIdentities enumerates subscription-scope Azure RBAC — role assignments
// and the role definitions they reference — and emits one identity asset per
// service-principal principal, carrying the union of its granted Actions in
// Metadata["permissions"] and NotActions in Metadata["not_permissions"]. This
// feeds the CIEM privilege-escalation analyzer, which resolves each required
// action with a deny-aware matcher (ciem.buildAzurePermissions) so a role's
// NotActions correctly suppress techniques it excludes.
//
// Asset IDs use the "azure_managed_identity:<principalID>" form so they line up
// with the exec_role reference the VM collector writes (vms.go), letting the
// ExecutesAs correlator link a VM to the identity it runs as.
//
// Scope: subscription ARM RBAC only. Entra ID directory-role and Graph
// app-permission techniques (azure-privesc-08..14) need the Microsoft Graph API
// and a separate collector — not covered here.
//
// execRolePrincipals are the "azure_managed_identity:<principalID>" IDs the VM
// and web-app collectors already wrote into Metadata["exec_role"] earlier in
// this same sweep (azure.go's collectAll runs them first). A managed identity
// with zero role assignments is still a real principal, so it must still get
// an asset here — otherwise ExecutesAs has nothing to link the workload to and
// the edge never exists.
//
// It also returns the full listing (every principal type) so the
// subscription-wide RBAC facts and the Entra joins (disabled users, users
// without MFA) are computed from the same fully read pages.
func collectIdentities(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time, execRolePrincipals []string) ([]asset.Asset, rbacListing, error) {
	defsClient, err := armauthorization.NewRoleDefinitionsClient(cred, readOnlyARM())
	if err != nil {
		return nil, rbacListing{}, fmt.Errorf("collectIdentities: role definitions client: %w", err)
	}
	assignClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, rbacListing{}, fmt.Errorf("collectIdentities: role assignments client: %w", err)
	}

	return collectIdentitiesWithClients(ctx, defsClient, assignClient, subscriptionID, now, execRolePrincipals)
}

func collectIdentitiesWithClients(ctx context.Context, defsClient *armauthorization.RoleDefinitionsClient, assignClient *armauthorization.RoleAssignmentsClient, subscriptionID string, now time.Time, execRolePrincipals []string) ([]asset.Asset, rbacListing, error) {
	scope := "/subscriptions/" + subscriptionID

	defs := map[string]roleDef{}
	dp := defsClient.NewListPager(scope, nil)
	for dp.More() {
		page, err := dp.NextPage(ctx)
		if err != nil {
			return nil, rbacListing{}, fmt.Errorf("collectIdentities: list role definitions: %w", err)
		}
		if page.Value == nil {
			return nil, rbacListing{}, fmt.Errorf("collectIdentities: role definition list missing value")
		}
		for _, rd := range page.Value {
			if rd == nil || rd.ID == nil || rd.Properties == nil {
				return nil, rbacListing{}, fmt.Errorf("collectIdentities: incomplete role definition response")
			}
			defs[strings.ToLower(*rd.ID)] = readRoleDefinition(rd.Properties)
		}
	}

	var assignments []roleAssignment
	ap := assignClient.NewListForSubscriptionPager(nil)
	for ap.More() {
		page, err := ap.NextPage(ctx)
		if err != nil {
			return nil, rbacListing{}, fmt.Errorf("collectIdentities: list role assignments: %w", err)
		}
		if page.Value == nil {
			return nil, rbacListing{}, fmt.Errorf("collectIdentities: role assignment list missing value")
		}
		for _, ra := range page.Value {
			if ra == nil || ra.Properties == nil || ra.Properties.PrincipalID == nil || ra.Properties.RoleDefinitionID == nil {
				return nil, rbacListing{}, fmt.Errorf("collectIdentities: incomplete role assignment response")
			}
			assignments = append(assignments, roleAssignment{
				principalID:      *ra.Properties.PrincipalID,
				principalType:    principalTypeOf(ra.Properties.PrincipalType),
				roleDefID:        *ra.Properties.RoleDefinitionID,
				scope:            strVal(ra.Properties.Scope),
				condition:        strVal(ra.Properties.Condition),
				conditionVersion: strVal(ra.Properties.ConditionVersion),
				observed:         ra.Properties.Scope != nil && strVal(ra.Properties.Scope) != "",
			})
		}
	}

	// Only service principals / managed identities are workload identities
	// the CIEM analyzer scores; user/group assignments have no exec path. They
	// still count toward the subscription-wide RBAC facts (rbacListing).
	knownWorkloads := map[string]bool{}
	for _, ref := range execRolePrincipals {
		if pid, ok := strings.CutPrefix(ref, "azure_managed_identity:"); ok && pid != "" {
			knownWorkloads[strings.ToLower(pid)] = true
		}
	}
	var workload []roleAssignment
	for _, ra := range assignments {
		if ra.principalType == "" {
			if !knownWorkloads[strings.ToLower(ra.principalID)] {
				return nil, rbacListing{}, fmt.Errorf("collectIdentities: principal type unknown for %s", ra.principalID)
			}
			workload = append(workload, ra)
		} else if ra.principalType == string(armauthorization.PrincipalTypeServicePrincipal) {
			workload = append(workload, ra)
		}
	}
	assets, err := buildIdentityAssets(workload, defs, subscriptionID, now, execRolePrincipals)
	if err != nil {
		return nil, rbacListing{}, fmt.Errorf("collectIdentities: %w", err)
	}
	return assets, rbacListing{assignments: assignments, defs: defs}, nil
}

// rbacListing is a fully read role-definition and role-assignment listing.
type rbacListing struct {
	assignments []roleAssignment
	defs        map[string]roleDef
}

// roleDef is the resolved action set of one Azure role definition.
type roleDef struct {
	name             string
	roleType         string // "BuiltInRole" or "CustomRole"
	assignableScopes []string
	actions          []string
	notActions       []string
	permissions      []ciem.AzureRoleGrant
	complete         bool
}

// roleAssignment is one principal ⇄ role-definition binding at a scope.
type roleAssignment struct {
	principalID      string
	principalType    string
	roleDefID        string
	scope            string
	condition        string
	conditionVersion string
	observed         bool
}

func principalTypeOf(p *armauthorization.PrincipalType) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

// rolePermissionActions is the control-plane summary for display. DataActions
// grant a different authorization plane and cannot establish ARM authority.
func rolePermissionActions(perms []*armauthorization.Permission) (actions, notActions []string) {
	for _, p := range perms {
		if p == nil {
			continue
		}
		actions = append(actions, derefAll(p.Actions)...)
		notActions = append(notActions, derefAll(p.NotActions)...)
	}
	return actions, notActions
}

// buildIdentityAssets is the pure core: it emits one identity asset per service
// principal, carrying each role assignment whole in Metadata["role_grants"] and
// the union of all of them in the flat permissions pair. Separated from the SDK
// paging so it can be unit-tested.
//
// Both forms are written because they answer different questions: the union is
// what a human reads ("what can this principal touch"), while the per-role list
// is what the CIEM evaluator needs — Azure evaluates each assignment on its own,
// so unioning NotActions across assignments would let one role's exclusions
// wrongly cancel another role's grant. See ciem.EffectivePermission.Grant.
//
// execRolePrincipals ("azure_managed_identity:<id>") get an asset even with zero
// role assignments — see collectIdentities' doc comment for why.
func buildIdentityAssets(assignments []roleAssignment, defs map[string]roleDef, subscriptionID string, now time.Time, execRolePrincipals []string) ([]asset.Asset, error) {
	type acc struct {
		actions, notActions, roles, scopes map[string]struct{}
		grants                             []ciem.AzureRoleGrant
	}
	principals := map[string]*acc{}
	get := func(pid string) *acc {
		pid = strings.ToLower(pid)
		a := principals[pid]
		if a == nil {
			a = &acc{actions: set(), notActions: set(), roles: set(), scopes: set()}
			principals[pid] = a
		}
		return a
	}
	for _, ra := range assignments {
		a := get(ra.principalID)
		def, ok := defs[strings.ToLower(ra.roleDefID)]
		if !ok {
			// Keep the assignment and its unknown definition visible. Another
			// known grant can still produce candidates; no wildcard is invented.
			a.grants = append(a.grants, ciem.AzureRoleGrant{Role: ra.roleDefID, Scope: ra.scope})
			continue
		}
		addAll(a.actions, def.actions)
		addAll(a.notActions, def.notActions)
		blocks := def.permissions
		if len(blocks) == 0 {
			blocks = []ciem.AzureRoleGrant{{Actions: def.actions, NotActions: def.notActions}}
		}
		for _, block := range blocks {
			block.Role, block.Scope = def.name, ra.scope
			block.Condition, block.ConditionVersion = ra.condition, ra.conditionVersion
			block.EvidenceComplete = def.complete && ra.observed
			a.grants = append(a.grants, block)
		}
		if def.name != "" {
			a.roles[def.name] = struct{}{}
		}
		if ra.scope != "" {
			a.scopes[ra.scope] = struct{}{}
		}
	}
	// A referenced identity with no role assignment still needs its own
	// (empty) accumulator, or it never becomes an asset at all.
	const identityPrefix = "azure_managed_identity:"
	for _, ref := range execRolePrincipals {
		if !strings.HasPrefix(ref, identityPrefix) {
			continue // not our ID shape — never fabricate an asset for something we can't parse
		}
		pid := strings.TrimPrefix(ref, identityPrefix)
		if pid == "" {
			continue
		}
		get(pid)
	}

	assets := make([]asset.Asset, 0, len(principals))
	for pid, a := range principals {
		// Assignment order follows ARM paging, which is not guaranteed stable across
		// sweeps; sort so the marshalled blob doesn't churn sync fingerprints.
		sort.Slice(a.grants, func(i, j int) bool {
			if a.grants[i].Role != a.grants[j].Role {
				return a.grants[i].Role < a.grants[j].Role
			}
			if a.grants[i].Scope != a.grants[j].Scope {
				return a.grants[i].Scope < a.grants[j].Scope
			}
			left, _ := ciem.MarshalAzureRoleGrants([]ciem.AzureRoleGrant{a.grants[i]})
			right, _ := ciem.MarshalAzureRoleGrants([]ciem.AzureRoleGrant{a.grants[j]})
			return left < right
		})
		grants, err := ciem.MarshalAzureRoleGrants(a.grants)
		if err != nil {
			return nil, fmt.Errorf("buildIdentityAssets: %s: %w", pid, err)
		}
		assets = append(assets, asset.Asset{
			ID:        managedIdentityID(pid),
			Name:      pid,
			Type:      "azure_service_principal",
			Provider:  asset.ProviderAzure,
			AccountID: subscriptionID,
			Metadata: map[string]string{
				"permissions":          strings.Join(sortedKeys(a.actions), ","),
				"not_permissions":      strings.Join(sortedKeys(a.notActions), ","),
				"roles":                strings.Join(sortedKeys(a.roles), ","),
				"scopes":               strings.Join(sortedKeys(a.scopes), ","),
				"role_grants":          grants,
				"role_grants_complete": fmt.Sprintf("%t", azureGrantsComplete(a.grants)),
			},
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	// Stable output order (map iteration is random) so sync fingerprints don't churn.
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	return assets, nil
}

func derefAll(ss []*string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != nil && *s != "" {
			out = append(out, *s)
		}
	}
	return out
}

func set() map[string]struct{} { return map[string]struct{}{} }

func addAll(m map[string]struct{}, vs []string) {
	for _, v := range vs {
		m[v] = struct{}{}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Principal object IDs are GUIDs; ARM responses may vary their casing. The
// collector and workload references must use the same canonical graph key.
func managedIdentityID(principalID string) string {
	return "azure_managed_identity:" + strings.ToLower(principalID)
}
