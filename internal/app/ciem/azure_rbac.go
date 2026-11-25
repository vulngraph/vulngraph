package ciem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// azureRBACSource marks permissions derived from subscription ARM RBAC — the only
// Azure authorization plane any collector reads today.
const azureRBACSource = "azure-rbac"

// azureGraphTechniques are the Azure techniques whose RequiredActions are Microsoft
// Graph application permissions ("Application.ReadWrite.All"), not ARM actions
// ("Microsoft.Authorization/roleAssignments/write"). The two are separate
// authorization planes: an ARM role assignment grants nothing in the Entra ID
// directory, however wide it is.
//
// They are listed rather than inferred from the action strings because the shapes
// collide — a GCP permission ("resourcemanager.projects.setIamPolicy") is also
// dotted with no slash, and getting that wrong would silence GCP rules.
var azureGraphTechniques = map[string]bool{
	"azure-privesc-08": true, // Application.ReadWrite.All
	"azure-privesc-09": true, // AppRoleAssignment.ReadWrite.All
	"azure-privesc-10": true, // RoleManagement.ReadWrite.Directory
	"azure-privesc-11": true, // GroupMember.ReadWrite.All
	"azure-privesc-12": true, // Application/ServicePrincipalEndpoint.ReadWrite.All
	"azure-privesc-13": true, // DelegatedPermissionGrant.ReadWrite.All
	"azure-privesc-14": true, // User.ReadWrite.All + RoleManagement.ReadWrite.Directory
}

// azureRulesInScope drops the Graph-plane techniques when every permission the
// principal holds came from ARM RBAC.
//
// Owner and Contributor are defined with Actions ["*"], and "*" matches any
// string — including a Graph permission name — so without this, every
// wildcard ARM role would fire all seven Graph techniques at critical.
// Nothing collects Graph permissions yet (Entra ID needs the Graph API and its
// own collector), so these rules go correctly dark instead, and light up on
// their own once a collector emits permissions from that plane.
func azureRulesInScope(rules []PrivescRule, perms []EffectivePermission) []PrivescRule {
	for _, p := range perms {
		if p.SourcePolicy != azureRBACSource {
			return rules // some other plane is represented; trust the catalogue
		}
	}
	out := make([]PrivescRule, 0, len(rules))
	for _, r := range rules {
		if !azureGraphTechniques[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// AzureRoleGrant is one role assignment of an Azure principal, kept whole.
//
// It is the wire contract between the Azure collector (which marshals a slice of
// these into asset Metadata["role_grants"]) and buildAzurePermissions, which
// turns each grant into its own independently-evaluated Grant. Defined here, in
// the package that consumes it, so the two sides cannot drift — the same reason
// the AWS collector reuses this package's evaluator rather than approximating it.
type AzureRoleGrant struct {
	Role             string   `json:"role"`
	Scope            string   `json:"scope"`
	Actions          []string `json:"actions"`
	NotActions       []string `json:"not_actions,omitempty"`
	DataActions      []string `json:"data_actions,omitempty"`
	NotDataActions   []string `json:"not_data_actions,omitempty"`
	Condition        string   `json:"condition,omitempty"`
	ConditionVersion string   `json:"condition_version,omitempty"`
	// EvidenceComplete distinguishes current collection from legacy grants
	// that discarded conditions or merged control and data-plane actions.
	EvidenceComplete bool `json:"evidence_complete,omitempty"`
}

// MarshalAzureRoleGrants renders grants for asset Metadata["role_grants"].
// Empty input yields "" so the collector never writes a useless "null".
func MarshalAzureRoleGrants(grants []AzureRoleGrant) (string, error) {
	if len(grants) == 0 {
		return "", nil
	}
	b, err := json.Marshal(grants)
	if err != nil {
		return "", fmt.Errorf("MarshalAzureRoleGrants: %w", err)
	}
	return string(b), nil
}

// parseAzureRoleGrants reads the metadata blob back. A malformed blob returns an
// error so the caller can fall back to the flattened form rather than silently
// treating the principal as having no permissions at all.
func parseAzureRoleGrants(raw string) ([]AzureRoleGrant, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var grants []AzureRoleGrant
	if err := json.Unmarshal([]byte(raw), &grants); err != nil {
		return nil, fmt.Errorf("parseAzureRoleGrants: %w", err)
	}
	return grants, nil
}

// buildAzurePermissions converts an Azure principal's RBAC into
// EffectivePermissions. Azure grants an action iff some role's Actions match it
// AND that same role's NotActions do not — so Actions become Allow entries,
// NotActions become Deny entries, and each assignment gets its own Grant tag so
// the deny-aware matcher (principalHasAllActions) keeps them from bleeding into
// each other. This is why Azure cannot reuse the AWS set-subtraction evaluator:
// subtracting a NotAction pattern from a wildcard Action (e.g. Contributor's "*")
// is not expressible as set difference over wildcards.
//
// Two input forms are accepted. PolicyAzureRoleGrants carries the per-role
// structure and is preferred. The flattened PolicyIdentity +
// PolicyAzureNotActions pair is legacy input when role_grants is absent or
// unparseable. Its exclusion union cannot be assigned back to individual roles,
// so the fallback retains Allow candidates and requires an inventory refresh.
func buildAzurePermissions(p Principal) []EffectivePermission {
	var perms []EffectivePermission
	add := func(action, effect, grant, scope string) {
		if action = strings.TrimSpace(action); action == "" {
			return
		}
		perms = append(perms, EffectivePermission{
			Action: action, Resource: scope, Effect: effect,
			Grant: grant, SourcePolicy: azureRBACSource, Approximate: true,
		})
	}

	var flatAllow []string
	structured := false
	for policyIndex, pol := range p.Policies {
		switch pol.Type {
		case PolicyAzureRoleGrants:
			grants, err := parseAzureRoleGrants(pol.Document)
			if err != nil {
				continue // fall back to the flattened pair below
			}
			structured = structured || grants != nil
			for i, g := range grants {
				// Two assignments of the same role at different scopes are separate
				// grants; the index keeps even two identical ones apart.
				grant := strconv.Itoa(policyIndex) + ":" + strconv.Itoa(i) + ":" + g.Role + "@" + g.Scope
				scope, known := normalizeAzureScope(g.Scope)
				if !known {
					scope = "*" // retain candidate actions, never authority proof
				}
				// Deny assignments are not collected. Even an unconditional,
				// fully read role assignment is only an allow-side candidate;
				// it cannot prove current unrestricted authority.
				for _, a := range g.Actions {
					add(a, EffectAllow, grant, scope)
				}
				// Old structured grants also mixed NotDataActions into this
				// field. Incomplete evidence cannot prove an ARM exclusion.
				if g.EvidenceComplete {
					for _, na := range g.NotActions {
						add(na, EffectDeny, grant, scope)
					}
				}
			}
		case PolicyAzureNotActions:
			// Flattened exclusions lost their assignment identity. Applying
			// their union could erase an action another role grants. Retain
			// candidates until structured inventory can be refreshed.
		default:
			flatAllow = append(flatAllow, strings.Split(pol.Document, ",")...)
		}
	}
	if structured {
		return perms
	}
	for _, a := range flatAllow {
		add(a, EffectAllow, "", "*")
	}
	return perms
}
