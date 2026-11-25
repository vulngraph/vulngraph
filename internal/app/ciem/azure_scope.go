package ciem

import "strings"

// ARM scopes are identifiers, not IAM glob patterns. Keep the path boundary so
// rg/dev never contains rg/development, and reject unresolved/malformed paths.
func normalizeAzureScope(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "/"))
	if strings.TrimSpace(raw) == "/" {
		return "/", true
	}
	if !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "*?%#\\") || strings.Contains(s, "${") {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(s, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
			return "", false
		}
	}
	if len(parts) >= 2 && parts[0] == "subscriptions" {
		if len(parts) == 2 {
			return s, true
		}
		if len(parts) >= 4 && parts[2] == "resourcegroups" {
			if len(parts) == 4 || len(parts) >= 8 && len(parts)%2 == 0 && parts[4] == "providers" {
				return s, true
			}
		}
		if len(parts) >= 6 && len(parts)%2 == 0 && parts[2] == "providers" {
			return s, true
		}
	}
	if len(parts) == 4 && parts[0] == "providers" && parts[1] == "microsoft.management" && parts[2] == "managementgroups" {
		return s, true
	}
	return "", false
}

func azureScopeContains(parent, child string) bool {
	// Unknown legacy scopes can still enforce a NotAction within the SAME
	// grant. They are never accepted by the authority proof below.
	if parent == "*" && child == "*" {
		return true
	}
	p, parentKnown := normalizeAzureScope(parent)
	c, childKnown := normalizeAzureScope(child)
	return parentKnown && childKnown && (p == "/" || p == c || strings.HasPrefix(c, p+"/"))
}

func azureSubscriptionScope(accountID string) string {
	if accountID == "" || strings.ContainsAny(accountID, "/ *?%#\\") {
		return ""
	}
	return "/subscriptions/" + strings.ToLower(accountID)
}

// azurePrincipalTier only proves authority over the analyzed subscription.
// Management-group ancestry is not inventoried, so its grants remain candidates.
func azurePrincipalTier(accountID string, perms []EffectivePermission) privilegeTier {
	subscription := azureSubscriptionScope(accountID)
	if subscription == "" {
		return tierNormal
	}
	return azureTierAtScope(subscription, perms)
}

func azureTierAtScope(scope string, perms []EffectivePermission) privilegeTier {
	var broad []EffectivePermission
	for _, p := range perms {
		if p.SourcePolicy == azureRBACSource && !p.Approximate && azureScopeContains(p.Resource, scope) {
			broad = append(broad, p)
		}
	}
	// A wildcard with no exclusions is proven admin. With exclusions, a
	// surviving role-assignment write still proves a direct self-grant route,
	// but does not prove that every excluded action is currently available.
	for _, p := range broad {
		if p.Effect == EffectDeny || p.Action != "*" {
			continue
		}
		restricted := false
		for _, d := range broad {
			if d.Effect == EffectDeny && (d.Grant == "" || d.Grant == p.Grant) &&
				!azurePatternRestored(broad, d.Action, p.Grant) {
				restricted = true
			}
		}
		if !restricted {
			return tierAdmin
		}
	}
	if HasPermission(broad, "Microsoft.Authorization/roleAssignments/write") {
		return tierSelfGrant
	}
	return tierNormal
}

// azurePatternRestored proves that another grant restores an entire excluded
// action pattern. Partial overlap cannot establish unrestricted authority.
func azurePatternRestored(perms []EffectivePermission, action, excludedGrant string) bool {
	for _, p := range perms {
		if p.Effect == EffectDeny || p.Grant == excludedGrant ||
			!patternCoversPattern(strings.ToLower(p.Action), strings.ToLower(action)) {
			continue
		}
		restricted := false
		for _, d := range perms {
			if d.Effect == EffectDeny && (d.Grant == "" || d.Grant == p.Grant) &&
				patternsIntersect(strings.ToLower(d.Action), strings.ToLower(action), true) {
				restricted = true
			}
		}
		if !restricted {
			return true
		}
	}
	return false
}

func azureTierCoversScopes(tier privilegeTier, perms []EffectivePermission, scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}
	for _, scope := range scopes {
		if _, known := normalizeAzureScope(scope); !known || azureTierAtScope(scope, perms) < tier {
			return false
		}
	}
	return true
}
