package ciem

import (
	"fmt"
	"strings"
)

// EffectivePermission is one resolved permission after evaluating identity
// policies, permission boundaries, and SCPs. Effect is "Allow" or "Deny":
// explicit denies are RETAINED (not pre-subtracted) so the per-required-action
// matcher can apply AWS explicit-deny-always-wins semantics — set subtraction
// over wildcards cannot ("Allow *" minus "Deny iam:PassRole" is not expressible
// as a static allow set). This is the same deny-aware model Azure NotActions use.
type EffectivePermission struct {
	Action   string
	Resource string
	Effect   string // "Allow" | "Deny"

	// NotActions / NotResources are the complete exception sets of one Deny
	// statement. The entry matches outside their UNION, not outside any one
	// exception independently. Positive Action/Resource lists may be expanded
	// into separate entries; negated lists must stay grouped.
	NotActions   []string
	NotResources []string

	// Approximate marks an Allow whose conditions or policy restrictions were
	// not fully evaluated. It may retain a detection candidate, but cannot prove
	// unrestricted authority for a severity reduction.
	Approximate bool

	// Grant names the independently-evaluated grant this entry came from. A Deny
	// only neutralises Allows carrying the SAME Grant; an empty Grant (AWS, GCP)
	// applies account-wide, against every Allow.
	//
	// This exists for Azure RBAC, which evaluates each role assignment on its own:
	// an action is granted if some role's Actions match it AND *that role's*
	// NotActions do not. Flattening a principal's assignments into one
	// (Actions, NotActions) pair makes one role's exclusions cancel another
	// role's genuine grant: a principal
	// holding Contributor (NotActions over the whole Authorization namespace)
	// alongside User Access Administrator (Actions over exactly that namespace)
	// would read as unable to write role assignments.
	//
	// The alternative — intersecting NotActions instead of unioning them — was
	// rejected: it trades this false negative for false positives on every
	// single-role Contributor, on a provider that already carries known FPs.
	Grant string

	SourcePolicy string
}

// MatchesAction reports whether this entry covers the given action, honouring
// the negated NotAction form.
func (p EffectivePermission) MatchesAction(action string) bool {
	if len(p.NotActions) > 0 {
		for _, exception := range p.NotActions {
			if WildcardMatch(exception, action) {
				return false
			}
		}
		return true
	}
	return WildcardMatch(p.Action, action)
}

// CoversResource reports whether this entry covers the WHOLE of the given
// resource scope, where scope is itself an IAM resource pattern (an Allow
// statement's Resource field), not a concrete ARN.
//
// That distinction is the entire point. A Deny only neutralises an Allow when it
// covers the Allow's whole scope: "Deny iam:PassRole on role/break-glass" does
// not cover "Allow iam:PassRole on *", because PassRole remains allowed on every
// other role. Getting there requires pattern-vs-pattern containment, not a
// value-match of the Deny pattern against the Allow pattern's literal text —
// that comparison can judge a narrow Deny to cover a wildcard Allow it does
// not, silently erasing a real finding.
//
// Matching is case-SENSITIVE: resource ARNs are, unlike action names, so
// "role/Alice" and "role/alice" are distinct principals and a Deny scoped to one
// must not neutralise access to the other.
func (p EffectivePermission) CoversResource(scope string) bool {
	if p.SourcePolicy == azureRBACSource {
		return azureScopeContains(p.Resource, scope)
	}
	if scope == "" {
		scope = "*"
	}
	if len(p.NotResources) > 0 {
		// The whole scope is denied only when it is disjoint from EVERY
		// exception. An overlapping exception leaves part of the grant alive.
		// IAM substitutes policy variables from request context. Literal glob
		// disjointness cannot prove disjointness of those unresolved values.
		if strings.Contains(scope, "${") {
			return false
		}
		for _, exception := range p.NotResources {
			if strings.Contains(exception, "${") || patternsIntersect(exception, scope, true) {
				return false
			}
		}
		return true
	}
	if p.Resource == "" {
		return true
	}
	return patternCoversPattern(p.Resource, scope)
}

// isConcreteResource reports whether a resource string is a literal ARN rather
// than a pattern.
func isConcreteResource(s string) bool {
	return !strings.ContainsAny(s, "*?")
}

// patternCoversPattern reports whether every resource matched by the `scope`
// pattern is also matched by the `deny` pattern — glob language containment,
// restricted to the cases it can prove.
//
// Deliberately conservative: when containment cannot be proven it returns false,
// meaning the Deny does NOT neutralise the Allow and the finding survives. For a
// security tool an unproven suppression is the dangerous direction — it hides a
// real privilege — whereas an unproven retention is at worst noise. Every shape
// that occurs in practice is covered:
//
//	deny "*"                              ⊇ anything
//	deny == scope                         ⊇ itself
//	deny "arn:…:bucket/*", concrete scope → value match
//	deny "arn:…:bucket/*", scope "…/x*"   → literal-prefix containment
func patternCoversPattern(deny, scope string) bool {
	if deny == "*" || deny == scope {
		return true
	}
	if isConcreteResource(scope) {
		return wildcardMatchDP(deny, scope)
	}
	// A trailing-wildcard Deny with a wildcard-free prefix covers any scope that
	// begins with that same literal prefix: everything the scope can expand to
	// still starts with the prefix, so the Deny matches all of it.
	if prefix, ok := strings.CutSuffix(deny, "*"); ok && isConcreteResource(prefix) {
		return strings.HasPrefix(scope, prefix)
	}
	return false
}

// WildcardMatch reports whether value matches pattern using * (any run of
// chars) and ? (exactly one char). Case-insensitive.
func WildcardMatch(pattern, value string) bool {
	return wildcardMatchDP(strings.ToLower(pattern), strings.ToLower(value))
}

func wildcardMatchDP(pattern, value string) bool {
	pIdx, vIdx := 0, 0
	starIdx, matchIdx := -1, 0

	for vIdx < len(value) {
		if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = vIdx
			pIdx++
		} else if pIdx < len(pattern) && (pattern[pIdx] == '?' || pattern[pIdx] == value[vIdx]) {
			pIdx++
			vIdx++
		} else if starIdx >= 0 {
			pIdx = starIdx + 1
			matchIdx++
			vIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == len(pattern)
}

// EvaluateEffectivePermissions computes a principal's permissions:
//  1. Collect Allow statements from identity policies
//  2. Intersect with permission boundary (if any)
//  3. Intersect with SCPs (if any)
//  4. Return explicit Deny statements as Deny-effect entries (applied per
//     required action by the matcher, not subtracted here — deny always wins)
func EvaluateEffectivePermissions(principal Principal) ([]EffectivePermission, error) {
	if len(principal.Policies) == 0 {
		return nil, nil
	}

	var identityAllows []actionResourceSource
	var boundaryAllows []actionResourceSource
	var scpAllows []actionResourceSource
	var scpLevels []evaluatedSCPLevel
	var allDenies []actionResource
	var hasBoundary, hasSCP bool
	var approximate bool
	var scpCount, boundaryCount int
	var boundaryIncomplete, scpIncomplete bool

	for _, policy := range principal.Policies {
		// Trust policy statements (AssumeRolePolicyDocument) describe who may
		// assume THIS role — they grant the ASSUMING principal, never this
		// principal's own effective permissions. Every IAM role has a mandatory
		// trust statement (that is what makes it assumable), so folding it in
		// would make "sts:AssumeRole" read as a self-granted permission on
		// every role, including plain service-linked ones.
		if policy.Type == PolicyTrust {
			continue
		}
		if policy.Type == PolicySCP && policy.SCPLevel != nil {
			level := evaluateSCPLevel(*policy.SCPLevel)
			scpLevels = append(scpLevels, level)
			allDenies = append(allDenies, level.denies...)
			approximate = approximate || level.approximate || !level.complete
			continue
		}
		if policy.Incomplete {
			approximate = true
			boundaryIncomplete = boundaryIncomplete || policy.Type == PolicyBoundary
			scpIncomplete = scpIncomplete || policy.Type == PolicySCP
			if policy.Document == "" {
				continue
			}
		}
		switch policy.Type {
		case PolicyBoundary:
			boundaryCount++
		case PolicySCP:
			scpCount++
		}
		stmts, err := ParseAWSPolicy(policy.Document)
		if err != nil {
			// A boundary/SCP only CAPS permissions. If its document can't be
			// parsed, failing the whole principal would make an admin-ish role's
			// findings vanish (evaluation error → no findings) — worse than not
			// applying the cap. Fail open: skip the unparseable cap, keep going.
			// An identity policy parse error stays fatal (it is the grant itself).
			if policy.Type == PolicyBoundary || policy.Type == PolicySCP {
				approximate = true
				boundaryIncomplete = boundaryIncomplete || policy.Type == PolicyBoundary
				scpIncomplete = scpIncomplete || policy.Type == PolicySCP
				continue
			}
			return nil, fmt.Errorf("EvaluateEffectivePermissions: parse policy %s: %w", policy.Name, err)
		}
		// AWS restriction documents require statements. An empty or null
		// document is missing evidence, rather than a confirmed deny-all.
		if len(stmts) == 0 && (policy.Type == PolicyBoundary || policy.Type == PolicySCP) {
			approximate = true
			boundaryIncomplete = boundaryIncomplete || policy.Type == PolicyBoundary
			scpIncomplete = scpIncomplete || policy.Type == PolicySCP
			continue
		}
		// A boundary/SCP that parsed at all is present and must be applied as a
		// cap, even if it contains no Allow statement: a permission boundary
		// grants nothing by itself, so the effective set is identity ∩
		// boundary, and a boundary whose only statements are Denies permits
		// NOTHING. Presence must be tracked regardless of whether any Allow was
		// found, or such a boundary is never intersected and the principal
		// keeps its full identity grant. SCPs get the same treatment for the
		// same reason; a deny-only SCP set here means the collector genuinely
		// saw no allow-list SCP, so capping to nothing is the faithful answer.
		switch policy.Type {
		case PolicyBoundary:
			hasBoundary = true
		case PolicySCP:
			hasSCP = true
		}
		for _, stmt := range stmts {
			switch stmt.Effect {
			case "Allow":
				pairs := expandActionsResources(stmt, policy.Name)
				switch policy.Type {
				case PolicyBoundary:
					boundaryAllows = append(boundaryAllows, pairs...)
				case PolicySCP:
					scpAllows = append(scpAllows, pairs...)
				default:
					identityAllows = append(identityAllows, pairs...)
				}
			case "Deny":
				// A Deny gated by a Condition (e.g. the common "deny everything
				// unless MFA is present" guardrail) only blocks when the condition
				// actually holds — treating it as unconditional would silently
				// suppress a real privesc path for exactly the principals that
				// matter most (those without MFA). stmt.Conditions is parsed by
				// ParseAWSPolicy specifically so this check can be made; only a
				// Deny with no Condition at all is treated as unconditional.
				if len(stmt.Conditions) > 0 {
					approximate = true
					continue
				}
				allDenies = append(allDenies, expandDenyActionsResources(stmt)...)
			}
		}
	}

	if len(identityAllows) == 0 {
		return nil, nil
	}

	effective := identityAllows
	if hasBoundary && !boundaryIncomplete {
		effective = intersectPermissions(effective, boundaryAllows)
	}
	if hasSCP && !scpIncomplete {
		effective = intersectPermissions(effective, scpAllows)
	}
	for _, level := range scpLevels {
		if level.complete {
			effective = intersectPermissions(effective, level.allows)
		}
	}
	// The flat input cannot distinguish same-level SCP unions from different
	// hierarchy levels that must intersect. Retain candidates, but not proof of
	// admin. Multiple boundaries are similarly not a single observed boundary.
	approximate = approximate || scpCount > 1 || boundaryCount > 1

	// Denies are NOT subtracted here — they are returned as Deny-effect entries so
	// principalHasAllActions applies them per required action (explicit deny wins,
	// even against a wildcard Allow). Pre-subtracting could not remove "iam:PassRole"
	// from an "Allow *", which produced false-positive privesc paths.
	result := make([]EffectivePermission, 0, len(effective)+len(allDenies))
	for _, ep := range effective {
		result = append(result, EffectivePermission{
			Action:       ep.action,
			Resource:     ep.resource,
			Effect:       EffectAllow,
			SourcePolicy: ep.source,
			Approximate:  approximate || ep.approximate,
		})
	}
	for _, d := range allDenies {
		result = append(result, EffectivePermission{
			Action:       d.action,
			NotActions:   d.notActions,
			Resource:     d.resource,
			NotResources: d.notResources,
			Effect:       EffectDeny,
			SourcePolicy: "explicit-deny",
		})
	}
	return result, nil
}

// EffectivePermissionsForPolicies computes an AWS principal's effective
// permissions (identity ∩ boundary ∩ SCP, with explicit Deny retained per real
// AWS deny-wins semantics — including Condition-gated denies correctly NOT
// treated as unconditional) from a flat policy list in the same {type,
// document} shape collectors store on asset metadata.
//
// Exported so callers outside this package — the AWS collector's admin-ish
// detection (internal/collect/aws/iam.go) and the graph correlators
// (internal/app/correlate) — reuse this evaluator instead of hand-rolling a
// narrower approximation that can drift from it.
func EffectivePermissionsForPolicies(policies []Policy) ([]EffectivePermission, error) {
	return EvaluateEffectivePermissions(Principal{Provider: "aws", Policies: policies})
}

// HasPermission reports whether permissions grant a specific action on at least
// one resource scope — i.e. some Allow matches the action and no Deny wins
// against that Allow's own scope (explicit deny wins).
//
// The scope qualifier matters: a Deny only neutralises an Allow whose resource
// scope it fully covers. Matching a Deny on action alone would let "Deny
// iam:PassRole on arn:…:role/break-glass" cancel "Allow iam:PassRole on *",
// reporting the action as unavailable when it remains available on every other
// role. See AllowedResourceScopes for the per-scope detail.
func HasPermission(permissions []EffectivePermission, action string) bool {
	return len(AllowedResourceScopes(permissions, action)) > 0
}

// AllowedResourceScopes returns the resource patterns on which action is
// effectively allowed: every Allow entry matching the action whose scope is not
// fully covered by a matching Deny. Order follows the permission list; the
// result is deduplicated. Empty means the action is not available at all.
func AllowedResourceScopes(permissions []EffectivePermission, action string) []string {
	var scopes []string
	seen := map[string]struct{}{}
	for _, p := range permissions {
		if p.Effect == EffectDeny || !p.MatchesAction(action) {
			continue
		}
		scope := p.Resource
		if scope == "" {
			scope = "*"
		}
		if _, dup := seen[scope]; dup {
			continue
		}
		if scopeDenied(permissions, action, scope, p.Grant) {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes
}

// scopeDenied reports whether an explicit Deny covers action on the whole of
// resource scope, within the grant the Allow came from. A Deny that only overlaps
// part of the scope (a narrower resource pattern) does not neutralise it, and
// neither does a Deny belonging to a different grant (see Grant).
//
// Dedup order is safe here because the caller records a scope in `seen` only
// after it survives this check: a scope denied under one grant is re-tested
// against the next grant that allows it.
func scopeDenied(permissions []EffectivePermission, action, scope, grant string) bool {
	for _, d := range permissions {
		if d.Effect != EffectDeny || !d.MatchesAction(action) {
			continue
		}
		if d.Grant != "" && d.Grant != grant {
			continue
		}
		if d.CoversResource(scope) {
			return true
		}
	}
	return false
}

// ─── internal evaluation helpers ─────────────────────────────────────────────

type actionResourceSource struct {
	action, resource, source string
	approximate              bool
}

// actionResource is one expanded Deny target. notActions/notResources carry AWS's
// negated forms verbatim (see EffectivePermission) rather than being flattened,
// because a negated set has no equivalent wildcard pattern.
type actionResource struct {
	action, resource         string
	notActions, notResources []string
}

func expandActionsResources(stmt PermissionStatement, policyName string) []actionResourceSource {
	actions := stmt.Actions
	if widensNotAction(stmt) {
		// NotAction = "all actions except these"; treated conservatively as
		// Allow * so we don't miss dangerous actions the principal may still hold.
		// NotActionAllowPolicies names the policies this applies to, for logging.
		actions = []string{"*"}
	}
	resources := stmt.Resources
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	pairs := make([]actionResourceSource, 0)
	approximate := len(stmt.Conditions) > 0 || widensNotAction(stmt) || len(stmt.NotResources) > 0
	for _, a := range actions {
		for _, r := range resources {
			pairs = append(pairs, actionResourceSource{
				action: a, resource: r, source: policyName, approximate: approximate,
			})
		}
	}
	return pairs
}

// widensNotAction reports whether an Allow statement is NotAction-only and is
// therefore evaluated as Allow * (see expandActionsResources).
func widensNotAction(stmt PermissionStatement) bool {
	return stmt.Effect == "Allow" && len(stmt.Actions) == 0 && len(stmt.NotActions) > 0
}

// NotActionAllowPolicies names the policies holding a NotAction-only Allow,
// which the evaluator over-approximates as Allow *. It exists so a caller can
// log that over-approximation: the evaluator itself does no I/O. Unparseable
// documents are skipped; EvaluateEffectivePermissions reports those.
func NotActionAllowPolicies(policies []Policy) []string {
	var names []string
	for _, policy := range policies {
		if policy.Type == PolicySCP && policy.SCPLevel != nil {
			var documents []Policy
			for _, document := range policy.SCPLevel.Policies {
				documents = append(documents, Policy{Name: document.Name, Type: PolicySCP, Document: document.Document})
			}
			names = append(names, NotActionAllowPolicies(documents)...)
			continue
		}
		if policy.Type == PolicyTrust {
			continue
		}
		stmts, err := ParseAWSPolicy(policy.Document)
		if err != nil {
			continue
		}
		for _, stmt := range stmts {
			if widensNotAction(stmt) {
				names = append(names, policy.Name)
				break
			}
		}
	}
	return names
}

// expandDenyActionsResources expands one Deny statement into its (action,
// resource) targets, preserving NotAction/NotResource as negations.
//
// Both negated forms are load-bearing. A Deny written with NotAction — "Deny
// NotAction: [s3:*] on *", the standard "only S3 is permitted here"
// service/region-restriction SCP idiom — must not expand to zero targets (which
// would vanish the deny entirely) nor widen to "Deny *" (which would also deny
// S3, the one service the policy actually permits).
func expandDenyActionsResources(stmt PermissionStatement) []actionResource {
	// A statement carrying neither Action nor NotAction denies nothing.
	if len(stmt.Actions) == 0 && len(stmt.NotActions) == 0 {
		return nil
	}
	actions := stmt.Actions
	if len(stmt.NotActions) > 0 {
		actions = []string{""}
	}
	resources := stmt.Resources
	if len(stmt.NotResources) > 0 {
		resources = []string{""}
	}
	if len(resources) == 0 {
		resources = []string{"*"}
	}

	pairs := make([]actionResource, 0, len(actions)*len(resources))
	for _, a := range actions {
		for _, r := range resources {
			pairs = append(pairs, actionResource{
				action: a, resource: r,
				notActions: stmt.NotActions, notResources: stmt.NotResources,
			})
		}
	}
	return pairs
}

// intersectPermissions computes the effective grant of an identity set capped by
// a boundary/SCP allow set: the action (and resource) is granted only if BOTH
// sets permit it, and the effective pattern is the NARROWER of the two.
//
// Two wildcard patterns overlap when either matches the other; the effective
// pattern is the one matched BY the other (the more specific). This is essential
// for the dominant case — an admin identity ("*") capped by a boundary that
// allows a specific action (e.g. "sts:AssumeRole"): the effective grant is
// "sts:AssumeRole", NOT empty. A naive `WildcardMatch(boundaryPattern, "*")`
// check drops the "*" identity entry entirely, emptying effective permissions and
// silently hiding every privesc path on any boundaried admin principal.
func intersectPermissions(src, allowed []actionResourceSource) []actionResourceSource {
	var result []actionResourceSource
	seen := map[[3]string]int{}
	for _, perm := range src {
		for _, a := range allowed {
			action, aok := narrowerPattern(perm.action, a.action, false)
			if !aok {
				continue
			}
			resource, rok := narrowerPattern(resourceVariablePattern(perm.resource), resourceVariablePattern(a.resource), true)
			if !rok {
				continue
			}
			// Overlapping patterns may be retained wider than their actual
			// intersection. Such a candidate is not proof of full authority.
			exact := patternCoversPattern(strings.ToLower(perm.action), strings.ToLower(action)) &&
				patternCoversPattern(strings.ToLower(a.action), strings.ToLower(action)) &&
				!strings.Contains(perm.resource, "${") && !strings.Contains(a.resource, "${") &&
				patternCoversPattern(perm.resource, resource) && patternCoversPattern(a.resource, resource)
			candidate := actionResourceSource{
				action: action, resource: resource, source: perm.source,
				approximate: perm.approximate || a.approximate || !exact,
			}
			key := [3]string{strings.ToLower(action), resource, perm.source}
			if index, exists := seen[key]; exists {
				result[index].approximate = result[index].approximate && candidate.approximate
				continue
			}
			seen[key] = len(result)
			result = append(result, candidate)
		}
	}
	return result
}

// Resource variables are request-context substitutions, not literal ARN text.
// Preserve their fixed surroundings but retain any possible substituted value;
// callers must mark this intersection approximate until context is evaluated.
func resourceVariablePattern(pattern string) string {
	for {
		start := strings.Index(pattern, "${")
		if start < 0 {
			return pattern
		}
		end := strings.IndexByte(pattern[start:], '}')
		if end < 0 {
			return pattern[:start] + "*"
		}
		pattern = pattern[:start] + "*" + pattern[start+end+1:]
	}
}

// narrowerPattern returns the more-specific of two overlapping wildcard patterns
// and true, or ("", false) when they do not overlap. caseSensitive selects ARN
// semantics (resources) over action-name semantics; see patternsIntersect.
//
// WildcardMatch(p, v) tests whether v is within pattern p, so WildcardMatch(a,
// b)==true means b ⊆ a (b is narrower); the reverse means a is narrower.
//
// When neither pattern contains the other but their value sets still intersect
// (e.g. identity "ec2:Describe*" capped by a boundary allowing "ec2:*Instances",
// which both admit ec2:DescribeInstances), no single glob expresses the
// intersection, so the grant is kept anyway, over-approximating the cap: for a
// security tool an over-broad cap is a mild false positive, while dropping a
// real grant is an invisible false negative. Same fail-open reasoning as the
// unparseable boundary/SCP path above.
func narrowerPattern(a, b string, caseSensitive bool) (string, bool) {
	if patternMatches(a, b, caseSensitive) {
		return b, true
	}
	if patternMatches(b, a, caseSensitive) {
		return a, true
	}
	if patternsIntersect(a, b, caseSensitive) {
		return a, true
	}
	return "", false
}

// patternMatches is WildcardMatch with explicit case semantics. IAM action names
// are case-insensitive; resource ARNs are not — an IAM role named "role/Alice"
// and one named "role/alice" are different principals, so folding their case let
// a boundary or Deny scoped to one silently cap or neutralise the other.
func patternMatches(pattern, value string, caseSensitive bool) bool {
	if caseSensitive {
		return wildcardMatchDP(pattern, value)
	}
	return WildcardMatch(pattern, value)
}

// patternsIntersect reports whether two glob patterns ("*" = any run, "?" =
// exactly one char) admit at least one common value. Containment (WildcardMatch
// in either direction) is only the special case where one pattern's value set
// sits wholly inside the other's; two patterns can overlap without either
// containing the other, which plain containment checks miss.
func patternsIntersect(a, b string, caseSensitive bool) bool {
	if !caseSensitive {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	memo := make(map[[2]int]bool)
	var rec func(i, j int) bool
	rec = func(i, j int) bool {
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v
		}
		var res bool
		switch {
		case i == len(a) && j == len(b):
			res = true
		case i == len(a):
			res = onlyStars(b[j:])
		case j == len(b):
			res = onlyStars(a[i:])
		case a[i] == '*':
			// a's star matches nothing more, or absorbs whatever b[j] produces.
			res = rec(i+1, j) || rec(i, j+1)
		case b[j] == '*':
			res = rec(i, j+1) || rec(i+1, j)
		case a[i] == '?' || b[j] == '?' || a[i] == b[j]:
			res = rec(i+1, j+1)
		}
		memo[key] = res
		return res
	}
	return rec(0, 0)
}

func onlyStars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '*' {
			return false
		}
	}
	return true
}
