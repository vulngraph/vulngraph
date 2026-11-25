package ciem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for the five scope/negation defects in the shared evaluator
// and matcher. Each of these evaluated to a wrong answer BEFORE the fix, and
// every AWS privesc finding, allows_action edge, secret-access edge and
// isAdminish verdict routes through this code — so a defect here is systemic.

func evalPolicies(t *testing.T, policies ...Policy) []EffectivePermission {
	t.Helper()
	perms, err := EffectivePermissionsForPolicies(policies)
	require.NoError(t, err)
	return perms
}

func identity(doc string) Policy {
	return Policy{Name: "identity", Type: PolicyIdentity, Document: doc}
}

// A Deny narrowed to ONE resource must not suppress an action that remains
// allowed on every other resource. Previously the matcher compared Deny entries
// on Action alone, so a single break-glass guardrail on an administrator hid the
// whole privesc path — worst on exactly the principals most likely to carry one.
func TestScopedDenyDoesNotSuppressBroaderGrant(t *testing.T) {
	perms := evalPolicies(t, identity(`{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"iam:PassRole","Resource":"arn:aws:iam::1:role/break-glass"}]}`))

	require.True(t, HasPermission(perms, "iam:PassRole"),
		"PassRole is still allowed on every role other than break-glass")
	require.True(t, principalHasAllActions(perms, []string{"iam:PassRole", "ec2:RunInstances"}),
		"a resource-scoped Deny must not suppress the privesc path globally")
	require.Equal(t, []string{"*"}, AllowedResourceScopes(perms, "iam:PassRole"))
}

// The unconditional deny-all case must keep working: a Deny covering the whole
// scope really does neutralise the grant.
func TestUnscopedDenyStillSuppresses(t *testing.T) {
	perms := evalPolicies(t, identity(`{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`))

	require.False(t, HasPermission(perms, "iam:PassRole"))
	require.False(t, principalHasAllActions(perms, []string{"iam:PassRole"}))
	require.True(t, HasPermission(perms, "ec2:RunInstances"), "unrelated actions are untouched")
}

// "Deny everything except S3" — the standard service-restriction SCP. Expressed
// with NotAction, it used to expand to zero deny targets and vanish entirely,
// leaving the principal fully permitted.
func TestDenyWithNotActionIsNotDropped(t *testing.T) {
	perms := evalPolicies(t,
		identity(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		Policy{Name: "scp", Type: PolicySCP, Document: `{"Statement":[
			{"Effect":"Allow","Action":"*","Resource":"*"},
			{"Effect":"Deny","NotAction":["s3:*"],"Resource":"*"}]}`})

	require.False(t, HasPermission(perms, "iam:CreateUser"), "denied by the NotAction guardrail")
	require.False(t, HasPermission(perms, "ec2:RunInstances"), "denied by the NotAction guardrail")
	require.True(t, HasPermission(perms, "s3:GetObject"),
		"S3 is the exception the policy exists to permit — widening the Deny to * would wrongly deny it")
}

// A Deny scoped with NotResource denies everywhere EXCEPT the named scope.
func TestDenyWithNotResourceHonoursTheException(t *testing.T) {
	perms := evalPolicies(t, identity(`{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::allowed/*"},
		{"Effect":"Deny","Action":"s3:GetObject","NotResource":"arn:aws:s3:::allowed/*"}]}`))

	require.True(t, HasPermission(perms, "s3:GetObject"),
		"the Allow sits inside the Deny's NotResource exception")
}

// A permission boundary grants nothing on its own, so a boundary whose only
// statements are Denies caps the principal to nothing. Presence used to be
// recorded only inside the Allow branch, so such a boundary was never
// intersected and every action it did not name explicitly leaked through.
func TestDenyOnlyBoundaryCapsEverything(t *testing.T) {
	perms := evalPolicies(t,
		identity(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		Policy{Name: "boundary", Type: PolicyBoundary, Document: `{"Statement":[
			{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}]}`})

	require.False(t, HasPermission(perms, "sts:AssumeRole"), "explicitly denied")
	require.False(t, HasPermission(perms, "iam:PassRole"),
		"a boundary that allows nothing permits nothing — not just the action it names")
}

// Two patterns can overlap without either containing the other. Dropping such a
// pair as non-overlapping erased the grant and silently hid every privesc path
// under the boundary; the grant is kept instead (over-approximating the cap).
func TestBoundaryOverlapWithoutContainmentKeepsGrant(t *testing.T) {
	perms := evalPolicies(t,
		identity(`{"Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`),
		Policy{Name: "boundary", Type: PolicyBoundary, Document: `{"Statement":[
			{"Effect":"Allow","Action":"ec2:*Instances","Resource":"*"}]}`})

	require.True(t, HasPermission(perms, "ec2:DescribeInstances"),
		"both patterns admit ec2:DescribeInstances, so the capped grant survives")

	require.True(t, patternsIntersect("ec2:Describe*", "ec2:*Instances", false))
	require.False(t, patternsIntersect("ec2:Describe*", "s3:Get*", false),
		"genuinely disjoint patterns must still be rejected")
}

// Action names are case-insensitive; resource ARNs are not. Folding resource
// case let a Deny or boundary scoped to role/Alice cap or neutralise access to
// the entirely different principal role/alice.
func TestResourceMatchingIsCaseSensitive(t *testing.T) {
	deny := EffectivePermission{
		Action: "iam:PassRole", Resource: "arn:aws:iam::1:role/Alice", Effect: EffectDeny,
	}
	require.True(t, deny.CoversResource("arn:aws:iam::1:role/Alice"))
	require.False(t, deny.CoversResource("arn:aws:iam::1:role/alice"),
		"role/alice is a different principal from role/Alice")

	// Action matching stays case-insensitive, per AWS.
	require.True(t, deny.MatchesAction("iam:passrole"))
}

// A Deny with neither Action nor NotAction denies nothing and must not be
// widened into a deny-all.
func TestDenyWithoutAnyActionDeniesNothing(t *testing.T) {
	perms := evalPolicies(t, identity(`{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Resource":"*"}]}`))

	require.True(t, HasPermission(perms, "iam:CreateUser"))
}

// Adversary emulation: a decoy Deny whose resource pattern blocks nothing real
// must not erase a broad Allow. "Resource: ?" matches only a one-character ARN —
// no real ARN — so iam:PassRole stays allowed everywhere. Comparing the Deny
// pattern against the Allow pattern's literal TEXT judged "?" to cover "*"
// (the one-char string "*" matches the pattern "?"), so one innocuous statement
// that blocks no API call erased a critical PassRole+RunInstances finding.
func TestDecoyDenyPatternDoesNotEraseBroadAllow(t *testing.T) {
	perms := evalPolicies(t, identity(`{"Statement":[
		{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"},
		{"Effect":"Deny","Action":"iam:PassRole","Resource":"?"}]}`))

	require.True(t, HasPermission(perms, "iam:PassRole"),
		"a Deny matching only one-character ARNs blocks nothing real")
	require.True(t, principalHasAllActions(perms, []string{"iam:PassRole", "ec2:RunInstances"}))
}

// Pattern-vs-pattern containment: the cases that must still suppress, and the
// cases that must not.
func TestDenyCoversScopeContainment(t *testing.T) {
	covers := []struct{ deny, scope string }{
		{"*", "*"},                       // deny-all
		{"*", "arn:aws:s3:::bucket/key"}, // deny-all over concrete
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/*"},     // identical
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key"},   // pattern over concrete
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/logs*"}, // literal-prefix containment
	}
	for _, c := range covers {
		require.True(t, patternCoversPattern(c.deny, c.scope), "%s should cover %s", c.deny, c.scope)
	}

	notCovers := []struct{ deny, scope string }{
		{"?", "*"},                                             // the decoy
		{"arn:aws:iam::1:role/break-glass", "*"},               // narrow deny, broad allow
		{"arn:aws:s3:::other/*", "arn:aws:s3:::bucket/*"},      // disjoint prefixes
		{"arn:aws:s3:::bucket/logs*", "arn:aws:s3:::bucket/*"}, // deny narrower than allow
	}
	for _, c := range notCovers {
		require.False(t, patternCoversPattern(c.deny, c.scope), "%s must not cover %s", c.deny, c.scope)
	}
}

// A Deny is scoped to the grant it came from. Without that, one Azure role
// assignment's NotActions cancel another's Actions; with it, an AWS/GCP Deny
// (which carries no Grant) must still apply to everything.
func TestGrantScopedDeny(t *testing.T) {
	perms := []EffectivePermission{
		{Action: "*", Resource: "*", Grant: "0:Contributor"},
		{Action: "Microsoft.Authorization/*/Write", Resource: "*", Effect: EffectDeny, Grant: "0:Contributor"},
		{Action: "Microsoft.Authorization/*", Resource: "*", Grant: "1:User Access Administrator"},
	}
	require.True(t, HasPermission(perms, "Microsoft.Authorization/roleAssignments/write"),
		"the second grant allows it and its own role excludes nothing")

	// Drop the second grant: the exclusion now has nothing to compete with.
	require.False(t, HasPermission(perms[:2], "Microsoft.Authorization/roleAssignments/write"),
		"Contributor alone is excluded from Authorization writes")

	// An ungranted Deny (AWS explicit deny, SCP, boundary) still cuts across every
	// Allow regardless of which grant produced it.
	global := []EffectivePermission{
		{Action: "*", Resource: "*", Grant: "0:Contributor"},
		{Action: "iam:PassRole", Resource: "*", Effect: EffectDeny},
	}
	require.False(t, HasPermission(global, "iam:PassRole"))
}

// A NotAction-only Allow is over-approximated as Allow *; NotActionAllowPolicies
// names exactly the policies that holds for, so the caller can log it. A
// NotAction Deny and a trust policy are not widened and are not named.
func TestNotActionAllowPoliciesNamesWidenedAllows(t *testing.T) {
	policies := []Policy{
		{Name: "widened", Type: PolicyIdentity, Document: `{"Statement":[{"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"}]}`},
		{Name: "plain", Type: PolicyIdentity, Document: `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`},
		{Name: "deny-guardrail", Type: PolicySCP, Document: `{"Statement":[{"Effect":"Deny","NotAction":["s3:*"],"Resource":"*"}]}`},
		{Name: "trust", Type: PolicyTrust, Document: `{"Statement":[{"Effect":"Allow","NotAction":["sts:*"],"Resource":"*"}]}`},
	}
	require.Equal(t, []string{"widened"}, NotActionAllowPolicies(policies))

	perms := evalPolicies(t, policies[0])
	require.True(t, HasPermission(perms, "iam:CreateUser"), "the widening is conservative: excluded actions still read as held")
}
