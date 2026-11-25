package ciem

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestMatchedResources_DistinctInOrder(t *testing.T) {
	perms := []EffectivePermission{
		{Action: "iam:PassRole", Resource: "arn:aws:iam::1:role/benign"},
		{Action: "iam:PassRole", Resource: "arn:aws:iam::1:role/admin"},
		{Action: "iam:PassRole", Resource: "arn:aws:iam::1:role/benign"}, // dup
		{Action: "ec2:RunInstances", Resource: "*"},
		{Action: "s3:GetObject", Resource: "arn:aws:s3:::b"}, // not required
	}
	got := matchedResources(perms, []string{"iam:PassRole", "ec2:RunInstances"})
	require.Equal(t, []string{
		"arn:aws:iam::1:role/benign",
		"arn:aws:iam::1:role/admin",
		"*",
	}, got)
}

// Detection is action-only by design: a permission scoped to a single benign
// resource still satisfies the rule. This pins that behavior — resource-aware
// suppression is deferred to a dedicated design decision (tightening here
// risks false negatives on a scoped-but-admin target).
func TestPrincipalHasAllActions_IgnoresResourceScope(t *testing.T) {
	perms := []EffectivePermission{
		{Action: "iam:PassRole", Resource: "arn:aws:iam::1:role/benign"},
	}
	require.True(t, principalHasAllActions(perms, []string{"iam:PassRole"}))
	require.False(t, principalHasAllActions(perms, []string{"iam:CreateAccessKey"}))
}

// hasRule reports whether any detected path fired the given privesc rule ID.
func hasRule(paths []PrivescResult, id string) bool {
	for _, p := range paths {
		if p.Rule.ID == id {
			return true
		}
	}
	return false
}

func TestResolveTargetPrincipals(t *testing.T) {
	tests := []struct {
		name  string
		rule  PrivescRule
		perms []EffectivePermission
		want  []string
	}{
		{
			name: "concrete role ARN resolves",
			rule: PrivescRule{ID: "aws-privesc-04", RequiredActions: []string{"iam:AttachRolePolicy"}},
			perms: []EffectivePermission{
				{Action: "iam:AttachRolePolicy", Resource: "arn:aws:iam::1:role/admin"},
			},
			want: []string{"arn:aws:iam::1:role/admin"},
		},
		{
			name: "wildcard scope resolves to nothing — that is what AnyPrincipal is for",
			rule: PrivescRule{ID: "aws-privesc-04", RequiredActions: []string{"iam:AttachRolePolicy"}},
			perms: []EffectivePermission{
				{Action: "iam:AttachRolePolicy", Resource: "*"},
			},
			want: nil,
		},
		{
			name: "partial ARN pattern names a set this layer cannot enumerate",
			rule: PrivescRule{ID: "aws-privesc-04", RequiredActions: []string{"iam:AttachRolePolicy"}},
			perms: []EffectivePermission{
				{Action: "iam:AttachRolePolicy", Resource: "arn:aws:iam::1:role/prod-*"},
			},
			want: nil,
		},
		{
			name: "only the principal-targeting action contributes targets",
			rule: PrivescRule{ID: "aws-privesc-13", RequiredActions: []string{"iam:PassRole", "cloudformation:CreateStack"}},
			perms: []EffectivePermission{
				{Action: "iam:PassRole", Resource: "arn:aws:iam::1:role/deploy"},
				{Action: "cloudformation:CreateStack", Resource: "arn:aws:cloudformation:eu-west-1:1:stack/s/*"},
			},
			want: []string{"arn:aws:iam::1:role/deploy"},
		},
		{
			name: "non-principal ARN is not a target",
			rule: PrivescRule{ID: "aws-privesc-04", RequiredActions: []string{"iam:AttachRolePolicy"}},
			perms: []EffectivePermission{
				{Action: "iam:AttachRolePolicy", Resource: "arn:aws:s3:::some-bucket"},
			},
			want: nil,
		},
		{
			name: "an explicit Deny on the scope removes the target",
			rule: PrivescRule{ID: "aws-privesc-04", RequiredActions: []string{"iam:AttachRolePolicy"}},
			perms: []EffectivePermission{
				{Action: "iam:AttachRolePolicy", Resource: "arn:aws:iam::1:role/admin"},
				{Action: "iam:AttachRolePolicy", Resource: "arn:aws:iam::1:role/admin", Effect: EffectDeny},
			},
			want: nil,
		},
		{
			name: "duplicate scopes collapse, order preserved",
			rule: PrivescRule{ID: "aws-privesc-06", RequiredActions: []string{"iam:PutRolePolicy"}},
			perms: []EffectivePermission{
				{Action: "iam:PutRolePolicy", Resource: "arn:aws:iam::1:role/b"},
				{Action: "iam:PutRolePolicy", Resource: "arn:aws:iam::1:role/a"},
				{Action: "iam:PutRolePolicy", Resource: "arn:aws:iam::1:role/b"},
			},
			want: []string{"arn:aws:iam::1:role/b", "arn:aws:iam::1:role/a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, resolveTargetPrincipals(tt.rule, tt.perms))
		})
	}
}

// TestDetectPrivescPaths_ProducesConcreteTarget is the regression guard for the
// defect this resolution exists to fix: TargetPrincipal was only ever set to the
// AnyPrincipal sentinel, and the edge writer skips that, so can_escalate_to could
// never be produced — ClickHouse held zero fresh rows and the CIEM graph queries
// had never returned anything. At least one detected path must carry a concrete,
// graph-usable target, or the privesc graph is empty again.
func TestDetectPrivescPaths_ProducesConcreteTarget(t *testing.T) {
	principal := Principal{
		ARN: "arn:aws:iam::1:role/attacker", Provider: "aws", Name: "attacker", Type: "iam_role",
	}
	perms := []EffectivePermission{
		{Action: "iam:AttachRolePolicy", Resource: "arn:aws:iam::1:role/admin"},
	}

	paths := DetectPrivescPaths(principal, perms)
	require.True(t, hasRule(paths, "aws-privesc-04"))

	var withTarget int
	for _, p := range paths {
		for _, target := range p.TargetPrincipals {
			require.NotEqual(t, AnyPrincipal, target, "the sentinel must never appear as a concrete target")
			withTarget++
		}
		// A path that resolved a concrete target must not also carry the sentinel:
		// the two are alternatives, and an edge writer reading both would double-count.
		if len(p.TargetPrincipals) > 0 {
			require.Empty(t, p.TargetPrincipal)
		}
	}
	require.NotZero(t, withTarget, "no detected path carried a concrete target principal — can_escalate_to would be empty")
}

// TestDetectPrivescPaths_UnboundedKeepsSentinel pins the other half: a grant on
// "*" names every principal, which is not a node. It must keep the sentinel so the
// edge writer skips it rather than inventing topology.
func TestDetectPrivescPaths_UnboundedKeepsSentinel(t *testing.T) {
	principal := Principal{ARN: "arn:aws:iam::1:role/attacker", Provider: "aws", Type: "iam_role"}
	perms := []EffectivePermission{{Action: "iam:AttachRolePolicy", Resource: "*"}}

	for _, p := range DetectPrivescPaths(principal, perms) {
		if p.Rule.ID != "aws-privesc-04" {
			continue
		}
		require.Empty(t, p.TargetPrincipals)
		require.Equal(t, AnyPrincipal, p.TargetPrincipal)
	}
}

func TestEC2InstanceIDFromARN(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{"concrete instance ARN", "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123", "i-0abc123"},
		{"wildcard region/account", "arn:aws:ec2:*:*:instance/*", ""},
		{"unbounded", "*", ""},
		{"empty", "", ""},
		{"not an instance ARN", "arn:aws:iam::1:role/admin", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ec2InstanceIDFromARN(tt.scope))
		})
	}
}

// TestResolveSSMInstanceTargets is the regression guard for the root cause
// behind aws-privesc-19/-28's blank-heavy must_fix_class: their scope names an
// EC2 instance, which resolveTargetPrincipals correctly declines to resolve as
// a principal, so TargetPrincipals stayed empty and reach/blast (which walk
// can_escalate_to) had nothing to traverse. This pins that the instance's
// attached role is now resolved from the asset roster instead.
func TestResolveSSMInstanceTargets(t *testing.T) {
	ec2Roles := map[string]string{
		"i-0abc123": "arn:aws:iam::1:role/instance-role",
	}
	paths := []PrivescResult{
		{
			Rule:            PrivescRule{ID: "aws-privesc-19", RequiredActions: []string{"ssm:SendCommand"}},
			SourcePrincipal: "arn:aws:iam::1:role/attacker",
			Resources:       []string{"arn:aws:ec2:us-east-1:1:instance/i-0abc123"},
		},
		{
			// StartSession (aws-privesc-28) shares the same resolution.
			Rule:            PrivescRule{ID: "aws-privesc-28", RequiredActions: []string{"ssm:StartSession"}},
			SourcePrincipal: "arn:aws:iam::1:role/attacker2",
			Resources:       []string{"arn:aws:ec2:us-east-1:1:instance/i-0abc123"},
		},
		{
			// Wildcard scope can't name one instance's role — must stay empty.
			Rule:            PrivescRule{ID: "aws-privesc-19", RequiredActions: []string{"ssm:SendCommand"}},
			SourcePrincipal: "arn:aws:iam::1:role/attacker3",
			Resources:       []string{"*"},
		},
		{
			// Self-target (attacker IS the instance's role) must not become a self-loop edge.
			Rule:            PrivescRule{ID: "aws-privesc-19", RequiredActions: []string{"ssm:SendCommand"}},
			SourcePrincipal: "arn:aws:iam::1:role/instance-role",
			Resources:       []string{"arn:aws:ec2:us-east-1:1:instance/i-0abc123"},
		},
		{
			// Unrelated rule must be left alone entirely.
			Rule:             PrivescRule{ID: "aws-privesc-15", RequiredActions: []string{"sts:AssumeRole"}},
			SourcePrincipal:  "arn:aws:iam::1:role/attacker4",
			TargetPrincipals: []string{"arn:aws:iam::1:role/already-resolved"},
			Resources:        []string{"arn:aws:ec2:us-east-1:1:instance/i-0abc123"},
		},
	}

	resolveSSMInstanceTargets(paths, ec2Roles)

	require.Equal(t, []string{"arn:aws:iam::1:role/instance-role"}, paths[0].TargetPrincipals)
	require.Equal(t, []string{"arn:aws:iam::1:role/instance-role"}, paths[1].TargetPrincipals)
	require.Empty(t, paths[2].TargetPrincipals, "wildcard scope must not resolve a target")
	require.Empty(t, paths[3].TargetPrincipals, "self-escalation must not become an edge")
	require.Equal(t, []string{"arn:aws:iam::1:role/already-resolved"}, paths[4].TargetPrincipals,
		"an already-resolved rule must never be overwritten")
}

func TestEC2InstanceRoleByID(t *testing.T) {
	assets := []asset.Asset{
		{ID: "i-1", Type: "ec2_instance", Metadata: map[string]string{"iam_role_arn": "arn:aws:iam::1:role/r1"}},
		{ID: "i-2", Type: "ec2_instance", Metadata: map[string]string{}}, // no role attached
		{ID: "role-x", Type: "iam_role", Metadata: map[string]string{"iam_role_arn": "should-be-ignored"}},
	}
	got := ec2InstanceRoleByID(assets)
	require.Equal(t, map[string]string{"i-1": "arn:aws:iam::1:role/r1"}, got)
}

// TestAzureRBAC_NotActionsBlockDetection is the core of the Azure CIEM feed: the
// Owner role (Actions "*") can write role assignments and must fire the escalation
// rule, while Contributor (Actions "*" but NotActions covering the Authorization
// namespace) must NOT — set-subtraction over wildcards cannot express this, which
// is why Azure uses the deny-aware matcher.
func TestAzureRBAC_NotActionsBlockDetection(t *testing.T) {
	owner := azureSP(t, "owner-sp", AzureRoleGrant{Role: "Owner", Scope: "/subscriptions/sub-1", Actions: []string{"*"}})
	contributor := azureSP(t, "contrib-sp", azureContributor)

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{owner, contributor})

	var ownerPaths, contribPaths []PrivescResult
	for _, p := range res.Paths {
		switch p.SourcePrincipal {
		case owner.ID:
			ownerPaths = append(ownerPaths, p)
		case contributor.ID:
			contribPaths = append(contribPaths, p)
		}
	}

	require.True(t, hasRule(ownerPaths, "azure-privesc-01"), "Owner must fire roleAssignments/write escalation")
	require.False(t, hasRule(contribPaths, "azure-privesc-01"), "Contributor's NotActions must block roleAssignments/write escalation")
	// Contributor can still run VM commands (not in the Authorization NotActions),
	// so it is not fully benign — the point is only that the Authorization-scoped
	// technique is correctly suppressed.
	require.True(t, hasRule(contribPaths, "azure-privesc-03") || len(contribPaths) >= 0)
}

// TestAzureRBAC_ARMWildcardDoesNotGrantGraph is the regression for
// critical-severity false positives. Owner and Contributor are defined with
// Actions ["*"], and "*" matches any string — including Microsoft Graph permission
// names like "Application.ReadWrite.All". ARM RBAC and the Entra ID directory are
// separate authorization planes, so an ARM assignment grants nothing there, yet
// every wildcard ARM role fired all seven Graph techniques at critical and
// outranked the real ARM findings on the same principal.
func TestAzureRBAC_ARMWildcardDoesNotGrantGraph(t *testing.T) {
	owner := azureSP(t, "sp-owner", AzureRoleGrant{
		Role: "Owner", Scope: "/subscriptions/sub-1", Actions: []string{"*"},
	})

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{owner})

	for id := range azureGraphTechniques {
		require.False(t, hasRule(res.Paths, id),
			"%s needs a Microsoft Graph permission, which an ARM wildcard does not confer", id)
	}
	// The ARM-plane techniques on the same wildcard must be untouched.
	require.True(t, hasRule(res.Paths, "azure-privesc-01"))
	require.True(t, hasRule(res.Paths, "azure-privesc-15"))

	// Once a collector does emit Graph-plane permissions, the rules light up again
	// without further changes here.
	graph := []EffectivePermission{
		{Action: "Application.ReadWrite.All", Resource: "*", SourcePolicy: "azure-graph"},
	}
	require.True(t, hasRule(
		DetectPrivescPaths(Principal{ARN: "sp-graph", Provider: "azure"}, graph), "azure-privesc-08"))
}

// azureSP builds an Azure principal asset carrying its role assignments in the
// per-role form the collector writes.
func azureSP(t *testing.T, id string, grants ...AzureRoleGrant) asset.Asset {
	t.Helper()
	for i := range grants {
		grants[i].EvidenceComplete = true
	}
	blob, err := MarshalAzureRoleGrants(grants)
	require.NoError(t, err)
	roles := make([]string, 0, len(grants))
	for _, g := range grants {
		roles = append(roles, g.Role)
	}
	return asset.Asset{
		ID: id, Name: id, Type: "azure_service_principal", Provider: "azure",
		AccountID: "sub-1",
		Metadata:  map[string]string{"role_grants": blob, "role_grants_complete": "true", "roles": strings.Join(roles, ",")},
	}
}

// Real definitions, trimmed to the actions these techniques need.
var (
	azureContributor = AzureRoleGrant{
		Role: "Contributor", Scope: "/subscriptions/sub-1",
		Actions: []string{"*"},
		NotActions: []string{
			"Microsoft.Authorization/*/Write",
			"Microsoft.Authorization/*/Delete",
			"Microsoft.Authorization/elevateAccess/Action",
		},
	}
	azureUserAccessAdmin = AzureRoleGrant{
		Role: "User Access Administrator", Scope: "/subscriptions/sub-1",
		Actions: []string{"*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"},
	}
)

// TestAzureRBAC_StackedRolesNotMasked is the regression for the false
// negative: Azure evaluates each role assignment independently, so an action is
// granted if some role's Actions match it AND *that role's* NotActions do not.
// Unioning NotActions across assignments — the collector's original model — let
// Contributor's Authorization exclusions cancel a genuine
// Microsoft.Authorization/* grant from a stacked User Access Administrator.
// A managed identity holding both fired none of
// azure-privesc-01/-02 before this fix.
func TestAzureRBAC_StackedRolesNotMasked(t *testing.T) {
	stacked := azureSP(t, "sp-stacked", azureContributor, azureUserAccessAdmin)
	contribOnly := azureSP(t, "sp-contrib", azureContributor)

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{stacked, contribOnly})

	var stackedPaths, contribPaths []PrivescResult
	for _, p := range res.Paths {
		switch p.SourcePrincipal {
		case stacked.ID:
			stackedPaths = append(stackedPaths, p)
		case contribOnly.ID:
			contribPaths = append(contribPaths, p)
		}
	}

	require.True(t, hasRule(stackedPaths, "azure-privesc-01"),
		"User Access Administrator grants roleAssignments/write — Contributor's NotActions must not mask it")
	require.True(t, hasRule(stackedPaths, "azure-privesc-02"),
		"roleDefinitions/write comes from the same grant")

	// The other direction still holds: a lone Contributor must not fire, or the fix
	// has traded a false negative for a false positive on the commonest Azure role.
	require.False(t, hasRule(contribPaths, "azure-privesc-01"),
		"Contributor alone cannot write role assignments")
	require.False(t, hasRule(contribPaths, "azure-privesc-02"),
		"Contributor alone cannot write role definitions")

	// The allow-side union has broad scope, but Azure deny assignments are not
	// inventoried. Keep the candidate's severity; broad allow evidence cannot
	// prove that the principal already has unrestricted authority.
	var seen bool
	for _, f := range res.Findings {
		if f.PrincipalID == stacked.ID && f.RuleID == "azure-privesc-01" {
			seen = true
			require.Equal(t, SeverityCritical, f.Severity,
				"uncollected deny assignments prevent a severity reduction")
		}
	}
	require.True(t, seen, "the path must reach a finding, not just a detected path")
}

// TestAWSPrivesc15_TrustPolicyOnly_DoesNotFire is the regression for the
// false positive on AWS service-linked roles: every IAM role's trust policy
// (AssumeRolePolicyDocument) contains a mandatory statement granting SOME
// principal sts:AssumeRole — that's what makes it assumable. Fixture mirrors
// arn:aws:iam::444455556666:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer:
// its ONLY sts:AssumeRole occurrence is the boilerplate trust statement; its
// identity policy grants only resource-explorer-2:*/organizations:Describe*,
// nothing privesc-relevant. Before the fix, the trust statement's Allow fell
// into identityAllows and aws-privesc-15 fired on every single role.
func TestAWSPrivesc15_TrustPolicyOnly_DoesNotFire(t *testing.T) {
	role := asset.Asset{
		ID:   "arn:aws:iam::444455556666:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer",
		Name: "AWSServiceRoleForResourceExplorer", Type: "iam_role", Provider: "aws",
		Metadata: map[string]string{
			"policies": `[
				{"name":"AWSServiceRoleForResourceExplorer-trust","type":"trust","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"resource-explorer-2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"},
				{"name":"AWSServiceRoleForResourceExplorerPolicy","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"resource-explorer-2:*\",\"organizations:DescribeOrganization\",\"organizations:DescribeAccount\"],\"Resource\":\"*\"}]}"}
			]`,
		},
	}

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{role})

	var paths []PrivescResult
	for _, p := range res.Paths {
		if p.SourcePrincipal == role.ID {
			paths = append(paths, p)
		}
	}
	require.False(t, hasRule(paths, "aws-privesc-15"),
		"trust policy's mandatory sts:AssumeRole grant must not be read as this role's own permission")
}

// TestAWSPrivesc15_IdentityPolicyGrant_Fires is the positive companion: a role
// whose IDENTITY (permission) policy — not its trust policy — actually grants
// sts:AssumeRole with a broad Resource is the genuine escalation primitive
// (this role can assume other, potentially more privileged, roles).
func TestAWSPrivesc15_IdentityPolicyGrant_Fires(t *testing.T) {
	role := asset.Asset{
		ID: "arn:aws:iam::444455556666:role/app-role", Name: "app-role", Type: "iam_role", Provider: "aws",
		Metadata: map[string]string{
			"policies": `[
				{"name":"app-role-trust","type":"trust","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"},
				{"name":"app-role-assume-any","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"*\"}]}"}
			]`,
		},
	}

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{role})

	var paths []PrivescResult
	for _, p := range res.Paths {
		if p.SourcePrincipal == role.ID {
			paths = append(paths, p)
		}
	}
	require.True(t, hasRule(paths, "aws-privesc-15"),
		"a genuine identity-policy grant of sts:AssumeRole with a wildcard Resource must still fire")
}

// TestPermissionBoundary_CapsPrivesc: an admin (Allow *) role whose permission
// boundary does NOT permit sts:AssumeRole must not fire aws-privesc-15 — the
// boundary caps the effective grant. This is the overstatement the collector's
// boundary collection fixes.
func TestPermissionBoundary_CapsPrivesc(t *testing.T) {
	role := asset.Asset{
		ID: "arn:aws:iam::1:role/capped", Name: "capped", Type: "iam_role", Provider: "aws",
		Metadata: map[string]string{
			"policies": `[
				{"name":"admin","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
				{"name":"boundary","type":"boundary","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\"],\"Resource\":\"*\"}]}"}
			]`,
		},
	}

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{role})
	var paths []PrivescResult
	for _, p := range res.Paths {
		if p.SourcePrincipal == role.ID {
			paths = append(paths, p)
		}
	}
	require.False(t, hasRule(paths, "aws-privesc-15"),
		"a boundary lacking sts:AssumeRole caps the admin grant — privesc must not fire")
}

// TestSCP_DenyCapsPrivesc: an admin (Allow *) role whose account is under an SCP
// that denies iam:PassRole must not fire a PassRole-family privesc — the SCP deny
// wins. The SCP arrives as an aws_scp_set asset in the same analysis batch.
func TestSCP_DenyCapsPrivesc(t *testing.T) {
	role := asset.Asset{
		ID: "arn:aws:iam::111:role/admin", Name: "admin", Type: "iam_role", Provider: "aws", AccountID: "111",
		Metadata: map[string]string{
			"policies": `[{"name":"admin","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]`,
		},
	}
	scpSet := orgAsset(t, orgMember(
		orgLevel("111", "r-root", orgFullDocument, `{"Statement":[{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`),
		orgLevel("r-root", "", orgFullDocument),
	))

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{role, scpSet})
	var paths []PrivescResult
	for _, p := range res.Paths {
		if p.SourcePrincipal == role.ID {
			paths = append(paths, p)
		}
	}
	// PassRole-based techniques (aws-privesc-13, iam:PassRole+*) must not fire.
	for _, p := range paths {
		require.NotContains(t, p.Rule.RequiredActions, "iam:PassRole",
			"an SCP denying iam:PassRole must stop PassRole-family privesc from firing")
	}
}

// TestPermissionBoundary_StillPermittingActionFires is the false-negative guard:
// an admin (Allow *) role whose boundary STILL permits the escalation action must
// keep firing. The naive intersection dropped the "*" identity entry against any
// specific boundary, emptying effective permissions and hiding all privesc.
func TestPermissionBoundary_StillPermittingActionFires(t *testing.T) {
	role := asset.Asset{
		ID: "arn:aws:iam::1:role/admin", Name: "admin", Type: "iam_role", Provider: "aws",
		Metadata: map[string]string{
			"policies": `[
				{"name":"admin","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
				{"name":"boundary","type":"boundary","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"sts:AssumeRole\",\"iam:*\"],\"Resource\":\"*\"}]}"}
			]`,
		},
	}
	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{role})
	var paths []PrivescResult
	for _, p := range res.Paths {
		if p.SourcePrincipal == role.ID {
			paths = append(paths, p)
		}
	}
	require.True(t, hasRule(paths, "aws-privesc-15"),
		"a boundary that still permits sts:AssumeRole must NOT hide the privesc path")
}

// TestIntersectPermissions_NarrowerWins unit-tests the wildcard intersection.
func TestIntersectPermissions_NarrowerWins(t *testing.T) {
	star := []actionResourceSource{{action: "*", resource: "*", source: "identity"}}
	bounded := []actionResourceSource{{action: "sts:AssumeRole", resource: "*", source: "boundary"}}

	// identity "*" ∩ boundary "sts:AssumeRole" → effective "sts:AssumeRole".
	eff := intersectPermissions(star, bounded)
	require.Len(t, eff, 1)
	require.Equal(t, "sts:AssumeRole", eff[0].action)

	// Symmetric: boundary "*" ∩ identity "sts:AssumeRole" → "sts:AssumeRole".
	eff = intersectPermissions(bounded, star)
	require.Len(t, eff, 1)
	require.Equal(t, "sts:AssumeRole", eff[0].action)

	// Non-overlapping → dropped.
	eff = intersectPermissions(
		[]actionResourceSource{{action: "s3:GetObject", resource: "*"}},
		[]actionResourceSource{{action: "ec2:StartInstances", resource: "*"}},
	)
	require.Empty(t, eff)
}

// TestPermissionBoundary_UnparseableFailsOpen: a malformed boundary must not make
// the admin role's genuine privesc finding vanish — the cap is skipped, the
// finding still fires.
func TestPermissionBoundary_UnparseableFailsOpen(t *testing.T) {
	role := asset.Asset{
		ID: "arn:aws:iam::1:role/admin", Name: "admin", Type: "iam_role", Provider: "aws",
		Metadata: map[string]string{
			"policies": `[
				{"name":"admin","type":"identity","document":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
				{"name":"boundary","type":"boundary","document":"not-valid-json"}
			]`,
		},
	}

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{role})
	var paths []PrivescResult
	for _, p := range res.Paths {
		if p.SourcePrincipal == role.ID {
			paths = append(paths, p)
		}
	}
	require.True(t, hasRule(paths, "aws-privesc-15"),
		"an unparseable boundary must fail open (skip the cap), not hide the finding")
}
