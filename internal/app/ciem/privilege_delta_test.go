package ciem

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestPrincipalTier(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		roles    string
		perms    []EffectivePermission
		want     privilegeTier
	}{
		{
			name:     "gcp owner label cannot prove unrestricted authority without deny policies",
			provider: "gcp",
			roles:    "roles/owner,roles/billing.projectManager",
			want:     tierNormal,
		},
		{
			// The distinction that keeps real findings: Editor→Owner IS an escalation.
			name:     "gcp editor is NOT admin",
			provider: "gcp",
			roles:    "roles/editor,roles/storage.admin",
			want:     tierNormal,
		},
		{
			name:     "aws full wildcard is admin",
			provider: "aws",
			perms:    []EffectivePermission{{Action: "*", Resource: "*"}},
			want:     tierAdmin,
		},
		{
			name:     "aws IAM wildcard does not prove all-service authority",
			provider: "aws",
			perms:    []EffectivePermission{{Action: "iam:*", Resource: "*"}},
			want:     tierNormal,
		},
		{
			name:     "gcp project setIamPolicy is only an allow candidate",
			provider: "gcp",
			perms:    []EffectivePermission{{Action: "resourcemanager.projects.setIamPolicy", Resource: "*"}},
			want:     tierNormal,
		},
		{
			// Critical non-regression: these actions ARE the required actions of
			// aws-privesc-01/05/06. Treating them as "already privileged" would cap
			// those rules by their own predicate and silence them entirely.
			name:     "aws iam:PutRolePolicy is NOT self-grant — it is the technique itself",
			provider: "aws",
			perms:    []EffectivePermission{{Action: "iam:PutRolePolicy", Resource: "*"}},
			want:     tierNormal,
		},
		{
			name:     "a denied wildcard does not confer admin",
			provider: "aws",
			perms:    []EffectivePermission{{Action: "*", Resource: "*", Effect: EffectDeny}},
			want:     tierNormal,
		},
		{
			name:     "ordinary grants stay normal",
			provider: "gcp",
			perms:    []EffectivePermission{{Action: "storage.objects.get", Resource: "*"}},
			want:     tierNormal,
		},
		{
			// Azure Owner: wildcard with nothing carved out.
			name:     "azure owner wildcard is admin",
			provider: "azure",
			perms:    []EffectivePermission{{Action: "*", Resource: "/subscriptions/s", SourcePolicy: azureRBACSource, Grant: "0:Owner@/subscriptions/s"}},
			want:     tierAdmin,
		},
		{
			// Contributor touches every resource but cannot grant itself a role, so it
			// is NOT at the ceiling. Reading its "*" as admin capped every Contributor
			// privesc finding at low.
			name:     "azure contributor wildcard carved out of Authorization is not admin",
			provider: "azure",
			perms: []EffectivePermission{
				{Action: "*", Resource: "/subscriptions/s", SourcePolicy: azureRBACSource, Grant: "0:Contributor@/subscriptions/s"},
				{Action: "Microsoft.Authorization/*/Write", Resource: "/subscriptions/s", SourcePolicy: azureRBACSource, Effect: EffectDeny, Grant: "0:Contributor@/subscriptions/s"},
				{Action: "Microsoft.Authorization/elevateAccess/Action", Resource: "/subscriptions/s", SourcePolicy: azureRBACSource, Effect: EffectDeny, Grant: "0:Contributor@/subscriptions/s"},
			},
			want: tierNormal,
		},
		{
			// User Access Administrator is defined as the namespace pattern, never the
			// concrete write action — an exact-string self-grant list misses it.
			name:     "azure User Access Administrator self-grants via pattern",
			provider: "azure",
			perms:    []EffectivePermission{{Action: "Microsoft.Authorization/*", Resource: "/subscriptions/s", SourcePolicy: azureRBACSource, Grant: "0:User Access Administrator@/subscriptions/s"}},
			want:     tierSelfGrant,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, principalTier(tt.provider, tt.roles, tt.perms, "s"))
		})
	}
}

func TestCapToPrivilegeDelta(t *testing.T) {
	tests := []struct {
		name     string
		sev      string
		tier     privilegeTier
		scopeMax privilegeTier
		want     string
	}{
		{
			name: "already-owner critical caps to low",
			sev:  SeverityCritical, tier: tierAdmin, scopeMax: tierAdmin, want: SeverityLow,
		},
		{
			name: "already self-granting critical caps to medium",
			sev:  SeverityCritical, tier: tierSelfGrant, scopeMax: tierAdmin, want: SeverityMedium,
		},
		{
			// e.g. ci-runner@example-project-a / deployer@example-project-b:
			// real permissions, but the highest role anywhere in the project is Editor.
			name: "nothing more privileged in scope caps to medium",
			sev:  SeverityCritical, tier: tierSelfGrant, scopeMax: tierSelfGrant, want: SeverityMedium,
		},
		{
			// The case that must survive: Editor in a project that has an Owner.
			name: "editor in a project containing an owner is uncapped",
			sev:  SeverityCritical, tier: tierNormal, scopeMax: tierAdmin, want: SeverityCritical,
		},
		{
			name: "a cap never raises severity",
			sev:  SeverityLow, tier: tierSelfGrant, scopeMax: tierAdmin, want: SeverityLow,
		},
		{
			name: "no privileged principal anywhere in scope — no cap",
			sev:  SeverityHigh, tier: tierNormal, scopeMax: tierNormal, want: SeverityHigh,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, capToPrivilegeDelta(tt.sev, tt.tier, tt.scopeMax))
		})
	}
}

// An Owner allow can be restricted by an uncollected deny policy. Its role name
// cannot establish a severity ceiling for another escalation candidate.
func TestAnalyzeIAMAssets_GCPOwnerAllowCannotCapSeverity(t *testing.T) {
	owner := asset.Asset{
		ID: "serviceAccount:owner-sa@proj.iam.gserviceaccount.com", Type: "gcp_service_account",
		Name: "owner-sa", Provider: asset.ProviderGCP, AccountID: "proj",
		Metadata: map[string]string{
			"roles": "roles/owner",
			// Owner implies these; the collector writes the flattened permission list.
			"permissions": "iam.serviceAccounts.actAs,compute.instances.create,iam.serviceAccountKeys.create",
		},
	}

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{owner})

	require.NotEmpty(t, res.Findings)
	for _, f := range res.Findings {
		require.Equal(t, SeverityCritical, f.Severity,
			"%s must retain rule severity without proof of unrestricted authority", f.RuleID)
	}
}

// TestAnalyzeIAMAssets_EditorWithOwnerInScopeStaysHigh is the other half — the cap
// must not swallow the genuine Editor→Owner path, e.g. a default compute SA such as
// 123456789012-compute@developer in a project that also has an Owner.
func TestAnalyzeIAMAssets_EditorWithOwnerInScopeStaysHigh(t *testing.T) {
	editor := asset.Asset{
		ID: "serviceAccount:editor-sa@proj.iam.gserviceaccount.com", Type: "gcp_service_account",
		Name: "editor-sa", Provider: asset.ProviderGCP, AccountID: "proj",
		Metadata: map[string]string{
			"roles":       "roles/editor",
			"permissions": "iam.serviceAccounts.actAs,compute.instances.create,iam.serviceAccountKeys.create",
		},
	}
	owner := asset.Asset{
		ID: "serviceAccount:owner-sa@proj.iam.gserviceaccount.com", Type: "gcp_service_account",
		Name: "owner-sa", Provider: asset.ProviderGCP, AccountID: "proj",
		Metadata: map[string]string{"roles": "roles/owner", "permissions": "resourcemanager.projects.setIamPolicy"},
	}

	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{editor, owner})

	var editorFindings int
	for _, f := range res.Findings {
		if f.PrincipalID != editor.ID {
			continue
		}
		editorFindings++
		require.NotEqual(t, SeverityLow, f.Severity,
			"%s on an Editor principal in a project containing an Owner is a real escalation and must not be capped to low", f.RuleID)
	}
	require.NotZero(t, editorFindings, "the Editor principal must still produce findings")
}
