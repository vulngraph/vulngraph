package iac

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func harvestValues(t *testing.T, src string, kind string) []string {
	t.Helper()
	var out []string
	for _, d := range HarvestIdentities([]byte(src)) {
		if d.Kind == kind {
			out = append(out, d.Value)
		}
	}
	return out
}

// The point of the harvest: the same extractor reads every tool's output, because
// they all write identities identically. Each case below is a representative
// shape of how a tool writes an identity.
func TestHarvestIdentities_ToolAgnostic(t *testing.T) {
	tests := []struct {
		name, src, kind string
		want            []string
	}{
		{
			name: "GitHub OIDC trust policy (raw IAM JSON)",
			src: `{"Statement":[{"Effect":"Allow","Principal":{"Federated":
				"arn:aws:iam::555555555555:oidc-provider/token.actions.githubusercontent.com"},
				"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example-corp/orders-api:*"}}}]}`,
			kind: IdentityGitHubOIDC,
			want: []string{"example-corp/orders-api"},
		},
		{
			name: "terraform literal role arn",
			src:  `role_arn = "arn:aws:iam::123456789012:role/orders-api-task"`,
			kind: IdentityIamRole,
			want: []string{"arn:aws:iam::123456789012:role/orders-api-task"},
		},
		{
			name: "IRSA annotation in a k8s manifest",
			src:  "annotations:\n  eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/irsa-app\n",
			kind: IdentityIamRole,
			want: []string{"arn:aws:iam::123456789012:role/irsa-app"},
		},
		{
			name: "GKE Workload Identity annotation",
			src:  "iam.gke.io/gcp-service-account: app-publisher@example-project.iam.gserviceaccount.com",
			kind: IdentityGCPSA,
			want: []string{"serviceAccount:app-publisher@example-project.iam.gserviceaccount.com"},
		},
		{
			name: "path-qualified SSO role ARN survives whole",
			src:  `"arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_AdminAccess_1a2b3c4d5e6f7a8b"`,
			kind: IdentityIamRole,
			want: []string{"arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_AdminAccess_1a2b3c4d5e6f7a8b"},
		},
		{
			name: "iam user arn",
			src:  `arn:aws:iam::123456789012:user/deploy-bot`,
			kind: IdentityIamUser,
			want: []string{"arn:aws:iam::123456789012:user/deploy-bot"},
		},
		{
			name: "default compute and appspot service accounts",
			src:  "a: 5004567890123-compute@developer.gserviceaccount.com\nb: example-project-a@appspot.gserviceaccount.com",
			kind: IdentityGCPSA,
			want: []string{
				"serviceAccount:5004567890123-compute@developer.gserviceaccount.com",
				"serviceAccount:example-project-a@appspot.gserviceaccount.com",
			},
		},
		{
			name: "govcloud partition",
			src:  `arn:aws-us-gov:iam::123456789012:role/gov-app`,
			kind: IdentityIamRole,
			want: []string{"arn:aws-us-gov:iam::123456789012:role/gov-app"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, harvestValues(t, tt.src, tt.kind))
		})
	}
}

// Rejecting non-literals is what keeps the downstream join exact rather than
// heuristic: an unresolved template names no single identity, and joining a
// wildcard would attach evidence to the wrong role.
func TestHarvestIdentities_RejectsNonLiterals(t *testing.T) {
	for _, src := range []string{
		`role_arn = "${aws_iam_role.app.arn}"`,
		`role_arn = "arn:aws:iam::123456789012:role/${var.env}-app"`,
		`"Resource": "arn:aws:iam::123456789012:role/*"`,
		`!Sub "arn:aws:iam::${AWS::AccountId}:role/thing"`,
		`sa: "${project}@${project}.iam.gserviceaccount.com"`,
		`"repo:example-corp/${repo}:*"`,
		// A template after or before a literal-looking prefix: the regex stops at
		// the template character, so the match is a truncated, wrong identity.
		`role_arn = "arn:aws:iam::123456789012:role/app-${var.env}"`,
		`sa: "${prefix}-sa@proj.iam.gserviceaccount.com"`,
		`sa: "${prefix}sa@proj.iam.gserviceaccount.com"`,
		`"repo:example-corp/app-${x}:*"`,
		`role_arn: "arn:aws:iam::123456789012:role/app-{{ .Values.env }}"`,
		`"Resource": "arn:aws:iam::123456789012:role/app-*"`,
	} {
		require.Empty(t, HarvestIdentities([]byte(src)), "must not harvest a template: %s", src)
	}

	// A path with no role name after it identifies nothing.
	require.Empty(t, HarvestIdentities([]byte(`arn:aws:iam::123456789012:role/`)))
}

// Ordinary delimiters around a literal are not templates: prose, Markdown, XML
// and shell all wrap identities in brackets, and the harvest reads them all.
func TestHarvestIdentities_KeepsDelimitedLiterals(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/deploy"
	tests := []struct {
		name, src, kind string
		want            []string
	}{
		{"parenthesised in prose", "See (" + role + ") for details", IdentityIamRole, []string{role}},
		{"XML element", "<RoleArn>" + role + "</RoleArn>", IdentityIamRole, []string{role}},
		{"shell command substitution", "ROLE=$(echo " + role + ")", IdentityIamRole, []string{role}},
		{"Markdown link target", "[role](" + role + ")", IdentityIamRole, []string{role}},
		{"angle-bracketed email", "Members: <ci-sa@proj.iam.gserviceaccount.com>", IdentityGCPSA,
			[]string{"serviceAccount:ci-sa@proj.iam.gserviceaccount.com"}},
		{"parenthesised OIDC subject", "(repo:example-corp/app)", IdentityGitHubOIDC, []string{"example-corp/app"}},
		{"YAML flow mapping", "Principal: {AWS: " + role + "}", IdentityIamRole, []string{role}},
		{"Markdown bold", "Deploys as **" + role + "**.", IdentityIamRole, []string{role}},
		{"brace-wrapped email", "{ci-sa@proj.iam.gserviceaccount.com}", IdentityGCPSA,
			[]string{"serviceAccount:ci-sa@proj.iam.gserviceaccount.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, harvestValues(t, tt.src, tt.kind))
		})
	}
}

func TestHarvestIdentities_DedupesAndKeepsOrder(t *testing.T) {
	src := `
	arn:aws:iam::123456789012:role/b
	arn:aws:iam::123456789012:role/a
	arn:aws:iam::123456789012:role/b
	`
	require.Equal(t, []string{"arn:aws:iam::123456789012:role/b", "arn:aws:iam::123456789012:role/a"},
		harvestValues(t, src, IdentityIamRole))
}

// An account id is always 12 digits. Anything shorter is a fixture or a
// placeholder, not an identity to join against.
func TestHarvestIdentities_RequiresFullAccountID(t *testing.T) {
	require.Empty(t, HarvestIdentities([]byte(`arn:aws:iam::1:role/short`)))
}

// A file mixing several kinds — the common case in a real trust policy, which
// names the role's account, the OIDC provider and the subject at once.
func TestHarvestIdentities_MixedKinds(t *testing.T) {
	src := `{
		"role": "arn:aws:iam::555555555555:role/orders-api-build",
		"sub": "repo:example-corp/orders-api:ref:refs/heads/main",
		"sa": "deployer@proj.iam.gserviceaccount.com"
	}`
	got := HarvestIdentities([]byte(src))
	kinds := map[string]string{}
	for _, d := range got {
		kinds[d.Kind] = d.Value
	}
	require.Len(t, got, 3)
	require.Equal(t, "arn:aws:iam::555555555555:role/orders-api-build", kinds[IdentityIamRole])
	require.Equal(t, "example-corp/orders-api", kinds[IdentityGitHubOIDC])
	require.Equal(t, "serviceAccount:deployer@proj.iam.gserviceaccount.com", kinds[IdentityGCPSA])
}
