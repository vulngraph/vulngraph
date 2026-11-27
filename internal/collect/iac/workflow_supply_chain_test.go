package iac

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkflowTokenScopesAndCredentials(t *testing.T) {
	for _, tc := range []struct{ name, with, scope, owner, permission string }{
		{"default current", "", "current", "org", "installation"},
		{"owner installation", "          owner: org\n", "installation", "org", "installation"},
		{"repository owner expression", "          owner: ${{ github.repository_owner }}\n", "installation", "org", "installation"},
		{"selected", "          repositories: private, tools\n", "selected", "org", "installation"},
		{"unknown target", "          repositories: ${{ inputs.repositories }}\n", "unknown", "org", "installation"},
		{"unknown owner", "          owner: ${{ matrix.owner }}\n", "unknown", "", "installation"},
		{"narrowed permissions", "          permission-contents: read\n", "current", "org", "selected"},
		{"unknown permissions", "          permission-contents: ${{ inputs.level }}\n", "current", "org", "unknown"},
		{"enterprise", "          enterprise: example\n", "unknown", "org", "installation"},
		{"different host", "          github-api-url: https://other.example/api/v3\n", "unknown", "org", "installation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := "on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: 123\n          private-key: ${{ secrets.APP_KEY }}\n" + tc.with
			out, err := ParseWorkflowSupplyChain(".github/workflows/ci.yml", []byte(content), "org/public")
			require.NoError(t, err)
			require.Len(t, out.Tokens, 1)
			token := out.Tokens[0]
			require.Equal(t, "123", token.AppID)
			require.Equal(t, tc.scope, token.Scope)
			require.Equal(t, tc.owner, token.Owner)
			require.Equal(t, tc.permission, token.PermissionScope)
			require.Equal(t, []string{"APP_KEY"}, token.CredentialRefs)
			require.False(t, token.UntrustedExecution, "trigger alone is not untrusted execution")
		})
	}
}

func TestWorkflowPublicInputConditionsAndSecretRedaction(t *testing.T) {
	const source = `on: [pull_request_target]
jobs:
  danger:
    if: github.actor != 'bot'
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./test.sh
      - uses: actions/create-github-app-token@v3
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: DO-NOT-STORE-THIS-KEY
          permission-contents: write
  safe:
    if: false
    steps:
      - uses: actions/create-github-app-token@v3
        with:
          app-id: 123
          private-key: ${{ secrets['KEY'] }}
  reusable:
    uses: org/private/.github/workflows/build.yml@abcdef
    secrets: inherit
  lookalike:
    steps:
      - uses: actions/create-github-app-token-malicious@v1
      - uses: aws-actions/configure-aws-credentials-malicious@v1
`
	out, err := ParseWorkflowSupplyChain("ci.yml", []byte(source), "org/public")
	require.NoError(t, err)
	require.Len(t, out.Tokens, 2)
	require.True(t, out.Tokens[0].PublicInput)
	require.True(t, out.Tokens[0].UntrustedExecution)
	require.Equal(t, "conditional", out.Tokens[0].Condition)
	require.Empty(t, out.Tokens[0].AppID)
	require.Equal(t, "disabled", out.Tokens[1].Condition)
	require.Len(t, out.Calls, 1)
	require.Equal(t, "inherit", out.Calls[0].Secrets)
	b, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(b), "DO-NOT-STORE")
	require.NotContains(t, string(b), "github.actor")
	require.Empty(t, out.Cloud)
}

func TestWorkflowCloudDeclarations(t *testing.T) {
	const source = `on: issue_comment
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - run: echo "${{ github.event.comment.body }}"
      - uses: azure/login@v2
        with:
          client-id: 11111111-1111-1111-1111-111111111111
          tenant-id: 22222222-2222-2222-2222-222222222222
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
      - uses: google-github-actions/auth@v3
        with:
          service_account: ${{ secrets.GCP_SA }}
`
	out, err := ParseWorkflowSupplyChain("ci.yml", []byte(source), "org/public")
	require.NoError(t, err)
	require.Len(t, out.Cloud, 3)
	require.True(t, out.Cloud[0].Resolved)
	require.Equal(t, "azure", out.Cloud[0].Provider)
	require.Equal(t, "requested", out.Cloud[0].OIDC)
	require.True(t, out.Cloud[0].UntrustedExecution)
	require.True(t, out.Cloud[1].Resolved)
	require.False(t, out.Cloud[2].Resolved)
	require.Empty(t, out.Cloud[2].Target)
}

func TestWorkflowMalformedAndMissingJobs(t *testing.T) {
	for _, s := range []string{"jobs: [invalid", "on: push", ""} {
		_, err := ParseWorkflowSupplyChain("ci.yml", []byte(s), "org/repo")
		require.Error(t, err)
	}
}

func TestWorkflowDisabledUntrustedStep(t *testing.T) {
	out, err := ParseWorkflowSupplyChain("ci.yml", []byte(strings.ReplaceAll(`on: pull_request_target
jobs:
  build:
    steps:
      - run: echo "${{ github.event.comment.body }}"
        if: false
      - uses: actions/create-github-app-token@v3
`, "\t", "  ")), "org/repo")
	require.NoError(t, err)
	require.False(t, out.Tokens[0].UntrustedExecution)
}
