package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCollectIdentityHarvest_ProjectsFileIdentifiers proves identifiers written
// inside any file land as declared_cloud_identity assets, whichever tool wrote
// the file.
func TestCollectIdentityHarvest_ProjectsFileIdentifiers(t *testing.T) {
	c := &Collector{
		harvestFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			return map[string]string{
				// Content names only the OIDC subject and the provider ARN — no role ARN.
				"roles/orders-api-build.json": `{"Statement":[{"Effect":"Allow",
					"Principal":{"Federated":"arn:aws:iam::555555555555:oidc-provider/token.actions.githubusercontent.com"},
					"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example-corp/orders-api:*"}}}]}`,
				"infra/main.tf": `role_arn = "arn:aws:iam::123456789012:role/hardcoded"`,
			}
		},
	}
	repos := []repo{{FullName: "example-org/iam-config", Name: "iam-config", DefaultBranch: "main"}}

	assets := c.collectRepoHarvest(context.Background(), "", "", repos)

	got := map[string]string{} // value -> kind
	for _, a := range assets {
		require.Equal(t, "declared_cloud_identity", a.Type)
		require.Equal(t, "example-org/iam-config", a.Metadata["repo"])
		got[a.Metadata["value"]] = a.Metadata["kind"]
	}

	// Read from the trust policy's condition.
	require.Equal(t, "github_oidc_sub", got["example-corp/orders-api"])
	// Read verbatim from unrelated Terraform.
	require.Equal(t, "iam_role", got["arn:aws:iam::123456789012:role/hardcoded"])
	// The oidc-provider ARN is not a role and must not be harvested as one.
	require.NotContains(t, got, "arn:aws:iam::555555555555:oidc-provider/token.actions.githubusercontent.com")
}

// Archived repos are skipped, as in every other ingest here.
func TestCollectIdentityHarvest_SkipsArchived(t *testing.T) {
	var called bool
	c := &Collector{
		harvestFiles: func(_ context.Context, _, _ string, _ repo) map[string]string {
			called = true
			return nil
		},
	}
	repos := []repo{{FullName: "org/old", Name: "old", DefaultBranch: "main", Archived: true}}
	require.Empty(t, c.collectRepoHarvest(context.Background(), "", "", repos))
	require.False(t, called)
}
