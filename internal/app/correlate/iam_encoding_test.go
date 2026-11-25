package correlate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

func roleWithEncodedTrust(t *testing.T, doc string) asset.Asset {
	t.Helper()
	policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": doc}})
	require.NoError(t, err)
	return asset.Asset{ID: "arn:aws:iam::111122223333:role/target", Type: "iam_role", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"policies": string(policies)}}
}

func TestIAMCanAssume_EncodedDocumentsPreserveActualGraphEndpoint(t *testing.T) {
	for _, name := range []string{"OpsAdmin", "Ops+Admin", "team%2F/Ops+Admin", "team%ZZ/Ops+Admin"} {
		arn := "arn:aws:iam::111122223333:role/" + name
		doc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":%q}}}`, arn)
		for encoding, input := range map[string]string{
			"plain": doc, "percent": url.PathEscape(doc), "query": url.QueryEscape(doc),
			"collected": awspolicy.NormalizeDocument(url.PathEscape(doc)),
		} {
			t.Run(name+"/"+encoding, func(t *testing.T) {
				role := roleWithEncodedTrust(t, input)
				edges := IAMCanAssume{}.Correlate(NewGraph([]asset.Asset{role, {ID: arn, Type: "iam_role", Provider: asset.ProviderAWS}}))
				require.Len(t, edges, 1)
				require.Equal(t, arn, edges[0].SrcID)
				require.Equal(t, role.ID, edges[0].DstID)
			})
		}
	}
}

func TestFederationTrust_EncodedDocumentsPreserveSubjects(t *testing.T) {
	for _, subject := range []string{
		"repo:example/api:ref:refs/heads/release+hotfix",
		"repo:example/api:environment:Production%3AV1",
		"repo:example/api:ref:refs/heads/percent%GG+é雪",
	} {
		doc := fmt.Sprintf(`{ "Statement":{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity",
			"Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
			"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":%q}}}}`, subject)
		for encoding, input := range map[string]string{
			"plain": doc, "percent": url.PathEscape(doc), "query": url.QueryEscape(doc),
			"collected": awspolicy.NormalizeDocument(url.PathEscape(doc)),
		} {
			t.Run(subject+"/"+encoding, func(t *testing.T) {
				require.Equal(t, []string{subject}, extractGitHubSubjects(input))
				role := roleWithEncodedTrust(t, input)
				edges := FederationTrust{}.Correlate(NewGraph([]asset.Asset{role, {ID: "example/api", Type: "github_repo"}, {ID: "other/api", Type: "github_repo"}}))
				require.Len(t, edges, 1)
				require.Equal(t, "example/api", edges[0].SrcID)
				require.Equal(t, subject, edges[0].Properties["subject"])
			})
		}
	}
}

func TestFederationTrust_MalformedOrRepeatedEncodingGrantsNoEdge(t *testing.T) {
	const doc = `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"}}}`
	for _, input := range []string{"%", "%7B%GG", `{"Statement":`, url.PathEscape(`{"Statement":`), url.PathEscape(url.PathEscape(doc))} {
		require.Empty(t, trustStatements(input), input)
		role := roleWithEncodedTrust(t, input)
		require.Empty(t, FederationTrust{}.Correlate(NewGraph([]asset.Asset{role, {ID: "example/api", Type: "github_repo"}})), input)
	}
}
