package aws

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
)

type encodingIAM struct {
	fakeIAM
	policy, trust string
}

func (c encodingIAM) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(c.policy)}}, nil
}

func (c encodingIAM) ListRoles(ctx context.Context, in *iam.ListRolesInput, opts ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	out, err := c.fakeIAM.ListRoles(ctx, in, opts...)
	out.Roles[0].AssumeRolePolicyDocument = awssdk.String(c.trust)
	return out, err
}

func TestIAMDocumentCollection_PreservesResourceAndGraphEndpoint(t *testing.T) {
	const principal = "arn:aws:iam::111122223333:role/team%2F/Ops+Admin"
	const resource = "arn:aws:s3:::example/object+é%2F%GG"
	policy := fmt.Sprintf(`{ "Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":%q}}`, resource)
	trust := fmt.Sprintf(`{ "Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":%q}}}`, principal)
	for name, encode := range map[string]func(string) string{
		"plain": func(s string) string { return s },
		"RFC3986": func(s string) string {
			return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
		},
		"percent with literal plus": url.PathEscape,
		"form":                      url.QueryEscape,
	} {
		t.Run(name, func(t *testing.T) {
			client := encodingIAM{policy: encode(policy), trust: encode(trust)}
			cache := newManagedPolicyCache(client)
			collected, _, err := collectRoles(t.Context(), client, cache, "1", time.Now())
			require.NoError(t, err)
			var role asset.Asset
			for _, a := range collected {
				if a.Type == "iam_role" {
					role = a
				}
			}
			require.NotEmpty(t, role.ID)
			docs := decodePolicies(t, role.Metadata["policies"])
			seen := map[string]bool{}
			for _, doc := range docs {
				switch doc.Type {
				case "identity":
					seen[doc.Type] = true
					require.Equal(t, policy, doc.Document)
					statements, err := ciem.ParseAWSPolicy(doc.Document)
					require.NoError(t, err)
					require.Len(t, statements, 1)
					require.Equal(t, []string{resource}, statements[0].Resources)
				case "trust":
					seen[doc.Type] = true
					require.Equal(t, trust, doc.Document)
				}
			}
			require.Equal(t, map[string]bool{"identity": true, "trust": true}, seen)
			graph := correlate.NewGraph(append(collected, asset.Asset{ID: principal, Type: "iam_role", Provider: asset.ProviderAWS}))
			edges := correlate.IAMCanAssume{}.Correlate(graph)
			require.Len(t, edges, 1)
			require.Equal(t, principal, edges[0].SrcID)
			require.Equal(t, role.ID, edges[0].DstID)
		})
	}
}

func TestIAMDocumentCollection_InlineAndCustomerVersionNormalizeOnce(t *testing.T) {
	const resource = "arn:aws:iam::111122223333:role/team%2F/Ops+Admin"
	doc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":%q}}`, resource)
	for _, input := range []string{doc, url.PathEscape(doc), url.QueryEscape(doc)} {
		var inline principalPolicies
		inline.addInline("inline", input)
		require.Len(t, inline.docs, 1)
		_, customer := customerPolicyAsset(iamtypes.ManagedPolicyDetail{
			Arn:               awssdk.String("arn:aws:iam::111122223333:policy/example"),
			PolicyVersionList: []iamtypes.PolicyVersion{{IsDefaultVersion: true, Document: awssdk.String(input)}},
		}, "111122223333", time.Now())
		for _, normalized := range []string{inline.docs[0].Document, customer} {
			require.Equal(t, doc, normalized)
			statements, err := ciem.ParseAWSPolicy(normalized)
			require.NoError(t, err)
			require.Equal(t, []string{resource}, statements[0].Resources)
		}
	}
}

func TestIAMDocumentCollection_MalformedInputRemainsUnparseable(t *testing.T) {
	const valid = `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	for _, input := range []string{"%7B%GG", url.PathEscape(`{"Statement":`), url.PathEscape(url.PathEscape(valid))} {
		cache := newManagedPolicyCache(encodingIAM{policy: input})
		doc, ok := cache.document(t.Context(), "arn:aws:iam::111122223333:policy/example")
		require.True(t, ok, "the API response was read, but its content is still invalid")
		require.Equal(t, input, doc)
		_, err := ciem.ParseAWSPolicy(doc)
		require.Error(t, err)
		require.False(t, isAdminish(t.Context(), "principal", []policyDoc{{Type: "identity", Document: doc}}))
	}
}
