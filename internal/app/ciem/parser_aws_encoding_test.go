package ciem

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

func TestParseAWSPolicy_PreservesLiteralResourceAndConditionText(t *testing.T) {
	for _, resource := range []string{
		"arn:aws:iam::111122223333:role/Ops+Admin",
		"arn:aws:iam::111122223333:role/team%2F/Ops+Admin",
		"arn:aws:s3:::example/key%25%GG+é雪",
	} {
		doc := fmt.Sprintf(`{ "Statement":[
			{"Effect":"Allow","Action":"s3:GetObject","Resource":%q,"Condition":{"StringEquals":{"aws:PrincipalTag/team":%q}}},
			{"Effect":"Deny","Action":"s3:GetObject","NotResource":%q}]}`, resource, "é + %2B %GG", resource)
		for name, input := range map[string]string{
			"plain": doc, "percent": url.PathEscape(doc), "form": url.QueryEscape(doc),
			"already normalized": awspolicy.NormalizeDocument(url.PathEscape(doc)),
		} {
			t.Run(resource+"/"+name, func(t *testing.T) {
				statements, err := ParseAWSPolicy(input)
				require.NoError(t, err)
				require.Len(t, statements, 2)
				require.Equal(t, []string{resource}, statements[0].Resources)
				require.Equal(t, []string{resource}, statements[1].NotResources)
				require.Equal(t, []string{"é + %2B %GG"}, statements[0].Conditions["StringEquals"]["aws:PrincipalTag/team"])
			})
		}
	}
}

func TestAWSPolicyReaders_RejectMalformedOrRepeatedTransportEncoding(t *testing.T) {
	const doc = `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:role/Ops+Admin"},"Action":"sts:AssumeRole","Resource":"*"}}`
	for _, input := range []string{"%", "%7B%GG", `{"Statement":`, url.PathEscape(`{"Statement":`), url.PathEscape(url.PathEscape(doc))} {
		_, err := ParseAWSPolicy(input)
		require.Error(t, err, input)
		require.Empty(t, parseTrustStatements(input), input)
		require.Empty(t, EvaluateTrustPolicy(input).AWSPrincipals, input)
	}
}

func TestEvaluateTrustPolicy_PreservesPrincipalAndFederationText(t *testing.T) {
	for _, tt := range []struct {
		kind, principal, action string
	}{
		{"AWS", "arn:aws:iam::111122223333:role/Ops+Admin", "sts:AssumeRole"},
		{"AWS", "arn:aws:iam::111122223333:role/team%2F%GG/Ops+Admin", "sts:AssumeRole"},
		{"Federated", "arn:aws:iam::111122223333:oidc-provider/idp.example.com/team+blue/%2F", "sts:AssumeRoleWithWebIdentity"},
	} {
		doc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{%q:%q},"Action":%q}}`, tt.kind, tt.principal, tt.action)
		for _, input := range []string{doc, url.PathEscape(doc), url.QueryEscape(doc)} {
			eval := EvaluateTrustPolicy(input)
			if tt.kind == "AWS" {
				require.Equal(t, []string{tt.principal}, eval.AWSPrincipals, input)
			} else {
				require.Equal(t, tt.principal, eval.FederationProvider, input)
			}
		}
	}
}

func FuzzParseAWSPolicy_TransportPreservesStatements(f *testing.F) {
	for _, seed := range []string{"Ops+Admin", "%2F", "%252B", "%GG", "é雪", "space + percent%"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		data, err := json.Marshal(map[string]any{"Statement": map[string]any{
			"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/" + text,
			"Condition": map[string]any{"StringEquals": map[string]string{"aws:PrincipalTag/team": text}},
		}})
		require.NoError(t, err)
		doc := string(data)
		plain, err := ParseAWSPolicy(doc)
		require.NoError(t, err)
		for _, input := range []string{url.PathEscape(doc), strings.ReplaceAll(url.QueryEscape(doc), "+", "%20")} {
			parsed, err := ParseAWSPolicy(input)
			require.NoError(t, err)
			require.Equal(t, plain, parsed)
			parsedAgain, err := ParseAWSPolicy(awspolicy.NormalizeDocument(input))
			require.NoError(t, err)
			require.Equal(t, plain, parsedAgain)
		}
	})
}
