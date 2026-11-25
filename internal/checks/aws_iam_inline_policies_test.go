package checks

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// policiesMeta builds a principal's `policies` metadata from (name, type,
// managed, document) entries.
func policiesMeta(t *testing.T, entries ...iamPolicyEntry) map[string]string {
	t.Helper()
	b, err := json.Marshal(entries)
	require.NoError(t, err)
	return map[string]string{"policies": string(b)}
}

func inlineDoc(name, doc string) iamPolicyEntry {
	return iamPolicyEntry{Name: name, Type: "identity", Document: doc}
}

func principal(kind string, meta map[string]string) asset.Asset {
	return asset.Asset{ID: "arn:aws:iam::123456789012:" + kind + "/x", Type: "iam_" + kind, Provider: asset.ProviderAWS, AccountID: "123456789012", Metadata: meta}
}

func TestInlineCloudTrailFullAccess(t *testing.T) {
	tests := []struct {
		name  string
		entry iamPolicyEntry
		fires bool
	}{
		{"service wildcard on all resources", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"}]}`), true},
		{"single statement object, list resource", inlineDoc("p", `{"Statement":{"Effect":"Allow","Action":["cloudtrail:*"],"Resource":["*"]}}`), true},
		{"action wildcard", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`), true},
		{"prefix wildcard", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloud*","Resource":"*"}]}`), true},
		{"effect case ignored", inlineDoc("p", `{"Statement":[{"Effect":" allow ","Action":"CloudTrail:*","Resource":"*"}]}`), true},
		{"NotAction leaving cloudtrail alone", inlineDoc("p", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`), true},
		{"allow condition does not exempt", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`), true},
		{"resource scoped", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"arn:aws:cloudtrail:*:*:trail/x"}]}`), false},
		{"read actions only", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:Get*","Resource":"*"}]}`), false},
		{"other service", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`), false},
		{"NotAction excluding cloudtrail", inlineDoc("p", `{"Statement":[{"Effect":"Allow","NotAction":"cloudtrail:*","Resource":"*"}]}`), false},
		{"deny of one action", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"cloudtrail:DeleteTrail","Resource":"*"}]}`), false},
		{"deny on a specific resource still counts", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"},{"Effect":"Deny","Action":"cloudtrail:StopLogging","Resource":"arn:aws:cloudtrail:*:*:trail/x"}]}`), false},
		{"deny of an unrelated service", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`), true},
		{"deny everything but cloudtrail", inlineDoc("p", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"},{"Effect":"Deny","NotAction":"cloudtrail:*","Resource":"*"}]}`), true},
		{"managed policy is not inline", iamPolicyEntry{Name: "m", Type: "identity", Managed: true, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}, false},
		{"unparseable document", inlineDoc("p", `not json`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range []Check{awsIAMUserInlineCloudTrailFullAccess, awsIAMGroupInlineCloudTrailFullAccess, awsIAMRoleInlineCloudTrailFullAccess} {
				a := principal(c.AssetType[len("iam_"):], policiesMeta(t, tt.entry))
				require.Equal(t, tt.fires, c.Violates(a), c.ID)
			}
		})
	}
}

func TestInlineMarketplaceSubscribe(t *testing.T) {
	tests := []struct {
		name  string
		doc   string
		fires bool
	}{
		{"exact action", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:Subscribe","Resource":"*"}]}`, true},
		{"service wildcard", `{"Statement":[{"Effect":"Allow","Action":["aws-marketplace:*"],"Resource":["*"]}]}`, true},
		{"admin wildcard", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, true},
		{"NotAction not excluding it", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`, true},
		{"conditional allow still counts", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:Subscribe","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}`, true},
		{"conditional deny does not cancel", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:Subscribe","Resource":"*"},{"Effect":"Deny","Action":"aws-marketplace:Subscribe","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`, true},
		{"unconditional deny cancels", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:*","Resource":"*"},{"Effect":"Deny","Action":"aws-marketplace:Subscribe","Resource":"*"}]}`, false},
		{"deny by NotAction cancels", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}]}`, false},
		{"deny on a specific resource does not cancel", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:Subscribe","Resource":"*"},{"Effect":"Deny","Action":"aws-marketplace:Subscribe","Resource":"arn:aws:aws-marketplace:*"}]}`, true},
		{"resource scoped allow", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:Subscribe","Resource":"arn:aws:aws-marketplace:us-east-1:123456789012:*"}]}`, false},
		{"other marketplace action", `{"Statement":[{"Effect":"Allow","Action":"aws-marketplace:ViewSubscriptions","Resource":"*"}]}`, false},
		{"no statements", `{"Statement":[]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range []Check{awsIAMUserInlineMarketplaceSubscribe, awsIAMGroupInlineMarketplaceSubscribe, awsIAMRoleInlineMarketplaceSubscribe} {
				a := principal(c.AssetType[len("iam_"):], policiesMeta(t, inlineDoc("p", tt.doc)))
				require.Equal(t, tt.fires, c.Violates(a), c.ID)
			}
		})
	}
}

func TestInlineGrantChecksNeedPoliciesRead(t *testing.T) {
	for _, bare := range awsIAMInlinePolicyChecks() {
		c, ok := Default().ByID(bare.ID)
		require.True(t, ok, bare.ID)
		t.Run(c.ID, func(t *testing.T) {
			for _, meta := range []map[string]string{nil, {}, {"policies": "not json"}} {
				a := principal(c.AssetType[len("iam_"):], meta)
				require.False(t, c.Violates(a), "unread policies are not evidence")
			}
			unread := principal(c.AssetType[len("iam_"):], map[string]string{})
			require.False(t, c.Evaluable(unread), "an unread principal must not close a finding")
			require.Equal(t, []string{"policies"}, c.RequiredKeys)
			clean := principal(c.AssetType[len("iam_"):], map[string]string{"policies": "[]"})
			require.True(t, c.Evaluable(clean))
		})
	}
}

func TestInlineGrantEvidenceNamesThePolicies(t *testing.T) {
	a := principal("role", policiesMeta(t,
		inlineDoc("ct", `{"Statement":[{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"}]}`),
		inlineDoc("s3", `{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`),
	))
	require.Equal(t, map[string]string{"inline_policies": "ct"}, awsIAMRoleInlineCloudTrailFullAccess.EvidenceFor(a))
}

func TestIAMGlob(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "cloudtrail:*", true},
		{"cloudtrail:*", "cloudtrail:*", true},
		{"cloudtrail:Get*", "cloudtrail:*", false},
		{"CLOUDTRAIL:*", "cloudtrail:*", true},
		{"sts:Assume?ole", "sts:AssumeRole", true},
		{"sts:*Role", "sts:AssumeRole", true},
		{"sts:A*Role", "sts:AssumeRole", true},
		{"sts:AssumeRoleWithSAML", "sts:AssumeRole", false},
		{"sts:AssumeRole*", "sts:AssumeRole", true},
		{"", "x", false},
		{"**", "", true},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, iamGlob(tt.pattern, tt.value), tt.pattern+" vs "+tt.value)
	}
}
