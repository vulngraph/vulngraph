package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func trustEntry(doc string) iamPolicyEntry {
	return iamPolicyEntry{Name: "r-trust", Type: "trust", Document: doc}
}

func managedEntry(name string) iamPolicyEntry {
	return iamPolicyEntry{Name: name, Type: "identity", Managed: true}
}

func roleAsset(t *testing.T, id string, entries ...iamPolicyEntry) asset.Asset {
	a := principal("role", policiesMeta(t, entries...))
	if id != "" {
		a.ID = id
	}
	return a
}

func svcTrust(condition string) string {
	c := ""
	if condition != "" {
		c = `,"Condition":` + condition
	}
	return `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"` + c + `}]}`
}

func TestCrossAccountReadOnly(t *testing.T) {
	ro := managedEntry("ReadOnlyAccess")
	tests := []struct {
		name    string
		entries []iamPolicyEntry
		fires   bool
	}{
		{"other account trusted", []iamPolicyEntry{ro, trustEntry(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`)}, true},
		{"wildcard principal", []iamPolicyEntry{ro, trustEntry(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`)}, true},
		{"one foreign account in a list", []iamPolicyEntry{ro, trustEntry(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root","arn:aws:iam::999999999999:root"]},"Action":"sts:AssumeRole"}]}`)}, true},
		{"own account only", []iamPolicyEntry{ro, trustEntry(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`)}, false},
		{"foreign account in a deny", []iamPolicyEntry{ro, trustEntry(`{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`)}, false},
		{"no ReadOnlyAccess", []iamPolicyEntry{managedEntry("ViewOnlyAccess"), trustEntry(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`)}, false},
		{"service role is skipped", []iamPolicyEntry{ro, trustEntry(svcTrust(""))}, false},
		{"federated principal only", []iamPolicyEntry{ro, trustEntry(`{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/x"},"Action":"sts:AssumeRoleWithSAML"}]}`)}, false},
		{"no trust document", []iamPolicyEntry{ro}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, awsIAMRoleCrossAccountReadOnly.Violates(roleAsset(t, "", tt.entries...)))
		})
	}
	t.Run("absent and account-less", func(t *testing.T) {
		require.False(t, awsIAMRoleCrossAccountReadOnly.Violates(principal("role", nil)))
		a := roleAsset(t, "", ro, trustEntry(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`))
		a.AccountID = ""
		require.False(t, awsIAMRoleCrossAccountReadOnly.Violates(a))
	})
}

func TestServiceConfusedDeputy(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		trust string
		fires bool
	}{
		{"no condition", "", svcTrust(""), true},
		{"empty condition", "", svcTrust(`{}`), true},
		{"condition on something else", "", svcTrust(`{"Bool":{"aws:SecureTransport":"true"}}`), true},
		{"source account", "", svcTrust(`{"StringEquals":{"aws:SourceAccount":"123456789012"}}`), false},
		{"source ARN like", "", svcTrust(`{"ArnLike":{"aws:SourceArn":"arn:aws:ecs:*:123456789012:*"}}`), false},
		{"organisation id", "", svcTrust(`{"StringEquals":{"aws:PrincipalOrgID":"o-abcdefghij"}}`), false},
		{"any value under a source key counts", "", svcTrust(`{"StringEquals":{"aws:PrincipalOrgID":"o-*"}}`), false},
		{"private source ip", "", svcTrust(`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}`), false},
		{"public source ip", "", svcTrust(`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","8.8.8.8"]}}`), true},
		{"eks is exempt", "", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, false},
		{"service-linked role", "arn:aws:iam::123456789012:role/aws-service-role/x/y", svcTrust(""), false},
		{"non-AWS service name", "", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"example.internal"},"Action":"sts:AssumeRole"}]}`, false},
		{"not a service role: also trusts an account", "", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com","AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`, false},
		{"other action", "", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:TagSession"}]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, awsIAMRoleServiceConfusedDeputy.Violates(roleAsset(t, tt.id, trustEntry(tt.trust))))
		})
	}
	require.False(t, awsIAMRoleServiceConfusedDeputy.Violates(principal("role", nil)))
	require.False(t, awsIAMRoleServiceConfusedDeputy.Violates(principal("role", map[string]string{"policies": "[]"})))
}

func TestServiceTrustUnpinnedSource(t *testing.T) {
	tests := []struct {
		name  string
		trust string
		fires bool
	}{
		{"literal account", svcTrust(`{"StringEquals":{"aws:SourceAccount":"123456789012"}}`), false},
		{"wildcard account", svcTrust(`{"StringLike":{"aws:SourceAccount":"1234*"}}`), true},
		{"account and source ARN, ARN unpinned", svcTrust(`{"StringEquals":{"aws:SourceAccount":"123456789012"},"ArnLike":{"aws:SourceArn":"arn:aws:s3:::*"}}`), false},
		{"source ARN with literal account", svcTrust(`{"ArnLike":{"aws:SourceArn":"arn:aws:events:us-east-1:123456789012:rule/*"}}`), false},
		{"source ARN with wildcard account", svcTrust(`{"ArnLike":{"aws:SourceArn":"arn:aws:events:us-east-1:*:rule/*"}}`), true},
		{"organisation id", svcTrust(`{"StringEquals":{"aws:SourceOrgID":"o-abcdefghij"}}`), false},
		{"organisation paths", svcTrust(`{"ForAnyValue:StringLike":{"aws:SourceOrgPaths":"o-abcdefghij/r-ab12/*"}}`), false},
		{"negated operator", svcTrust(`{"StringNotEquals":{"aws:SourceAccount":"123456789012"}}`), false},
		{"unguarded ForAllValues", svcTrust(`{"ForAllValues:StringEquals":{"aws:SourceAccount":"123456789012"},"Bool":{"aws:SecureTransport":"true"}}`), true},
		{"guarded ForAllValues", svcTrust(`{"ForAllValues:StringEquals":{"aws:SourceAccount":"123456789012"},"Null":{"aws:SourceAccount":"false"}}`), false},
		{"null guard with true and false", svcTrust(`{"StringEqualsIfExists":{"aws:SourceAccount":"123456789012"},"Null":{"aws:SourceAccount":["true","false"]}}`), true},
		{"Null alone pins nothing", svcTrust(`{"Null":{"aws:SourceAccount":"false"}}`), true},
		{"wholly unconditional plain role is the sibling's finding", svcTrust(""), false},
		{"unconditional but trust is not plain", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`, true},
		{"star principal", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, true},
		{"NotAction is left unevaluated", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"NotAction":"iam:*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, false},
		{"assume-role-with-saml is out of scope", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRoleWithSAML","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, false},
		{"action glob", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:Assume*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, awsIAMRoleServiceTrustUnpinnedSource.Violates(roleAsset(t, "", trustEntry(tt.trust))))
		})
	}
	linked := roleAsset(t, "arn:aws:iam::123456789012:role/aws-service-role/x/y", trustEntry(svcTrust(`{"Bool":{"aws:SecureTransport":"true"}}`)))
	require.False(t, awsIAMRoleServiceTrustUnpinnedSource.Violates(linked))
	require.False(t, awsIAMRoleServiceTrustUnpinnedSource.Violates(principal("role", nil)))
}

func TestRoleTrustChecksNeedPoliciesRead(t *testing.T) {
	for _, bare := range awsIAMRoleTrustChecks() {
		c, ok := Default().ByID(bare.ID)
		require.True(t, ok, bare.ID)
		require.False(t, c.Evaluable(principal("role", map[string]string{})), "%s must not close findings on an unread role", c.ID)
		require.True(t, c.Evaluable(principal("role", map[string]string{"policies": "[]"})), c.ID)
	}
}

func TestConfusedDeputy_ExemptsOwnerAccountServices(t *testing.T) {
	for service, want := range map[string]bool{
		"ec2.amazonaws.com": false, "lambda.amazonaws.com": false, "eks.amazonaws.com": false, "secretsmanager.amazonaws.com": false,
		"ecs-tasks.amazonaws.com": true, "states.amazonaws.com": true,
	} {
		trust := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"` + service + `"},"Action":"sts:AssumeRole"}]}`
		if got := awsIAMRoleServiceConfusedDeputy.Violates(roleAsset(t, "", trustEntry(trust))); got != want {
			t.Errorf("%s: Violates = %v, want %v", service, got, want)
		}
	}
}
