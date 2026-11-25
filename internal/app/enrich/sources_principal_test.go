package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestClassifyPrincipal(t *testing.T) {
	cases := []struct {
		name string
		rid  string
		want principalClass
	}{
		// SSO roles are no longer blanket-suppressed here — the SSO graph
		// owns that call in IdentityHygiene so an admin-granting permission set is
		// not hidden. PrincipalClass now classifies them as unknown.
		{"sso permission set (now unknown — handled by IdentityHygiene)", "arn:aws:iam::111:role/aws-reserved/sso.amazonaws.com/eu-west-3/AWSReservedSSO_AdministratorAccess_abc", principalUnknown},
		{"org access role", "arn:aws:iam::111:role/OrganizationAccountAccessRole", principalExpectedRole},
		{"service-linked", "arn:aws:iam::111:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS", principalExpectedRole},
		{"cdk exec", "arn:aws:iam::111:role/cdk-hnb659fds-cfn-exec-role-111-eu-west-2", principalExpectedRole},
		{"github actions deploy", "arn:aws:iam::111:role/example-app-github-actions-deploy", principalExpectedRole},
		{"lambda execution role", "arn:aws:iam::111:role/LambdaExecutionRole", principalExpectedRole},
		{"ecs task role", "arn:aws:iam::111:role/stg-example-api-ecs-task", principalExpectedRole},
		{"human user", "arn:aws:iam::111:user/alex.example@example.com", principalHumanUser},
		{"human user with familiar deploy substring", "arn:aws:iam::111:user/github-actions-deploy@example.com", principalHumanUser},
		{"non-prod role", "arn:aws:iam::111:role/tst-example-webserver", principalNonProd},
		{"staging role", "arn:aws:iam::111:role/stg-example-admin", principalNonProd},
		{"plain prod role", "arn:aws:iam::111:role/admin", principalUnknown},
		{"machine user no email", "arn:aws:iam::111:user/ci-bot", principalUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, classifyPrincipal(c.rid))
		})
	}
}

func privescFinding(rid string, kev bool) finding.Finding {
	return finding.Finding{
		CheckID: "aws-privesc-16", Title: "IAM privilege escalation: iam:UpdateAssumeRolePolicy",
		Severity: finding.SeverityCritical, ResourceID: rid, KnownExploited: kev,
	}
}

func TestPrincipalClass_ExpectedNameDoesNotSuppress(t *testing.T) {
	for _, id := range []string{
		"arn:aws:iam::111:role/OrganizationAccountAccessRole",
		"arn:aws:iam::111:role/github-actions-deploy",
		"serviceAccount:example-project-a@appspot.gserviceaccount.com",
	} {
		t.Run(id, func(t *testing.T) {
			factor, applied, err := (PrincipalClass{}).Evaluate(t.Context(), privescFinding(id, false))
			require.NoError(t, err)
			require.False(t, applied)
			require.False(t, factor.Suppress, "a familiar name cannot establish a security control")
		})
	}
}

func TestPrincipalClass_NeverSuppressesKEV(t *testing.T) {
	_, ok, err := PrincipalClass{}.Evaluate(context.Background(),
		privescFinding("arn:aws:iam::111:role/OrganizationAccountAccessRole", true))
	require.NoError(t, err)
	require.False(t, ok, "a known-exploited finding must not be suppressed")
}

func TestPrincipalClass_ElevatesHumanUser(t *testing.T) {
	f, ok, err := PrincipalClass{}.Evaluate(context.Background(),
		privescFinding("arn:aws:iam::111:user/marco@example.com", false))
	require.NoError(t, err)
	require.True(t, ok)
	require.False(t, f.Suppress)
	require.Equal(t, ThresholdHigh, f.Floor, "human-user privesc is floored into the actionable band")
}

func TestPrincipalClass_IgnoresNonPrivesc(t *testing.T) {
	_, ok, err := PrincipalClass{}.Evaluate(context.Background(), finding.Finding{
		CheckID: "aws-s3-public", Title: "Public bucket", ResourceID: "arn:aws:iam::111:role/OrganizationAccountAccessRole",
	})
	require.NoError(t, err)
	require.False(t, ok, "only privilege-escalation findings are classified")
}

func TestIsPrivesc(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
		want bool
	}{
		{"aws ciem privesc", finding.Finding{CheckID: "aws-privesc-15", Title: "privilege escalation: sts:assumerole"}, true},
		{"gcp ciem privesc", finding.Finding{CheckID: "gcp-privesc-13"}, true},
		{"azure ciem privesc", finding.Finding{CheckID: "azure-privesc-01"}, true},
		{"iam privesc check id", finding.Finding{CheckID: "iam-privesc-01"}, true},
		// The accident this commit removes: k8s pod-misconfig matched only by title.
		{"k8s pod misconfig is NOT privesc", finding.Finding{CheckID: "k8s-allow-privilege-escalation", Title: "Kubernetes Pod allows privilege escalation", ResourceType: "k8s_pod"}, false},
		// CVE titles mentioning escalation are vulnerabilities, not IAM privesc.
		{"cve title is NOT privesc", finding.Finding{CheckID: "CVE-2020-8559", Title: "Privilege escalation in Kubernetes"}, false},
		{"plain misconfig", finding.Finding{CheckID: "aws-s3-public", Title: "Public bucket"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, isPrivesc(c.f))
		})
	}
}

// TestPrincipalClass_IgnoresK8sPodMisconfig locks in that the k8s pod-misconfig
// check no longer routes through the IAM-privesc machinery — the string-match
// accident that made it the sole source of elevated k8s findings.
func TestPrincipalClass_IgnoresK8sPodMisconfig(t *testing.T) {
	_, ok, err := PrincipalClass{}.Evaluate(context.Background(), finding.Finding{
		CheckID: "k8s-allow-privilege-escalation", Title: "Kubernetes Pod allows privilege escalation",
		ResourceType: "k8s_pod", ResourceID: "k8s:pod:default/web",
	})
	require.NoError(t, err)
	require.False(t, ok, "k8s pod misconfig must not be classified as IAM privesc")
}
