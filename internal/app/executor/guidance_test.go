package executor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Every action a resource type maps to must have both a registry spec (what it
// changes, whether it is destructive) and a guide (rollback, CLI) — a gap would
// either panic GuideFor or silently offer no guidance for a wired action.
func TestResourceFixesAreFullyDescribed(t *testing.T) {
	require.NotEmpty(t, resourceFixes)
	for rt, actions := range resourceFixes {
		require.NotEmptyf(t, actions, "resource type %q lists no actions — remove it instead", rt)
		for _, a := range actions {
			_, ok := specs[a]
			require.Truef(t, ok, "%s maps to %s, which has no actionSpec", rt, a)
			g, ok := guides[a]
			require.Truef(t, ok, "%s maps to %s, which has no guide", rt, a)
			require.NotEmptyf(t, g.fits, "%s fits no action class, so it is never offered", a)
		}
	}
	for a := range guides {
		_, ok := specs[a]
		require.Truef(t, ok, "guide for %s has no actionSpec", a)
	}
}

func TestGuideFor(t *testing.T) {
	cases := []struct {
		name                           string
		resourceType, id, region       string
		actionClass                    string
		wantAction                     Action
		wantDestructive, wantRevers    bool
		changeHas, cliHas, rollbackHas string
	}{
		{
			name: "aws security group from its ARN", resourceType: "security_group",
			id: "arn:aws:ec2:eu-west-1:123:security-group/sg-0abc", region: "eu-west-1", actionClass: "remediate",
			wantAction: ActionSGRuleRemove, wantRevers: true,
			changeHas: "security group sg-0abc in eu-west-1", cliHas: "aws ec2 revoke-security-group-ingress --region eu-west-1 --group-id sg-0abc",
			rollbackHas: "authorize-security-group-ingress",
		},
		{
			name: "azure nsg is told apart by its id", resourceType: "security_group",
			id: "/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1", actionClass: "modify",
			wantAction: ActionAzureNSGRuleRemove, wantDestructive: true,
			changeHas: "from nsg1 in resource group rg1 (subscription s1)", cliHas: "az network nsg rule delete --subscription s1",
			rollbackHas: "Not reversible",
		},
		{
			name: "s3 bucket ARN", resourceType: "s3_bucket", id: "arn:aws:s3:::data-lake", region: "us-east-1", actionClass: "remediate",
			wantAction: ActionS3BlockPublic, wantRevers: true,
			changeHas: "S3 bucket data-lake", cliHas: "put-public-access-block --bucket data-lake", rollbackHas: "delete-public-access-block --bucket data-lake",
		},
		{
			name: "iam user: the key id is a placeholder the finding cannot supply", resourceType: "iam_user",
			id: "arn:aws:iam::123:user/ops/alice", actionClass: "isolate",
			wantAction: ActionIAMKeyDisable, wantRevers: true,
			changeHas: "<access_key_id> of user alice", cliHas: "--user-name alice --access-key-id <access_key_id> --status Inactive",
			rollbackHas: "--status Active",
		},
		{
			name: "stopping an instance isolates it", resourceType: "ec2_instance",
			id: "arn:aws:ec2:us-east-1:123:instance/i-0123", region: "us-east-1", actionClass: "isolate",
			wantAction: ActionEC2Stop, wantDestructive: true, wantRevers: true,
			changeHas: "stop EC2 instance i-0123", cliHas: "stop-instances --region us-east-1 --instance-ids i-0123", rollbackHas: "start-instances",
		},
		{
			name: "gcp firewall carries its project in the path", resourceType: "gcp_firewall",
			id: "projects/prod-1/global/firewalls/allow-ssh", actionClass: "remediate",
			wantAction: ActionGCPFirewallRemove, wantDestructive: true,
			changeHas: "allow-ssh in project prod-1", cliHas: "firewall-rules delete allow-ssh --project prod-1", rollbackHas: "Not reversible",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ok := GuideFor(tc.resourceType, tc.id, tc.region, tc.actionClass)
			require.True(t, ok)
			require.Equal(t, tc.wantAction, g.Action)
			require.Equal(t, tc.wantDestructive, g.Destructive)
			require.Equal(t, tc.wantRevers, g.Reversible)
			require.Contains(t, g.Change, tc.changeHas)
			require.Contains(t, g.CLI, tc.cliHas)
			require.Contains(t, g.Rollback, tc.rollbackHas)
		})
	}
}

func TestGuideFor_NoFittingAction(t *testing.T) {
	for _, tc := range []struct{ name, resourceType, actionClass string }{
		{"stopping an instance does not remediate a vulnerability on it", "ec2_instance", "remediate"},
		{"observe changes nothing", "s3_bucket", "observe"},
		{"destroy has no executor action", "s3_bucket", "destroy"},
		{"no executor action for the type", "rds_instance", "remediate"},
		{"empty type", "", "remediate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := GuideFor(tc.resourceType, "id-1", "eu-west-1", tc.actionClass)
			require.False(t, ok)
		})
	}
}

// A missing region renders as a placeholder, never as an empty flag value that
// would make the CLI line run against the default region.
func TestGuideFor_MissingRegionIsAPlaceholder(t *testing.T) {
	g, ok := GuideFor("s3_bucket", "arn:aws:s3:::b", "", "remediate")
	require.True(t, ok)
	require.Contains(t, g.Change, "(<region>)")
}

// A region from finding data that is not an AWS region never reaches the CLI
// line a person copies — it renders as the placeholder instead.
func TestGuideFor_MalformedRegionIsAPlaceholder(t *testing.T) {
	g, ok := GuideFor("ec2_instance", "i-1", "eu-west-1 --profile prod; curl evil", "isolate")
	require.True(t, ok)
	require.NotContains(t, g.CLI, "curl")
	require.Contains(t, g.CLI, "--region <region>")
}
