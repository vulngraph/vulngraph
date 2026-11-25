package demo_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect/demo"
)

const (
	webInstance = "i-0acme00000000web1"
	webRole     = "arn:aws:iam::demo-acme:role/acme-web"
	adminRole   = "arn:aws:iam::demo-acme:role/acme-ec2-admin"
	gateway     = "arn:aws:ecs:us-east-1:demo-acme:service/acme-prod/ai-gateway"
	supportBot  = "arn:aws:ecs:us-east-1:demo-acme:service/acme-prod/support-bot"
)

func collectDemo(t *testing.T) ([]asset.Asset, []asset.Edge) {
	t.Helper()
	res, err := demo.New().Collect(context.Background(), nil)
	require.NoError(t, err)
	return res.Assets, res.Edges
}

func TestCollect_IsDeterministicAndNeedsNoConfig(t *testing.T) {
	a1, e1 := collectDemo(t)
	a2, e2 := collectDemo(t)
	ids := func(as []asset.Asset) []string {
		out := make([]string, len(as))
		for i, a := range as {
			out[i] = a.ID
		}
		return out
	}
	require.NotEmpty(t, a1)
	require.Equal(t, ids(a1), ids(a2))
	require.Len(t, e2, len(e1))
}

func TestCollect_EdgesPointAtAssets(t *testing.T) {
	assets, edges := collectDemo(t)
	have := map[string]bool{}
	for _, a := range assets {
		have[a.ID] = true
	}
	for _, e := range edges {
		require.True(t, have[e.SrcID], "edge %s source %s is not an asset", e.EdgeType, e.SrcID)
		require.True(t, have[e.DstID], "edge %s target %s is not an asset", e.EdgeType, e.DstID)
	}
}

func TestChecks_FindTheSeededMisconfigurations(t *testing.T) {
	assets, _ := collectDemo(t)
	// SyncWorker derives and stamps effective privileges before posture checks.
	analysis := ciem.AnalyzeIAMAssets(t.Context(), assets)
	require.True(t, analysis.OrganizationPolicyCoverage[adminRole])
	require.Equal(t, ciem.TierAdmin, analysis.Tiers[adminRole].Tier)
	ciem.StampAWSOrganizationCoverage(assets, analysis.OrganizationPolicyCoverage)
	ciem.StampTiers(assets, analysis.Tiers)
	got := map[string]bool{}
	for _, f := range checks.Default().Run(assets, time.Now()) {
		got[f.CheckID] = true
	}
	for _, id := range []string{
		"aws-security-group-world-open-admin-port", "aws-ec2-imdsv2-not-required", "aws-ec2-public-ip",
		"aws-iam-user-no-mfa", "aws-rds-not-encrypted", "aws-s3-no-default-encryption", "aws-iam-role-full-admin",
		"dns-cname-takeover-risk",
	} {
		require.True(t, got[id], "check %s did not fire on the demo data", id)
	}
}

// The graph story: the web server is exposed and runs as a role that can launch
// an instance as the admin role; the gateway service is exposed, deployed from
// a repository, and runs the same LiteLLM as the private support bot.
func TestCorrelation_BuildsTheAttackPath(t *testing.T) {
	assets, edges := collectDemo(t)
	g := correlate.NewGraph(assets)
	for _, r := range []correlate.Rule{
		correlate.InternetReachability{}, correlate.EC2InstanceProfile{}, correlate.ExecutesAs{},
		correlate.DeploysTo{}, correlate.SecretAccess{}, correlate.SecurityGroupAllows{}, correlate.TFOwnership{},
	} {
		edges = append(edges, r.Correlate(g)...)
	}
	has := func(typ, src, dst string) bool {
		for _, e := range edges {
			if e.EdgeType == typ && e.SrcID == src && e.DstID == dst {
				return true
			}
		}
		return false
	}
	require.True(t, has("exposed_to_internet", webInstance, correlate.InternetNodeID))
	require.True(t, has("exposed_to_internet", gateway, correlate.InternetNodeID))
	require.False(t, has("exposed_to_internet", supportBot, correlate.InternetNodeID), "the support bot is private")
	require.True(t, has("has_role", webInstance, webRole))
	require.True(t, has("deploys_to", "acme-corp/ai-gateway", gateway))
	require.True(t, has("defined_in", gateway, "acme-corp/infra"), "the gateway is declared in the Terraform repo")

	var litellmRunners int
	for _, e := range edges {
		if e.EdgeType == "runs_package" && strings.Contains(e.DstID, "litellm") {
			litellmRunners++
		}
	}
	require.Equal(t, 2, litellmRunners, "both images run litellm")
}

func TestCIEM_WebRoleCanEscalateToAdmin(t *testing.T) {
	assets, _ := collectDemo(t)
	var found bool
	for _, p := range ciem.AnalyzeIAMAssets(context.Background(), assets).Paths {
		if p.SourcePrincipal == webRole && len(p.TargetPrincipals) == 1 && p.TargetPrincipals[0] == adminRole {
			found = true
		}
	}
	require.True(t, found, "no escalation path from the web role to the admin role")
}
