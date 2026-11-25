package graphstore

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func pathEdge(src, srcType, dst, dstType, typ string) asset.Edge {
	return asset.Edge{SrcID: src, SrcType: srcType, DstID: dst, DstType: dstType, EdgeType: typ}
}

func runNamedQueryIDs(t *testing.T, svc *Service, name string) map[string]bool {
	t.Helper()
	res, err := svc.RunNamedQuery(context.Background(), name, nil)
	require.NoError(t, err, name)
	ids := map[string]bool{}
	for _, n := range res.Nodes {
		ids[n.ID] = true
	}
	return ids
}

// A public EC2 instance reaches its IAM role through its instance profile
// (has_role), not executes_as. Every internet → workload → role query must
// return that path.
func TestNamedQueries_EC2InstanceRoleOnAttackPaths(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{
		{ID: "i-web", Name: "web", Type: "ec2_instance", Provider: "aws", PublicIP: "203.0.113.10", RiskScore: 50},
		{ID: "role-app", Name: "app", Type: "iam_role", Provider: "aws", RiskScore: 30},
		{ID: "role-admin", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: 80},
	}
	edges := []asset.Edge{
		pathEdge("i-web", "ec2_instance", "internet", "internet", "exposed_to_internet"),
		pathEdge("i-web", "ec2_instance", "role-app", "iam_role", "has_role"),
		pathEdge("role-app", "iam_role", "role-admin", "iam_role", "can_assume"),
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	for _, name := range []string{
		"attack_path_internet_to_iam",
		"ciem_full_attack_chain",
		"iam_privilege_escalation",
		"two_hop_privesc_from_internet",
		"internet_to_high_risk_role_3hop",
	} {
		ids := runNamedQueryIDs(t, svc, name)
		for _, want := range []string{"i-web", "role-app", "role-admin"} {
			require.True(t, ids[want], "%s: missing %s in %v", name, want, ids)
		}
	}
}

// Every named query that follows ExecutesAs from an Asset also follows HasRole,
// the only edge an EC2 instance has to its role. cross_cloud_iam_lateral_movement
// is Lambda-only, and Lambda roles are executes_as.
func TestNamedQueries_WorkloadRoleHopIncludesHasRole(t *testing.T) {
	for _, nq := range NamedQueries {
		if nq.Name == "cross_cloud_iam_lateral_movement" {
			continue
		}
		for _, line := range strings.Split(nq.Query, "\n") {
			if strings.Contains(line, ":ExecutesAs]") {
				t.Errorf("%s follows ExecutesAs without HasRole: %s", nq.Name, strings.TrimSpace(line))
			}
		}
	}
}

// sgFixture: three ways an internet-exposed instance relates to a database.
//
//   - i-web and rds-shared are both in sg-shared, which has no rule naming
//     itself: sharing the SG is not a path.
//   - rds-cross is in sg-db, whose ingress rule names sg-web, i-web's other
//     SG: a path.
//   - i-self and rds-self are in sg-self, whose ingress rule names sg-self: a
//     path through the self-loop.
func sgFixture() ([]asset.Asset, []asset.Edge) {
	assets := []asset.Asset{
		{ID: "i-web", Name: "web", Type: "ec2_instance", Provider: "aws", PublicIP: "203.0.113.10", RiskScore: 50},
		{ID: "i-self", Name: "self", Type: "ec2_instance", Provider: "aws", PublicIP: "203.0.113.11", RiskScore: 50},
		{ID: "rds-shared", Name: "shared", Type: "rds_instance", Provider: "aws"},
		{ID: "rds-cross", Name: "cross", Type: "rds_instance", Provider: "aws"},
		{ID: "rds-self", Name: "self-db", Type: "rds_instance", Provider: "aws"},
		{ID: "sg-web", Name: "web", Type: "security_group", Provider: "aws"},
		{ID: "sg-shared", Name: "shared", Type: "security_group", Provider: "aws"},
		{ID: "sg-db", Name: "db", Type: "security_group", Provider: "aws"},
		{ID: "sg-self", Name: "self", Type: "security_group", Provider: "aws"},
	}
	member := func(id, typ, sg string) asset.Edge {
		return pathEdge(id, typ, sg, "security_group", "connected_via_sg")
	}
	edges := []asset.Edge{
		pathEdge("i-web", "ec2_instance", "internet", "internet", "exposed_to_internet"),
		pathEdge("i-self", "ec2_instance", "internet", "internet", "exposed_to_internet"),
		member("i-web", "ec2_instance", "sg-web"),
		member("i-web", "ec2_instance", "sg-shared"),
		member("rds-shared", "rds_instance", "sg-shared"),
		member("rds-cross", "rds_instance", "sg-db"),
		member("i-self", "ec2_instance", "sg-self"),
		member("rds-self", "rds_instance", "sg-self"),
		pathEdge("sg-db", "security_group", "sg-web", "security_group", "sg_allows_from"),
		pathEdge("sg-self", "security_group", "sg-self", "security_group", "sg_allows_from"),
	}
	return assets, edges
}

func TestNamedQueries_SGReachabilityFollowsAllowRules(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges := sgFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	for _, name := range []string{"lateral_movement_via_sg", "databases_reachable_from_internet"} {
		ids := runNamedQueryIDs(t, svc, name)
		require.False(t, ids["rds-shared"], "%s: a shared SG with no rule naming it is not a path: %v", name, ids)
		require.False(t, ids["sg-shared"], "%s: %v", name, ids)
		require.True(t, ids["rds-cross"], "%s: sg-db admits sg-web, so i-web reaches rds-cross: %v", name, ids)
		require.True(t, ids["sg-web"] && ids["sg-db"], "%s: the path names both SGs: %v", name, ids)
		require.True(t, ids["rds-self"], "%s: sg-self admits its own members: %v", name, ids)
		require.True(t, ids["i-self"] && ids["sg-self"], "%s: %v", name, ids)
	}
}
