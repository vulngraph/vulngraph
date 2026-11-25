package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// A node the reach BFS did not visit is ReachNone only when the reach edge set
// was fetched completely. When it was truncated (or the bulk pass failed),
// "not reached" is not evidence — the node must read ReachUnknown so must-fix
// classification stays neutral instead of demoting to "contained".
func TestBuildNodeRows_IncompleteReachDegradesToUnknown(t *testing.T) {
	assets := []asset.Asset{
		{ID: "web-1", Name: "web", Type: "ec2_instance_x", Provider: "aws", RiskScore: 50},
		{ID: "db-1", Name: "db", Type: "rds_instance", Provider: "aws", RiskScore: 70},
	}
	edges := []asset.Edge{
		{SrcID: "web-1", DstID: "internet", EdgeType: "exposed_to_internet"},
	}

	hopsOf := func(reachComplete bool) map[string]any {
		byLabel := buildNodeRows(assets, edges, nil, reachComplete)
		for _, row := range byLabel[NodeAsset] {
			if row["id"] == "db-1" {
				return row
			}
		}
		t.Fatal("db-1 row not built")
		return nil
	}

	require.EqualValues(t, ReachNone, hopsOf(true)["internet_hops"],
		"complete edge set: not-reached node is definitively unreachable")
	require.EqualValues(t, ReachUnknown, hopsOf(false)["internet_hops"],
		"truncated edge set: not-reached node must fail open")

	// The exposed seed itself is direct (0 hops) either way — truncation only
	// degrades the ABSENCE of a path, never a found one.
	byLabel := buildNodeRows(assets, edges, nil, false)
	for _, row := range byLabel[NodeAsset] {
		if row["id"] == "web-1" {
			require.EqualValues(t, 0, row["internet_hops"])
		}
	}
}

// TestBuildNodeRows_PermissionSetGrantsAdmin guards the SSO graph:
// a PermissionSet row must carry its name and, when Metadata["grants_admin"]
// is "true", grants_admin=1 (INT32) so Cypher can filter admin permission
// sets directly (`p.grants_admin = 1`) without a GrantsAdmin traversal.
func TestBuildNodeRows_PermissionSetGrantsAdmin(t *testing.T) {
	assets := []asset.Asset{
		{
			ID: "sso_permission_set:AdministratorAccess", Name: "AdministratorAccess",
			Type: "sso_permission_set", Provider: "aws", AccountID: "111111111111",
			Metadata: map[string]string{"grants_admin": "true"},
		},
		{
			ID: "sso_permission_set:ReadOnly", Name: "ReadOnly",
			Type: "sso_permission_set", Provider: "aws", AccountID: "111111111111",
			Metadata: map[string]string{"grants_admin": "false"},
		},
	}

	byLabel := buildNodeRows(assets, nil, nil, true)
	rows := byLabel[NodeSSOPermSet]
	require.Len(t, rows, 2)

	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[r["id"].(string)] = r
	}

	admin := byID["sso_permission_set:AdministratorAccess"]
	require.NotNil(t, admin)
	require.Equal(t, "AdministratorAccess", admin["name"])
	require.EqualValues(t, 1, admin["grants_admin"], "admin permission set must carry grants_admin=1")

	readOnly := byID["sso_permission_set:ReadOnly"]
	require.NotNil(t, readOnly)
	require.EqualValues(t, 0, readOnly["grants_admin"], "non-admin permission set must carry grants_admin=0")
}
