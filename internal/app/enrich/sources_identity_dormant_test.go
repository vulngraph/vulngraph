package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// The dormant-admin finding's subject is the dormancy, so right-sizing must not
// demote it for being dormant; any other finding on the same idle admin role
// still gets the demote.
func TestIdentityHygiene_DormantAdminFindingNotDemotedByItsOwnDormancy(t *testing.T) {
	ctx := context.Background()
	g := fakeAssetGetter{a: asset.Asset{Metadata: map[string]string{"admin": "true", "last_used_days": "200"}}}

	dormant := finding.Finding{ResourceID: "role:x", ResourceType: "iam_role", CheckID: checkAdminRoleDormant}
	_, ok, err := IdentityHygiene{Assets: g}.Evaluate(ctx, dormant)
	require.NoError(t, err)
	require.False(t, ok, "no dormancy demote on the dormancy finding")

	other := finding.Finding{ResourceID: "role:x", ResourceType: "iam_role", CheckID: "aws-iam-public-trust-policy"}
	factor, ok, err := IdentityHygiene{Assets: g}.Evaluate(ctx, other)
	require.NoError(t, err)
	require.True(t, ok)
	require.Negative(t, factor.Points)
}

// The constant must name a registered check, or the exemption is inert.
func TestCheckAdminRoleDormantIsRegistered(t *testing.T) {
	_, ok := checks.Default().ByID(checkAdminRoleDormant)
	require.True(t, ok)
}
