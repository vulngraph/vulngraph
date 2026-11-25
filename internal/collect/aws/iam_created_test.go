package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/stretchr/testify/require"
)

// createdIAM stamps a CreateDate on every listed role and user.
type createdIAM struct {
	fakeIAM
	created time.Time
}

func (c createdIAM) ListRoles(ctx context.Context, in *iam.ListRolesInput, o ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	out, err := c.fakeIAM.ListRoles(ctx, in, o...)
	for i := range out.Roles {
		out.Roles[i].CreateDate = &c.created
	}
	return out, err
}

func (c createdIAM) ListUsers(ctx context.Context, in *iam.ListUsersInput, o ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	out, err := c.fakeIAM.ListUsers(ctx, in, o...)
	for i := range out.Users {
		out.Users[i].CreateDate = &c.created
	}
	return out, err
}

// created_days is what lets the dormant-admin check tell a never-used old
// principal (dormant) from a never-used new one (not yet used).
func TestCollectPrincipals_CreatedDays(t *testing.T) {
	now := time.Now()
	c := createdIAM{created: now.Add(-120 * 24 * time.Hour)}

	roles, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", now)
	require.NoError(t, err)
	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", now)
	require.NoError(t, err)

	for _, a := range append(roles, users...) {
		if a.Type == "iam_role" || a.Type == "iam_user" {
			require.Equal(t, "120", a.Metadata["created_days"], a.ID)
		}
	}

	// No CreateDate → no key: absent age is unknown, never "0 days old".
	roles, _, err = collectRoles(context.Background(), fakeIAM{}, newManagedPolicyCache(fakeIAM{}), "1", now)
	require.NoError(t, err)
	for _, a := range roles {
		require.NotContains(t, a.Metadata, "created_days", a.ID)
	}
}
