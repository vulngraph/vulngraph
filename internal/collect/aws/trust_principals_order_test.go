package aws

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"
)

// manyPrincipalsIAM embeds the default fake and replaces the single role with
// one whose trust policy names more principals than trust_principals keeps.
type manyPrincipalsIAM struct {
	fakeIAM
	principals []string
}

func (f manyPrincipalsIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	quoted := make([]string, 0, len(f.principals))
	for _, p := range f.principals {
		quoted = append(quoted, fmt.Sprintf("%q", p))
	}
	doc := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":[%s]}}]}`,
		strings.Join(quoted, ","))
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: awssdk.String("cross-account"), Arn: awssdk.String("arn:aws:iam::1:role/cross-account"),
		Path: awssdk.String("/"), AssumeRolePolicyDocument: awssdk.String(url.QueryEscape(doc)),
	}}}, nil
}

// TestTrustPrincipalsAreSortedBeforeTruncation covers two failures at once.
//
// The visible one is churn: trust_principals is a set flattened into one string,
// and an unstable order re-serialised the same unchanged trust policy differently
// every sweep — recording pure reorderings as changes and bloating
// asset_change_log.
//
// The one that actually matters is that the list is capped at 5. With an
// unstable order the cap kept an ARBITRARY five of the principals, so a role's
// recorded entry points changed between sweeps while its trust policy did not,
// and no consumer could tell which five it was looking at. Sorting must happen
// BEFORE the truncation, not after.
func TestTrustPrincipalsAreSortedBeforeTruncation(t *testing.T) {
	// Deliberately not in sorted order, and more than the cap of 5.
	fake := manyPrincipalsIAM{principals: []string{
		"arn:aws:iam::9:root",
		"arn:aws:iam::3:root",
		"arn:aws:iam::7:root",
		"arn:aws:iam::1:root",
		"arn:aws:iam::5:root",
		"arn:aws:iam::2:root",
		"arn:aws:iam::8:root",
	}}

	want := strings.Join([]string{
		"arn:aws:iam::1:root", "arn:aws:iam::2:root", "arn:aws:iam::3:root",
		"arn:aws:iam::5:root", "arn:aws:iam::7:root",
	}, ",")

	for range 5 {
		assets, _, err := collectRoles(context.Background(), fake, newManagedPolicyCache(fake), "1", time.Now())
		require.NoError(t, err)
		role := assetByID(t, assets, "arn:aws:iam::1:role/cross-account")
		require.Equal(t, want, role.Metadata["trust_principals"],
			"trust_principals must be the sorted LOWEST five, deterministically")
	}
}
