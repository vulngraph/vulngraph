package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeSecretsManager exercises collectSecretsManagerSecrets' resource-policy
// wiring; ListSecrets always returns the same single secret, and the
// resourcePolicy/policyErr fields drive GetResourcePolicy's response.
type fakeSecretsManager struct {
	resourcePolicy string
	policyErr      error
	entry          *smtypes.SecretListEntry // overrides the default secret
}

func (f *fakeSecretsManager) ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.entry != nil {
		return &secretsmanager.ListSecretsOutput{SecretList: []smtypes.SecretListEntry{*f.entry}}, nil
	}
	return &secretsmanager.ListSecretsOutput{SecretList: []smtypes.SecretListEntry{
		{ARN: awssdk.String("arn:aws:secretsmanager:eu-west-1:1:secret:db-abc123"), Name: awssdk.String("db")},
	}}, nil
}

func (f *fakeSecretsManager) GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &secretsmanager.GetResourcePolicyOutput{ResourcePolicy: awssdk.String(f.resourcePolicy)}, nil
}

func TestSecretsManagerResourcePolicy(t *testing.T) {
	now := time.Now()

	// GetResourcePolicy for a secret with no resource policy — the common case —
	// answers with a SUCCESSFUL response carrying a nil ResourcePolicy, confirmed
	// against the SDK (secretsmanager defines no NotFound-shaped error for this
	// operation). This is a real observation, not silence: nothing is granted.
	t.Run("no resource policy — common case, graded PublicAccessNone", func(t *testing.T) {
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessNone, s[0].Metadata["public_access"])
		require.NotContains(t, s[0].Metadata, "policies", "no document exists to store, only the observation")
	})

	// A genuine API failure (throttle, AccessDenied) is the case that stays
	// absent: the secret was never described at all, and must not be guessed.
	t.Run("policy fetch error leaves the key unobserved", func(t *testing.T) {
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{policyErr: errNoPolicy}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.NotContains(t, s[0].Metadata, "public_access")
		require.NotContains(t, s[0].Metadata, "policies")
	})

	t.Run("closed policy — scoped principal, no grant", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{resourcePolicy: doc}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessNone, s[0].Metadata["public_access"],
			"a policy that was READ and grants nothing must be an observation, not absence")
		require.Contains(t, s[0].Metadata["policies"], `"type":"resource"`)
	})

	t.Run("genuinely public grant of GetSecretValue", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{resourcePolicy: doc}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessConfirmed, s[0].Metadata["public_access"])
	})

	t.Run("public grant of DescribeSecret only — not sensitive, not public", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:DescribeSecret","Resource":"*"}]}`
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{resourcePolicy: doc}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessNone, s[0].Metadata["public_access"])
	})

	t.Run("wildcard principal scoped by Condition — cross-account pattern, NOT public", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*",
			"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{resourcePolicy: doc}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessNone, s[0].Metadata["public_access"])
	})

	t.Run("explicit Deny overrides the public Allow", func(t *testing.T) {
		doc := `{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"},
			{"Effect":"Deny","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}
		]}`
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{resourcePolicy: doc}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessNone, s[0].Metadata["public_access"])
	})

	t.Run("single-object Statement (not array)", func(t *testing.T) {
		doc := `{"Statement":{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}}`
		s, err := collectSecretsManagerSecrets(context.Background(), &fakeSecretsManager{resourcePolicy: doc}, "eu-west-1", "1", now)
		require.NoError(t, err)
		require.Len(t, s, 1)
		require.Equal(t, asset.PublicAccessConfirmed, s[0].Metadata["public_access"])
	})
}

// Dates are stored, not day counts, so the asset does not change daily; a
// never-read secret is an observed empty last_accessed.
func TestSecretsManagerRotationAndAccessDates(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	f := &fakeSecretsManager{entry: &smtypes.SecretListEntry{
		ARN: awssdk.String("arn:aws:secretsmanager:eu-west-1:1:secret:db-abc123"), Name: awssdk.String("db"),
		CreatedDate: &created, RotationEnabled: awssdk.Bool(true),
		RotationRules: &smtypes.RotationRulesType{AutomaticallyAfterDays: awssdk.Int64(30)},
	}}
	s, err := collectSecretsManagerSecrets(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	md := s[0].Metadata
	require.Equal(t, "2025-01-02T03:04:05Z", md["created_at"])
	require.Equal(t, "", md["last_accessed"])
	require.Contains(t, md, "last_accessed")
	require.Equal(t, "30", md["rotation_interval_days"])
	require.Equal(t, "", md["next_rotation"])
	require.Contains(t, md, "next_rotation", "a rotating secret with no NextRotationDate has none scheduled — observed")

	next := time.Date(2025, 2, 1, 0, 0, 0, 0, time.FixedZone("x", 3600))
	f.entry.NextRotationDate = &next
	f.entry.RotationRules = &smtypes.RotationRulesType{ScheduleExpression: awssdk.String("cron(0 4 ? * SUN *)")}
	s, err = collectSecretsManagerSecrets(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "2025-01-31T23:00:00Z", s[0].Metadata["next_rotation"], "a cron schedule is graded through its next date")
	require.NotContains(t, s[0].Metadata, "rotation_interval_days")

	f.entry.RotationEnabled = awssdk.Bool(false)
	s, err = collectSecretsManagerSecrets(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.NotContains(t, s[0].Metadata, "rotation_interval_days", "an interval means nothing with rotation off")
	require.NotContains(t, s[0].Metadata, "next_rotation")
}
