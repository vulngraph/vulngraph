package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBaseConfig_RequiresRegion(t *testing.T) {
	_, err := baseConfig(context.Background(), map[string]string{})
	require.ErrorContains(t, err, "region is required")
}

func TestBaseConfig_RequiresSomeCredential(t *testing.T) {
	// region but no keys and no role — nothing to authenticate with.
	_, err := baseConfig(context.Background(), map[string]string{"region": "eu-west-1"})
	require.ErrorContains(t, err, "role_arn or aws_access_key_id is required")
}

func TestBaseConfig_StaticKeyNeedsSecret(t *testing.T) {
	_, err := baseConfig(context.Background(), map[string]string{
		"region":            "eu-west-1",
		"aws_access_key_id": "AKIA...",
	})
	require.ErrorContains(t, err, "aws_secret_access_key required")
}

func TestBaseConfig_StaticKeysAccepted(t *testing.T) {
	cfg, err := baseConfig(context.Background(), map[string]string{
		"region":                "eu-west-1",
		"aws_access_key_id":     "AKIATEST",
		"aws_secret_access_key": "secret",
	})
	require.NoError(t, err)
	require.Equal(t, "eu-west-1", cfg.Region)
}

func TestBaseConfig_RoleOnlyAccepted(t *testing.T) {
	// OIDC path: a role to assume, base identity from the default chain.
	cfg, err := baseConfig(context.Background(), map[string]string{
		"region":   "eu-west-1",
		"role_arn": "arn:aws:iam::123456789012:role/GraphReadOnly",
	})
	require.NoError(t, err)
	require.Equal(t, "eu-west-1", cfg.Region)
}

func TestBaseConfig_StaticBasePlusRoleAssumption(t *testing.T) {
	// The hub-and-spoke model: static hub keys + assume a member-account role.
	cfg, err := baseConfig(context.Background(), map[string]string{
		"region":                "eu-west-1",
		"aws_access_key_id":     "AKIAHUB",
		"aws_secret_access_key": "hubsecret",
		"role_arn":              "arn:aws:iam::999988887777:role/GraphReadOnly",
	})
	require.NoError(t, err)
	require.Equal(t, "eu-west-1", cfg.Region)
	require.NotNil(t, cfg.Credentials) // assume-role provider installed
}

// Within one sweep every region shares the same credentials provider (one
// AssumeRole for the whole sweep), while each config targets its own region.
func TestBaseConfig_CachedPerSweep(t *testing.T) {
	ctx := withConfigCache(context.Background())
	base := map[string]string{
		"aws_access_key_id":     "AKIAHUB",
		"aws_secret_access_key": "hubsecret",
		"role_arn":              "arn:aws:iam::999988887777:role/GraphReadOnly",
	}
	euw1, err := baseConfig(ctx, withRegion(base, "eu-west-1"))
	require.NoError(t, err)
	use1, err := baseConfig(ctx, withRegion(base, "us-east-1"))
	require.NoError(t, err)

	require.Equal(t, "eu-west-1", euw1.Region)
	require.Equal(t, "us-east-1", use1.Region)
	require.Same(t, euw1.Credentials, use1.Credentials, "one credentials cache per sweep")

	other, err := baseConfig(withConfigCache(context.Background()), withRegion(base, "eu-west-1"))
	require.NoError(t, err)
	require.NotSame(t, euw1.Credentials, other.Credentials, "a new sweep never reuses a previous sweep's credentials")
}

// A failed build is not cached.
func TestBaseConfig_CacheDoesNotKeepFailures(t *testing.T) {
	ctx := withConfigCache(context.Background())
	_, err := baseConfig(ctx, map[string]string{"region": "eu-west-1"})
	require.Error(t, err)
	_, err = baseConfig(ctx, map[string]string{"region": "eu-west-1", "aws_access_key_id": "AKIA", "aws_secret_access_key": "s"})
	require.NoError(t, err)
}
