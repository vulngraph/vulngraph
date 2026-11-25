package aws

import (
	"context"
	"fmt"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// BaseConfig is the exported form of baseConfig for use outside the collector package.
func BaseConfig(ctx context.Context, cfg map[string]string) (awssdk.Config, error) {
	return baseConfig(ctx, cfg)
}

// baseConfig builds the AWS SDK config for a connector.
//
// It composes three independent dimensions:
//
//	base identity   — where the initial credentials come from:
//	                  static keys (aws_access_key_id/secret) if present,
//	                  otherwise the default chain (OIDC web-identity on GKE).
//	hub hop         — if hub_role_arn is set (an aws_org child whose hub trusts
//	                  a principal, ADR 091), the base identity first assumes
//	                  the hub role.
//	role assumption — if role_arn is set, the base (or hub) identity assumes it.
//
// This uses a hub-and-spoke model: the hub identity (the base identity, or
// the hub role it assumes) assumes GraphReadOnly in each member account
// (role_arn). It also
// supports the pure OIDC path (no static keys) and the direct
// static-key path (a profile with its own keys and no role to assume).
//
// region is always required.
//
// Inside a Collect call (withConfigCache) the config is built once per sweep
// and copied per region: every collector in every region shares one
// credentials cache, so a role_arn connector assumes its role once per sweep
// instead of once per collector per region (~300 AssumeRole calls).
func baseConfig(ctx context.Context, cfg map[string]string) (awssdk.Config, error) {
	region := cfg["region"]
	if region == "" {
		return awssdk.Config{}, fmt.Errorf("baseConfig: region is required")
	}
	if c, ok := ctx.Value(configCacheKey{}).(*configCache); ok {
		return c.get(ctx, cfg, region)
	}
	return buildConfig(ctx, cfg)
}

// configCacheKey carries a sweep's *configCache on the context.
type configCacheKey struct{}

// configCache holds one sweep's AWS config. It lives on the Collect call's
// context, so it can never leak credentials across connectors or sweeps.
type configCache struct {
	mu   sync.Mutex
	base *awssdk.Config
}

// withConfigCache scopes a config cache to one Collect call.
// It also scopes the sweep's shared listings (sweepmemo.go).
func withConfigCache(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, sweepMemoKey{}, &sweepMemo{})
	return context.WithValue(ctx, configCacheKey{}, &configCache{})
}

// get returns the sweep's config retargeted at region. A failed build is not
// cached, so the next caller retries it.
func (c *configCache) get(ctx context.Context, cfg map[string]string, region string) (awssdk.Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		built, err := buildConfig(ctx, cfg)
		if err != nil {
			return awssdk.Config{}, err
		}
		c.base = &built
	}
	out := c.base.Copy()
	out.Region = region
	return out, nil
}

func buildConfig(ctx context.Context, cfg map[string]string) (awssdk.Config, error) {
	// If no static keys AND no role, there is no usable credential source.
	if cfg["aws_access_key_id"] == "" && cfg["role_arn"] == "" {
		return awssdk.Config{}, fmt.Errorf("baseConfig: role_arn or aws_access_key_id is required")
	}
	awsCfg, err := identityConfig(ctx, cfg)
	if err != nil {
		return awssdk.Config{}, err
	}

	// Layer role assumption on top of the base identity when requested.
	if roleARN := cfg["role_arn"]; roleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		awsCfg.Credentials = awssdk.NewCredentialsCache(
			stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
				if ext := cfg["external_id"]; ext != "" {
					o.ExternalID = awssdk.String(ext)
				}
			}),
		)
	}

	return awsCfg, nil
}

// identityConfig is the connector's identity before any role is assumed:
// static keys if present, else the default chain (OIDC), and the hub hop when
// hub_role_arn is set.
func identityConfig(ctx context.Context, cfg map[string]string) (awssdk.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(cfg["region"])}
	if keyID := cfg["aws_access_key_id"]; keyID != "" {
		secret := cfg["aws_secret_access_key"]
		if secret == "" {
			return awssdk.Config{}, fmt.Errorf("baseConfig: aws_secret_access_key required with aws_access_key_id")
		}
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(keyID, secret, cfg["aws_session_token"]),
		))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("baseConfig: load config: %w", err)
	}
	if hub := cfg[keyHubRoleARN]; hub != "" {
		awsCfg = withHubRole(awsCfg, hub)
	}
	return awsCfg, nil
}

// keyHubRoleARN is the hub role an aws_org connector names when its hub trusts
// a principal (TrustType=principal) rather than handing graph a hub session
// directly; org children carry it in memory only, resolved from the org.
const keyHubRoleARN = "hub_role_arn"

// withHubRole returns base re-credentialed as the hub role: base's own
// credentials (ambient or a stored key) call sts:AssumeRole on hubRoleARN,
// cached and refreshed before expiry. Every Vulngraph role in the chain trusts
// only the hub role, so without this hop a principal-trust hub is refused.
func withHubRole(base awssdk.Config, hubRoleARN string) awssdk.Config {
	out := base.Copy()
	out.Credentials = awssdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(base), hubRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "graph-hub"
		}))
	return out
}
