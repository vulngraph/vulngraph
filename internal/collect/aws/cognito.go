package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// cognitoPageSize is the largest page ListUserPools / ListIdentityPools accept
// (MaxResults is required by both).
const cognitoPageSize = 60

type cognitoUserPoolAPI interface {
	ListUserPools(context.Context, *cognitoidentityprovider.ListUserPoolsInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error)
	DescribeUserPool(context.Context, *cognitoidentityprovider.DescribeUserPoolInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error)
}

type cognitoIdentityPoolAPI interface {
	ListIdentityPools(context.Context, *cognitoidentity.ListIdentityPoolsInput, ...func(*cognitoidentity.Options)) (*cognitoidentity.ListIdentityPoolsOutput, error)
	DescribeIdentityPool(context.Context, *cognitoidentity.DescribeIdentityPoolInput, ...func(*cognitoidentity.Options)) (*cognitoidentity.DescribeIdentityPoolOutput, error)
}

func collectCognitoUserPools(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCognitoUserPools: %w", err)
	}
	return readCognitoUserPools(ctx, cognitoidentityprovider.NewFromConfig(awsCfg), region, accountID, now)
}

func collectCognitoIdentityPools(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCognitoIdentityPools: %w", err)
	}
	return readCognitoIdentityPools(ctx, cognitoidentity.NewFromConfig(awsCfg), region, accountID, now)
}

func readCognitoUserPools(ctx context.Context, client cognitoUserPoolAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	var next *string
	for {
		out, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{MaxResults: awssdk.Int32(cognitoPageSize), NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readCognitoUserPools: ListUserPools: %w", err)
		}
		for _, p := range out.UserPools {
			id := awssdk.ToString(p.Id)
			a := asset.Asset{
				ID:   fmt.Sprintf("arn:%s:cognito-idp:%s:%s:userpool/%s", partitionFor(region), region, accountID, id),
				Name: awssdk.ToString(p.Name), Type: "cognito_user_pool", Provider: asset.ProviderAWS,
				Region: region, AccountID: accountID, Metadata: map[string]string{"user_pool_id": id},
				DiscoveredAt: now, LastSeen: now,
			}
			desc, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: p.Id})
			if err != nil || desc.UserPool == nil {
				log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("user_pool", id).
					Msg("cognito: DescribeUserPool failed (check cognito-idp:DescribeUserPool); user pool posture unknown this sweep")
			} else {
				if arn := awssdk.ToString(desc.UserPool.Arn); arn != "" {
					a.ID = arn
				}
				userPoolMetadata(*desc.UserPool, a.Metadata)
			}
			assets = append(assets, a)
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}

// userPoolMetadata records the FSBP Cognito.3-.6 inputs from a described pool.
func userPoolMetadata(p idptypes.UserPoolType, meta map[string]string) {
	if p.MfaConfiguration != "" {
		meta["mfa_configuration"] = string(p.MfaConfiguration)
	}
	if p.DeletionProtection != "" {
		meta["deletion_protection"] = string(p.DeletionProtection)
	}
	// No add-ons configured means threat protection was never activated.
	meta["threat_protection_mode"] = string(idptypes.AdvancedSecurityModeTypeOff)
	meta["threat_protection_custom_auth_mode"] = ""
	if ao := p.UserPoolAddOns; ao != nil {
		if ao.AdvancedSecurityMode != "" {
			meta["threat_protection_mode"] = string(ao.AdvancedSecurityMode)
		}
		if ao.AdvancedSecurityAdditionalFlows != nil {
			meta["threat_protection_custom_auth_mode"] = string(ao.AdvancedSecurityAdditionalFlows.CustomAuthMode)
		}
	}
	if p.Policies == nil {
		return
	}
	// With no sign-in policy the only first factor is PASSWORD (the API
	// default); a pool that also offers a passwordless factor is out of
	// Cognito.5's scope.
	passwordOnly := true
	if sp := p.Policies.SignInPolicy; sp != nil && len(sp.AllowedFirstAuthFactors) > 0 {
		passwordOnly = !slices.ContainsFunc(sp.AllowedFirstAuthFactors, func(f idptypes.AuthFactorType) bool {
			return f != idptypes.AuthFactorTypePassword
		})
	}
	meta["password_only_sign_in"] = strconv.FormatBool(passwordOnly)
	pp := p.Policies.PasswordPolicy
	if pp == nil {
		return
	}
	if pp.MinimumLength != nil {
		meta["password_min_length"] = strconv.Itoa(int(*pp.MinimumLength))
	}
	meta["password_require_lowercase"] = strconv.FormatBool(pp.RequireLowercase)
	meta["password_require_uppercase"] = strconv.FormatBool(pp.RequireUppercase)
	meta["password_require_numbers"] = strconv.FormatBool(pp.RequireNumbers)
	meta["password_require_symbols"] = strconv.FormatBool(pp.RequireSymbols)
	// Zero is the field omitted, not a zero-day validity (the minimum is 1).
	if pp.TemporaryPasswordValidityDays > 0 {
		meta["temporary_password_validity_days"] = strconv.Itoa(int(pp.TemporaryPasswordValidityDays))
	}
}

func readCognitoIdentityPools(ctx context.Context, client cognitoIdentityPoolAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	var next *string
	for {
		out, err := client.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: awssdk.Int32(cognitoPageSize), NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readCognitoIdentityPools: ListIdentityPools: %w", err)
		}
		for _, p := range out.IdentityPools {
			id := awssdk.ToString(p.IdentityPoolId)
			meta := map[string]string{"identity_pool_id": id}
			desc, err := client.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{IdentityPoolId: p.IdentityPoolId})
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("identity_pool", id).
					Msg("cognito: DescribeIdentityPool failed (check cognito-identity:DescribeIdentityPool); guest access unknown this sweep")
			} else {
				meta["allow_unauthenticated_identities"] = strconv.FormatBool(desc.AllowUnauthenticatedIdentities)
			}
			assets = append(assets, asset.Asset{
				ID:   fmt.Sprintf("arn:%s:cognito-identity:%s:%s:identitypool/%s", partitionFor(region), region, accountID, id),
				Name: awssdk.ToString(p.IdentityPoolName), Type: "cognito_identity_pool", Provider: asset.ProviderAWS,
				Region: region, AccountID: accountID, Metadata: meta, DiscoveredAt: now, LastSeen: now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}
