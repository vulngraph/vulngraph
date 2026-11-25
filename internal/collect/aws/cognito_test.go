package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cidtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/stretchr/testify/require"
)

type fakeUserPools struct {
	pages   []*cognitoidentityprovider.ListUserPoolsOutput
	pools   map[string]*idptypes.UserPoolType
	pageErr error
}

func (f *fakeUserPools) ListUserPools(_ context.Context, in *cognitoidentityprovider.ListUserPoolsInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
	if awssdk.ToInt32(in.MaxResults) < 1 {
		return nil, errors.New("MaxResults is required")
	}
	if in.NextToken != nil {
		if f.pageErr != nil {
			return nil, f.pageErr
		}
		return f.pages[1], nil
	}
	return f.pages[0], nil
}

func (f *fakeUserPools) DescribeUserPool(_ context.Context, in *cognitoidentityprovider.DescribeUserPoolInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	p, ok := f.pools[awssdk.ToString(in.UserPoolId)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return &cognitoidentityprovider.DescribeUserPoolOutput{UserPool: p}, nil
}

func TestReadCognitoUserPools(t *testing.T) {
	weak := &idptypes.UserPoolType{
		Id: awssdk.String("eu-west-1_weak"), Arn: awssdk.String("arn:aws:cognito-idp:eu-west-1:1:userpool/eu-west-1_weak"),
		MfaConfiguration: idptypes.UserPoolMfaTypeOff, DeletionProtection: idptypes.DeletionProtectionTypeInactive,
		Policies: &idptypes.UserPoolPolicyType{PasswordPolicy: &idptypes.PasswordPolicyType{
			MinimumLength: awssdk.Int32(6), RequireLowercase: true, TemporaryPasswordValidityDays: 30,
		}},
	}
	strong := &idptypes.UserPoolType{
		Id: awssdk.String("eu-west-1_strong"), MfaConfiguration: idptypes.UserPoolMfaTypeOn, DeletionProtection: idptypes.DeletionProtectionTypeActive,
		UserPoolAddOns: &idptypes.UserPoolAddOnsType{
			AdvancedSecurityMode:            idptypes.AdvancedSecurityModeTypeEnforced,
			AdvancedSecurityAdditionalFlows: &idptypes.AdvancedSecurityAdditionalFlowsType{CustomAuthMode: idptypes.AdvancedSecurityEnabledModeTypeEnforced},
		},
		Policies: &idptypes.UserPoolPolicyType{
			PasswordPolicy: &idptypes.PasswordPolicyType{MinimumLength: awssdk.Int32(12), RequireLowercase: true, RequireUppercase: true, RequireNumbers: true, RequireSymbols: true, TemporaryPasswordValidityDays: 7},
			SignInPolicy:   &idptypes.SignInPolicyType{AllowedFirstAuthFactors: []idptypes.AuthFactorType{idptypes.AuthFactorTypePassword, idptypes.AuthFactorTypeWebAuthn}},
		},
	}
	f := &fakeUserPools{
		pages: []*cognitoidentityprovider.ListUserPoolsOutput{
			{UserPools: []idptypes.UserPoolDescriptionType{{Id: weak.Id, Name: awssdk.String("weak")}}, NextToken: awssdk.String("n")},
			{UserPools: []idptypes.UserPoolDescriptionType{{Id: strong.Id, Name: awssdk.String("strong")}, {Id: awssdk.String("eu-west-1_denied"), Name: awssdk.String("denied")}}},
		},
		pools: map[string]*idptypes.UserPoolType{"eu-west-1_weak": weak, "eu-west-1_strong": strong},
	}
	got, err := readCognitoUserPools(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	w, s, d := got[0].Metadata, got[1].Metadata, got[2].Metadata
	require.Equal(t, "arn:aws:cognito-idp:eu-west-1:1:userpool/eu-west-1_weak", got[0].ID)
	require.Equal(t, "OFF", w["mfa_configuration"])
	require.Equal(t, "INACTIVE", w["deletion_protection"])
	require.Equal(t, "OFF", w["threat_protection_mode"], "no add-ons is threat protection never activated")
	require.Equal(t, "true", w["password_only_sign_in"], "no sign-in policy defaults to PASSWORD only")
	require.Equal(t, "6", w["password_min_length"])
	require.Equal(t, "false", w["password_require_symbols"])
	require.Equal(t, "30", w["temporary_password_validity_days"])
	require.Equal(t, "ENFORCED", s["threat_protection_custom_auth_mode"])
	require.Equal(t, "false", s["password_only_sign_in"], "a passwordless first factor takes the pool out of Cognito.5's scope")
	require.Equal(t, map[string]string{"user_pool_id": "eu-west-1_denied"}, d, "an undescribed pool carries no posture keys")
	require.Equal(t, "arn:aws:cognito-idp:eu-west-1:1:userpool/eu-west-1_denied", got[2].ID)

	f.pageErr = errors.New("throttled")
	_, err = readCognitoUserPools(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}

type fakeIdentityPools struct {
	pools   map[string]bool
	descErr error
	listErr error
}

func (f *fakeIdentityPools) ListIdentityPools(_ context.Context, in *cognitoidentity.ListIdentityPoolsInput, _ ...func(*cognitoidentity.Options)) (*cognitoidentity.ListIdentityPoolsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if awssdk.ToInt32(in.MaxResults) < 1 {
		return nil, errors.New("MaxResults is required")
	}
	out := &cognitoidentity.ListIdentityPoolsOutput{}
	for id := range f.pools {
		out.IdentityPools = append(out.IdentityPools, cidtypes.IdentityPoolShortDescription{IdentityPoolId: awssdk.String(id), IdentityPoolName: awssdk.String(id)})
	}
	return out, nil
}

func (f *fakeIdentityPools) DescribeIdentityPool(_ context.Context, in *cognitoidentity.DescribeIdentityPoolInput, _ ...func(*cognitoidentity.Options)) (*cognitoidentity.DescribeIdentityPoolOutput, error) {
	if f.descErr != nil {
		return nil, f.descErr
	}
	return &cognitoidentity.DescribeIdentityPoolOutput{IdentityPoolId: in.IdentityPoolId, AllowUnauthenticatedIdentities: f.pools[awssdk.ToString(in.IdentityPoolId)]}, nil
}

func TestReadCognitoIdentityPools(t *testing.T) {
	f := &fakeIdentityPools{pools: map[string]bool{"eu-west-1:guest": true}}
	got, err := readCognitoIdentityPools(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "true", got[0].Metadata["allow_unauthenticated_identities"])
	require.Equal(t, "arn:aws:cognito-identity:eu-west-1:1:identitypool/eu-west-1:guest", got[0].ID)

	f.descErr = errors.New("AccessDeniedException")
	got, err = readCognitoIdentityPools(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.NotContains(t, got[0].Metadata, "allow_unauthenticated_identities", "an undescribed pool is unknown, not closed to guests")

	f.listErr = errors.New("throttled")
	_, err = readCognitoIdentityPools(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err)

	got, err = readCognitoIdentityPools(context.Background(), &fakeIdentityPools{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, got, "an unused service emits nothing")
}
