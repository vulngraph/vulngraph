package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/stretchr/testify/require"
)

type fakeAppSync struct {
	pages  []*appsync.ListGraphqlApisOutput
	caches map[string]error // nil error with an entry = cache present
	owner  appsynctypes.Ownership
}

func (f *fakeAppSync) ListGraphqlApis(_ context.Context, in *appsync.ListGraphqlApisInput, _ ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error) {
	f.owner = in.Owner
	if in.NextToken != nil {
		if len(f.pages) < 2 {
			return nil, errors.New("throttled")
		}
		return f.pages[1], nil
	}
	return f.pages[0], nil
}

func (f *fakeAppSync) GetApiCache(_ context.Context, in *appsync.GetApiCacheInput, _ ...func(*appsync.Options)) (*appsync.GetApiCacheOutput, error) {
	err, ok := f.caches[awssdk.ToString(in.ApiId)]
	if !ok {
		return nil, &appsynctypes.NotFoundException{Message: awssdk.String("cache not found")}
	}
	if err != nil {
		return nil, err
	}
	return &appsync.GetApiCacheOutput{ApiCache: &appsynctypes.ApiCache{AtRestEncryptionEnabled: false, TransitEncryptionEnabled: true}}, nil
}

func TestReadAppSync(t *testing.T) {
	f := &fakeAppSync{
		pages: []*appsync.ListGraphqlApisOutput{
			{GraphqlApis: []appsynctypes.GraphqlApi{{
				ApiId: awssdk.String("a1"), Arn: awssdk.String("arn:appsync:a1"), Name: awssdk.String("keyed"),
				AuthenticationType:                appsynctypes.AuthenticationTypeAwsIam,
				AdditionalAuthenticationProviders: []appsynctypes.AdditionalAuthenticationProvider{{AuthenticationType: appsynctypes.AuthenticationTypeApiKey}},
				LogConfig:                         &appsynctypes.LogConfig{FieldLogLevel: appsynctypes.FieldLogLevelNone},
			}}, NextToken: awssdk.String("n")},
			{GraphqlApis: []appsynctypes.GraphqlApi{
				{ApiId: awssdk.String("a2"), Arn: awssdk.String("arn:appsync:a2"), AuthenticationType: appsynctypes.AuthenticationTypeAmazonCognitoUserPools},
				{ApiId: awssdk.String("a3"), Arn: awssdk.String("arn:appsync:a3"), AuthenticationType: appsynctypes.AuthenticationTypeAwsLambda, LogConfig: &appsynctypes.LogConfig{FieldLogLevel: appsynctypes.FieldLogLevelError}},
			}},
		},
		caches: map[string]error{"a1": nil, "a3": errors.New("AccessDeniedException")},
	}
	got, err := readAppSync(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, appsynctypes.OwnershipCurrentAccount, f.owner, "APIs shared into the account belong to another account")
	require.Len(t, got, 3)
	a1, a2, a3 := got[0].Metadata, got[1].Metadata, got[2].Metadata
	require.Equal(t, "AWS_IAM,API_KEY", a1["authentication_types"], "additional providers are graded too")
	require.Equal(t, "NONE", a1["field_log_level"])
	require.Equal(t, "true", a1["api_cache"])
	require.Equal(t, "false", a1["cache_at_rest_encryption"])
	require.Equal(t, "true", a1["cache_transit_encryption"])
	require.Equal(t, "", a2["field_log_level"], "no log config is logging off, observed")
	require.Equal(t, "false", a2["api_cache"], "NotFoundException is no cache")
	require.NotContains(t, a3, "api_cache", "a denied cache read is unknown")

	f.pages = f.pages[:1]
	_, err = readAppSync(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err, "a failed page fails the call")
}

type fakeBeanstalk struct {
	envs     []ebtypes.EnvironmentDescription
	settings map[string][]ebtypes.ConfigurationOptionSetting
	include  *bool
}

func (f *fakeBeanstalk) DescribeEnvironments(_ context.Context, in *elasticbeanstalk.DescribeEnvironmentsInput, _ ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
	f.include = in.IncludeDeleted
	return &elasticbeanstalk.DescribeEnvironmentsOutput{Environments: f.envs}, nil
}

func (f *fakeBeanstalk) DescribeConfigurationSettings(_ context.Context, in *elasticbeanstalk.DescribeConfigurationSettingsInput, _ ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error) {
	s, ok := f.settings[awssdk.ToString(in.EnvironmentName)]
	if !ok {
		return nil, errors.New("AccessDenied")
	}
	// A saved draft listed ahead of the deployed configuration, with the
	// opposite settings: only the deployed one is the environment's posture.
	draft := ebtypes.ConfigurationSettingsDescription{DeploymentStatus: ebtypes.ConfigurationDeploymentStatusPending, OptionSettings: []ebtypes.ConfigurationOptionSetting{
		opt("aws:elasticbeanstalk:healthreporting:system", "SystemType", "basic"),
		opt("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled", "false"),
	}}
	if awssdk.ToString(in.EnvironmentName) == "draftonly" {
		return &elasticbeanstalk.DescribeConfigurationSettingsOutput{ConfigurationSettings: []ebtypes.ConfigurationSettingsDescription{draft}}, nil
	}
	return &elasticbeanstalk.DescribeConfigurationSettingsOutput{ConfigurationSettings: []ebtypes.ConfigurationSettingsDescription{
		draft, {DeploymentStatus: ebtypes.ConfigurationDeploymentStatusDeployed, OptionSettings: s},
	}}, nil
}

func opt(ns, name, v string) ebtypes.ConfigurationOptionSetting {
	return ebtypes.ConfigurationOptionSetting{Namespace: awssdk.String(ns), OptionName: awssdk.String(name), Value: awssdk.String(v)}
}

func TestReadElasticBeanstalk(t *testing.T) {
	f := &fakeBeanstalk{
		envs: []ebtypes.EnvironmentDescription{
			{EnvironmentName: awssdk.String("prod"), EnvironmentArn: awssdk.String("arn:eb:prod"), ApplicationName: awssdk.String("app"), Status: ebtypes.EnvironmentStatusReady},
			{EnvironmentName: awssdk.String("bare"), EnvironmentArn: awssdk.String("arn:eb:bare"), Status: ebtypes.EnvironmentStatusReady},
			{EnvironmentName: awssdk.String("denied"), EnvironmentArn: awssdk.String("arn:eb:denied"), Status: ebtypes.EnvironmentStatusUpdating},
			{EnvironmentName: awssdk.String("draftonly"), EnvironmentArn: awssdk.String("arn:eb:draftonly"), Status: ebtypes.EnvironmentStatusReady},
			{EnvironmentName: awssdk.String("old"), EnvironmentArn: awssdk.String("arn:eb:old"), Status: ebtypes.EnvironmentStatusTerminated},
		},
		settings: map[string][]ebtypes.ConfigurationOptionSetting{
			"prod": {
				opt("aws:elasticbeanstalk:healthreporting:system", "SystemType", "enhanced"),
				opt("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled", "true"),
				opt("aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs", "true"),
			},
			"bare":      {opt("aws:autoscaling:asg", "MinSize", "1")},
			"draftonly": {},
		},
	}
	got, err := readElasticBeanstalk(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, awssdk.ToBool(f.include), "terminated environments are not requested")
	require.Len(t, got, 4, "a terminated environment is history, not inventory")
	require.Equal(t, "enhanced", got[0].Metadata["health_reporting"])
	require.Equal(t, "true", got[0].Metadata["managed_actions_enabled"])
	require.Equal(t, "true", got[0].Metadata["stream_logs"])
	require.Equal(t, "basic", got[1].Metadata["health_reporting"], "unset options take the documented default")
	require.Equal(t, "false", got[1].Metadata["managed_actions_enabled"])
	require.Equal(t, "false", got[1].Metadata["stream_logs"])
	for _, i := range []int{2, 3} { // denied read; only a draft, no deployed configuration
		for _, k := range []string{"health_reporting", "managed_actions_enabled", "stream_logs"} {
			require.NotContains(t, got[i].Metadata, k, "%s: unread settings are unknown, not defaults", got[i].Name)
		}
	}
}
