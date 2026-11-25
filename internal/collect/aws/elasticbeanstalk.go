package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// beanstalkOption maps an Elastic Beanstalk option setting to the metadata
// key it is recorded under, with the value Elastic Beanstalk applies when the
// option is not set (the documented default in the "General options for all
// environments" reference). The default is recorded only when the
// environment's settings were read, so an unset option is still an
// observation.
type beanstalkOption struct {
	namespace, name, key, unset string
}

var beanstalkOptions = []beanstalkOption{
	{"aws:elasticbeanstalk:healthreporting:system", "SystemType", "health_reporting", "basic"},
	{"aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled", "managed_actions_enabled", "false"},
	{"aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs", "stream_logs", "false"},
}

type beanstalkAPI interface {
	DescribeEnvironments(context.Context, *elasticbeanstalk.DescribeEnvironmentsInput, ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error)
	DescribeConfigurationSettings(context.Context, *elasticbeanstalk.DescribeConfigurationSettingsInput, ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error)
}

func collectElasticBeanstalk(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectElasticBeanstalk: %w", err)
	}
	return readElasticBeanstalk(ctx, elasticbeanstalk.NewFromConfig(awsCfg), region, accountID, now)
}

func readElasticBeanstalk(ctx context.Context, client beanstalkAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	var next *string
	for {
		// IncludeDeleted defaults to true; terminated environments are history.
		out, err := client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
			IncludeDeleted: awssdk.Bool(false), NextToken: next,
		})
		if err != nil {
			return nil, fmt.Errorf("readElasticBeanstalk: DescribeEnvironments: %w", err)
		}
		for _, env := range out.Environments {
			if env.Status == ebtypes.EnvironmentStatusTerminated || env.Status == ebtypes.EnvironmentStatusTerminating {
				continue
			}
			meta := map[string]string{"application": awssdk.ToString(env.ApplicationName)}
			beanstalkSettings(ctx, client, region, env, meta)
			assets = append(assets, asset.Asset{
				ID: awssdk.ToString(env.EnvironmentArn), Name: awssdk.ToString(env.EnvironmentName),
				Type: "elasticbeanstalk_environment", Provider: asset.ProviderAWS, Region: region,
				AccountID: accountID, Metadata: meta, DiscoveredAt: now, LastSeen: now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}

func beanstalkSettings(ctx context.Context, client beanstalkAPI, region string, env ebtypes.EnvironmentDescription, meta map[string]string) {
	out, err := client.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		ApplicationName: env.ApplicationName, EnvironmentName: env.EnvironmentName,
	})
	// An environment can also carry a draft (saved, not applied); only the
	// deployed configuration is the environment's real posture.
	var deployed *ebtypes.ConfigurationSettingsDescription
	if err == nil {
		for i := range out.ConfigurationSettings {
			if out.ConfigurationSettings[i].DeploymentStatus == ebtypes.ConfigurationDeploymentStatusDeployed {
				deployed = &out.ConfigurationSettings[i]
				break
			}
		}
	}
	if deployed == nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("environment", awssdk.ToString(env.EnvironmentName)).
			Msg("elasticbeanstalk: no deployed configuration read (check elasticbeanstalk:DescribeConfigurationSettings); environment posture unknown this sweep")
		return
	}
	set := map[string]string{}
	for _, o := range deployed.OptionSettings {
		set[awssdk.ToString(o.Namespace)+"/"+awssdk.ToString(o.OptionName)] = awssdk.ToString(o.Value)
	}
	for _, opt := range beanstalkOptions {
		v, ok := set[opt.namespace+"/"+opt.name]
		if !ok || v == "" {
			v = opt.unset
		}
		meta[opt.key] = strings.ToLower(v)
	}
}
