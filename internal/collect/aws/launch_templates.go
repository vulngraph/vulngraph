package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type launchTemplateAPI interface {
	DescribeLaunchTemplateVersions(context.Context, *ec2.DescribeLaunchTemplateVersionsInput, ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
	DescribeSpotFleetRequests(context.Context, *ec2.DescribeSpotFleetRequestsInput, ...func(*ec2.Options)) (*ec2.DescribeSpotFleetRequestsOutput, error)
}

func collectLaunchTemplates(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectLaunchTemplates: %w", err)
	}
	return readLaunchTemplates(ctx, ec2.NewFromConfig(awsCfg), autoscaling.NewFromConfig(awsCfg), region, accountID, now)
}

// readLaunchTemplates emits each launch template's DEFAULT version, the one
// FSBP EC2.25/170/181 evaluate and the one a launch without an explicit
// version uses. `$Default` with no template id asks for every template's
// default version in one paginated listing.
//
// auto_scaling_group_count is how many Auto Scaling groups launch from the
// template. It only grades severity, and is omitted when the group listing
// fails: zero groups is a measurement, an unread listing is not.
func readLaunchTemplates(ctx context.Context, client launchTemplateAPI, asg autoScalingAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			Versions: []string{"$Default"}, NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("readLaunchTemplates: %w", err)
		}
		for _, v := range out.LaunchTemplateVersions {
			id := awssdk.ToString(v.LaunchTemplateId)
			if id == "" || v.LaunchTemplateData == nil {
				continue
			}
			meta := launchTemplateMeta(v.LaunchTemplateData)
			meta["default_version"] = strconv.FormatInt(awssdk.ToInt64(v.VersionNumber), 10)
			name := awssdk.ToString(v.LaunchTemplateName)
			if name == "" {
				name = id
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         name,
				Type:         "launch_template",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	if len(assets) == 0 {
		return assets, nil
	}
	groups, err := listAutoScalingGroups(ctx, asg, region)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).
			Msg("auto scaling group listing failed; launch template usage unknown this sweep")
		return assets, nil
	}
	for i := range assets {
		n := 0
		for _, g := range groups {
			if ref := groupLaunchTemplate(g); ref != nil &&
				(awssdk.ToString(ref.LaunchTemplateId) == assets[i].ID || awssdk.ToString(ref.LaunchTemplateName) == assets[i].Name) {
				n++
			}
		}
		assets[i].Metadata["auto_scaling_group_count"] = strconv.Itoa(n)
	}
	return assets, nil
}

// launchTemplateMeta records the instance settings a template version
// imposes, each as observed:
//   - public_ip_interfaces: interfaces with AssociatePublicIpAddress=true.
//   - http_tokens: the metadata-token setting, "" when the template leaves it
//     unset (the launch then takes the account or AMI default; FSBP EC2.170
//     fails only an explicit "optional").
//   - unencrypted_ebs_volumes: EBS mappings with Encrypted explicitly false
//     (EC2.181). An omitted flag inherits the snapshot's or the region's
//     EBS-encryption default and is not counted.
func launchTemplateMeta(d *ec2types.ResponseLaunchTemplateData) map[string]string {
	public := 0
	for _, ni := range d.NetworkInterfaces {
		if awssdk.ToBool(ni.AssociatePublicIpAddress) {
			public++
		}
	}
	unencrypted := 0
	for _, bd := range d.BlockDeviceMappings {
		if bd.Ebs != nil && bd.Ebs.Encrypted != nil && !*bd.Ebs.Encrypted {
			unencrypted++
		}
	}
	meta := map[string]string{
		"public_ip_interfaces":    strconv.Itoa(public),
		"unencrypted_ebs_volumes": strconv.Itoa(unencrypted),
		"http_tokens":             "",
	}
	if mo := d.MetadataOptions; mo != nil {
		meta["http_tokens"] = string(mo.HttpTokens)
		if mo.HttpEndpoint != "" {
			meta["http_endpoint"] = string(mo.HttpEndpoint)
		}
	}
	return meta
}

func collectSpotFleetRequests(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSpotFleetRequests: %w", err)
	}
	return readSpotFleetRequests(ctx, ec2.NewFromConfig(awsCfg), region, accountID, now)
}

// readSpotFleetRequests emits the live Spot Fleet requests (submitted, active,
// modifying). Cancelled and failed requests are history: they launch nothing.
// unencrypted_ebs_volumes counts EBS mappings in the request's own launch
// specifications with Encrypted explicitly false; a request that launches
// from launch templates has none (FSBP EC2.173 skips it, and the template is
// graded as a launch_template).
func readSpotFleetRequests(ctx context.Context, client launchTemplateAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeSpotFleetRequests(ctx, &ec2.DescribeSpotFleetRequestsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("readSpotFleetRequests: %w", err)
		}
		for _, r := range out.SpotFleetRequestConfigs {
			id := awssdk.ToString(r.SpotFleetRequestId)
			switch r.SpotFleetRequestState {
			case ec2types.BatchStateSubmitted, ec2types.BatchStateActive, ec2types.BatchStateModifying:
			default:
				continue
			}
			if id == "" || r.SpotFleetRequestConfig == nil {
				continue
			}
			specs := r.SpotFleetRequestConfig.LaunchSpecifications
			unencrypted := 0
			for _, s := range specs {
				for _, bd := range s.BlockDeviceMappings {
					if bd.Ebs != nil && bd.Ebs.Encrypted != nil && !*bd.Ebs.Encrypted {
						unencrypted++
					}
				}
			}
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      nameTag(r.Tags, id),
				Type:      "spot_fleet_request",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Tags:      tagMap(r.Tags),
				Metadata: map[string]string{
					"state":                      string(r.SpotFleetRequestState),
					"launch_specification_count": strconv.Itoa(len(specs)),
					"unencrypted_ebs_volumes":    strconv.Itoa(unencrypted),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}
