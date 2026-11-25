package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// emrSettingsType carries the region's EMR block-public-access setting (FSBP
// EMR.2): one asset per region where EMR is in use, never per cluster.
const emrSettingsType = "emr_settings"

// emrActiveStates are the cluster states that hold instances. A terminated
// cluster keeps listing for two months and is not "EMR in use".
var emrActiveStates = []emrtypes.ClusterState{
	emrtypes.ClusterStateStarting, emrtypes.ClusterStateBootstrapping,
	emrtypes.ClusterStateRunning, emrtypes.ClusterStateWaiting,
}

type emrAPI interface {
	ListClusters(context.Context, *emr.ListClustersInput, ...func(*emr.Options)) (*emr.ListClustersOutput, error)
	DescribeCluster(context.Context, *emr.DescribeClusterInput, ...func(*emr.Options)) (*emr.DescribeClusterOutput, error)
	ListInstances(context.Context, *emr.ListInstancesInput, ...func(*emr.Options)) (*emr.ListInstancesOutput, error)
	GetBlockPublicAccessConfiguration(context.Context, *emr.GetBlockPublicAccessConfigurationInput, ...func(*emr.Options)) (*emr.GetBlockPublicAccessConfigurationOutput, error)
	ListSecurityConfigurations(context.Context, *emr.ListSecurityConfigurationsInput, ...func(*emr.Options)) (*emr.ListSecurityConfigurationsOutput, error)
	DescribeSecurityConfiguration(context.Context, *emr.DescribeSecurityConfigurationInput, ...func(*emr.Options)) (*emr.DescribeSecurityConfigurationOutput, error)
}

func collectEMR(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectEMR: %w", err)
	}
	return readEMR(ctx, emr.NewFromConfig(awsCfg), region, accountID, now)
}

func readEMR(ctx context.Context, client emrAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	clusters, err := readEMRClusters(ctx, client, region, accountID, now)
	if err != nil {
		return nil, err
	}
	configs, err := readEMRSecurityConfigurations(ctx, client, region, accountID, now)
	if err != nil {
		return nil, err
	}
	out := make([]asset.Asset, 0, len(clusters)+len(configs)+1)
	out = append(append(out, clusters...), configs...)
	if len(clusters) > 0 {
		if s, ok := readEMRBlockPublicAccess(ctx, client, region, accountID, now); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func readEMRClusters(ctx context.Context, client emrAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	var marker *string
	for {
		out, err := client.ListClusters(ctx, &emr.ListClustersInput{ClusterStates: emrActiveStates, Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("readEMRClusters: ListClusters: %w", err)
		}
		for _, c := range out.Clusters {
			meta := map[string]string{}
			if c.Status != nil && c.Status.State != "" {
				meta["state"] = string(c.Status.State)
			}
			emrClusterNetwork(ctx, client, region, c.Id, meta)
			assets = append(assets, asset.Asset{
				ID: awssdk.ToString(c.ClusterArn), Name: awssdk.ToString(c.Name), Type: "emr_cluster",
				Provider: asset.ProviderAWS, Region: region, AccountID: accountID, Metadata: meta,
				DiscoveredAt: now, LastSeen: now,
			})
		}
		if out.Marker == nil {
			return assets, nil
		}
		marker = out.Marker
	}
}

// emrClusterNetwork records the security configuration and the primary
// node's public IPs (FSBP EMR.1). primary_public_ips is written only when
// every page of the primary-node listing was read.
func emrClusterNetwork(ctx context.Context, client emrAPI, region string, clusterID *string, meta map[string]string) {
	desc, err := client.DescribeCluster(ctx, &emr.DescribeClusterInput{ClusterId: clusterID})
	if err != nil || desc.Cluster == nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("cluster", awssdk.ToString(clusterID)).
			Msg("emr: DescribeCluster failed (check elasticmapreduce:DescribeCluster); primary-node exposure unknown this sweep")
		return
	}
	meta["security_configuration"] = awssdk.ToString(desc.Cluster.SecurityConfiguration)
	in := &emr.ListInstancesInput{ClusterId: clusterID}
	if desc.Cluster.InstanceCollectionType == emrtypes.InstanceCollectionTypeInstanceFleet {
		in.InstanceFleetType = emrtypes.InstanceFleetTypeMaster
	} else {
		in.InstanceGroupTypes = []emrtypes.InstanceGroupType{emrtypes.InstanceGroupTypeMaster}
	}
	var ips []string
	for {
		out, err := client.ListInstances(ctx, in)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("cluster", awssdk.ToString(clusterID)).
				Msg("emr: ListInstances failed (check elasticmapreduce:ListInstances); primary-node exposure unknown this sweep")
			return
		}
		for _, inst := range out.Instances {
			if inst.Status != nil && inst.Status.State == emrtypes.InstanceStateTerminated {
				continue
			}
			if ip := awssdk.ToString(inst.PublicIpAddress); ip != "" {
				ips = append(ips, ip)
			}
		}
		if out.Marker == nil {
			break
		}
		in.Marker = out.Marker
	}
	meta["primary_public_ips"] = strings.Join(ips, ",")
}

// readEMRBlockPublicAccess returns the region's settings asset, or false when
// the setting could not be read (no asset — unknown, never "enabled").
func readEMRBlockPublicAccess(ctx context.Context, client emrAPI, region, accountID string, now time.Time) (asset.Asset, bool) {
	out, err := client.GetBlockPublicAccessConfiguration(ctx, &emr.GetBlockPublicAccessConfigurationInput{})
	if err != nil || out.BlockPublicAccessConfiguration == nil || out.BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules == nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).
			Msg("emr: block public access unreadable (check elasticmapreduce:GetBlockPublicAccessConfiguration); EMR.2 unknown this sweep")
		return asset.Asset{}, false
	}
	bpa := out.BlockPublicAccessConfiguration
	var ports []string
	for _, r := range bpa.PermittedPublicSecurityGroupRuleRanges {
		lo := awssdk.ToInt32(r.MinRange)
		hi := lo
		if r.MaxRange != nil {
			hi = *r.MaxRange
		}
		if lo == hi {
			ports = append(ports, strconv.Itoa(int(lo)))
		} else {
			ports = append(ports, fmt.Sprintf("%d-%d", lo, hi))
		}
	}
	return asset.Asset{
		ID:   "aws:" + accountID + ":" + region + ":emr-settings",
		Name: "EMR settings (" + region + ")", Type: emrSettingsType, Provider: asset.ProviderAWS,
		Region: region, AccountID: accountID,
		Metadata: map[string]string{
			"block_public_security_group_rules": strconv.FormatBool(*bpa.BlockPublicSecurityGroupRules),
			"permitted_public_ports":            strings.Join(ports, ","),
		},
		DiscoveredAt: now, LastSeen: now,
	}, true
}

// emrSecurityConfigDoc is the slice of the security-configuration JSON the
// encryption controls read. A configuration without an EncryptionConfiguration
// block encrypts nothing.
type emrSecurityConfigDoc struct {
	EncryptionConfiguration *struct {
		EnableAtRestEncryption    bool
		EnableInTransitEncryption bool
	}
}

func readEMRSecurityConfigurations(ctx context.Context, client emrAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	var marker *string
	for {
		out, err := client.ListSecurityConfigurations(ctx, &emr.ListSecurityConfigurationsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("readEMRSecurityConfigurations: ListSecurityConfigurations: %w", err)
		}
		for _, sc := range out.SecurityConfigurations {
			name := awssdk.ToString(sc.Name)
			meta := map[string]string{}
			desc, err := client.DescribeSecurityConfiguration(ctx, &emr.DescribeSecurityConfigurationInput{Name: sc.Name})
			var doc emrSecurityConfigDoc
			switch {
			case err != nil:
				log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("security_configuration", name).
					Msg("emr: DescribeSecurityConfiguration failed (check elasticmapreduce:DescribeSecurityConfiguration); encryption unknown this sweep")
			case json.Unmarshal([]byte(awssdk.ToString(desc.SecurityConfiguration)), &doc) != nil:
				log.FromContext(ctx).Warn().Str("region", region).Str("security_configuration", name).
					Msg("emr: security configuration is not valid JSON; encryption unknown this sweep")
			default:
				ec := doc.EncryptionConfiguration
				meta["at_rest_encryption"] = strconv.FormatBool(ec != nil && ec.EnableAtRestEncryption)
				meta["in_transit_encryption"] = strconv.FormatBool(ec != nil && ec.EnableInTransitEncryption)
			}
			assets = append(assets, asset.Asset{
				ID:   fmt.Sprintf("arn:%s:elasticmapreduce:%s:%s:security-configuration/%s", partitionFor(region), region, accountID, name),
				Name: name, Type: "emr_security_configuration", Provider: asset.ProviderAWS,
				Region: region, AccountID: accountID, Metadata: meta, DiscoveredAt: now, LastSeen: now,
			})
		}
		if out.Marker == nil {
			return assets, nil
		}
		marker = out.Marker
	}
}
