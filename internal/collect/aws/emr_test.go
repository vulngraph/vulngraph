package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeEMR struct {
	clusters    []emrtypes.ClusterSummary
	fleet       map[string]bool
	instances   map[string][][]emrtypes.Instance // per cluster, pages
	instErr     error
	bpa         *emrtypes.BlockPublicAccessConfiguration
	bpaErr      error
	configs     map[string]string
	listErr     error
	gotStates   []emrtypes.ClusterState
	bpaRead     bool
	instFilters []string
}

func (f *fakeEMR) ListClusters(_ context.Context, in *emr.ListClustersInput, _ ...func(*emr.Options)) (*emr.ListClustersOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.gotStates = in.ClusterStates
	return &emr.ListClustersOutput{Clusters: f.clusters}, nil
}

func (f *fakeEMR) DescribeCluster(_ context.Context, in *emr.DescribeClusterInput, _ ...func(*emr.Options)) (*emr.DescribeClusterOutput, error) {
	ct := emrtypes.InstanceCollectionTypeInstanceGroup
	if f.fleet[awssdk.ToString(in.ClusterId)] {
		ct = emrtypes.InstanceCollectionTypeInstanceFleet
	}
	return &emr.DescribeClusterOutput{Cluster: &emrtypes.Cluster{Id: in.ClusterId, InstanceCollectionType: ct, SecurityConfiguration: awssdk.String("sc")}}, nil
}

func (f *fakeEMR) ListInstances(_ context.Context, in *emr.ListInstancesInput, _ ...func(*emr.Options)) (*emr.ListInstancesOutput, error) {
	if f.instErr != nil {
		return nil, f.instErr
	}
	f.instFilters = append(f.instFilters, string(in.InstanceFleetType)+fmtGroups(in.InstanceGroupTypes))
	pages := f.instances[awssdk.ToString(in.ClusterId)]
	i := 0
	if in.Marker != nil {
		i = 1
	}
	out := &emr.ListInstancesOutput{}
	if i < len(pages) {
		out.Instances = pages[i]
	}
	if i+1 < len(pages) {
		out.Marker = awssdk.String("m")
	}
	return out, nil
}

func fmtGroups(g []emrtypes.InstanceGroupType) string {
	s := ""
	for _, x := range g {
		s += "group:" + string(x)
	}
	return s
}

func (f *fakeEMR) GetBlockPublicAccessConfiguration(context.Context, *emr.GetBlockPublicAccessConfigurationInput, ...func(*emr.Options)) (*emr.GetBlockPublicAccessConfigurationOutput, error) {
	f.bpaRead = true
	if f.bpaErr != nil {
		return nil, f.bpaErr
	}
	return &emr.GetBlockPublicAccessConfigurationOutput{BlockPublicAccessConfiguration: f.bpa}, nil
}

func (f *fakeEMR) ListSecurityConfigurations(context.Context, *emr.ListSecurityConfigurationsInput, ...func(*emr.Options)) (*emr.ListSecurityConfigurationsOutput, error) {
	out := &emr.ListSecurityConfigurationsOutput{}
	for name := range f.configs {
		out.SecurityConfigurations = append(out.SecurityConfigurations, emrtypes.SecurityConfigurationSummary{Name: awssdk.String(name)})
	}
	return out, nil
}

func (f *fakeEMR) DescribeSecurityConfiguration(_ context.Context, in *emr.DescribeSecurityConfigurationInput, _ ...func(*emr.Options)) (*emr.DescribeSecurityConfigurationOutput, error) {
	doc := f.configs[awssdk.ToString(in.Name)]
	if doc == "DENIED" {
		return nil, errors.New("AccessDeniedException")
	}
	return &emr.DescribeSecurityConfigurationOutput{Name: in.Name, SecurityConfiguration: awssdk.String(doc)}, nil
}

func byType(assets []asset.Asset, typ string) []asset.Asset {
	var out []asset.Asset
	for _, a := range assets {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

func TestReadEMR(t *testing.T) {
	running := emrtypes.ClusterSummary{Id: awssdk.String("j-1"), ClusterArn: awssdk.String("arn:emr:j-1"), Name: awssdk.String("etl"), Status: &emrtypes.ClusterStatus{State: emrtypes.ClusterStateRunning}}
	fleet := emrtypes.ClusterSummary{Id: awssdk.String("j-2"), ClusterArn: awssdk.String("arn:emr:j-2"), Status: &emrtypes.ClusterStatus{State: emrtypes.ClusterStateWaiting}}
	f := &fakeEMR{
		clusters: []emrtypes.ClusterSummary{running, fleet},
		fleet:    map[string]bool{"j-2": true},
		instances: map[string][][]emrtypes.Instance{
			"j-1": {
				{{PublicIpAddress: awssdk.String("3.3.3.3"), Status: &emrtypes.InstanceStatus{State: emrtypes.InstanceStateRunning}}},
				{{PublicIpAddress: awssdk.String("4.4.4.4"), Status: &emrtypes.InstanceStatus{State: emrtypes.InstanceStateTerminated}}},
			},
			"j-2": {{{PrivateIpAddress: awssdk.String("10.0.0.1")}}},
		},
		bpa: &emrtypes.BlockPublicAccessConfiguration{
			BlockPublicSecurityGroupRules: awssdk.Bool(true),
			PermittedPublicSecurityGroupRuleRanges: []emrtypes.PortRange{
				{MinRange: awssdk.Int32(22), MaxRange: awssdk.Int32(22)}, {MinRange: awssdk.Int32(8080)}, {MinRange: awssdk.Int32(100), MaxRange: awssdk.Int32(200)},
			},
		},
		configs: map[string]string{
			"enc":    `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":false}}`,
			"auth":   `{"AuthenticationConfiguration":{}}`,
			"denied": "DENIED",
			"broken": "{not json",
		},
	}
	got, err := readEMR(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.ElementsMatch(t, emrActiveStates, f.gotStates, "only clusters holding instances are listed")
	require.ElementsMatch(t, []string{"group:MASTER", "group:MASTER", "MASTER"}, f.instFilters, "the primary-node filter follows the cluster's instance collection type")

	clusters := byType(got, "emr_cluster")
	require.Len(t, clusters, 2)
	require.Equal(t, "3.3.3.3", clusters[0].Metadata["primary_public_ips"], "terminated instances are ignored, every page read")
	require.Equal(t, "RUNNING", clusters[0].Metadata["state"])
	require.Equal(t, "", clusters[1].Metadata["primary_public_ips"])

	settings := byType(got, emrSettingsType)
	require.Len(t, settings, 1)
	require.Equal(t, "true", settings[0].Metadata["block_public_security_group_rules"])
	require.Equal(t, "22,8080,100-200", settings[0].Metadata["permitted_public_ports"])

	configs := map[string]map[string]string{}
	for _, a := range byType(got, "emr_security_configuration") {
		configs[a.Name] = a.Metadata
	}
	require.Equal(t, map[string]string{"at_rest_encryption": "true", "in_transit_encryption": "false"}, configs["enc"])
	require.Equal(t, map[string]string{"at_rest_encryption": "false", "in_transit_encryption": "false"}, configs["auth"], "no EncryptionConfiguration block encrypts nothing")
	require.Empty(t, configs["denied"])
	require.Empty(t, configs["broken"])
}

func TestReadEMRUnknownAndUnused(t *testing.T) {
	// ListInstances fails: the cluster is emitted without primary_public_ips.
	f := &fakeEMR{
		clusters: []emrtypes.ClusterSummary{{Id: awssdk.String("j-1"), ClusterArn: awssdk.String("arn:emr:j-1")}},
		instErr:  errors.New("AccessDeniedException"),
		bpaErr:   errors.New("AccessDeniedException"),
	}
	got, err := readEMR(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1, "an unreadable block-public-access setting emits no settings asset")
	require.NotContains(t, got[0].Metadata, "primary_public_ips")

	// No active cluster: EMR is not in use, the setting is not read or emitted.
	unused := &fakeEMR{}
	got, err = readEMR(context.Background(), unused, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, unused.bpaRead)

	_, err = readEMR(context.Background(), &fakeEMR{listErr: errors.New("throttled")}, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}
