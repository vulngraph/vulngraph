package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeNetwork struct {
	networks    []*compute.Network
	subnets     []*compute.Subnetwork
	unreachable []string
	subnetErr   error
	policies    []*dns.Policy
	policyErr   error
}

func (f fakeNetwork) ListNetworks(context.Context, string) ([]*compute.Network, error) {
	return f.networks, nil
}
func (f fakeNetwork) ListSubnetworks(context.Context, string) ([]*compute.Subnetwork, []string, error) {
	return f.subnets, f.unreachable, f.subnetErr
}
func (f fakeNetwork) ListDNSPolicies(context.Context, string) ([]*dns.Policy, error) {
	return f.policies, f.policyErr
}

func byID(assets []asset.Asset) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, a := range assets {
		out[a.ID] = a.Metadata
	}
	return out
}

func TestCollectNetworks(t *testing.T) {
	f := fakeNetwork{
		networks: []*compute.Network{
			{Name: "default", AutoCreateSubnetworks: true},
			{Name: "legacy", IPv4Range: "10.240.0.0/16"},
			{Name: "prod"},
			nil,
		},
		policies: []*dns.Policy{
			{Name: "logs", EnableLogging: true, Networks: []*dns.PolicyNetwork{{NetworkUrl: "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod"}}},
			{Name: "nolog", Networks: []*dns.PolicyNetwork{{NetworkUrl: "projects/p/global/networks/default"}}},
		},
		subnets: []*compute.Subnetwork{
			{Name: "off", Region: "regions/europe-west4", Network: "global/networks/prod"},
			{Name: "weak", Region: "regions/europe-west4", LogConfig: &compute.SubnetworkLogConfig{
				Enable: true, AggregationInterval: "INTERVAL_10_MIN", FlowSampling: 0.5, Metadata: "EXCLUDE_ALL_METADATA", FilterExpr: "true"}},
			{Name: "good", Region: "regions/europe-west4", LogConfig: &compute.SubnetworkLogConfig{
				Enable: true, AggregationInterval: "INTERVAL_5_SEC", FlowSampling: 1, Metadata: "INCLUDE_ALL_METADATA"}},
			{Name: "legacyflag", Region: "regions/us-east1", EnableFlowLogs: true},
			{Name: "proxy", Region: "regions/us-east1", Purpose: "REGIONAL_MANAGED_PROXY"},
		},
	}
	got, err := collectNetworks(context.Background(), f, "p", time.Now())
	require.NoError(t, err)
	md := byID(got)

	require.Equal(t, "true", md["p/network/default"]["default_network"])
	require.Equal(t, "false", md["p/network/default"]["dns_logging"], "a policy with logging off logs nothing")
	require.Equal(t, "true", md["p/network/legacy"]["legacy_network"])
	require.Equal(t, "false", md["p/network/legacy"]["dns_logging"], "no policy binds it")
	require.Equal(t, "true", md["p/network/prod"]["dns_logging"])
	require.Equal(t, "false", md["p/network/prod"]["legacy_network"])

	require.Equal(t, "false", md["p/subnetwork/europe-west4/off"]["flow_logs"])
	require.NotContains(t, md["p/subnetwork/europe-west4/off"], "flow_logs_config_gaps")
	require.Equal(t, "aggregation_interval=INTERVAL_10_MIN,flow_sampling=0.5,metadata=EXCLUDE_ALL_METADATA,filter_expr",
		md["p/subnetwork/europe-west4/weak"]["flow_logs_config_gaps"])
	require.Equal(t, "", md["p/subnetwork/europe-west4/good"]["flow_logs_config_gaps"])
	require.Equal(t, "true", md["p/subnetwork/us-east1/legacyflag"]["flow_logs"])
	require.NotContains(t, md["p/subnetwork/us-east1/legacyflag"], "flow_logs_config_gaps",
		"settings unread when only the legacy flag came back")
	require.NotContains(t, md["p/subnetwork/us-east1/proxy"], "flow_logs", "proxy-only subnets have no flow logs to grade")
}

// An unread DNS policy list is unknown (key absent, sweep partial), while a
// project that never enabled Cloud DNS has no policy and logs nothing.
func TestCollectNetworks_DNSPolicyKnownness(t *testing.T) {
	nets := []*compute.Network{{Name: "prod"}}
	got, err := collectNetworks(context.Background(), fakeNetwork{networks: nets, policyErr: errors.New("boom")}, "p", time.Now())
	require.Error(t, err)
	require.NotContains(t, byID(got)["p/network/prod"], "dns_logging")

	disabled := &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "SERVICE_DISABLED"}}}
	got, err = collectNetworks(context.Background(), fakeNetwork{networks: nets, policyErr: disabled}, "p", time.Now())
	require.NoError(t, err)
	require.Equal(t, "false", byID(got)["p/network/prod"]["dns_logging"])
}

func TestCollectNetworks_PartialSubnetsKeepNetworks(t *testing.T) {
	got, err := collectNetworks(context.Background(), fakeNetwork{
		networks: []*compute.Network{{Name: "prod"}}, unreachable: []string{"regions/asia-east1"},
	}, "p", time.Now())
	require.Error(t, err, "an unreachable region is a partial subnet listing")
	require.Contains(t, byID(got), "p/network/prod")
}
