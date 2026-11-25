package aws

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

var errRedshiftDenied = errors.New("AccessDenied")

type fakeRedshift struct {
	pages      []*redshift.DescribeClustersOutput
	pageCalls  int
	logging    map[string]*bool // cluster id → LoggingEnabled; missing = error
	params     map[string][]*redshift.DescribeClusterParametersOutput
	paramCalls map[string]int
	mu         sync.Mutex
}

func (f *fakeRedshift) DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	f.pageCalls++
	if f.pageCalls > len(f.pages) {
		return nil, errRedshiftDenied
	}
	return f.pages[f.pageCalls-1], nil
}

func (f *fakeRedshift) DescribeLoggingStatus(_ context.Context, in *redshift.DescribeLoggingStatusInput, _ ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error) {
	v, ok := f.logging[awssdk.ToString(in.ClusterIdentifier)]
	if !ok {
		return nil, errRedshiftDenied
	}
	return &redshift.DescribeLoggingStatusOutput{LoggingEnabled: v}, nil
}

func (f *fakeRedshift) DescribeClusterParameters(_ context.Context, in *redshift.DescribeClusterParametersInput, _ ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error) {
	g := awssdk.ToString(in.ParameterGroupName)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paramCalls == nil {
		f.paramCalls = map[string]int{}
	}
	f.paramCalls[g]++
	pages := f.params[g]
	n := f.paramCalls[g]
	if n > len(pages) || pages[n-1] == nil {
		return nil, errRedshiftDenied
	}
	return pages[n-1], nil
}

func redshiftCluster(id, group string, sgs ...string) redshifttypes.Cluster {
	c := redshifttypes.Cluster{
		ClusterIdentifier:                awssdk.String(id),
		PubliclyAccessible:               awssdk.Bool(false),
		Encrypted:                        awssdk.Bool(true),
		AllowVersionUpgrade:              awssdk.Bool(true),
		EnhancedVpcRouting:               awssdk.Bool(true),
		AutomatedSnapshotRetentionPeriod: awssdk.Int32(7),
		MultiAZ:                          awssdk.String("Enabled"),
		MasterUsername:                   awssdk.String("warehouse_admin"),
		Endpoint:                         &redshifttypes.Endpoint{Address: awssdk.String(id + ".example"), Port: awssdk.Int32(5439)},
		ClusterParameterGroups:           []redshifttypes.ClusterParameterGroupStatus{{ParameterGroupName: awssdk.String(group)}},
	}
	for _, sg := range sgs {
		c.VpcSecurityGroups = append(c.VpcSecurityGroups, redshifttypes.VpcSecurityGroupMembership{VpcSecurityGroupId: awssdk.String(sg)})
	}
	return c
}

func param(name, value string) redshifttypes.Parameter {
	return redshifttypes.Parameter{ParameterName: awssdk.String(name), ParameterValue: awssdk.String(value)}
}

func TestRedshiftClustersPostureAndSubReads(t *testing.T) {
	legacy := redshiftCluster("legacy", "default.redshift-1.0", "sg-1")
	legacy.PubliclyAccessible = awssdk.Bool(true)
	legacy.Encrypted = awssdk.Bool(false)
	legacy.MultiAZ = awssdk.String("Disabled")
	legacy.MasterUsername = awssdk.String("awsuser")
	legacy.AutomatedSnapshotRetentionPeriod = awssdk.Int32(0)
	sparse := redshifttypes.Cluster{ClusterIdentifier: awssdk.String("sparse")} // every pointer nil

	f := &fakeRedshift{
		pages: []*redshift.DescribeClustersOutput{
			{Clusters: []redshifttypes.Cluster{redshiftCluster("ok", "custom")}, Marker: awssdk.String("m")},
			{Clusters: []redshifttypes.Cluster{legacy, sparse}},
		},
		logging: map[string]*bool{"ok": awssdk.Bool(true), "legacy": awssdk.Bool(false)},
		params: map[string][]*redshift.DescribeClusterParametersOutput{
			// require_ssl on the second page: the read must page to it.
			"custom": {
				{Parameters: []redshifttypes.Parameter{param("datestyle", "ISO, MDY")}, Marker: awssdk.String("p2")},
				{Parameters: []redshifttypes.Parameter{param("require_ssl", "TRUE")}},
			},
			"default.redshift-1.0": {{Parameters: []redshifttypes.Parameter{param("require_ssl", "false")}}},
		},
	}
	got, err := collectRedshiftClusters(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	by := map[string]asset.Asset{}
	for _, a := range got {
		require.Equal(t, "redshift_cluster", a.Type)
		by[a.Name] = a
	}
	require.Equal(t, "arn:aws:redshift:eu-west-1:1:cluster:ok", by["ok"].ID)
	ok := by["ok"].Metadata
	require.Equal(t, "true", ok["audit_logging_enabled"])
	require.Equal(t, "true", ok["require_ssl"])
	require.Equal(t, "true", ok["multi_az"])
	require.Equal(t, "5439", ok["port"])
	require.NotContains(t, ok, "public_access")

	l := by["legacy"].Metadata
	require.Equal(t, "true", l["publicly_accessible"])
	require.Equal(t, asset.PublicAccessPossible, l["public_access"])
	require.Equal(t, "false", l["encrypted"])
	require.Equal(t, "false", l["multi_az"])
	require.Equal(t, "awsuser", l["master_username"])
	require.Equal(t, "0", l["automated_snapshot_retention"])
	require.Equal(t, "false", l["audit_logging_enabled"])
	require.Equal(t, "false", l["require_ssl"])
	require.Equal(t, "sg-1", l["security_groups"])

	// Nil pointers and failed sub-reads are unknown, never false/0.
	s := by["sparse"].Metadata
	for _, k := range []string{"publicly_accessible", "encrypted", "allow_version_upgrade", "enhanced_vpc_routing",
		"automated_snapshot_retention", "multi_az", "master_username", "port", "audit_logging_enabled", "require_ssl"} {
		require.NotContains(t, s, k)
	}
}

func TestRedshiftParameterPageErrorIsUnknown(t *testing.T) {
	f := &fakeRedshift{
		pages: []*redshift.DescribeClustersOutput{{Clusters: []redshifttypes.Cluster{redshiftCluster("a", "g"), redshiftCluster("b", "g")}}},
		params: map[string][]*redshift.DescribeClusterParametersOutput{
			"g": {{Parameters: []redshifttypes.Parameter{param("datestyle", "ISO")}, Marker: awssdk.String("p2")}, nil},
		},
	}
	got, err := collectRedshiftClusters(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	for _, a := range got {
		require.NotContains(t, a.Metadata, "require_ssl", "a parameter that may sit on the failed page is unknown")
	}
	require.Equal(t, 2, f.paramCalls["g"], "the shared group is read once, not once per cluster")
}

func TestRedshiftClusterListingPageFailureFails(t *testing.T) {
	f := &fakeRedshift{pages: []*redshift.DescribeClustersOutput{{Clusters: []redshifttypes.Cluster{redshiftCluster("a", "g")}, Marker: awssdk.String("m")}}}
	_, err := collectRedshiftClusters(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}

func TestStampRedshiftPortWorldOpen(t *testing.T) {
	sg := func(id, ingress string) asset.Asset {
		md := map[string]string{"ingress_rules": "1"}
		if ingress != "" {
			md["ingress"] = ingress
		} else {
			md["ingress_rules"] = "0" // secgroups.go omits ingress only for a group with no rules
		}
		return asset.Asset{ID: id, Type: "security_group", Provider: asset.ProviderAWS, Metadata: md}
	}
	cluster := func(name, sgs string) asset.Asset {
		return asset.Asset{ID: name, Name: name, Type: "redshift_cluster", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"port": "5439", "security_groups": sgs}}
	}
	assets := []asset.Asset{
		sg("sg-world", `[{"protocol":"tcp","from_port":5439,"to_port":5439,"cidrs":["0.0.0.0/0"]}]`),
		sg("sg-v6all", `[{"protocol":"-1","from_port":0,"to_port":0,"cidrs":["::/0"]}]`),
		sg("sg-other-port", `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["0.0.0.0/0"]}]`),
		sg("sg-office", `[{"protocol":"tcp","from_port":5439,"to_port":5439,"cidrs":["10.0.0.0/8"]}]`),
		sg("sg-empty", ""),
		sg("sg-garbled", `not json`),
		{ID: "sg-rules-unserialized", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress_rules": "2"}},
		cluster("open", "sg-office,sg-world"),
		cluster("open-v6", "sg-v6all"),
		cluster("closed", "sg-other-port,sg-office,sg-empty"),
		cluster("partly-unread", "sg-office,sg-missing"),
		cluster("unread-but-open", "sg-world,sg-missing"),
		cluster("garbled", "sg-office,sg-garbled"),
		cluster("rules-unserialized", "sg-rules-unserialized"),
	}
	stampRedshiftPortWorldOpen(assets)
	by := map[string]map[string]string{}
	for _, a := range assets {
		by[a.Name] = a.Metadata
	}
	require.Equal(t, "true", by["open"]["port_world_open"])
	require.Equal(t, "sg-world", by["open"]["world_open_security_groups"])
	require.Equal(t, "true", by["open-v6"]["port_world_open"])
	require.Equal(t, "false", by["closed"]["port_world_open"])
	require.NotContains(t, by["partly-unread"], "port_world_open", "an uncollected group could be the open one")
	require.Equal(t, "true", by["unread-but-open"]["port_world_open"], "one proven open group is enough")
	require.NotContains(t, by["garbled"], "port_world_open", "an unparsable ingress document is unknown, not closed")
	require.NotContains(t, by["rules-unserialized"], "port_world_open", "rules counted but not serialized are unknown")
}

type fakeRedshiftServerless struct {
	workgroups []rsstypes.Workgroup
	namespaces map[string]*rsstypes.Namespace
	nsCalls    int
}

func (f *fakeRedshiftServerless) ListWorkgroups(context.Context, *redshiftserverless.ListWorkgroupsInput, ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error) {
	return &redshiftserverless.ListWorkgroupsOutput{Workgroups: f.workgroups}, nil
}

func (f *fakeRedshiftServerless) GetNamespace(_ context.Context, in *redshiftserverless.GetNamespaceInput, _ ...func(*redshiftserverless.Options)) (*redshiftserverless.GetNamespaceOutput, error) {
	f.nsCalls++
	ns, ok := f.namespaces[awssdk.ToString(in.NamespaceName)]
	if !ok {
		return nil, errRedshiftDenied
	}
	return &redshiftserverless.GetNamespaceOutput{Namespace: ns}, nil
}

func TestRedshiftServerlessWorkgroupsAndNamespaces(t *testing.T) {
	f := &fakeRedshiftServerless{
		workgroups: []rsstypes.Workgroup{
			{WorkgroupArn: awssdk.String("arn:wg/a"), WorkgroupName: awssdk.String("a"), NamespaceName: awssdk.String("ns1"),
				EnhancedVpcRouting: awssdk.Bool(false), PubliclyAccessible: awssdk.Bool(true),
				ConfigParameters: []rsstypes.ConfigParameter{{ParameterKey: awssdk.String("require_ssl"), ParameterValue: awssdk.String("false")}}},
			{WorkgroupArn: awssdk.String("arn:wg/b"), WorkgroupName: awssdk.String("b"), NamespaceName: awssdk.String("ns1")},
		},
		namespaces: map[string]*rsstypes.Namespace{
			"ns1": {NamespaceArn: awssdk.String("arn:ns/1"), AdminUsername: awssdk.String("admin"), LogExports: []rsstypes.LogExport{rsstypes.LogExportUserLog}},
		},
	}
	got, partial, err := collectRedshiftServerlessResources(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial)
	require.Len(t, got, 3, "two workgroups sharing one namespace yield one namespace asset")
	require.Equal(t, 1, f.nsCalls)
	by := map[string]asset.Asset{}
	for _, a := range got {
		by[a.ID] = a
	}
	a := by["arn:wg/a"].Metadata
	require.Equal(t, "false", a["enhanced_vpc_routing"])
	require.Equal(t, "true", a["publicly_accessible"])
	require.Equal(t, asset.PublicAccessPossible, a["public_access"])
	require.Equal(t, "false", a["require_ssl"])
	b := by["arn:wg/b"].Metadata
	require.NotContains(t, b, "require_ssl")
	require.NotContains(t, b, "publicly_accessible")
	ns := by["arn:ns/1"]
	require.Equal(t, "redshift_serverless_namespace", ns.Type)
	require.Equal(t, "admin", ns.Metadata["admin_username"])
	require.Equal(t, "userlog", ns.Metadata["log_exports"])

	// A namespace that cannot be read is not emitted, and the sweep says so.
	f.namespaces = nil
	got, partial, err = collectRedshiftServerlessResources(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.True(t, partial)
	require.Len(t, got, 2)
}

func TestStampRedshiftPortWorldOpenIgnoresOutOfRangePort(t *testing.T) {
	assets := []asset.Asset{
		{ID: "sg", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{
			"ingress_rules": "1", "ingress": `[{"protocol":"tcp","from_port":5439,"to_port":5439,"cidrs":["0.0.0.0/0"]}]`}},
		{ID: "wraps", Type: "redshift_cluster", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"port": "4294972735", "security_groups": "sg"}},
	}
	stampRedshiftPortWorldOpen(assets)
	require.NotContains(t, assets[1].Metadata, "port_world_open")
}
