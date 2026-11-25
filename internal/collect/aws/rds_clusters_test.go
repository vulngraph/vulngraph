package aws

import (
	"context"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeRDSPosture serves the cluster, parameter, proxy, global-cluster and
// event-subscription reads. Pages are served in order; an error at index i
// fails page i.
type fakeRDSPosture struct {
	clusterPages [][]rdstypes.DBCluster
	clusterErrAt int // page index that fails; -1 = none
	params       map[string][]rdstypes.Parameter
	clusterParms map[string][]rdstypes.Parameter
	paramErr     map[string]bool
	proxies      []rdstypes.DBProxy
	proxyErr     error
	globals      []rdstypes.GlobalCluster
	subs         []rdstypes.EventSubscription
	engines      map[string][]string
	engineErr    map[string]bool
	subsErr      error

	mu         sync.Mutex
	paramCalls map[string]int
}

func newFakeRDSPosture() *fakeRDSPosture {
	return &fakeRDSPosture{clusterErrAt: -1, paramCalls: map[string]int{}}
}

func pageMarker(i, n int) *string {
	if i+1 < n {
		return awssdk.String("next")
	}
	return nil
}

func (f *fakeRDSPosture) DescribeDBClusters(_ context.Context, in *rds.DescribeDBClustersInput, _ ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	i := 0
	if in.Marker != nil {
		i = 1
	}
	if i == f.clusterErrAt {
		return nil, apiErr{code: "Throttling"}
	}
	if len(f.clusterPages) == 0 {
		return &rds.DescribeDBClustersOutput{}, nil
	}
	return &rds.DescribeDBClustersOutput{DBClusters: f.clusterPages[i], Marker: pageMarker(i, len(f.clusterPages))}, nil
}

func (f *fakeRDSPosture) paramPage(group string, in *string, all []rdstypes.Parameter) ([]rdstypes.Parameter, *string, error) {
	f.mu.Lock()
	f.paramCalls[group]++
	f.mu.Unlock()
	if f.paramErr[group] {
		return nil, nil, apiErr{code: "AccessDenied"}
	}
	// Two pages: the first parameter alone, then the rest.
	if in == nil && len(all) > 1 {
		return all[:1], awssdk.String("p2"), nil
	}
	if in == nil {
		return all, nil, nil
	}
	return all[1:], nil, nil
}

func (f *fakeRDSPosture) DescribeDBParameters(_ context.Context, in *rds.DescribeDBParametersInput, _ ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
	g := awssdk.ToString(in.DBParameterGroupName)
	ps, m, err := f.paramPage(g, in.Marker, f.params[g])
	if err != nil {
		return nil, err
	}
	return &rds.DescribeDBParametersOutput{Parameters: ps, Marker: m}, nil
}

func (f *fakeRDSPosture) DescribeDBClusterParameters(_ context.Context, in *rds.DescribeDBClusterParametersInput, _ ...func(*rds.Options)) (*rds.DescribeDBClusterParametersOutput, error) {
	g := awssdk.ToString(in.DBClusterParameterGroupName)
	ps, m, err := f.paramPage(g, in.Marker, f.clusterParms[g])
	if err != nil {
		return nil, err
	}
	return &rds.DescribeDBClusterParametersOutput{Parameters: ps, Marker: m}, nil
}

func (f *fakeRDSPosture) DescribeDBProxies(context.Context, *rds.DescribeDBProxiesInput, ...func(*rds.Options)) (*rds.DescribeDBProxiesOutput, error) {
	if f.proxyErr != nil {
		return nil, f.proxyErr
	}
	return &rds.DescribeDBProxiesOutput{DBProxies: f.proxies}, nil
}

func (f *fakeRDSPosture) DescribeGlobalClusters(context.Context, *rds.DescribeGlobalClustersInput, ...func(*rds.Options)) (*rds.DescribeGlobalClustersOutput, error) {
	return &rds.DescribeGlobalClustersOutput{GlobalClusters: f.globals}, nil
}

func (f *fakeRDSPosture) DescribeEventSubscriptions(context.Context, *rds.DescribeEventSubscriptionsInput, ...func(*rds.Options)) (*rds.DescribeEventSubscriptionsOutput, error) {
	if f.subsErr != nil {
		return nil, f.subsErr
	}
	return &rds.DescribeEventSubscriptionsOutput{EventSubscriptionsList: f.subs}, nil
}

func (f *fakeRDSPosture) DescribeDBEngineVersions(_ context.Context, in *rds.DescribeDBEngineVersionsInput, _ ...func(*rds.Options)) (*rds.DescribeDBEngineVersionsOutput, error) {
	engine := awssdk.ToString(in.Engine)
	if f.engineErr[engine] {
		return nil, apiErr{code: "AccessDenied"}
	}
	versions := f.engines[engine]
	out := &rds.DescribeDBEngineVersionsOutput{}
	if in.Marker == nil && len(versions) > 1 {
		out.DBEngineVersions = []rdstypes.DBEngineVersion{{Engine: in.Engine, EngineVersion: awssdk.String(versions[0])}}
		out.Marker = awssdk.String("p2")
		return out, nil
	}
	if in.Marker != nil {
		versions = versions[1:]
	}
	for _, v := range versions {
		out.DBEngineVersions = append(out.DBEngineVersions, rdstypes.DBEngineVersion{Engine: in.Engine, EngineVersion: awssdk.String(v)})
	}
	return out, nil
}

func TestCollectRDSClusters_TypesAndKeys(t *testing.T) {
	f := newFakeRDSPosture()
	f.clusterPages = [][]rdstypes.DBCluster{
		{
			{
				DBClusterIdentifier: awssdk.String("orders"), DBClusterArn: awssdk.String("arn:aws:rds:eu-west-1:111:cluster:orders"),
				Engine: awssdk.String("aurora-mysql"), EngineVersion: awssdk.String("8.0.mysql_aurora.3.08.0"), EngineMode: awssdk.String("provisioned"),
				StorageEncrypted: awssdk.Bool(true), DeletionProtection: awssdk.Bool(false), IAMDatabaseAuthenticationEnabled: awssdk.Bool(false),
				MultiAZ: awssdk.Bool(true), CopyTagsToSnapshot: awssdk.Bool(true), BackupRetentionPeriod: awssdk.Int32(1),
				MasterUsername: awssdk.String("admin"), DBClusterParameterGroup: awssdk.String("aurora-audit"),
				EnabledCloudwatchLogsExports: []string{"audit", "error"},
				DBClusterMembers: []rdstypes.DBClusterMember{
					{DBInstanceIdentifier: awssdk.String("orders-1"), DBClusterParameterGroupStatus: awssdk.String("in-sync")},
					{DBInstanceIdentifier: awssdk.String("orders-2"), DBClusterParameterGroupStatus: awssdk.String("pending-reboot")},
				},
			},
		},
		{
			{DBClusterIdentifier: awssdk.String("docs"), DBClusterArn: awssdk.String("arn:aws:rds:eu-west-1:111:cluster:docs"), Engine: awssdk.String("docdb")},
			{DBClusterIdentifier: awssdk.String("graph"), DBClusterArn: awssdk.String("arn:aws:rds:eu-west-1:111:cluster:graph"), Engine: awssdk.String("neptune"),
				AutoMinorVersionUpgrade: awssdk.Bool(true)},
		},
	}
	got, err := collectRDSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3, "both pages are read")

	orders := got[0]
	require.Equal(t, "rds_cluster", orders.Type)
	require.Equal(t, "arn:aws:rds:eu-west-1:111:cluster:orders", orders.ID)
	m := orders.Metadata
	require.Equal(t, "true", m["storage_encrypted"])
	require.Equal(t, "false", m["deletion_protection"])
	require.Equal(t, "false", m["iam_auth_enabled"])
	require.Equal(t, "1", m["backup_retention"])
	require.Equal(t, "audit,error", m["log_exports"])
	require.Equal(t, "0", m["backtrack_window"], "an unconfigured backtrack window is omitted by the API: backtracking off")
	require.Equal(t, "false", m["parameter_group_in_sync"], "a member pending reboot has not applied the group")
	require.Equal(t, "2", m["member_count"])
	require.NotContains(t, m, "auto_minor_version_upgrade", "an omitted setting stays unknown")

	require.Equal(t, "docdb_cluster", got[1].Type)
	docs := got[1].Metadata
	require.NotContains(t, docs, "storage_encrypted", "a nil boolean is not false")
	require.NotContains(t, docs, "backtrack_window")
	require.Equal(t, "", docs["log_exports"], "no exports is the API's omission of an empty list")
	require.Equal(t, "true", docs["parameter_group_in_sync"], "no members, nothing pending")

	require.Equal(t, "neptune_cluster", got[2].Type)
	require.Equal(t, "true", got[2].Metadata["auto_minor_version_upgrade"])
}

func TestCollectRDSClusters_FailedPageFailsTheListing(t *testing.T) {
	f := newFakeRDSPosture()
	f.clusterPages = [][]rdstypes.DBCluster{{{Engine: awssdk.String("aurora-postgresql")}}, {}}
	f.clusterErrAt = 1
	_, err := collectRDSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.Error(t, err, "a short page sequence is a failed read, not a short list")
}

func TestStampRDSParameterFacts(t *testing.T) {
	f := newFakeRDSPosture()
	f.params = map[string][]rdstypes.Parameter{
		// rds.force_ssl present without a value: the engine default (0).
		"sqlserver-default": {{ParameterName: awssdk.String("max degree")}, {ParameterName: awssdk.String("rds.force_ssl")}},
		"maria-tls":         {{ParameterName: awssdk.String("require_secure_transport"), ParameterValue: awssdk.String("ON")}},
		// MariaDB 10.4 groups have no require_secure_transport at all.
		"maria-104": {{ParameterName: awssdk.String("max_connections"), ParameterValue: awssdk.String("100")}},
		"pg":        {{ParameterName: awssdk.String("rds.force_ssl"), ParameterValue: awssdk.String("0")}},
		// The PostgreSQL default changed in 15: an unset value is not knowable.
		"pg-default": {{ParameterName: awssdk.String("rds.force_ssl")}},
		"my":         {{ParameterName: awssdk.String("require_secure_transport"), ParameterValue: awssdk.String("1")}},
	}
	f.paramErr = map[string]bool{"denied": true}
	f.clusterParms = map[string][]rdstypes.Parameter{
		"aurora-audit": {{ParameterName: awssdk.String("server_audit_logging"), ParameterValue: awssdk.String("1")}, {ParameterName: awssdk.String("server_audit_events")}},
		"docdb-tls":    {{ParameterName: awssdk.String("tls"), ParameterValue: awssdk.String("tls1.2+")}},
	}
	inst := func(engine, group string) asset.Asset {
		return asset.Asset{Type: "rds_instance", Metadata: map[string]string{"engine": engine, "db_parameter_group": group}}
	}
	instances := []asset.Asset{
		inst("sqlserver-se", "sqlserver-default"),
		inst("sqlserver-ex", "sqlserver-default"),
		inst("mariadb", "maria-tls"),
		inst("mariadb", "maria-104"),
		inst("mariadb", "denied"),
		inst("postgres", "pg"),
		inst("postgres", "pg-default"),
		inst("mysql", "my"),
		inst("aurora-postgresql", "aurora-pg"), // no instance parameter graded: never read
	}
	clusters := []asset.Asset{
		{Type: "rds_cluster", Metadata: map[string]string{"engine": "aurora-mysql", "db_cluster_parameter_group": "aurora-audit"}},
		{Type: "docdb_cluster", Metadata: map[string]string{"engine": "docdb", "db_cluster_parameter_group": "docdb-tls"}},
	}
	stampRDSParameterFacts(context.Background(), f, "eu-west-1", instances, clusters)

	require.Equal(t, "0", instances[0].Metadata["force_ssl"], "an unset parameter takes the documented engine default")
	require.Equal(t, "0", instances[1].Metadata["force_ssl"])
	require.Equal(t, 2, f.paramCalls["sqlserver-default"], "a shared group is read once (two pages)")
	require.Equal(t, "ON", instances[2].Metadata["require_secure_transport"])
	require.NotContains(t, instances[3].Metadata, "require_secure_transport", "a version without the parameter is not graded")
	require.NotContains(t, instances[4].Metadata, "require_secure_transport", "an unread group is unknown, not the default")
	require.Equal(t, "0", instances[5].Metadata["force_ssl"], "RDS.38 reads rds.force_ssl on PostgreSQL instances")
	require.NotContains(t, instances[6].Metadata, "force_ssl", "a version-dependent default is unknown, not 0")
	require.Equal(t, "1", instances[7].Metadata["require_secure_transport"], "RDS.39 reads require_secure_transport on MySQL instances")
	require.Zero(t, f.paramCalls["aurora-pg"])
	require.Equal(t, "1", clusters[0].Metadata["server_audit_logging"])
	require.Equal(t, "", clusters[0].Metadata["server_audit_events"])
	require.Equal(t, "tls1.2+", clusters[1].Metadata["tls"])
}

func TestRDSRegionSettings_EventCoverage(t *testing.T) {
	f := newFakeRDSPosture()
	sub := func(st string, enabled bool, cats []string, ids []string) rdstypes.EventSubscription {
		var src *string
		if st != "" {
			src = awssdk.String(st)
		}
		return rdstypes.EventSubscription{SourceType: src, Enabled: awssdk.Bool(enabled), EventCategoriesList: cats, SourceIdsList: ids}
	}
	f.subs = []rdstypes.EventSubscription{
		sub("db-cluster", true, []string{"failure", "maintenance", "notification"}, nil),
		sub("db-instance", true, []string{"failure"}, nil), // misses maintenance + configuration change
		sub("", false, nil, nil),                                                  // every source, but disabled
		sub("db-parameter-group", true, nil, nil),                                 // empty categories = all
		sub("db-security-group", true, nil, []string{"legacy-sg"}),                // scoped to one group
		sub("db-instance", true, []string{"configuration change"}, []string{"a"}), // scoped
	}
	inst := []asset.Asset{{Type: "rds_instance"}}
	a, err := rdsRegionSettings(context.Background(), f, "eu-west-1", "111", time.Now(), inst, nil)
	require.NoError(t, err)
	require.Equal(t, "aws:111:eu-west-1:rds-settings", a.ID)
	require.Equal(t, "aws_rds_settings", a.Type)
	m := a.Metadata
	require.Equal(t, "true", m["cluster_events_covered"])
	require.Equal(t, "false", m["instance_events_covered"])
	require.Equal(t, "true", m["parameter_group_events_covered"])
	require.Equal(t, "false", m["security_group_events_covered"])
	require.Equal(t, "true", m["has_event_subscriptions"])
	require.Equal(t, "true", m["has_instances"])
	require.Equal(t, "false", m["has_clusters"])

	// An enabled all-source subscription with every category covers everything.
	f.subs = []rdstypes.EventSubscription{sub("", true, nil, nil)}
	a, err = rdsRegionSettings(context.Background(), f, "eu-west-1", "111", time.Now(), inst, nil)
	require.NoError(t, err)
	for _, k := range []string{"cluster_events_covered", "instance_events_covered", "parameter_group_events_covered", "security_group_events_covered"} {
		require.Equal(t, "true", a.Metadata[k], k)
	}

	f.subs = nil
	a, err = rdsRegionSettings(context.Background(), f, "eu-west-1", "111", time.Now(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, "false", a.Metadata["has_event_subscriptions"])
	require.Equal(t, "0", a.Metadata["event_subscriptions"])
}

func TestCollectRDSGlobalClusters_EmittedByTheWriterRegionOnly(t *testing.T) {
	f := newFakeRDSPosture()
	member := func(arn string, writer bool) rdstypes.GlobalClusterMember {
		return rdstypes.GlobalClusterMember{DBClusterArn: awssdk.String(arn), IsWriter: awssdk.Bool(writer)}
	}
	f.globals = []rdstypes.GlobalCluster{
		{GlobalClusterIdentifier: awssdk.String("here"), GlobalClusterArn: awssdk.String("arn:aws:rds::111:global-cluster:here"),
			Engine: awssdk.String("aurora-mysql"), EngineVersion: awssdk.String("5.7.mysql_aurora.2.11.2"),
			GlobalClusterMembers: []rdstypes.GlobalClusterMember{member("arn:aws:rds:us-east-1:111:cluster:a", false), member("arn:aws:rds:eu-west-1:111:cluster:b", true)}},
		{GlobalClusterIdentifier: awssdk.String("there"), GlobalClusterArn: awssdk.String("arn:aws:rds::111:global-cluster:there"),
			GlobalClusterMembers: []rdstypes.GlobalClusterMember{member("arn:aws:rds:us-east-1:111:cluster:c", true), member("arn:aws:rds:eu-west-1:111:cluster:d", false)}},
		{GlobalClusterIdentifier: awssdk.String("empty"), GlobalClusterArn: awssdk.String("arn:aws:rds::111:global-cluster:empty")},
	}
	got, err := collectRDSGlobalClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "here", got[0].Name)
	require.Equal(t, "rds_global_cluster", got[0].Type)
	require.Equal(t, "5.7.mysql_aurora.2.11.2", got[0].Metadata["engine_version"])
}

func TestCollectRDSPosture_BestEffortListingsFlagPartial(t *testing.T) {
	f := newFakeRDSPosture()
	f.clusterPages = [][]rdstypes.DBCluster{{{DBClusterArn: awssdk.String("arn:c"), Engine: awssdk.String("aurora-postgresql")}}}
	f.proxies = []rdstypes.DBProxy{{DBProxyArn: awssdk.String("arn:p"), DBProxyName: awssdk.String("p"), RequireTLS: awssdk.Bool(false)}}

	got, partial, err := collectRDSPosture(context.Background(), f, "eu-west-1", "111", time.Now(), nil)
	require.NoError(t, err)
	require.False(t, partial)
	require.Len(t, byType(got, "rds_cluster"), 1)
	require.Equal(t, "false", byType(got, "rds_proxy")[0].Metadata["require_tls"])
	require.Len(t, byType(got, "aws_rds_settings"), 1)

	f.proxyErr = apiErr{code: "AccessDenied"}
	f.subsErr = apiErr{code: "AccessDenied"}
	got, partial, err = collectRDSPosture(context.Background(), f, "eu-west-1", "111", time.Now(), nil)
	require.NoError(t, err, "a best-effort listing does not lose the clusters")
	require.True(t, partial, "missing proxies and settings must not read as deleted")
	require.Len(t, byType(got, "rds_cluster"), 1)
	require.Empty(t, byType(got, "rds_proxy"))
	require.Empty(t, byType(got, "aws_rds_settings"), "no coverage verdict without the subscription listing")

	f.clusterErrAt = 0
	_, _, err = collectRDSPosture(context.Background(), f, "eu-west-1", "111", time.Now(), nil)
	require.Error(t, err, "instance checks hand cluster members to their cluster: an unread cluster set is an error")
}

func TestCollectRDSInstances_ParameterGroupAndVersion(t *testing.T) {
	f := &fakeRDS{dbs: []rdstypes.DBInstance{{
		DBInstanceIdentifier: awssdk.String("maria"), DBInstanceArn: awssdk.String("arn:db:maria"),
		Engine: awssdk.String("mariadb"), EngineVersion: awssdk.String("10.11.6"),
		DBParameterGroups: []rdstypes.DBParameterGroupStatus{{DBParameterGroupName: awssdk.String("maria-tls"), ParameterApplyStatus: awssdk.String("pending-reboot")}},
	}, {
		DBInstanceIdentifier: awssdk.String("bare"), DBInstanceArn: awssdk.String("arn:db:bare"), Engine: awssdk.String("postgres"),
	}}}
	got, err := collectRDSInstances(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "10.11.6", got[0].Metadata["engine_version"])
	require.Equal(t, "maria-tls", got[0].Metadata["db_parameter_group"])
	require.Equal(t, "false", got[0].Metadata["parameter_group_in_sync"])
	require.NotContains(t, got[1].Metadata, "db_parameter_group")
	require.NotContains(t, got[1].Metadata, "parameter_group_in_sync")
}
