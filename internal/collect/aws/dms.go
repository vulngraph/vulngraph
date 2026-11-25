package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	dms "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// AWS Database Migration Service: replication instances, replication tasks
// and endpoints (FSBP DMS.1, 6-13). All three listings sit behind
// dms:Describe* (SecurityAudit), so they are read together and any failure
// fails the region's DMS collection rather than emitting a lopsided half.

type dmsAPI interface {
	DescribeReplicationInstances(context.Context, *dms.DescribeReplicationInstancesInput, ...func(*dms.Options)) (*dms.DescribeReplicationInstancesOutput, error)
	DescribeReplicationTasks(context.Context, *dms.DescribeReplicationTasksInput, ...func(*dms.Options)) (*dms.DescribeReplicationTasksOutput, error)
	DescribeEndpoints(context.Context, *dms.DescribeEndpointsInput, ...func(*dms.Options)) (*dms.DescribeEndpointsOutput, error)
}

func collectDMS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectDMS: %w", err)
	}
	return collectDMSResources(ctx, dms.NewFromConfig(awsCfg), region, accountID, now)
}

func collectDMSResources(ctx context.Context, client dmsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	instances, err := listDMSReplicationInstances(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("collectDMSResources: %w", err)
	}
	tasks, err := listDMSReplicationTasks(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("collectDMSResources: %w", err)
	}
	endpoints, err := listDMSEndpoints(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("collectDMSResources: %w", err)
	}
	return append(append(instances, tasks...), endpoints...), nil
}

func dmsAsset(id, name, typ, region, accountID string, meta map[string]string, now time.Time) asset.Asset {
	return asset.Asset{
		ID: id, Name: name, Type: typ, Provider: asset.ProviderAWS,
		Region: region, AccountID: accountID, Metadata: meta,
		DiscoveredAt: now, LastSeen: now,
	}
}

func listDMSReplicationInstances(ctx context.Context, client dmsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out    []asset.Asset
		marker *string
	)
	for {
		page, err := client.DescribeReplicationInstances(ctx, &dms.DescribeReplicationInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("DescribeReplicationInstances: %w", err)
		}
		for _, ri := range page.ReplicationInstances {
			// The three posture fields are plain bools on every described
			// instance: the API has no "unset" state for them.
			meta := map[string]string{
				"publicly_accessible":        strconv.FormatBool(ri.PubliclyAccessible),
				"auto_minor_version_upgrade": strconv.FormatBool(ri.AutoMinorVersionUpgrade),
				"multi_az":                   strconv.FormatBool(ri.MultiAZ),
				"engine_version":             awssdk.ToString(ri.EngineVersion),
			}
			// Network reachability only: the instance connects out to its
			// endpoints and holds no listener a stranger can authenticate to,
			// so this is the possible tier, never confirmed.
			if ri.PubliclyAccessible {
				meta["public_access"] = asset.PublicAccessPossible
			}
			out = append(out, dmsAsset(awssdk.ToString(ri.ReplicationInstanceArn), awssdk.ToString(ri.ReplicationInstanceIdentifier),
				"dms_replication_instance", region, accountID, meta, now))
		}
		if page.Marker == nil || *page.Marker == "" {
			return out, nil
		}
		marker = page.Marker
	}
}

// dmsMinLogSeverities are the LogComponents severities at or above
// LOGGER_SEVERITY_DEFAULT, the floor FSBP DMS.7/DMS.8 require.
var dmsMinLogSeverities = []string{"LOGGER_SEVERITY_DEFAULT", "LOGGER_SEVERITY_DEBUG", "LOGGER_SEVERITY_DETAILED_DEBUG"}

type dmsTaskSettings struct {
	Logging *struct {
		EnableLogging bool `json:"EnableLogging"`
		LogComponents []struct {
			ID       string `json:"Id"`
			Severity string `json:"Severity"`
		} `json:"LogComponents"`
	} `json:"Logging"`
}

// dmsComponentsLogged reports whether logging is on and every named component
// logs at LOGGER_SEVERITY_DEFAULT or above. A component missing from the list
// is not logged at the required level (the Config rule behind DMS.7/8 reads
// the list the same way). ok is false when the settings are absent or
// unparseable: nothing was observed.
func dmsComponentsLogged(settings string, components ...string) (logged, ok bool) {
	var s dmsTaskSettings
	if settings == "" || json.Unmarshal([]byte(settings), &s) != nil {
		return false, false
	}
	if s.Logging == nil || !s.Logging.EnableLogging {
		return false, true
	}
	for _, want := range components {
		found := false
		for _, c := range s.Logging.LogComponents {
			if c.ID == want && slices.Contains(dmsMinLogSeverities, c.Severity) {
				found = true
				break
			}
		}
		if !found {
			return false, true
		}
	}
	return true, true
}

func listDMSReplicationTasks(ctx context.Context, client dmsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out    []asset.Asset
		marker *string
	)
	for {
		// WithoutSettings=false: the logging verdict lives in the settings JSON.
		page, err := client.DescribeReplicationTasks(ctx, &dms.DescribeReplicationTasksInput{Marker: marker, WithoutSettings: awssdk.Bool(false)})
		if err != nil {
			return nil, fmt.Errorf("DescribeReplicationTasks: %w", err)
		}
		for _, t := range page.ReplicationTasks {
			meta := map[string]string{
				"replication_instance_arn": awssdk.ToString(t.ReplicationInstanceArn),
				"source_endpoint_arn":      awssdk.ToString(t.SourceEndpointArn),
				"target_endpoint_arn":      awssdk.ToString(t.TargetEndpointArn),
				"migration_type":           string(t.MigrationType),
			}
			settings := awssdk.ToString(t.ReplicationTaskSettings)
			if v, ok := dmsComponentsLogged(settings, "SOURCE_CAPTURE", "SOURCE_UNLOAD"); ok {
				meta["source_logging_enabled"] = strconv.FormatBool(v)
			}
			if v, ok := dmsComponentsLogged(settings, "TARGET_APPLY", "TARGET_LOAD"); ok {
				meta["target_logging_enabled"] = strconv.FormatBool(v)
			}
			out = append(out, dmsAsset(awssdk.ToString(t.ReplicationTaskArn), awssdk.ToString(t.ReplicationTaskIdentifier),
				"dms_replication_task", region, accountID, meta, now))
		}
		if page.Marker == nil || *page.Marker == "" {
			return out, nil
		}
		marker = page.Marker
	}
}

func listDMSEndpoints(ctx context.Context, client dmsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out    []asset.Asset
		marker *string
	)
	for {
		page, err := client.DescribeEndpoints(ctx, &dms.DescribeEndpointsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("DescribeEndpoints: %w", err)
		}
		for _, e := range page.Endpoints {
			out = append(out, dmsAsset(awssdk.ToString(e.EndpointArn), awssdk.ToString(e.EndpointIdentifier),
				"dms_endpoint", region, accountID, dmsEndpointMeta(e), now))
		}
		if page.Marker == nil || *page.Marker == "" {
			return out, nil
		}
		marker = page.Marker
	}
}

// dmsEndpointMeta records the transport and authentication settings each
// engine exposes. Engine-specific keys are written only for that engine and
// only when its settings block was returned; the defaults filled in are the
// documented API defaults for an omitted field.
func dmsEndpointMeta(e dmstypes.Endpoint) map[string]string {
	engine := awssdk.ToString(e.EngineName)
	meta := map[string]string{
		"engine":        engine,
		"endpoint_type": string(e.EndpointType),
		"ssl_mode":      string(e.SslMode),
	}
	switch engine {
	case "neptune":
		if e.NeptuneSettings != nil {
			// IamAuthEnabled defaults to false when omitted.
			meta["neptune_iam_auth_enabled"] = strconv.FormatBool(awssdk.ToBool(e.NeptuneSettings.IamAuthEnabled))
		}
	case "mongodb":
		if e.MongoDbSettings != nil {
			auth := string(e.MongoDbSettings.AuthType)
			if auth == "" {
				auth = string(dmstypes.AuthTypeValuePassword) // documented default
			}
			meta["mongodb_auth_type"] = auth
		}
	case "redis":
		if e.RedisSettings != nil {
			proto := string(e.RedisSettings.SslSecurityProtocol)
			if proto == "" {
				proto = string(dmstypes.SslSecurityProtocolValueSslEncryption) // documented default
			}
			meta["redis_ssl_security_protocol"] = proto
		}
	}
	return meta
}
