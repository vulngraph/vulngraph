package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// rdsClusterAssetType maps a DB cluster's engine to its asset type.
// DescribeDBClusters also returns DocumentDB and Neptune clusters (they share
// the RDS control plane); each gets its own type because FSBP grades them
// under their own controls (DocumentDB.n, Neptune.n), and an inventory that
// called a graph database an "RDS cluster" would mislead whoever reads it.
func rdsClusterAssetType(engine string) string {
	switch engine {
	case "docdb":
		return "docdb_cluster"
	case "neptune":
		return "neptune_cluster"
	}
	return "rds_cluster"
}

// collectRDSClusters lists every DB cluster in the region: Aurora (MySQL and
// PostgreSQL), Multi-AZ DB clusters (mysql, postgres), DocumentDB and Neptune.
// Every page is read; a failing page fails the listing.
func collectRDSClusters(ctx context.Context, client rdsPostureAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out    []asset.Asset
		marker *string
	)
	for {
		page, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectRDSClusters: %w", err)
		}
		for _, c := range page.DBClusters {
			out = append(out, rdsClusterAsset(c, region, accountID, now))
		}
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

// rdsClusterAsset builds one cluster's asset. A boolean or count the response
// omits stays absent (unknown) rather than defaulting to false or 0, except
// where the API's omission IS the documented value: an empty log-export list
// is omitted from the response, and so is an Aurora MySQL backtrack window
// that was never configured (backtracking off).
func rdsClusterAsset(c rdstypes.DBCluster, region, accountID string, now time.Time) asset.Asset {
	engine := awssdk.ToString(c.Engine)
	meta := map[string]string{
		"engine":      engine,
		"log_exports": strings.Join(c.EnabledCloudwatchLogsExports, ","),
		"status":      awssdk.ToString(c.Status),
	}
	setStr := func(k string, v *string) {
		if s := awssdk.ToString(v); s != "" {
			meta[k] = s
		}
	}
	setBool := func(k string, v *bool) {
		if v != nil {
			meta[k] = strconv.FormatBool(*v)
		}
	}
	setStr("engine_version", c.EngineVersion)
	// provisioned | serverless (Aurora Serverless v1) | parallelquery | global |
	// multimaster. Serverless v1 cannot export audit logs or backtrack, which
	// FSBP RDS.34 excludes it for.
	setStr("engine_mode", c.EngineMode)
	setStr("master_username", c.MasterUsername)
	setStr("db_cluster_parameter_group", c.DBClusterParameterGroup)
	setStr("global_cluster_id", c.GlobalClusterIdentifier)
	setBool("storage_encrypted", c.StorageEncrypted)
	setBool("deletion_protection", c.DeletionProtection)
	setBool("iam_auth_enabled", c.IAMDatabaseAuthenticationEnabled)
	// MultiAZ: the cluster has DB instances in more than one Availability
	// Zone (FSBP RDS.15, CIS 3.2.4). AvailabilityZones is not that: Aurora
	// storage always spans three zones, whatever the instances do.
	setBool("multi_az", c.MultiAZ)
	setBool("copy_tags_to_snapshot", c.CopyTagsToSnapshot)
	// Returned for Multi-AZ DB clusters and, since 2024, Aurora; omitted
	// (unknown) where the cluster does not carry the setting itself.
	setBool("auto_minor_version_upgrade", c.AutoMinorVersionUpgrade)
	setBool("publicly_accessible", c.PubliclyAccessible)
	if c.BackupRetentionPeriod != nil {
		meta["backup_retention"] = strconv.Itoa(int(*c.BackupRetentionPeriod))
	}
	if c.Port != nil {
		meta["port"] = strconv.Itoa(int(*c.Port))
	}
	if engine == "aurora-mysql" {
		meta["backtrack_window"] = strconv.FormatInt(awssdk.ToInt64(c.BacktrackWindow), 10)
	}
	meta["member_count"] = strconv.Itoa(len(c.DBClusterMembers))
	// The cluster parameter group is applied when every member reports
	// in-sync; a cluster with no instances has nothing pending.
	inSync := true
	for _, m := range c.DBClusterMembers {
		if awssdk.ToString(m.DBClusterParameterGroupStatus) != "in-sync" {
			inSync = false
		}
	}
	meta["parameter_group_in_sync"] = strconv.FormatBool(inSync)
	return asset.Asset{
		ID:           awssdk.ToString(c.DBClusterArn),
		Name:         awssdk.ToString(c.DBClusterIdentifier),
		Type:         rdsClusterAssetType(engine),
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Endpoint:     awssdk.ToString(c.Endpoint),
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
