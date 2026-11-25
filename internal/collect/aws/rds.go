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

type rdsAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeDBSnapshotAttributes(context.Context, *rds.DescribeDBSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error)
	DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error)
	DescribeDBClusterSnapshotAttributes(context.Context, *rds.DescribeDBClusterSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error)
}

// collectRDS lists the region's RDS instances, manual DB and cluster
// snapshots, DB clusters (Aurora, Multi-AZ DB clusters, DocumentDB, Neptune),
// proxies, global clusters, the parameter-group facts the TLS and audit
// checks read, and the region's event-subscription coverage (rds_posture.go).
// Regional service — called once per region from the collect loop.
//
// partial reports a best-effort listing (proxies, global clusters, event
// subscriptions) that failed: its resources are missing from this sweep, so
// their absence must not read as deletion.
func collectRDS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, bool, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("collectRDS: %w", err)
	}
	client := rds.NewFromConfig(awsCfg)
	assets, err := collectRDSInstances(ctx, client, region, accountID, now)
	if err != nil {
		return nil, false, err
	}
	snaps, err := collectRDSSnapshots(ctx, client, region, accountID, now)
	if err != nil {
		return nil, false, err
	}
	more, partial, err := collectRDSPosture(ctx, client, region, accountID, now, assets)
	if err != nil {
		return nil, false, err
	}
	return append(append(assets, snaps...), more...), partial, nil
}

func collectRDSInstances(ctx context.Context, client rdsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		marker *string
	)
	for {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectRDSInstances: %w", err)
		}
		for _, db := range out.DBInstances {
			endpoint := ""
			port := ""
			if db.Endpoint != nil {
				endpoint = awssdk.ToString(db.Endpoint.Address)
				port = strconv.Itoa(int(awssdk.ToInt32(db.Endpoint.Port)))
			}
			meta := map[string]string{
				"engine": awssdk.ToString(db.Engine),
				// Network reachability only — DB credentials are always required
				// (and the SG may still block), so this is the possible tier,
				// never confirmed public.
				"publicly_accessible": fmt.Sprintf("%t", awssdk.ToBool(db.PubliclyAccessible)),
				"storage_encrypted":   fmt.Sprintf("%t", awssdk.ToBool(db.StorageEncrypted)),
				// VPC security groups — same CSV format as ec2_instance so the
				// SharedSecurityGroup correlate rule can find EC2↔RDS pairs.
				"security_groups":     rdsVPCSGs(db.VpcSecurityGroups),
				"backup_retention":    strconv.Itoa(int(awssdk.ToInt32(db.BackupRetentionPeriod))),
				"deletion_protection": strconv.FormatBool(awssdk.ToBool(db.DeletionProtection)),
				"multi_az":            strconv.FormatBool(awssdk.ToBool(db.MultiAZ)),
				// Cluster membership and replica source are written empty when
				// absent from the described instance: "not a cluster member" is
				// what lets the instance-level Multi-AZ / deletion-protection /
				// backup checks grade it, and an unread membership must not.
				"db_cluster_id":       awssdk.ToString(db.DBClusterIdentifier),
				"read_replica_source": awssdk.ToString(db.ReadReplicaSourceDBInstanceIdentifier),
				// The remaining posture fields come back on every
				// DescribeDBInstances entry; the SDK zero value is the API's own
				// default (0 = enhanced monitoring off, no log exports).
				"monitoring_interval":        strconv.Itoa(int(awssdk.ToInt32(db.MonitoringInterval))),
				"log_exports":                strings.Join(db.EnabledCloudwatchLogsExports, ","),
				"iam_auth_enabled":           strconv.FormatBool(awssdk.ToBool(db.IAMDatabaseAuthenticationEnabled)),
				"auto_minor_version_upgrade": strconv.FormatBool(awssdk.ToBool(db.AutoMinorVersionUpgrade)),
				"copy_tags_to_snapshot":      strconv.FormatBool(awssdk.ToBool(db.CopyTagsToSnapshot)),
			}
			// The master user NAME (never a credential): FSBP RDS.25 fails the
			// engine defaults an attacker tries first.
			if u := awssdk.ToString(db.MasterUsername); u != "" {
				meta["master_username"] = u
			}
			if port != "" {
				meta["port"] = port
			}
			if v := awssdk.ToString(db.EngineVersion); v != "" {
				meta["engine_version"] = v
			}
			// The instance's DB parameter group and whether its settings are
			// applied (in-sync) — read by the TLS checks (rds_parameters.go).
			if len(db.DBParameterGroups) > 0 {
				meta["db_parameter_group"] = awssdk.ToString(db.DBParameterGroups[0].DBParameterGroupName)
				meta["parameter_group_in_sync"] = strconv.FormatBool(awssdk.ToString(db.DBParameterGroups[0].ParameterApplyStatus) == "in-sync")
			}
			// The subnet group's members, for annotateRouting's in_public_subnet.
			// Omitted when the response carries no group, so an unread placement
			// stays unknown instead of reading as "in no public subnet".
			if ids := rdsSubnetIDs(db.DBSubnetGroup); ids != "" {
				meta["subnet_ids"] = ids
			}
			// Publicly-accessible RDS is network-reachable but auth-gated — the
			// possible tier, so exposure findings surface at a lower severity.
			if awssdk.ToBool(db.PubliclyAccessible) {
				meta["public_access"] = asset.PublicAccessPossible
			}
			assets = append(assets, asset.Asset{
				ID:           awssdk.ToString(db.DBInstanceArn),
				Name:         awssdk.ToString(db.DBInstanceIdentifier),
				Type:         "rds_instance",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Endpoint:     endpoint,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.Marker == nil {
			return assets, nil
		}
		marker = out.Marker
	}
}

// rdsVPCSGs returns a CSV of the VPC security group IDs attached to an RDS
// instance — the same format ec2_instance uses for Metadata["security_groups"],
// so the SharedSecurityGroup correlate rule can find EC2↔RDS pairs in one pass.
func rdsVPCSGs(groups []rdstypes.VpcSecurityGroupMembership) string {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		if id := awssdk.ToString(g.VpcSecurityGroupId); id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

// rdsSubnetIDs returns a CSV of the subnets in an RDS instance's DB subnet
// group, or "" when the group is absent from the response.
func rdsSubnetIDs(g *rdstypes.DBSubnetGroup) string {
	if g == nil {
		return ""
	}
	ids := make([]string, 0, len(g.Subnets))
	for _, sn := range g.Subnets {
		if id := awssdk.ToString(sn.SubnetIdentifier); id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}
