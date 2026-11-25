package checks

// aws_elasticache.go — ElastiCache posture (FSBP ElastiCache.1-7) from
// elasticache:DescribeReplicationGroups / DescribeCacheClusters.
//
// FSBP grades backups, minor upgrades and the subnet group on the cache
// cluster (node). A Redis OSS / Valkey replication group's nodes share those
// settings, so a node with a replication_group_id steps aside and the group
// carries the one finding; standalone nodes (and Memcached clusters, which
// have no groups) are graded on the node. The group's settings checks
// (failover, encryption, AUTH) exist only on the group.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsElastiCacheChecks() []Check {
	return []Check{
		awsElastiCacheClusterNoBackup,
		awsElastiCacheGroupNoBackup,
		awsElastiCacheClusterAutoMinorUpgradeDisabled,
		awsElastiCacheGroupAutoMinorUpgradeDisabled,
		awsElastiCacheGroupNoAutoFailover,
		awsElastiCacheGroupNotEncryptedAtRest,
		awsElastiCacheGroupNotEncryptedInTransit,
		awsElastiCacheGroupRedisNoAuth,
		awsElastiCacheClusterDefaultSubnetGroup,
		awsElastiCacheGroupDefaultSubnetGroup,
	}
}

// standaloneCacheNode is a cache cluster that belongs to no replication
// group. An unread membership (key absent) is not standalone: the node stays
// silent rather than duplicate a group's finding.
func standaloneCacheNode(a asset.Asset) bool { return observedNone(a, "replication_group_id") }

// snapshotRetentionBelow reports a parsed SnapshotRetentionLimit under FSBP
// ElastiCache.1's default minimum of one day.
func snapshotRetentionBelow(a asset.Asset) bool {
	n, err := strconv.Atoi(a.Metadata["snapshot_retention_limit"])
	return err == nil && n < 1
}

// redisFamilyEngine is an engine with backups, AUTH and replication groups
// (Redis OSS and its fork Valkey); Memcached has none of them.
func redisFamilyEngine(engine string) bool { return engine == "redis" || engine == "valkey" }

const elastiCacheBackupRemediation = "Console: ElastiCache → the cache → Modify → Backup → enable automatic backups with a retention of at least 1 day. CLI: `aws elasticache modify-replication-group --replication-group-id ID --snapshot-retention-limit 7 --apply-immediately` (or `modify-cache-cluster --cache-cluster-id ID` for a standalone node)."

var awsElastiCacheClusterNoBackup = Check{
	ID:          "aws-elasticache-cluster-no-backup",
	Title:       "ElastiCache node has automatic backups disabled",
	Description: "This standalone Redis OSS / Valkey cache node keeps no automatic backups (SnapshotRetentionLimit 0), so a failed node or a flushed keyspace cannot be restored. FSBP ElastiCache.1. Nodes of a replication group are graded on the group.",
	Remediation: elastiCacheBackupRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_cluster",
	Violates: func(a asset.Asset) bool {
		return redisFamilyEngine(a.Metadata["engine"]) && standaloneCacheNode(a) && snapshotRetentionBelow(a)
	},
}

var awsElastiCacheGroupNoBackup = Check{
	ID:          "aws-elasticache-replication-group-no-backup",
	Title:       "ElastiCache replication group has automatic backups disabled",
	Description: "The replication group keeps no automatic backups (SnapshotRetentionLimit 0), so losing the group or its data cannot be undone from a snapshot. FSBP ElastiCache.1.",
	Remediation: elastiCacheBackupRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates:    snapshotRetentionBelow,
}

var awsElastiCacheClusterAutoMinorUpgradeDisabled = Check{
	ID:          "aws-elasticache-cluster-auto-minor-upgrade-disabled",
	Title:       "ElastiCache node does not apply minor engine upgrades automatically",
	Description: "Automatic minor version upgrade is off on this standalone Redis OSS / Valkey node, so engine security patches wait for a manual upgrade. FSBP ElastiCache.2 (Memcached is out of scope; nodes of a replication group are graded on the group).",
	Remediation: "Console: ElastiCache → the cache → Modify → enable \"Auto upgrade minor versions\". CLI: `aws elasticache modify-cache-cluster --cache-cluster-id ID --auto-minor-version-upgrade --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["auto_minor_version_upgrade"] == "false" && standaloneCacheNode(a) &&
			redisFamilyEngine(a.Metadata["engine"])
	},
}

var awsElastiCacheGroupAutoMinorUpgradeDisabled = Check{
	ID:          "aws-elasticache-replication-group-auto-minor-upgrade-disabled",
	Title:       "ElastiCache replication group does not apply minor engine upgrades automatically",
	Description: "Automatic minor version upgrade is off for the group, so none of its nodes receive engine security patches until someone upgrades by hand. FSBP ElastiCache.2, graded once per group rather than once per node.",
	Remediation: "Console: ElastiCache → the cache → Modify → enable \"Auto upgrade minor versions\". CLI: `aws elasticache modify-replication-group --replication-group-id ID --auto-minor-version-upgrade --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["auto_minor_version_upgrade"] == "false" },
}

var awsElastiCacheGroupNoAutoFailover = Check{
	ID:          "aws-elasticache-replication-group-no-auto-failover",
	Title:       "ElastiCache replication group has automatic failover disabled",
	Description: "If the primary node fails, no replica is promoted automatically, so writes stop until someone intervenes. Availability only. FSBP ElastiCache.3.",
	Remediation: "Add at least one replica, then Console: ElastiCache → the cache → Modify → enable Auto failover (and Multi-AZ). CLI: `aws elasticache modify-replication-group --replication-group-id ID --automatic-failover-enabled --multi-az-enabled --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["automatic_failover"] == "disabled" },
}

var awsElastiCacheGroupNotEncryptedAtRest = Check{
	ID:          "aws-elasticache-replication-group-not-encrypted-at-rest",
	Title:       "ElastiCache replication group is not encrypted at rest",
	Description: "At-rest encryption is off, so the group's on-disk data — swap, backups and snapshots exported to S3 — is stored unencrypted. FSBP ElastiCache.4.",
	Remediation: "At-rest encryption is set at creation. Console: ElastiCache → Backups → back up the group, then Restore with \"Encryption at rest\" enabled and move clients to the new endpoint. CLI: `aws elasticache create-snapshot --replication-group-id ID --snapshot-name SNAP`, then `aws elasticache create-replication-group --replication-group-id NEW --snapshot-name SNAP --at-rest-encryption-enabled ...`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["at_rest_encryption_enabled"] == "false" },
}

var awsElastiCacheGroupNotEncryptedInTransit = Check{
	ID:          "aws-elasticache-replication-group-not-encrypted-in-transit",
	Title:       "ElastiCache replication group is not encrypted in transit",
	Description: "In-transit encryption is off, so cached data and any AUTH token cross the VPC between clients and nodes, and between nodes, in clear text. FSBP ElastiCache.5.",
	Remediation: "Console: ElastiCache → the cache → Modify → Encryption in transit → enable (set the mode to preferred, move clients to TLS, then required). CLI: `aws elasticache modify-replication-group --replication-group-id ID --transit-encryption-enabled --transit-encryption-mode preferred --apply-immediately`, then `--transit-encryption-mode required` once clients use TLS.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["transit_encryption_enabled"] == "false" },
}

// redisMajorBelow6 reports a Redis OSS engine version whose major release is
// below 6.0 — the versions without RBAC, where an AUTH token is the only
// access control.
func redisMajorBelow6(version string) bool {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	return err == nil && n < 6
}

var awsElastiCacheGroupRedisNoAuth = Check{
	ID:          "aws-elasticache-replication-group-redis-no-auth",
	Title:       "ElastiCache Redis OSS group before 6.0 has no AUTH token",
	Description: "The group runs Redis OSS earlier than 6.0, which has no role-based access control, and no AUTH token is set: any client that can reach the nodes on the network can read, overwrite or flush every key. FSBP ElastiCache.6.",
	Remediation: "AUTH needs in-transit encryption. Console: ElastiCache → the cache → Modify → Access control → Redis OSS AUTH default user access with a token (or upgrade to 6.x+ and use RBAC user groups). CLI: `aws elasticache modify-replication-group --replication-group-id ID --auth-token TOKEN --auth-token-update-strategy ROTATE --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["engine"] == "redis" && a.Metadata["auth_token_enabled"] == "false" &&
			redisMajorBelow6(a.Metadata["engine_version"])
	},
	TableProbes: []string{"5.0.6"},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"engine_version": a.Metadata["engine_version"]}
	},
}

const elastiCacheSubnetRemediation = "Create a subnet group of private subnets (Console: ElastiCache → Subnet groups → Create; CLI: `aws elasticache create-cache-subnet-group --cache-subnet-group-name NAME --cache-subnet-group-description DESC --subnet-ids SUBNETS`). The subnet group cannot be changed in place: back up the cache and restore it into the new group (`aws elasticache create-replication-group ... --cache-subnet-group-name NAME --snapshot-name SNAP`)."

var awsElastiCacheClusterDefaultSubnetGroup = Check{
	ID:          "aws-elasticache-cluster-default-subnet-group",
	Title:       "ElastiCache node uses the default subnet group",
	Description: "This standalone cache node sits in the \"default\" subnet group, which takes its subnets from the default VPC rather than subnets chosen for the cache, so its placement and inherited routing were never deliberately restricted. FSBP ElastiCache.7. Nodes of a replication group are graded on the group.",
	Remediation: elastiCacheSubnetRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cache_subnet_group"] == "default" && standaloneCacheNode(a)
	},
}

var awsElastiCacheGroupDefaultSubnetGroup = Check{
	ID:          "aws-elasticache-replication-group-default-subnet-group",
	Title:       "ElastiCache replication group uses the default subnet group",
	Description: "The group's nodes sit in the \"default\" subnet group, which takes its subnets from the default VPC rather than subnets chosen for the cache. FSBP ElastiCache.7, graded once per group rather than once per node.",
	Remediation: elastiCacheSubnetRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticache_replication_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["cache_subnet_group"] == "default" },
}
