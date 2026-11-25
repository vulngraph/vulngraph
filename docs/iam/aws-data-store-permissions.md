# AWS data-store posture reads

These reads feed the CIS AWS Foundations (storage) and AWS FSBP data-service
checks. Every call is a read; graph never changes these resources (ADR 087).

| Service | Calls | Granted by |
|---|---|---|
| RDS, Aurora, DocumentDB, Neptune | `rds:DescribeDBInstances`, `DescribeDBClusters`, `DescribeDBParameters`, `DescribeDBClusterParameters`, `DescribeDBProxies`, `DescribeGlobalClusters`, `DescribeEventSubscriptions`, `DescribeDBSnapshots`, `DescribeDBClusterSnapshots` (+ snapshot attributes), `DescribeDBEngineVersions` (once per engine in use, to tell a deprecated engine version from a supported one) | SecurityAudit, ViewOnlyAccess (`rds:Describe*`) |
| Redshift | `redshift:DescribeClusters`, `DescribeLoggingStatus`, `DescribeClusterParameters` | SecurityAudit (`redshift:Describe*`) |
| Redshift Serverless | `redshift-serverless:ListWorkgroups`, `GetNamespace` (`ListNamespaces` is in neither managed policy and is not used) | SecurityAudit |
| OpenSearch / Elasticsearch | `es:ListDomainNames`, `es:DescribeDomains` | SecurityAudit (`es:Describe*`) |
| DMS | `dms:DescribeReplicationInstances`, `DescribeReplicationTasks`, `DescribeEndpoints` | SecurityAudit (`dms:Describe*`) |
| ElastiCache | `elasticache:DescribeReplicationGroups`, `DescribeCacheClusters` | SecurityAudit, ViewOnlyAccess |
| MSK / MSK Connect | `kafka:ListClustersV2`, `kafkaconnect:ListConnectors` | SecurityAudit (`kafka:List*`, `kafkaconnect:List*`) |
| EFS | `elasticfilesystem:DescribeFileSystems`, `DescribeAccessPoints`, `DescribeBackupPolicy`, `DescribeFileSystemPolicy` | SecurityAudit |
| FSx | `fsx:DescribeFileSystems` | SecurityAudit, ViewOnlyAccess |
| AWS Backup | `backup:ListBackupVaults`, `GetBackupVaultAccessPolicy`, `ListBackupPlans`, `ListBackupSelections`, `GetBackupSelection`, `DescribeRegionSettings`; `backup:ListRecoveryPointsByBackupVault` | SecurityAudit; the last one ViewOnlyAccess only |
| DynamoDB / DAX | `dynamodb:ListTables`, `DescribeTable`, `DescribeContinuousBackups`, `GetResourcePolicy`; `application-autoscaling:DescribeScalableTargets`; `dax:DescribeClusters` | SecurityAudit, ViewOnlyAccess |
| S3 | `s3:GetBucketPublicAccessBlock`, `GetBucketPolicy`, `GetBucketPolicyStatus`, `GetBucketAcl`, `GetBucketOwnershipControls`, `GetLifecycleConfiguration`, `s3:ListAccessPoints`, `GetAccessPoint`, `GetAccessPointPolicyStatus`, `ListMultiRegionAccessPoints`, `s3express:ListAllMyDirectoryBuckets` | SecurityAudit |
| S3 directory buckets | `s3express:GetLifecycleConfiguration` | **neither** — supplemental statement |
| Kinesis | `kinesis:ListStreams`, `DescribeStreamSummary` | SecurityAudit |
| Data Firehose | `firehose:ListDeliveryStreams`, `DescribeDeliveryStream` | SecurityAudit, ViewOnlyAccess |
| Glue | `glue:GetJobs`; `glue:GetMLTransforms` | SecurityAudit; GetMLTransforms **neither** — supplemental statement |
| Athena | `athena:ListWorkGroups`, `GetWorkGroup`, `ListQueryExecutions` | SecurityAudit |
| SQS | `sqs:GetQueueAttributes` (Policy, KmsMasterKeyId, SqsManagedSseEnabled) | SecurityAudit, ViewOnlyAccess |

The `GraphReadOnly` template (`deploy/aws/graph-readonly-role.yaml`, shared by
the Terraform modules and the org StackSet) carries the two extras in its
`GraphDataStorePostureRead` statement. A hand-written role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphDataStorePostureRead",
      "Effect": "Allow",
      "Action": ["glue:GetMLTransforms", "s3express:GetLifecycleConfiguration"],
      "Resource": "*"
    }
  ]
}
```

## Without the permissions

Nothing is guessed. A denied per-resource read leaves its metadata key absent
and logs a warning naming the permission; the check that reads it stays silent
and an open finding is held open, not closed. A denied primary
`List*`/`Describe*` skips that collector for the region and flags the sweep
partial, so the missing resources are not read as deleted. A DNS failure is a
failed read too, with one exception the region ledger alone decides
(regional_offered.go): an NXDOMAIN for a region-limited service's own standard endpoint,
with no FIPS, dual-stack or custom endpoint configured and the region's EC2
listing up in the same sweep, reads as the service not being offered there.

`glue:GetMLTransforms` is the exception: a role deployed before the
supplemental statement existed would otherwise flag every sweep partial. Until
the call has succeeded once for the connector (the proven capability
`glue_get_ml_transforms`), a denial skips the transforms quietly — the
connector has never stored one, so nothing can read as deleted. After that, a
denial is a regression and flags the sweep partial.
