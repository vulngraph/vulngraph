# AWS CloudFront and WAF reads

These reads feed the AWS FSBP CloudFront and WAF checks. They live in
`internal/collect/aws/cloudfront.go`, `cloudfront_origins.go`, `waf.go`,
`waf_classic.go` and `waf_classic_clients.go`. CloudFront, the CLOUDFRONT
WAF v2 scope and global WAF Classic are read once per sweep from the
partition's home region (us-east-1 in the commercial partition); WAF v2
REGIONAL and WAF Classic regional are read in every collected region.

| Permission | Read | Feeds |
|---|---|---|
| `cloudfront:ListDistributions` | origins, cache behaviours, viewer certificate, web ACL, origin groups (`cloudfront_distribution`) | every `aws-cloudfront-*` check |
| `cloudfront:GetDistributionConfig` | default root object, legacy standard logging | `aws-cloudfront-no-default-root-object`, `aws-cloudfront-logging-disabled` |
| `logs:DescribeDeliverySources`, `logs:DescribeDeliveries` | standard logging (v2) deliveries naming a distribution | `aws-cloudfront-logging-disabled` |
| `s3:ListBucket` (via `s3:HeadBucket`) | whether each S3 origin bucket still exists (404 = gone; 403/301 = exists, possibly in another account) | `aws-cloudfront-dangling-s3-origin` |
| `s3:ListAllMyBuckets` (via `s3:ListBuckets`) | the account's own buckets, read only when an origin bucket answered 403/301, to tell its own bucket from another account's | `aws-cloudfront-dangling-s3-origin` |
| `wafv2:ListWebACLs`, `wafv2:GetWebACL` | v2 web ACL rules and visibility config (`waf_web_acl`) | `aws-waf-web-acl-empty`, `aws-wafv2-web-acl-rule-metrics-disabled` |
| `wafv2:ListRuleGroups`, `wafv2:GetRuleGroup` | v2 rule group rules (`waf_rule_group`) | `aws-wafv2-rule-group-rule-metrics-disabled` |
| `waf:ListWebACLs`, `waf:GetWebACL`, `waf-regional:ListWebACLs`, `waf-regional:GetWebACL` | Classic web ACL rules | `aws-waf-web-acl-empty` |
| `waf:ListRules`, `waf:GetRule`, `waf-regional:ListRules`, `waf-regional:GetRule` | Classic rule conditions (`waf_rule`) | `aws-waf-classic-rule-no-conditions` |
| `waf:ListRuleGroups`, `waf:ListActivatedRulesInRuleGroup` (and `waf-regional:`) | Classic rule group contents | `aws-waf-classic-rule-group-empty` |
| `waf:ListLoggingConfigurations` | global Classic web ACL logging | `aws-waf-classic-logging-disabled` |

`SecurityAudit` and `ViewOnlyAccess` grant all of these except
`waf:GetRule`, `waf-regional:GetRule` and `wafv2:GetRuleGroup`. The
`GraphReadOnly` role (`deploy/aws/graph-readonly-role.yaml`, also used by
the Terraform StackSet modules) adds them in its `GraphWAFRuleContents`
statement. A hand-written least-privilege policy needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphCloudFrontWAFRead",
      "Effect": "Allow",
      "Action": [
        "cloudfront:ListDistributions",
        "cloudfront:GetDistributionConfig",
        "logs:DescribeDeliverySources",
        "logs:DescribeDeliveries",
        "s3:ListBucket",
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListRuleGroups",
        "wafv2:GetRuleGroup",
        "waf:ListWebACLs",
        "waf:GetWebACL",
        "waf:ListRules",
        "waf:GetRule",
        "waf:ListRuleGroups",
        "waf:ListActivatedRulesInRuleGroup",
        "waf:ListLoggingConfigurations",
        "waf-regional:ListWebACLs",
        "waf-regional:GetWebACL",
        "waf-regional:ListRules",
        "waf-regional:GetRule",
        "waf-regional:ListRuleGroups",
        "waf-regional:ListActivatedRulesInRuleGroup"
      ],
      "Resource": "*"
    }
  ]
}
```

`s3:HeadBucket` against a bucket in another account needs no permission
there: S3 answers 403 for a bucket that exists and 404 for one that does not,
and only 404 is read as missing.

## Without the permissions

Nothing is guessed. A failed listing (or any failed page of one) skips that
service for the region and flags the sweep partial; a failed per-resource
read (`GetDistributionConfig`, `GetWebACL`, `GetRule`, `GetRuleGroup`, a
throttled `HeadBucket`) leaves that resource's key absent, so its check stays
silent and an open finding is held open rather than closed. CloudFront and the
global WAFs are read only in the partitions CloudFront exists in (commercial
and China); elsewhere they are not called. A regional endpoint that does not
resolve — WAF Classic in regions launched after it — is judged by the region
ledger (regional_offered.go): "not offered" only for an NXDOMAIN on a region-limited
service's own standard host with no custom endpoint and the region's EC2
listing up; any other DNS failure is a failed read.

WAF Classic itself was retired on 2025-09-30 and AWS does not document the
error a retired Classic API returns. Any 4xx rejection of a Classic listing
that is neither a denial (`AccessDenied*`, a bad credential) nor throttling
is therefore read as "WAF Classic not offered to this account": an empty
listing, not a partial sweep in every region on every run. Denials,
throttling and 5xx errors still skip the service and flag the sweep partial.
