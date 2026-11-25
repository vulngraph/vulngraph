# AWS load balancer posture reads

These reads feed the AWS FSBP ELB checks (internal/checks/aws_elb.go). They live in
`internal/collect/aws/elb.go`, `elb_detail.go`, `elb_target_groups.go` and
`elb_classic.go`, run once per region.

| Permission | Read | Feeds |
|---|---|---|
| `elasticloadbalancing:DescribeLoadBalancers` | ALB/NLB/GWLB listing (v2), already read; Classic Load Balancer listing (v1) with listeners and certificates | `aws-elb-single-az`, `aws-elb-plaintext-listener`, `aws-elb-classic-non-acm-certificate` |
| `elasticloadbalancing:DescribeLoadBalancerAttributes` | v2: `deletion_protection.enabled`, `routing.http.drop_invalid_header_fields.enabled`, `routing.http.desync_mitigation_mode`; Classic: connection draining, cross-zone, `elb.http.desyncmitigationmode` | `aws-elb-no-deletion-protection`, `aws-elb-alb-invalid-headers-allowed`, `aws-elb-desync-mitigation-weak`, `aws-elb-classic-connection-draining-disabled`, `aws-elb-classic-cross-zone-disabled` |
| `elasticloadbalancing:DescribeLoadBalancerAttributes` (ALB and Classic) | v2 `access_logs.s3.enabled` (ALBs only) and Classic `AccessLog.Enabled`, both stored as `access_logs_s3_enabled` | `aws-alb-access-logs-disabled` (ELB.5, CIS 4.10) |
| `elasticloadbalancing:DescribeListeners` | v2 listener protocols and `SslPolicy` | `aws-elb-plaintext-listener`, `aws-elb-weak-tls-policy` |
| `elasticloadbalancing:DescribeRules` | rules of each ALB HTTP listener (HTTPS redirect vs forward) | `aws-elb-http-no-https-redirect` |
| `elasticloadbalancing:DescribeTargetGroups` | target group protocol and health-check protocol (`lb_target_group` assets) | `aws-elb-target-group-unencrypted`, `aws-elb-target-group-health-check-unencrypted` |
| `elasticloadbalancing:DescribeLoadBalancerPolicies` | Classic SSL negotiation policies (`Reference-Security-Policy`), only for balancers with an HTTPS/SSL listener | `aws-elb-weak-tls-policy` |

Access-log attributes are returned by the same attribute call but are not
stored here: access logging is graded by the logging checks.

The AWS-managed `SecurityAudit` policy (`elasticloadbalancing:Describe*`) that
the `GraphReadOnly` role attaches grants all of them, so a deployed
connector needs no change. A hand-written least-privilege policy needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphLoadBalancerRead",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeLoadBalancerPolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

## Without the permissions

Nothing is guessed. A denied listing (Classic balancers, target groups) is a
skipped regional collector and flags the sweep partial. A denied per-balancer
read (attributes, listeners, rules, policies) leaves only that read's keys
absent and logs a warning; the checks that read them stay silent and an
already-open finding is held open rather than closed as fixed.
