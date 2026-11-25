# AWS logging, monitoring and detection-service reads

These reads feed the CIS AWS Foundations (2.18, 3.1.3, 4.1, 4.3, 4.7–4.10,
5.1–5.16) and AWS FSBP (CloudTrail.1, Config.1, EC2.6, ELB.5, APIGateway.1/9,
NetworkFirewall.2, GuardDuty.1/5–13, Inspector.1–4, Macie.1/2) checks. They
live in `internal/collect/aws/cloudtrail_selectors.go`, `cloudwatch_alarms.go`,
`region_detection.go`, `guardduty_detector.go`, `vpc_flowlogs.go`,
and, for the web front ends, the network collectors `elb_detail.go`,
`elb_classic.go`, `apigateway_stages.go` and `networkfirewall.go`.

| Permission | Read | Granted by |
|---|---|---|
| `cloudtrail:GetEventSelectors` | each trail's management / S3 data event selectors (home region) | SecurityAudit |
| `logs:DescribeMetricFilters` | metric filters on the multi-region trail's log group | SecurityAudit, ViewOnlyAccess (`logs:Describe*`) |
| `cloudwatch:DescribeAlarms` | the region's metric alarms, matched to each filter's metric by name and namespace | SecurityAudit (`cloudwatch:Describe*`) |
| `sns:ListSubscriptionsByTopic` | confirmed subscribers of each alarm topic | SecurityAudit, ViewOnlyAccess |
| `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus`, `config:DescribeDeliveryChannels` | per region | SecurityAudit, ViewOnlyAccess |
| `securityhub:DescribeHub` | per region | SecurityAudit |
| `access-analyzer:ListAnalyzers` | per region | SecurityAudit |
| `guardduty:ListDetectors`, `guardduty:GetDetector` | detector status and protection plans, per region | SecurityAudit |
| `inspector2:BatchGetAccountStatus` | Inspector status and scan types, per region | SecurityAudit |
| `macie2:GetMacieSession`, `macie2:GetAutomatedDiscoveryConfiguration` | Macie status and automated discovery, per region | **neither** — the `GraphMacieStatus` statement in `deploy/aws/graph-readonly-role.yaml` |
| `ec2:DescribeFlowLogs`, `ec2:DescribeNetworkInterfaces` | VPC flow logs; whether a default VPC is used | SecurityAudit, ViewOnlyAccess |
| `elasticloadbalancing:DescribeLoadBalancerAttributes` | ALB and Classic Load Balancer access logging | SecurityAudit, ViewOnlyAccess |
| `apigateway:GET` | REST, HTTP and WebSocket API stages (`api_gateway_stage`) | SecurityAudit |
| `network-firewall:ListFirewalls`, `network-firewall:DescribeLoggingConfiguration` | firewalls and their logging | SecurityAudit |

The `GraphReadOnly` role (`deploy/aws/graph-readonly-role.yaml`, used by both
the CloudFormation and the Terraform paths) carries the Macie statement. A
hand-written least-privilege policy needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphLoggingDetectionRead",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:GetEventSelectors",
        "logs:DescribeMetricFilters",
        "cloudwatch:DescribeAlarms",
        "sns:ListSubscriptionsByTopic",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "securityhub:DescribeHub",
        "access-analyzer:ListAnalyzers",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "inspector2:BatchGetAccountStatus",
        "macie2:GetMacieSession",
        "macie2:GetAutomatedDiscoveryConfiguration",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeNetworkInterfaces",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "apigateway:GET",
        "network-firewall:ListFirewalls",
        "network-firewall:DescribeLoggingConfiguration"
      ],
      "Resource": "*"
    }
  ]
}
```

All are reads; none changes configuration.

## Without the permissions

Nothing is guessed. A denied read leaves its metadata keys absent and logs a
warning, the checks reading them stay silent, and an already-open finding is
held open rather than closed. A service counts as off only where AWS says so
explicitly: no configuration recorder, no GuardDuty detector, Security Hub's
not-subscribed error, Macie's "Macie is not enabled" answer. A missing
`macie2:GetMacieSession` is also an AccessDenied, but with a different message,
and stays unknown. A CloudWatch alarm chain with any unread link (filters,
alarms, subscriptions, or a trail whose log group sits in another account) is
unknown for the patterns it could have satisfied.
