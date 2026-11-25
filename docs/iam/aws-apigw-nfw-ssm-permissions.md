# API Gateway, Network Firewall, Systems Manager and Route 53 reads

These reads feed the AWS FSBP API Gateway, Network Firewall, SSM and Route 53
checks. They live in `internal/collect/aws/apigateway_stages.go`,
`apigatewayv2.go`, `apigateway_domains.go`, `networkfirewall.go`,
`ssm_documents.go`, `ssm_compliance.go`, `region_settings.go` and `route53.go`.

| Permission | Read | Feeds |
|---|---|---|
| `apigateway:GET` (`/restapis`, `/restapis/*/stages`) | REST APIs and their stages (`api_gateway_stage`) | `aws-apigateway-stage-execution-logging-disabled`, `-no-client-certificate`, `-xray-disabled`, `-no-waf`, `-cache-unencrypted` |
| `apigateway:GET` (`/apis`, `/apis/*/stages`, `/apis/*/routes`, `/apis/*/integrations`) | HTTP and WebSocket APIs (`api_gateway`), their stages, route authorization and VPC-link integrations | `aws-apigatewayv2-route-no-authorization`, `aws-apigatewayv2-private-integration-no-tls`, `aws-apigateway-stage-execution-logging-disabled` (WebSocket) |
| `apigateway:GET` (`/domainnames`, `/domainnames/*/apimappings`, via apigatewayv2) | custom domain mappings, read only when an API has its execute-api endpoint disabled (`custom_domain_mapped`) | `aws-apigateway-public-endpoint`, `aws-apigatewayv2-route-no-authorization` |
| `apigateway:GET` (`/domainnames`) | custom domains and their TLS security policy (`api_gateway_domain`) | `aws-apigateway-domain-weak-tls-policy` |
| `network-firewall:ListFirewalls`, `network-firewall:DescribeFirewall` | firewalls (`network_firewall`) | `aws-network-firewall-no-deletion-protection`, `-no-subnet-change-protection` |
| `network-firewall:DescribeLoggingConfiguration` | log types each firewall delivers: `logging_flow`, `logging_alert`, `logging_tls` (`true`/`false`, absent when unread) on `network_firewall` | `aws-network-firewall-logging-off` (NetworkFirewall.2) |
| `network-firewall:ListFirewallPolicies`, `network-firewall:DescribeFirewallPolicy` | firewall policies (`network_firewall_policy`) | `aws-network-firewall-policy-no-rule-groups`, `-stateless-default-pass`, `-fragment-default-pass` |
| `network-firewall:ListRuleGroups`, `network-firewall:DescribeRuleGroup` | stateless rule groups (`network_firewall_rule_group`) | `aws-network-firewall-rule-group-empty` |
| `ssm:ListDocuments`, `ssm:DescribeDocumentPermission` | account-owned documents and who they are shared with (`ssm_document`) | `aws-ssm-document-public` |
| `ssm:GetServiceSetting` | `/ssm/documents/console/public-sharing-permission` and `/ssm/automation/customer-script-log-destination` per region (`aws_region_settings`) | `aws-ssm-document-public-sharing-not-blocked`, `aws-ssm-automation-logging-disabled` |
| `ssm:ListResourceComplianceSummaries` | Patch and Association compliance per managed instance, stamped on `ec2_instance` | `aws-ec2-ssm-patch-noncompliant`, `aws-ec2-ssm-association-noncompliant` |
| `route53:ListQueryLoggingConfigs` | which hosted zones log DNS queries (`dns_zone`) | `aws-route53-zone-query-logging-disabled` |

Every one is a read, and the AWS-managed `SecurityAudit` policy the
`GraphReadOnly` role attaches grants all of them (`apigateway:GET`,
`network-firewall:Describe*`/`List*` as listed, `ssm:Describe*`,
`ssm:ListDocuments`, `ssm:GetServiceSetting`,
`ssm:ListResourceComplianceSummaries`, `route53:List*`), so a deployed
connector needs no change. A hand-written least-privilege policy instead needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphEdgeServicesRead",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "network-firewall:ListFirewalls",
        "network-firewall:DescribeFirewall",
        "network-firewall:DescribeLoggingConfiguration",
        "network-firewall:ListFirewallPolicies",
        "network-firewall:DescribeFirewallPolicy",
        "network-firewall:ListRuleGroups",
        "network-firewall:DescribeRuleGroup",
        "ssm:ListDocuments",
        "ssm:DescribeDocumentPermission",
        "ssm:GetServiceSetting",
        "ssm:ListResourceComplianceSummaries",
        "route53:ListQueryLoggingConfigs"
      ],
      "Resource": "*"
    }
  ]
}
```

## Without the permissions

Nothing is guessed. A listing that fails (any page) skips that collector for
the region and flags the sweep partial, so its stored assets are not read as
deleted. A per-resource read that fails — one API's routes or integrations,
one firewall's describe, one document's permissions — keeps the resource but
leaves the posture key absent, so its check stays silent and an open finding
is held rather than closed. The SSM compliance listing rides the software
inventory read and, like it, never flags the sweep partial: a denied listing
simply stamps no compliance verdict. A failed `ListQueryLoggingConfigs` leaves
`query_logging` absent on every zone while the DNS inventory itself is kept.

## Keys read by the logging checks

These collectors also store logging facts graded by the logging checks
(`internal/checks/aws_logging.go`): `api_gateway_stage.access_log_destination`
(the access-log destination ARN, `""` when access logging is off; REST, HTTP
and WebSocket stages) for `aws-apigateway-access-logging-off`, and
`network_firewall.logging_flow` / `logging_alert` / `logging_tls` for
`aws-network-firewall-logging-off`. Stage execution logging (`logging_level`,
`execution_logging`) is graded here, by
`aws-apigateway-stage-execution-logging-disabled`.
