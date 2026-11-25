# AWS VPC-edge, launch-path and Auto Scaling reads

These reads feed the CIS AWS Foundations 6.2 and AWS FSBP EC2 / AutoScaling
checks. They live in `internal/collect/aws/ec2_network.go`, `vpn.go`,
`launch_templates.go`, `autoscaling.go`, `network.go` (VPC endpoints) and
`instances.go` (ENI source/destination checking). Every call is regional and
runs once per enabled region.

| Permission | Read | Feeds |
|---|---|---|
| `ec2:DescribeNetworkAcls` | `network_acl` assets: ingress entries, subnet associations | `aws-nacl-world-open-admin-port`, `aws-nacl-unused` |
| `ec2:DescribeVpcEndpoints` | vpc `endpoint_services` | `aws-vpc-missing-service-endpoints` |
| `ec2:DescribeTransitGateways` | `transit_gateway` assets (owned only) | `aws-tgw-auto-accept-shared-attachments` |
| `ec2:DescribeVpnConnections` | `vpn_connection` assets: tunnel telemetry, logging, IKE versions | `aws-vpn-tunnel-down`, `aws-vpn-tunnel-logging-disabled`, `aws-vpn-ikev1-allowed` |
| `ec2:DescribeClientVpnEndpoints` | `client_vpn_endpoint` assets | `aws-client-vpn-connection-logging-disabled` |
| `ec2:DescribeLaunchTemplateVersions` | `launch_template` assets (default version) | `aws-ec2-launch-template-public-ip`, `aws-ec2-launch-template-imdsv1`, `aws-ec2-launch-template-unencrypted-ebs` |
| `ec2:DescribeSpotFleetRequests` | `spot_fleet_request` assets | `aws-ec2-spot-fleet-unencrypted-ebs` |
| `ec2:DescribeInstances` | ENI source/destination checking (already read for inventory) | `aws-ec2-eni-source-dest-check-disabled` |
| `autoscaling:DescribeAutoScalingGroups` | `autoscaling_group` assets; launch template and configuration usage | `aws-asg-no-elb-health-check`, `aws-asg-single-az`, `aws-asg-single-instance-type`, `aws-asg-uses-launch-configuration` |
| `autoscaling:DescribeLaunchConfigurations` | `autoscaling_launch_configuration` assets | `aws-asg-launch-config-imdsv1`, `aws-asg-launch-config-public-ip` |

The AWS-managed `SecurityAudit` policy that the `GraphReadOnly` role
attaches grants every one of them (`ec2:Describe*`, `autoscaling:Describe*`),
so a deployed connector needs no change. A hand-written least-privilege
policy needs this statement:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphVPCEdgeRead",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeClientVpnEndpoints",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeSpotFleetRequests",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations"
      ],
      "Resource": "*"
    }
  ]
}
```

## Without the permissions

Nothing is guessed. Each resource type is its own regional collector, so a
denied call loses only that type for the region, is reported as a skipped
collector and flags the sweep partial. Two reads are folded into another
collector and degrade to an absent key instead: a denied
`ec2:DescribeVpcEndpoints` leaves `endpoint_services` off every VPC (the VPCs
are still emitted), and a denied `autoscaling:DescribeAutoScalingGroups` in
the launch-template collector leaves `auto_scaling_group_count` off the
templates, which only keeps their findings at Low. An absent key never fires
a check, and an open finding whose keys went missing is held open rather
than closed as fixed.
