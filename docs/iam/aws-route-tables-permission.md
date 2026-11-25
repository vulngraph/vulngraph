# AWS route-table read access (`ec2:DescribeRouteTables`)

The AWS collector reads every region's route tables
(`internal/collect/aws/network.go`) to tell a public subnet from a private one.
That single fact drives three things:

- `public_subnet`, `egress_via` and `route_table_id` on each `subnet` asset;
- `in_public_subnet` on `ec2_instance` and `rds_instance` assets, which the
  internet-reachability correlator uses to withhold `exposed_to_internet` from
  a public IP whose subnet has no internet-gateway route;
- `in_public_subnet_v6` on `ec2_instance` assets, the same answer from IPv6
  routes alone, read for an instance reachable only over IPv6 (an IPv6 default
  route to an egress-only internet gateway carries no inbound traffic);
- the `aws-rds-public-subnet-igw` check.

The AWS-managed `SecurityAudit` and `ReadOnlyAccess` policies already grant it
(`ec2:Describe*`). A hand-written least-privilege policy for `GraphReadOnly`
needs this statement added:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphRouteTableRead",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRouteTables"
      ],
      "Resource": "*"
    }
  ]
}
```

Read-only and non-mutating; `Describe*` actions do not support resource-level
scoping, so `Resource` must be `*`.

`ec2:DescribeInternetGateways` and `ec2:DescribeNatGateways` are **not**
needed: a route to a detached internet gateway or a deleted NAT gateway is
reported in the route table with state `blackhole`, and the collector ignores
blackhole routes.

## Without the permission

Nothing is guessed. Subnets get no routing keys, instances get no
`in_public_subnet` or `in_public_subnet_v6`, exposure is computed exactly as it was before route tables
were collected (public IP + security group), `aws-rds-public-subnet-igw`
stays silent, and the sweep is flagged partial so findings that depend on the
missing keys are not auto-resolved.
