# ECR registry scanning read access (`ecr:GetRegistryScanningConfiguration`)

The ECR collector (`internal/collect/aws/ecr_scanning.go`) reads each region's
registry-level scanning configuration once per sweep. Enhanced scanning with
Amazon Inspector, and basic-scanning rules, are configured on the registry
rather than the repository, so this is what tells `aws-ecr-scanning-disabled`
whether a repository whose own `scanOnPush` flag is off is in fact scanned by
a registry rule (AWS FSBP ECR.1).

The AWS-managed `SecurityAudit` and `ReadOnlyAccess` policies already grant it.
A hand-written least-privilege policy for `GraphReadOnly` needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphECRRegistryScanningRead",
      "Effect": "Allow",
      "Action": [
        "ecr:GetRegistryScanningConfiguration"
      ],
      "Resource": "*"
    }
  ]
}
```

Read-only. Without it the repositories are still collected, but their
`registry_scan_*` keys are omitted and `aws-ecr-scanning-disabled` stays silent
on every repository with `scanOnPush` off (scan coverage unknown) rather than
reporting repositories a registry rule may be scanning. The collector logs a
warning naming the permission.
