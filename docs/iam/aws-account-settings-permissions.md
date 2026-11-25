# AWS account-settings, root-detail and bucket-policy reads

These reads feed the CIS AWS Foundations and AWS FSBP account-wide checks.
They live in `internal/collect/aws/account_settings.go`, `region_settings.go`,
`iam_root.go` and `s3_policy.go`.

| Permission | Read | Feeds |
|---|---|---|
| `iam:GetAccountPasswordPolicy` | account password policy (`aws_account_settings`) | `aws-iam-weak-password-policy` |
| `account:GetAlternateContact` | SECURITY alternate contact (`aws_account_settings`) | `aws-account-no-security-contact` |
| `s3:GetAccountPublicAccessBlock` | account S3 Block Public Access (already read for bucket grading) | `aws-s3-account-bpa-disabled` |
| `iam:ListVirtualMFADevices` | whether root's MFA is a virtual device | `aws-iam-root-virtual-mfa` |
| `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | root password / access-key last use, and whether root has a password at all (`password_enabled`, the root asset's `console_access`) | `aws-iam-root-recently-used`, `aws-iam-root-no-mfa` (without the report, or when its root row reads `not_supported`, a root without MFA is still reported with the password status unknown; the root's MFA badge and score penalty stay unknown) |
| `ec2:GetEbsEncryptionByDefault` | per region (`aws_region_settings`) | `aws-ebs-default-encryption-disabled` |
| `ec2:GetSnapshotBlockPublicAccessState` | per region | `aws-ebs-snapshot-bpa-disabled` |
| `ec2:DescribeVpcBlockPublicAccessOptions` | per region | `aws-vpc-block-public-access-off` |
| `s3:GetBucketPolicy` | each bucket's policy document | `aws-s3-no-tls-enforcement`, `aws-s3-policy-cross-account-write` |
| `ssm:DescribeInstanceInformation` | managed-node listing (already read for software inventory); `ssm_managed` is written only when it succeeds | `aws-ec2-not-ssm-managed` |

The AWS-managed `SecurityAudit` policy that the `GraphReadOnly` StackSet
role attaches already grants all of them, so a deployed connector needs no
change. A hand-written least-privilege policy instead needs this statement:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphAccountSettingsRead",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:ListVirtualMFADevices",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "account:GetAlternateContact",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPolicy",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetSnapshotBlockPublicAccessState",
        "ec2:DescribeVpcBlockPublicAccessOptions",
        "ssm:DescribeInstanceInformation"
      ],
      "Resource": "*"
    }
  ]
}
```

`iam:GenerateCredentialReport` is the only one that is not a pure read: it asks
IAM to build the account's credential report (AWS reuses one younger than four
hours). It changes no configuration.

## Without the permissions

Nothing is guessed. A denied read leaves its metadata key absent and logs a
warning naming the permission, the check that reads it stays silent, and an
already-open finding is held open rather than closed (every one of these
checks has scanner-derived required keys, so the lifecycle sees it could not
evaluate the asset). The
`aws_account_settings` asset is emitted on every sweep even when all of its
reads fail, for the same reason. A region where all three EC2 setting reads
are denied is reported as a skipped collector, which flags the sweep partial
exactly as a denied `ec2:DescribeRouteTables` does.
