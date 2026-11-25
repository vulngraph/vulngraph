# Granting Vulngraph ECR image pull access (image CVE scanning)

Vulngraph's image-vuln sweep (`internal/jobs/imagevuln.go`) pulls every running
container image by digest — from k8s pods, ECS tasks and Cloud Run revisions —
reads its package manifests and matches them against OSV. That is what lets an
internet-exposed workload running an image with a known-exploited CVE reach
`must_fix`.

For images in a **private Amazon ECR registry**
(`<account>.dkr.ecr.<region>.amazonaws.com`), the sweep authenticates with the
credentials of the enabled AWS connector **for the registry's account**
(`ecr:GetAuthorizationToken`, `internal/collect/aws/ecrauth.go`) and then pulls
the image. These permissions are **not** included in `ViewOnlyAccess` or
`SecurityAudit`. Together they are the AWS managed
`AmazonEC2ContainerRegistryReadOnly` policy minus its describe/list actions.

> Vulngraph never grants this itself: no code path grants IAM permissions to Vulngraph or
> anyone else. Its only IAM writes are human-approved key actions through the executor
> (disabling or deleting an AWS access key, disabling a GCP service-account key), run
> with the connector's separate execution role.
> Grant it through whatever IAM process your organization already uses.

## The grant

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphECRAuthToken",
      "Effect": "Allow",
      "Action": ["ecr:GetAuthorizationToken"],
      "Resource": "*"
    },
    {
      "Sid": "GraphECRPullByDigest",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:*:*:repository/*"
    }
  ]
}
```

`ecr:GetAuthorizationToken` cannot be resource-scoped. The two pull actions can
be narrowed to specific repository ARNs if your policy standards require it.

All three actions are read-only, and nothing is written to the registry.
Images are pulled by content digest, and the sweep reads only the OS/package
manifests inside the layers, in memory. The grant itself is broader:
`ecr:GetDownloadUrlForLayer` lets the role download the full content of every
layer, so any secret baked into an image is readable by whoever holds the role.
Add the statement to the role Vulngraph already assumes per account
(`GraphReadOnly`) via whatever mechanism provisions that role, as described in
[README.md](./README.md).

## Cross-account (shared-services) registries

The sweep picks credentials by **registry account**: an image in
`111111111111.dkr.ecr...` is authenticated with the AWS connector for account
`111111111111`. If your workloads pull from a central registry account, that
account needs its own enabled AWS connector carrying this grant. Its repository
policies are irrelevant here, because the principal is in the same account.
Without a connector for the registry account, those images fail with
`no enabled AWS connector for account <id>`.

## How to tell whether it worked

A failed pull never fails the sweep. It is recorded per digest:

- `image_scan_state.last_error` holds the reason for each digest's latest failed
  attempt. Look for `AccessDeniedException` on `ecr:GetAuthorizationToken`, a
  401/403 on the pull, or `no enabled AWS connector for account <id>`.
- `graph_image_scan_never_scanned` divided by `graph_image_scan_tracked_digests`
  rises while ECR images can't be pulled, and should fall within one sweep
  interval (≤24h) after the grant lands.

## ECS inventory (no extra grant)

Which images ECS runs, and how each service is exposed, comes from the AWS
collector (`internal/collect/aws/ecs.go`, `ecs_images.go`), not from the pull.
It uses only read actions already in `ViewOnlyAccess` and `SecurityAudit`
(`ecs:List*`, `ecs:Describe*`, `elasticloadbalancing:Describe*`):

| Action | Used for |
|---|---|
| `ecs:ListClusters`, `ecs:DescribeClusters` | clusters |
| `ecs:ListServices`, `ecs:DescribeServices` | services, `assignPublicIp`, target groups |
| `ecs:DescribeTaskDefinition` | task role (`executes_as`) and container definitions |
| `ecs:ListTasks`, `ecs:DescribeTasks` | the image **digest** each running service task resolved (`containers[].imageDigest`) — the `container_image` + `runs_image` edges |
| `elasticloadbalancing:DescribeTargetGroups` | which load balancers forward to a service (`load_balancer -routes_to-> ecs_service`) |

A denied or failed `ListTasks`/`DescribeTasks`, `DescribeTaskDefinition` or
`DescribeTargetGroups` keeps the services but marks the sweep partial and logs
a warning: a missing image or load-balancer link is never read as "runs
nothing" or "not exposed".
