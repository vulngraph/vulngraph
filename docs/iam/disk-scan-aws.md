# Disk scanning on AWS (EBS snapshots)

Vulngraph normally learns what is installed on an EC2 instance from the SSM agent's
inventory ([vm-software-inventory.md](vm-software-inventory.md)). Disk scanning covers
instances where that is missing: Vulngraph reads the instance's EBS snapshot, finds the
OS package database on the disk, and uses the package list the same way it uses SSM's.

It is **off by default and strictly opt-in per connector**. A connector without the
permissions below shows disk scanning as **not enabled**. That is its own state: it is
never reported as "clean" and never raised as an error.

A snapshot is a copy of the whole disk, so both modes give Vulngraph's credentials access
to everything on it, including any secrets. Vulngraph reads only the package databases
and a few OS release files, and keeps only the package list, but the IAM grant is not
limited to those files.

## Two modes

| Mode | What Vulngraph does | AWS permissions it needs | Writes in your account |
|---|---|---|---|
| `existing_snapshots` | Reads snapshots you already have (backups, AMI snapshots) | read-only, see below | none |
| `create_snapshots` | Creates a short-lived snapshot of a volume, reads it, deletes it | read-only, plus the disk-scan role | temporary tagged snapshots |

Start with `existing_snapshots`. A volume with no snapshot is reported as
`no_snapshot_available`, and a snapshot older than the staleness limit as `stale`.
Vulngraph never treats either as "no vulnerable packages".

### Mode 1: existing snapshots (read-only)

Deploy `graph-readonly-role.yaml` (or the org StackSet that wraps it) with
`GrantDiskScanRead=true`. The default is `false`. That adds, to `GraphReadOnly`:

```json
{
  "Sid": "GraphReadSnapshotBlocks",
  "Effect": "Allow",
  "Action": [
    "ebs:GetSnapshotBlock",
    "ebs:ListSnapshotBlocks",
    "ebs:ListChangedBlocks",
    "ec2:DescribeSnapshots"
  ],
  "Resource": "*"
}
```

`ec2:DescribeSnapshots` is already in `SecurityAudit`; the three `ebs:` actions are not
in any managed policy Vulngraph uses. With this grant the role can read every snapshot in
the account.

### Mode 2: creating snapshots

Everything in mode 1, plus a separate role that is allowed to write only this:

- `ec2:CreateSnapshot`, and only when the request tags the new snapshot
  `vulngraph-disk-scan` (and no other tag);
- `ec2:CreateTags`, and only while a snapshot is being created, so the role cannot tag or
  re-tag a snapshot that already exists;
- `ec2:DeleteSnapshot`, and only for snapshots that already carry the
  `vulngraph-disk-scan` tag.

The role grants no read of any kind. Vulngraph reads the new snapshot with the read-only
role from mode 1. Before every delete Vulngraph re-reads the snapshot's live tags and
refuses to delete anything without the tag. A sweeper removes tagged snapshots older than
the snapshot TTL even if a scan crashed.

The disk-scan role is a different principal from the collection role, the read-only role
and the execution role (Approve & run). The connector refuses to enable creation if
`disk_scan_role_arn` equals any of them.

**This is not a remediation.** Vulngraph does not change your workloads. Creating a
snapshot adds a temporary resource in your account; it is the one write Vulngraph makes
outside Approve & run, it is limited to the actions above, and enabling it is an
audited, admin-only decision.

## Cost

- `existing_snapshots`: EBS direct API calls (`GetSnapshotBlock` is billed per request;
  see the EBS pricing page) and nothing else. Only blocks the snapshot actually holds are
  read, and Vulngraph reads the partition table and the package database, not the whole
  disk. Results are cached per snapshot, and a newer snapshot of the same volume reuses
  the previous result when `ListChangedBlocks` shows no changed block touched what was read.
- `create_snapshots`: the same, plus snapshot storage while the temporary snapshot
  exists (the first snapshot of a volume stores its used blocks, later ones only changes).
  Per-connector limits cap concurrent snapshots, snapshots per day, volume size and bytes
  read per volume.

## Encrypted volumes and KMS

An encrypted snapshot can be read only by a principal allowed to use its KMS key. Neither
template grants `kms:Decrypt`, because the right key policy is yours to choose. To scan
encrypted volumes, allow the **read-only role** to use the key (`kms:Decrypt`, called
through the EBS service) in the key policy or a grant. Without it the volume is reported as
`encrypted_no_key`: unknown, not clean. Snapshots Vulngraph creates of an encrypted volume
use the volume's own key, so the same grant covers them.

AWS-managed keys (`aws/ebs`) cannot be shared with another account's role. For those, the
snapshot must be readable within the account the role lives in.

## Deploy the role (mode 2 only)

```
aws cloudformation deploy \
  --template-file deploy/aws/graph-diskscan-role.yaml \
  --stack-name graph-diskscan \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    HubRoleArn=arn:aws:iam::111111111111:role/GraphHub \
    ExternalId=<the connector's external_id>
```

Deploy it in each account where Vulngraph should create snapshots. `RoleName` defaults to
`GraphDiskScan`; `OrgId` optionally also requires the hub to be inside your organization.
Vulngraph assumes the role from the **worker's** identity, so the hub role must be allowed
to assume it: set the hub template's `DiskScanRoleName` to the role name (empty by default,
which grants no path to it).

## What the scanner pod holds

The scanner pod never assumes a role and needs no hub trust. At the start of each run the
worker assumes, through the same chain the collectors use (static keys or the ambient
identity, the hub hop, `external_id`), two **short-lived STS sessions** and seals them into
the run's volume jobs:

- a session of the connector's collection role for reads, cut by an inline session policy
  to `ec2:DescribeSnapshots`, `ec2:DescribeRegions`, `ebs:ListSnapshotBlocks`,
  `ebs:GetSnapshotBlock`, `ebs:ListChangedBlocks`, `kms:Decrypt` and `kms:DescribeKey`;
- only in `create_snapshots` mode, a session of the disk-scan role, cut to
  `ec2:CreateSnapshot`, `ec2:CreateTags` and `ec2:DeleteSnapshot` (the role's own tag
  conditions still apply).

A session policy can only narrow a role, never widen it. Each session lasts the run's
credential lifetime (one hour by default, between STS's 15-minute floor and its one-hour
chaining ceiling) and never outlives the sealed envelope. A volume job that starts after
that, or whose call is refused as expired, records the `stale` gap and is not retried; the
next plan reads the volume again. So a run is small (30 volumes by default), and a connector
with a run in flight is not planned again.

The one exception is a connector that has static `aws_access_key_id` keys and no `role_arn`:
there is no role to assume, so those keys are carried in the envelope as they are.

## Enable it on the connector

Disk scanning is switched on per connector by an admin, on the Connectors page or with
`PUT /api/connectors/{id}/disk-scan`. It is not available to API keys or over MCP.

1. Choose `existing_snapshots` (needs the read-only grant and no disk-scan role) or `create_snapshots` (needs
   the disk-scan role as well, and `disk_scan_role_arn` set to its ARN).
2. Confirm the typed prompt that names the cost and the permissions.

The change is audited with the previous and new mode, the role, the actor and the time.

## What "not enabled" means

| State | Meaning |
|---|---|
| mode `off` (the default) | Disk scanning was never switched on for this connector. |
| `not_enabled` | The connector is on but this volume cannot be scanned yet: a needed permission is missing (for example the disk-scan role cannot create snapshots, reported as `permission_denied`), or the connector is disabled. |
| `no_snapshot_available` | `existing_snapshots` mode found no usable snapshot of the volume. |
| `encrypted_no_key` | The snapshot is encrypted and the read-only role cannot use its key. |

In every one of these states the instance has no disk-derived package inventory and no
"clean" verdict from disk scanning. Whether the instance appears clean is decided as for
any VM: only when an inventory is known and its packages can be matched to advisories.

Vulngraph checks permission without writing: it calls `CreateSnapshot` with `DryRun` first.
An `UnauthorizedOperation` answer marks the volume `permission_denied`, is remembered for 24
hours, and is not retried in a loop.
