# ADR 096 — Opt-in VM disk scanning, and the one cloud write it needs

**Status:** accepted (2026-11-25) · amends ADR 034 (disk acquisition was deferred) and ADR 087
(no cloud mutation runs without a person)

## Context

ADR 034 deferred scanning VM disks and said a future change must ship a producer, a source and a
job together. ADR 087 says no state-changing action proceeds without a person, and CLAUDE.md
turns that into a rule: no cloud mutation runs as a River job.

Reading a VM's disk without an agent needs a snapshot, and creating a snapshot is a cloud write.
It is small: additive, tagged, ephemeral, and it touches no workload. It is still a write, so the
decision has to be explicit.

## Decision

1. **It is optional at every level.** `DISK_SCAN_ENABLED` is off by default and, when off, the
   chart renders no envelope key and no disk-scan variable (`TestChartDiskScanOffMeansOff`). Each
   connector has a mode, `off` (the zero value), `existing_snapshots` or `create_snapshots`. The
   cloud permissions are never part of the read-only role: the snapshot actions live in their own
   role and the read-only role's snapshot-read grant is a parameter that defaults to `false`. A
   missing permission is the state "not enabled", never an error and never clean.
2. **The admin opt-in is the standing approval for the one write.** Enabling `create_snapshots`
   is admin-only, needs a signed-in session (never an API key), needs a typed confirmation that
   names the cost and the permission, requires a disk-scan principal that differs from the
   collection and execution principals, and writes an audit row with before, after, role and
   actor. It is not routed through the executor: the executor refuses a run without a person on
   the request, and weakening that guard is a bigger change than a documented, tested exception.
3. **Two mutating calls, behind one chokepoint.** Only `internal/scanner/diskscan/snapshotter` may
   hold a mutating cloud client. It can create a snapshot carrying the `vulngraph-disk-scan` tag
   from the moment it exists and delete a snapshot that still carries it, after re-reading the
   live tags. Azure adds grant-read and revoke-read (a read URL, revoked on every path). A client
   is built only from an opt-in value that `diskscan.Authorize` returns for a connector whose mode
   and role allow it. `TestSnapshotMutationAllowlist` walks the tree and fails on any other
   mutating call; `TestMutatingClientsOnlyInSnapshotter` and `TestJobsNeverImportCloudMutators`
   keep the clients out of the jobs package. The executor guards (`TestOnlyHumanTransportsBuildExecutionRequests`
   and the policy gate tests) are unchanged.
3a. **Reading an existing snapshot is a separate, narrower grant.** On Azure it needs a time-limited
   read URL, so it has its own read opt-in that authorises only grant-read and revoke-read. AWS
   reads existing snapshots with read-only permissions and no opt-in.
4. **A snapshot is never left behind.** An intent row is written before the create call. The volume
   job deletes in a deferred cleanup on every path, with a fresh context. A sweeper lists by tag,
   independent of the database, and deletes anything past the TTL.
5. **The scanner pod parses untrusted disks and holds only what a run needs.** Disk contents are
   chosen by whoever controls the VM, so the readers (partition, ext4, XFS) run in the scanner
   pod, which has no master key. The worker decrypts the connector, takes only the disk-scan
   credentials and seals them into a per-run envelope bound to the run and the connector. On AWS
   those are short-lived STS credentials minted by the worker. The scanner reads connector mode only
   through a view, writes package lists to Postgres, and the worker's overlay turns them into
   assets and edges. The scanner's database grants are pinned exactly by a test.
6. **Unknown is never clean.** An unreadable, encrypted, unsupported or over-cap disk is a gap with
   `InventoryKnown=false`. The database refuses to store an unread disk as clean. Only boot
   volumes, Linux, ext4 and XFS, and only package databases and OS release files are read.
7. **A customer's own agent can supply the result instead.** An `inventory` API-key scope lets an
   agent submit a package list for an asset it names. The server decides whether the inventory is
   known (complete, fresh, resolvable to an advisory source), and the freshest known capture wins
   across SSM, OS Config, disk scan and that submission. Nothing in it can assert a finding.

## Consequences

- A deployment that never enables disk scanning is unchanged: no key, no variable, no job, no
  permission.
- The scanner pod, which held no secret, now holds the envelope key and expiring per-run
  credentials when the feature is on. The threat model records the residual blast radius.
- CLAUDE.md's jobs rule gains one bounded exception, pinned by tests.
- GCP reads existing snapshots only in a later change, and creating them there is not planned.
- Journals are not replayed, so a snapshot taken mid-write can show torn metadata. That reads as
  a gap, not a result.
