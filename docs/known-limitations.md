# Known limitations

Gaps that affect what Vulngraph reports, with what it does about each. Per-feature
limits are in [capabilities](capabilities.md).

- **Multi-hop Cypher once a graph node table holds more than 131,072 rows.** The pinned
  LadybugDB release (v0.21.2) can miss relationships in multi-hop and variable-length matches
  once a node table holds more than 131,072 rows (one node group) and its last groups have no
  outgoing edges of the queried type
  ([ladybug#1341](https://github.com/LadybugDB/ladybug/issues/1341)). The limit is per node
  table, not per estate. Most assets load into the catch-all `Asset` table, but packages, IAM
  principals, Kubernetes workloads, repositories, subnets, cloud accounts and a few other types
  have tables of their own, and some asset types are not loaded into the graph at all. So an
  estate with fewer than 131,072 assets can still cross the limit in one table (for example
  `Package`, which the `RunsPackage` paths walk), and a larger one may not. Above the limit,
  the named queries that walk more than one hop (the attack paths, `blast_radius_deep`), saved
  queries and detections, NL-to-Cypher and raw Cypher (Explore, chat, MCP) can return fewer
  paths than exist; the engine itself raises no error. Vulngraph counts every node table after
  each graph load and reports when one is over the limit: `multi_hop_may_be_incomplete` and
  `oversized_node_tables` on `GET /api/graph/status` and `/api/graph/stats` and in MCP
  `get_graph_stats`, a `multi_hop_may_be_incomplete: true` flag on each Cypher result that graph
  answers (the API, MCP `run_cypher` and the chat `run_cypher` tool), an `incomplete` status on
  saved-query and detection runs, a banner in Explore, the `graph_ladybug_multihop_may_be_incomplete` metric (per-table
  counts in `graph_ladybug_node_table_rows`) and the `GraphLadybugMultiHopMayBeIncomplete`
  alert. Single-hop matches (explore neighbours, the hop-by-hop blast-radius walk) and risk
  propagation, which runs in Go, are not affected. The fix
  ([#1342](https://github.com/LadybugDB/ladybug/pull/1342)) was merged upstream on 2026-10-22
  and is not in a release yet; Vulngraph will move to the first release that has it.
- **Lateral reachability inside a network is partial.** The security-group path queries
  (`lateral_movement_via_sg`, `databases_reachable_from_internet`) follow AWS ingress rules that
  name a security group, including a group naming itself. Sharing a security group is not a
  path, and these queries do not treat it as one. Ingress rules whose CIDR covers another
  instance's private address, network ACLs, and Azure NSG and GCP firewall paths to datastores
  are not modelled, so the queries can miss real paths. Blast radius and risk propagation still
  walk security-group membership both ways, so they can count members of one group that cannot
  reach each other: an upper bound, not a path.
- **Internet exposure is "confirmed" only at the network layers Vulngraph reads.** An EC2
  edge marked `public_access=confirmed` means a public address, a security group rule open to
  the internet on that port, and an observed public route. An unread route or security-group
  inventory retains possible exposure; it does not establish a confirmed route. AWS
  network ACLs are collected and graded on their own (`aws-nacl-world-open-admin-port`), but
  reachability does not apply them, so an instance whose subnet ACL denies the port is still
  shown as confirmed exposed. In GCP, only VPC firewall rules are read: hierarchical
  (organization and folder) and network firewall policies are not collected, so a deny there
  is not credited and an allow there is never reported, by the `gcp-firewall-*` checks or by
  the GCE exposure edges. An organization that has moved its rules into firewall policies
  gets an incomplete picture in both directions.
- **EKS Pod Identity associations are not collected.** A workload's IAM role is read from
  IRSA (the `eks.amazonaws.com/role-arn` ServiceAccount annotation) and GKE Workload Identity
  only. A pod whose role comes from an EKS Pod Identity association gets no `ExecutesAs` edge
  to that role, so attack paths and blast radius stop at the pod, and CIS EKS 5.2.1 is listed
  as missing. This is about the clusters Vulngraph scans; running Vulngraph itself with Pod
  Identity (the default in [AWS org onboarding](onboarding-aws-org.md)) is unaffected.
- **The LadybugDB binding has few tests of its own.** Its 11 tests cover opening and closing a
  database, memory safety, error surfacing, the `database/sql` driver and read-only statements
  ([details](../internal/graphdb/ladybug/README.md#tests)). Value conversion and result iteration
  are exercised through the graphstore tests that run Vulngraph's schema and loader on the
  engine, not by binding-level tests.
- **Disk scanning reads only part of a VM, and reports what it could not read as unknown.** It reads
  the boot volume of a Linux VM, on ext2/3/4 or XFS under an MBR or GPT table, and nothing else: no
  LVM, RAID, btrfs, ZFS or Windows disks, no encrypted volume without its key, no ext4 or XFS feature
  the readers do not handle (inline data, bigalloc, realtime volumes), and no data volumes. The journal is
  not replayed, so a snapshot taken mid-write can show slightly older package state. It reads OS
  package databases only: language packages (npm, pip, Go modules) on the disk are not read, so a VM
  can read as having no known OS package vulnerabilities while its application dependencies are
  unscanned. A disk it cannot read is a gap (`unsupported_fs`, `unsupported_partition`,
  `encrypted_no_key`, `read_error`, `over_cap`), never a clean result. GCP has no disk reader yet. On
  Azure, `existing_snapshots` mode needs the dedicated disk-scan principal too (a read-only role: snapshot
  read, `beginGetAccess` and `endGetAccess`), because reading snapshot bytes needs a read SAS; AWS and GCP
  `existing_snapshots` need no extra principal. On Azure the scanner pod holds that principal's client
  secret, which does not expire; on AWS it holds only short-lived sessions. A connector can be set to a disk-scan mode while `DISK_SCAN_ENABLED` is off; nothing
  is read until the switch is on ([capabilities](capabilities.md#vm-disk-scanning),
  [threats 17 to 19](threat-model.md)).
- **A package inventory a customer's own agent submits is believed as far as it claims to be complete.**
  Vulngraph cannot check a submitted list against the machine. A fresh `complete: true` inventory
  that omits a vulnerable package is trusted until its `observed_at` is 7 days old or the next
  submission replaces it, so that VM can read as having no known vulnerabilities for up to that window.
  What it does about it: the server, not the agent, decides known-ness (a list that is incomplete, stale
  or on an OS with no enabled advisory source is shown as unknown, never clean), the UI names the scanner
  that made the claim, and the effect stops at the one VM the key named
  ([bring your own agent](iam/byoa-inventory.md), [threat 16](threat-model.md)).
