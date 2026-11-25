# ADR 034 — Agentless workload scanning: scope (disk-acquisition deferred)

**Status:** accepted; amended 2026-07-06 (scanner reachable through the `agentless_scan`
River job, enabled by `AGENTLESS_ROOT`), 2026-08-02 (job intentionally has no producer),
2026-08-04 (snapshot acquisition re-examined and still deferred; package-inventory collector
identified as the better seam), 2026-10-05 (unwired inventory collectors removed), 2026-10-07
(SSM / OS Config inventory shipped in the collectors) and 2026-10-23 (the producer-less job,
its disk scanner and `AGENTLESS_ROOT` removed; the package parsers stay, used by the image
scanner and the collectors, in a package renamed to `internal/scanner/pkginventory`).
**Cloud snapshot acquisition (EBS/PD/Azure managed-disk) remains deferred, and nothing in the
tree scans a VM disk.** *Superseded in part by ADR 096 (2026-11-25): opt-in disk scanning for AWS
and Azure.*

## Context

Agentless workload vulnerability scanning — snapshot a VM's disk and scan it for CVEs,
secrets, and malware without an agent — is a common capability of agentless cloud security
products. On examination two things were true: (1) the platform already provides the
agentless vulnerability coverage that matters most — dependency CVEs from GitHub SBOMs
against OSV/KEV/EPSS, network scanning via nuclei, and full CSPM config evaluation — all from
API access, no agents; and (2) the *new* thing VM-disk scanning would add is "what is
physically installed/baked on a running instance's disk," which for workloads deployed from
repositories that are already SBOM-scanned is largely redundant. The genuinely hard part —
turning a cloud disk snapshot into a readable filesystem (block-read + in-process
ext4/XFS/NTFS parsing) — is a large, specialised effort. Cloud read access exposes a VM's
*config*, not its *files*; that boundary is by IAM design, not a permission that can be
granted.

## Decision

Build the **scanning core**, defer the **cloud disk-acquisition**.

- **`internal/scanner/agentless/`** (its package parsers now live in
  `internal/scanner/pkginventory`; see the 2026-10-23 amendment) is a cloud-agnostic engine
  over any `fs.FS`: regex secret detection (AWS/GCP/GitHub/Slack/Stripe keys, private keys,
  JWTs, generic api-key assignments; matches redacted) and package inventory from on-disk
  manifests (dpkg, apk, npm lockfile, requirements.txt) → CVE matching via the existing
  OSV/KEV/EPSS path (no new feed). `Scanner.Scan` emits `finding.Finding`s keyed to the
  source asset, so results land on the graph node and inherit enrichment/scoring/blast-radius.
  Fully unit-tested on `fstest`.
- **`SnapshotSource`** abstracts disk access. `LocalSnapshotSource` (a mounted path / container
  rootfs) works today. The per-cloud live implementations — EBS/PD snapshot → block-read or
  mount → strict teardown — are **deferred**: they involve cloud-mutating operations, a
  filesystem parser, and real-account testing, and are gated behind explicit demand.
- As originally accepted, the scanner was not wired into any job: no snapshots are created and
  nothing runs on any host. (See the 2026-07-06 amendment for the job wiring.)

## Consequences

- Product position: the platform does agentless vulnerability scanning (dependencies + network
  + config); it does **not** read running-VM disks, by deliberate scope, because source→deploy
  lineage (ADR 031, supply-chain ADR 012) already carries most of the practical coverage. The
  emphasis is lineage ("which commit, which owner, which deploy, every path from it"), not
  disk parity.
- The core is usable as soon as a `SnapshotSource` exists — including against any
  manually-mounted snapshot or a container image layer. No throwaway work.
- Container-image scanning (images in ECR/GCR, a registry pull instead of a disk snapshot)
  was the smaller alternative to the full VM-snapshot pipeline; ADR 057 built it.
- Carrying tested but lightly-wired code is a conscious choice over deleting it: zero runtime
  cost, and it documents the scoped boundary in executable form.

Cites ADR 012 (supply-chain first-class — why repo SBOMs cover most workload deps), 031
(identity/lineage — the differentiator vs disk parity), 009 (nuclei — the existing active
scanner), 032 (same content-inspection-out-of-scope reasoning for DSPM).

## Amendment (2026-07-06) — activation via the SnapshotSource seam

Leaving the scanner entirely unreachable was itself a gap. It is now wired into the job system
without crossing the deferred-infra boundary:

- **`agentless_scan` River job** (`internal/jobs/agentless.go`, removed 2026-10-23 with the
  scanner; see Status) runs `agentless.Scanner.Scan`
  for one asset, records the findings (`Source:"agentless"`), and re-enqueues them through
  enrichment so KEV/EPSS escalate the package CVEs. Registered on the `scan` queue; rescuable
  like every other kind (`TestAllJobKindsRescuable`).
- **Enabled by `AGENTLESS_ROOT`** (worker.go): sets a `LocalSnapshotSource` at that path and an
  OSV-backed `VulnQuerier`. Unset (the default) leaves the worker unregistered, so agentless
  scanning is off unless configured.
- **Not built:** the per-cloud `SnapshotSource` implementations (create snapshot → attach →
  mount → walk → strict teardown). They would plug into the exact same job. Container-image
  scanning (ADR 057) covers the nearest need through a registry pull instead.

## Amendment (2026-08-02) — no producer, by design; now pinned by a test

`AgentlessScanArgs` has a worker, a queue and a scanner, but **nothing enqueues it**, so VM
assets (`ec2_instance`, `gce_instance`) have no software inventory or VM-level CVE coverage
from this path.

The fan-out is deliberately still absent. The only `SnapshotSource` that exists,
`agentless.LocalSnapshotSource`, ignores its `assetID` and returns `os.DirFS(Root)` for every
call — so one job per VM would scan the same filesystem repeatedly and attribute identical
secrets and packages to every instance. Fabricated findings are worse than no findings. Real
coverage needs the per-cloud snapshot acquisition this ADR already defers behind the existing
seam; the fan-out lands with it.

`jobs.TestEveryJobKindHasAProducer` now pins this, so a registered worker with no producer is
a deliberate, commented entry rather than an oversight. The same test identified a second
case: `ExecutorArgs`/`ExecutorWorker` was registered and held a respond-queue slot, but both
live callers (the HTTP handler and the MCP execute tool) called `executor.Service.Execute`
synchronously, so the async path was unused. ADR 087 (item 5) later deleted the job outright.

## Amendment (2026-08-04) — feasibility re-examined; still deferred, and the seam is wrong

Without a producer, VM package-level visibility comes only from `runs_package` edges sourced
from `container_image`. Building the deferred EBS `SnapshotSource` was examined and rejected.
Four blockers, in order of how hard they are to remove:

1. **No filesystem parser.** The only disk read reachable from the worker without attaching
   volumes is the EBS direct API (`ebs:ListSnapshotBlocks` / `GetSnapshotBlock`), which
   returns raw 512 KiB blocks. Turning blocks into `/var/lib/dpkg/status` requires GPT +
   ext4/XFS parsing; the module has no such dependency, and this is the hard part the original
   decision identified.
2. **Deployment topology.** The worker runs in a single location, possibly in a different
   cloud. The attach-and-mount alternative needs a scanner EC2 instance in every AWS region
   *and AZ* holding a volume, which this single binary cannot deploy.
3. **Mutating IAM.** `ec2:CreateSnapshot` / `DeleteSnapshot` are writes, and the connector
   assumes a read-only role (ADR 016, `internal/collect/aws/auth.go`). CMK-encrypted volumes
   additionally need `kms:Decrypt` on a per-account key.
4. **Cost.** Snapshot storage at AWS's published $0.05/GB-month EBS snapshot rate plus $0.003
   per thousand `GetSnapshotBlock` units is a spend decision for whoever operates the
   deployment, not an engineering one.

**The feasible route is a different seam.** `ssm:ListInventoryEntries` (`AWS:Application`)
and GCP OS Config `Inventories` return an instance's installed package list directly:
read-only, no snapshot, no block parsing, no `fs.FS`. That is a collector producing
`[]InstalledPackage`, not a `SnapshotSource`, and it should be built as one — coverage limited
to SSM-managed / OS-Config-enabled instances, which can be assessed before any code is
written. (Collectors of this shape — `CollectSSMInventory`, `CollectOSInventory` — were later
written but never wired into a job. *Amended 2026-10-05:* they were removed as dead code;
the 2026-10-07 amendment below builds the seam inside the collectors instead.)

**Shipped in the meantime:** `agentless.Scanner.Scan` now returns a `Result` carrying
`package` assets and `ec2_instance -[runs_package]-> package` edges alongside its findings,
and `AgentlessScanWorker` ingests them before recording findings (the ordering ADR 057
established). Previously a scan produced findings and *no graph linkage at all*, so even a
working disk source would have left "where is package X used" unanswerable and left every VM
package CVE unable to inherit the host's `internet_hops`. `runs_package` is declared `FROM
Asset TO Package` and both `ec2_instance` and `gce_instance` map to `NodeAsset`, so this needs
no `graphschema` change and no `SchemaVersion` bump.

## Amendment (2026-10-07) — VM inventory shipped through the collectors

The inventory seam identified above now exists, inside the collectors rather than as a job:
the AWS collector reads SSM Inventory (`ssm:DescribeInstanceInformation` +
`ssm:ListInventoryEntries`, `AWS:Application`) and the GCP collector reads OS Config
inventories (`osconfig.inventories.list`, one call per zone). Both emit `package` assets and
`ec2_instance|gce_instance -[runs_package]-> package` edges with the disk/image scanners'
purl (`pkginventory.InventoryGraph`), so packages dedupe across VMs, images and repo SBOMs.

Every VM is stamped `package_inventory = ssm | osconfig | none` with a gap reason, and
`package_cve_matchable` saying whether an advisory source can match its whole inventory,
with `package_cve_gap` naming why not (end-of-life release, no source, binary names against
a source-keyed feed). A VM's CVE verdict is only as good as that stamp; see
[`docs/iam/vm-software-inventory.md`](../iam/vm-software-inventory.md) for the advisory
source per distribution.

`refresh_vm_vuln` (`internal/jobs/vmvuln.go`) places each open supply-chain advisory on the
VMs running the package, one finding per advisory × package version × fleet (ASG / MIG, else
AMI, else instance), so the general must-fix classifier weighs the host's own exposure, KEV
and blast radius. `agentless_scan` still has no producer: disk acquisition stays deferred for
the four reasons above, and the inventory path makes it unnecessary for package CVEs.

## Amendment (2026-10-23) — the job and the disk scanner are removed

A registered job that nothing enqueues, behind a `SnapshotSource` seam the 2026-08-04
amendment already called the wrong one, is speculative code: it reads as a capability, costs
review attention and guard rows, and can never run. It is deleted rather than kept "for
later":

- `agentless_scan` (`AgentlessScanArgs`, `AgentlessScanWorker`, its routing, rescue and
  no-producer entries) and the worker's `AGENTLESS_ROOT` wiring are gone.
- `agentless.Scanner`, `SnapshotSource`, `LocalSnapshotSource` and the on-disk secret
  scanner (`ScanSecrets`) are gone with it; they had no other caller. No finding source
  `agentless` exists any more.
- The package parsers stay, because live code uses them, and the package that keeps them is
  renamed to `internal/scanner/pkginventory` to say what it holds. Its users are the
  image scanner (`InventoryPackages`, `ClassifyManifest`, `ParseManifest`, `PURL`,
  `OSCVEGap`) and the SSM / OS Config collectors (`InventoryPackage`, `InventoryEcosystem`,
  `InventoryGraph`, `CVEGap`).

If per-cloud disk acquisition is ever built, it gets a producer, a source and a job in the
same change, starting from the blockers above.
