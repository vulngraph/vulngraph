# VM software inventory (SSM Inventory / GCP OS Config)

Vulngraph knows what is installed on a VM only through the cloud's own OS inventory
service. There is no agent of Vulngraph's own and no disk snapshotting
([ADR 034](../adr/034-agentless-scanning-scope.md)). The AWS and GCP collectors read the
package list the SSM agent / OS Config agent already reports, link each instance to its
packages (`runs_package`), and match those packages against the distribution's advisory
source (see [Advisory sources](#advisory-sources)). That is what lets "internet-exposed VM
with a known-exploited vulnerability" surface as must-fix.

**Coverage is exactly as wide as the agent rollout.** A VM with no agent reporting has
no inventory, and Vulngraph says so rather than calling it clean. A customer who runs their
own scanner can submit the package list instead, with no cloud permission granted to
Vulngraph: [bring your own agent](byoa-inventory.md) (`package_inventory` value `byoa`).

## Required permissions (read-only)

### AWS — add to the role Vulngraph assumes (`GraphReadOnly`)

```json
{
  "Sid": "GraphReadSSMInventory",
  "Effect": "Allow",
  "Action": [
    "ssm:DescribeInstanceInformation",
    "ssm:ListInventoryEntries"
  ],
  "Resource": "*"
}
```

AWS's `ReadOnlyAccess` managed policy already includes both. Coverage also needs, on the
instance side:

- the SSM agent running, and the instance managed by Systems Manager (an instance profile
  with `AmazonSSMManagedInstanceCore`, or Default Host Management Configuration);
- an Inventory association collecting **Applications** (Systems Manager → Inventory →
  "Setup Inventory", or a State Manager association running `AWS-GatherSoftwareInventory`).

### GCP — on each project Vulngraph collects

- `osconfig.inventories.list`, which is in `roles/osconfig.inventoryViewer`;
- the OS Config API (`osconfig.googleapis.com`) enabled, and VM Manager's OS inventory
  turned on (project metadata `enable-osconfig=TRUE`, with the OS Config agent present,
  which Google's standard images ship).

A missing permission never fails or degrades a sync. Every instance is then stamped
`package_inventory=none` with the reason (see below).

## What gets stamped on every VM

| Metadata key | Values |
|---|---|
| `package_inventory` | `ssm`, `osconfig`, or `none` |
| `package_inventory_gap` | why it is `none`: `not_ssm_managed`, `no_inventory_data`, `stale_inventory` (capture older than 7 days), `unsupported_platform` (Windows, macOS, Container-Optimized OS), `over_package_cap` (more than 10,000 packages), `inventory_pending`, `ssm_access_denied`, `ssm_unavailable`, `not_osconfig_managed`, `osconfig_api_disabled`, `osconfig_access_denied`, `osconfig_unavailable` |
| `package_inventory_observed_on` | UTC date the agent captured the inventory |
| `package_ecosystem` | the OS release the packages are stamped with, e.g. `Ubuntu:22.04:LTS`, `Red Hat:9`, `Amazon Linux:2023` |
| `package_cve_matchable` | `true` only when an advisory source can match the whole inventory |
| `package_cve_gap` | why it is `false`: `eol_distro`, `no_advisory_source`, `advisory_source_disabled`, `no_source_package_names`, `unknown_release` |

A VM supports a "no vulnerable packages" verdict only when `package_inventory` is `ssm`
or `osconfig` **and** `package_cve_matchable=true`. Packages are inventoried either way (so
"where is openssl installed" still answers), and any CVE that does match is still a
finding. `go run ./cmd/coverage-gen` reports the ratios under the lineage chain ("VMs with
a known package inventory", "VMs with a CVE-matchable inventory") and splits VMs by release
and by `package_cve_gap` under "VM OS advisory coverage".

## Advisory sources

| Distribution | `package_ecosystem` | Source | Keyed by | Matchable when |
|---|---|---|---|---|
| Ubuntu | `Ubuntu:22.04:LTS` | OSV (`api.osv.dev`) | source package | the inventory carries source names |
| Debian | `Debian:12` | OSV | source package | the inventory carries source names |
| Red Hat Enterprise Linux | `Red Hat:9` | OSV, Red Hat's CSAF data | binary package | always |
| AlmaLinux | `AlmaLinux:9` | OSV | binary package | always |
| Rocky Linux | `Rocky Linux:9` | OSV | source package | the inventory carries source names |
| SUSE Linux Enterprise | `SUSE:15.5` | OSV, SUSE's data | source package | the inventory carries source names |
| openSUSE Leap | `openSUSE:Leap 15.5` | OSV | source package | the inventory carries source names |
| Amazon Linux 2, 2023 | `Amazon Linux:2023` | ALAS, from the repositories' `updateinfo.xml` on `cdn.amazonlinux.com` | binary package | always (Amazon Linux 2 is `eol_distro` since 2026-06-30) |
| Oracle Linux 7–10 | `Oracle Linux:9` | ELSA, from the repositories' `updateinfo.xml` on `yum.oracle.com` | binary package | always |
| CentOS Linux 7/8, CentOS Stream | `CentOS:7` | none | — | never |

**Source package names.** Debian, Ubuntu, Rocky Linux and SUSE publish advisories against
the *source* package (`openssl`), while an inventory lists binaries (`libssl3`,
`openssl-libs`). Queried by binary name, only binaries that happen to share their source's
name can match. SSM Inventory reports an rpm package's source rpm as its `PackageId`, so
rpm inventories read through SSM are queried by source name and the advisory lands on every
binary built from it. dpkg inventories through SSM, and every GCP OS Config inventory,
report binary names only: SSM's dpkg gatherer reads `Package`, `Version` and `Architecture`
and builds its `PackageId` from them (`libssl3_3.0.2-0ubuntu1.15_amd64.deb`), and OS Config's
`VersionedPackage` has no source field at all. Those VMs get
`package_cve_gap=no_source_package_names`: their findings are real, their *absence* of
findings proves nothing, and the OSV refresh never resolves a finding on such a package by
absence. Container image scans read the dpkg database directly (its `Source` field,
distroless `status.d/` included) and Alpine's `origin`, so image packages are matched by
source package. VM disks are not scanned (ADR 034).

**Red Hat and SUSE in OSV.** OSV keys Red Hat by CPE product stream
(`Red Hat:enterprise_linux:9::baseos`, `…:9::appstream`, minor-scoped `…:10.1` from RHEL 10)
and SUSE by product and service pack (`SUSE:Linux Enterprise Module for Basesystem 15 SP5`).
An inventory knows neither the repository a package came from nor the modules a host
subscribes to, so Vulngraph queries the bare family and keeps an advisory only when an entry for
the host's major release (RHEL) or service pack (SUSE, including its LTSS products) holds the
installed version, compared with rpm's own version rules. RHEL EUS/AUS/E4S minor-release
pins cannot be told apart from an inventory and are matched as mainline.

**Amazon Linux and Oracle Linux.** OSV carries neither. Vulngraph reads the vendors' own yum
`updateinfo.xml`, the file `yum updateinfo` reads on every host, which lists per advisory
the exact package versions that fix it. Amazon Linux: the core repository of AL2 and
AL2023, plus the AL2 kernel extras topics (kernel-5.4, 5.10, 5.15 — their `ALAS2KERNEL-*`
advisories; the other `amazon-linux-extras` topics are **not** read). Oracle Linux: 7 (`latest`)
and 8–10 (BaseOS and AppStream), x86_64 and aarch64, plus the Unbreakable Enterprise Kernel
channels (UEKR4–R8 as each release publishes them). A kernel channel's advisories apply only to
hosts on that kernel line (a 5.15 fix is not an upgrade target for a 5.4 host); the few packages
those channels ship off the kernel's line (dtrace, xfsprogs builds) are not matched. Every
updateinfo is verified against the checksum its repomd lists (sha1, sha256 or sha512); one that
cannot be verified fails the release rather than being read. The refresh is
daily; with nothing changed it costs one conditional GET per repository. One finding is
recorded per CVE × package version, so KEV and EPSS see every CVE an advisory fixes.

**CentOS.** CentOS Linux 7 and 8 are end-of-life and their packages are different builds
from RHEL's. Vulngraph does not borrow RHEL advisories for them (that would be confident and
wrong); their VMs are `eol_distro`, and the end-of-life check below reports them.

**Not covered.** Amazon Linux 1 (end-of-life, `eol_distro`), AL2 extras topics other than the
kernel lines, CentOS Stream, SUSE releases outside an OSV product, and any other distribution.

### Turning off the advisory hosts (`OFFLINE_MODE`)

Package matching calls three advisory hosts. Each has its own switch:

| Host | Switch | Sends |
|---|---|---|
| `api.osv.dev` | `INTEL_OSV_DISABLED` | package ecosystem, name and version |
| `cdn.amazonlinux.com` | `INTEL_ALAS_DISABLED` | nothing (GETs of public repository metadata), and only once an Amazon Linux package is inventoried |
| `yum.oracle.com` | `INTEL_ELSA_DISABLED` | nothing (GETs of public repository metadata), and only once an Oracle Linux package is inventoried |

`OFFLINE_MODE=true` turns all three off. It is not an air gap: the cloud APIs the connectors
read are still called, and so are the other hosts listed under
[Network egress](../configuration.md#network-egress) that `OFFLINE_MODE` does not cover. With a source off, its VMs' packages match nothing:
they are stamped `package_cve_matchable=false`, `package_cve_gap=advisory_source_disabled`
(Debian, Ubuntu, Red Hat, AlmaLinux, Rocky, SUSE and openSUSE with OSV off; Amazon Linux
with ALAS off; Oracle Linux with ELSA off), and container images are not scanned at all with
OSV off. See [Network egress](../configuration.md#network-egress).

## End-of-life operating systems

`aws-ec2-os-end-of-life` and `gcp-gce-os-end-of-life` fire on a VM whose inventoried release
is past the end of its vendor's standard support: High with a public IP, Medium otherwise.
The dates live in a hand-maintained table (`internal/distro`), taken from the vendors'
lifecycle pages: [Amazon Linux](https://aws.amazon.com/amazon-linux-2/faqs/),
[Red Hat](https://access.redhat.com/support/policy/updates/errata),
[CentOS](https://www.centos.org/centos-linux-eol/),
[Ubuntu](https://ubuntu.com/about/release-cycle), [Debian](https://wiki.debian.org/LTS),
[Oracle Linux](https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf), as tracked by
[endoflife.date](https://endoflife.date) (last checked 2026-10-08; the table cites it). It
also covers Alpine, SUSE service packs and openSUSE Leap, which matter for container base
images (ADR 088). Update the table when a vendor moves a date. A release not in the table is
unknown and is never reported.

## Cost and freshness

- **GCP:** one `inventories.list` call per zone that holds instances, on every sync.
- **AWS:** `ListInventoryEntries` is per instance and returns 50 packages a page, so a
  host costs roughly 10–40 calls. Package lists are cached in the worker and each instance
  is re-read about every 20 hours, oldest first. Reads are paced to 20 calls per second
  per region and capped at 60 seconds per region and 6 minutes per sync. On a large fleet,
  instances not yet read show `inventory_pending`. So does every instance right after a
  worker restart, because the cache lives in memory. A list that misses its refresh for 40
  hours stops being emitted rather than going stale.

## Findings

- The OSV refresh records one `supply_chain` finding per CVE × package version, shared
  by every VM, image and repo that has the package; an advisory bundling several CVEs
  (DSA, USN, RHSA, SUSE-SU) is one finding per CVE, with the advisory ids in
  `metadata.advisory`. The distro advisory refresh (`refresh_distro_advisories`) records
  the same finding for Amazon Linux and Oracle Linux packages.
- `refresh_vm_vuln` then records one `vm_vuln` finding per CVE × package version ×
  **fleet**. The fleet is the instance's Auto Scaling group or managed instance group,
  else its AMI, else the instance itself. The finding is placed on a directly exposed
  member when there is one, and carries `affected_instances`, `affected_instance_ids` (up
  to 50) and `exposed_instances` as evidence. Must-fix classification uses that member's
  own reachability, KEV status and blast radius.
- A `vm_vuln` finding is resolved by absence only when every live member of its fleet
  has a known inventory. If a member's agent went dark, the finding stays open.
