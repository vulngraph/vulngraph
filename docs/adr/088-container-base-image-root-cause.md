# ADR 088 — Container base images: identify, grade, group, recommend

**Status:** accepted (2026-10-08) · amended 2026-10-09 (root-cause findings are the alerting unit) · builds on ADR 057 (image CVE scanning) and ADR 087 (no autonomous remediation)

## Context

ADR 057 gave every running container image a package inventory and a CVE axis, but each
CVE stays a separate `supply_chain` finding per (CVE × package version). An estate of 200
images built on `debian:11` shows the same few hundred OpenSSL, glibc and zlib CVEs once per
package, and nothing says that one `FROM` line causes them all, or that Debian 11 left LTS
on 2026-08-31 and its new vulnerabilities are no longer published.

Hardened-base vendors answer this by selling their own distribution. Vulngraph should answer it
with root-cause guidance that does not depend on any vendor: say which base an image was
built on, whether that base is still supported, how much of the estate's CVE load comes from
it, and what to rebuild on instead. An operator who already pays for hardened images should
see those proposed first.

## Decision

### 1. Identify the base of every scanned image

The image-vuln scanner (`internal/scanner/imagevuln/baseimage.go`) reports a
`BaseIdentity` for every scan, from these sources in order of confidence:

1. **`annotation`**: the OCI pre-defined `org.opencontainers.image.base.name` and
   `org.opencontainers.image.base.digest`. These come from the manifest annotations, or the
   same-named config label, with the manifest taking precedence. Docker's official images set
   them (for example, `python:3.12-slim` names `debian:trixie-slim` and its digest).
   BuildKit sets them when provenance is on. The value is attacker-controlled, so whitespace,
   control characters and anything over 255 bytes are discarded. A digest is kept only if it
   is a `sha256:` digest. An annotation naming `scratch` is ignored: Docker's own base images
   (`alpine`, `debian`) annotate that way, and such an image is itself a base, which its OS
   release identifies.
2. **`os_release`**: no annotation, but os-release plus the OS package database identify the
   base OS release as an ecosystem coordinate (`Debian:12`, `Alpine:v3.20`, `Red Hat:9`). The
   coordinate is the one `pkginventory.OSCVEGap` already derives, so this ADR adds no OS
   detection of its own. That includes rpm images, whose release is read even though the
   package database is not. In this case the base image itself is unknown:
   `python:3.12-slim` and `debian:12` are both Debian 12.
3. **`unknown`**: neither source applies. That covers scratch and static images, dpkg without
   os-release (unqualified `Debian`) and apk without a release (unqualified `Alpine`). A
   coordinate with no release is not an identity: it would pool every release into one group,
   and no lifecycle applies to it. **Unknown is never "fine"**. It never produces an
   end-of-life finding, it never joins a group, and it counts against coverage.

A live check on 2026-10-08, pulling anonymously, gave these results. `python:3.12-slim`
resolved to annotation `debian:trixie-slim` and Debian:13. `nginx:1.27` resolved to annotation
`debian:bookworm-slim` and Debian:12. `debian:11-slim`, `alpine:3.18` (whose annotation is
`scratch`) and `gcr.io/distroless/static-debian12` resolved through os_release to Debian:11,
Alpine:v3.18 and Debian:12. `ubi9/ubi-minimal` resolved through os_release to Red Hat:9, with
0 packages because its rpm database is not parsed yet.

Layer-prefix matching against known official base digests was considered and not built. It
needs a maintained digest corpus for every tag of every official image, re-fetched as tags
move, and it identifies only unmodified official bases, which are the images most likely to
carry the annotation already.

### 2. Store the identity per digest, not on the asset

The identity goes into a new ClickHouse table, `image_bases`
(`ReplacingMergeTree(scanned_at)`, 30-day TTL), keyed by the container_image asset id. It is
not written to the asset's metadata. The kubernetes, ECS and Cloud Run collectors rewrite the
whole `container_image` row on every sync, so any key the scanner wrote would disappear within
one sync interval. The sweep records the identity as part of every clean scan, including
`unknown`. A missing row therefore means "not scanned yet", and never "scanned and lost". A
digest is immutable, so its identity never changes once it has been read.

The base-image job puts the identity onto an in-memory copy of each running image's asset
(`base_image`, `base_image_digest`, `base_image_source`, `base_os`,
`workload_internet_exposed`). Nothing writes those keys to the assets table.

### 3. Grade end-of-life base operating systems

`internal/distro`'s lifecycle table now covers every container base family: Debian, Ubuntu,
Alpine, Amazon Linux, RHEL/UBI, Rocky, Alma, Oracle, SUSE service packs, openSUSE Leap and
CentOS. The dates come from endoflife.date, checked 2026-10-08 and cited in
`lifecycle.go`. `container-image-os-end-of-life` (`internal/checks/container_image_eol.go`)
fires on a running image whose `base_os` is past the end of standard support. It is High when
a workload running the image is directly internet-exposed and Medium otherwise. Exposure means
a direct `exposed_to_internet` edge on a `runs_image` workload, the same rule as the
supply-chain image lineage (`enrich.SupplyChainExposure.imageDeployExposure`). A workload
behind a load balancer reaches the finding through enrich's internet-hops BFS instead. An
unknown or unlisted release never fires, and an image without `base_os` is not evaluable.

The check sits in `checks.ContainerImageChecks()`, not `Default()`. The sync-time run only
ever sees collector rows, which never carry `base_os`, so in `Default()` the check would be
permanently blind. It would also pull down `graph_check_evaluable_ratio` for no benefit.

A further consequence of extending the table: an Alpine branch or openSUSE Leap release past
its end now reports the `eol_distro` CVE gap, as every other final release already did.

### 4. Root-cause grouping: one finding per base, on a real node

`refresh_base_images` (`internal/jobs/baseimage.go`) runs on the enrich lane. The image sweep
and the OSV refresh enqueue it at the end of each run. It works on **running** images, meaning
a live `container_image` (seen within 48 h) with a fresh `runs_image` edge. For each base, the
base image the images name or otherwise their base OS release, it records one
`base-image-root-cause` finding with these fields:

- running images, workloads and directly exposed workloads built on the base;
- **base-layer CVEs** against **application-layer CVEs**, counted as distinct check ids over
  the open `supply_chain` findings on the images' `runs_package` purls, with the KEV count of
  each;
- the base OS lifecycle;
- recommendations and suggested `FROM` patches (section 5).

The finding is emitted only when the base has something to fix: at least one base-layer CVE,
or an end-of-life OS. Severity is High when a KEV in the base layer or an end-of-life OS sits
behind an exposed workload. It is Medium for either of those without exposure, or for
critical/high base-layer CVEs, and Low otherwise.

**Attribution heuristic.** A package from the distribution's package manager (its ecosystem
is a distro family, or its purl type is `deb`/`apk`/`rpm`) belongs to the base layer. A
language-ecosystem package (npm, PyPI, Go, Maven, RubyGems, crates) belongs to the application
layer. This over-attributes to the base any OS packages a Dockerfile installs on top
(`apt-get install …`). Layer-exact attribution would need the base image's own layer digests
compared against the image's, which the streaming scan does not resolve. The heuristic is
stated on every finding (`attribution=os_package_is_base`, and in the description).

The finding follows the `vm_vuln` fleet findings. It is a projection over the per-package
findings, which remain the unit of record and are not duplicated. It is placed on a real
member image, an exposed one where there is one, so enrich classifies it with that image's own
reachability. Its id is `DeterministicID("base-image-group", key)`, so it stays stable as
membership changes. Both finding kinds use the dedicated source `base_image` rather than
`cspm`, because the sync-time lifecycle reconcile closes an unemitted `cspm` finding on a
re-collected resource unless a registry check vouches that it could not evaluate it, and this
check is not in that registry.

**Reconcile.** Nothing is resolved after a truncated listing. A finding whose image or base no
longer runs is `resource_gone`. A finding whose base no longer has anything to fix is
`fixed`, unless evidence is merely missing. Resolution is withheld when a listed member still
runs but has no identity, when a member has no `runs_package` edge left (its scan has aged out
of edge freshness), or when an end-of-life finding's running image has lost its identity.
Every read failure fails the run instead of producing an image that looks unexposed or clean.

### 5. Recommendations are guidance, never a change

`imagevuln.Catalogue` (`catalogue.go`) proposes bases by the **runtime** the application layer
needs. The runtime is inferred from the images' purls: exactly one of PyPI, npm, Maven or
RubyGems decides it. Go or Rust alone means a static binary. Anything else means a minimal
glibc base. The proposals are, in order:

1. up to three catalogue entries for that runtime. The defaults are Google distroless,
   Wolfi/Chainguard and Ubuntu Chiseled, all checked as pullable on 2026-10-08;
2. the newest supported release of the image's own distribution (`distro.LatestSupported`),
   which is the smallest change and keeps the same package manager;
3. the newest supported Alpine branch, for an image not already on Alpine, with its musl
   caveat.

Items 2 and 3 are derived from the lifecycle table, so they never name a release that has
reached its end. Operators put their preferred bases (Docker Hardened Images, a vendor's
hardened distro, an internal golden image) **first** with `BASE_IMAGE_CATALOGUE`, a JSON file,
or use only their own with `replace_defaults`. The code privileges no vendor. A configured
file that is missing or invalid stops the worker; it never silently falls back to the
defaults.

When the image→repo lineage exists (`defined_in` from the `image_ownership` correlator), the
remediation renders a suggested patch for each owning repo as text:

```
acme/api — final stage of the image's Dockerfile (the image is declared in deploy/values.yaml):
-FROM <current Debian:11 base>
+FROM gcr.io/distroless/python3-debian13
```

The Dockerfile path itself is not known; the lineage records only the file that names the
image. **Vulngraph does not open the pull request.** Writing to a repository is a mutation. Under
ADR 087 it would be an approval-gated action that a person triggers through the executor. It
is not built, and this change adds no write path.

### 6. Coverage

`graph_base_image_running_images{identity="annotation|os_release|unknown|unscanned"}` counts
running images by identity state after every run, and the job logs `identified=N/M`. Coverage
is `(annotation + os_release) / sum`. A rising share of `unknown` or `unscanned` means lost
visibility, not a cleaner estate.

## Consequences

- An estate's base-image debt reads as a handful of findings with concrete replacements,
  rather than thousands of per-package rows. The per-package rows stay in place for KEV/EPSS
  and must-fix.
- No Ladybug change: no new edge type, nothing new in the loading set, and no `SchemaVersion`
  bump.
- Identities appear as digests are re-scanned. After deploy, fresh digests are skipped for up
  to `imageRescanAfter` (20 h), so coverage ramps over a day.
- Cost: one full read of `image_bases` and batched, freshness-gated edge reads (100 images,
  200 workloads per call). Package findings are looked up in batches of 1000 distinct purls.
  The distinct set is small because images on one base share packages.
- **Known gaps.** An image that fails with `ErrNoManifests` (scratch, no package databases)
  records no identity, even when it is annotated. The annotation is read from the
  platform-resolved manifest only, never from the index. The base/application split is a
  heuristic (section 4). Exposure is direct only (section 3).

## Alternatives considered

- **Write the identity onto the container_image asset.** Rejected because the collectors
  rewrite the row whole on every sync (section 2).
- **A synthetic `base_image` graph node with a `built_on` edge.** Rejected for now. It adds an
  edge type and an asset type to the graph pipeline (graphschema registration, liveness gates,
  a Ladybug decision) for a view a finding already provides. vm_vuln's real-member placement
  gives enrich real reachability, which a synthetic node lacks.
- **Our own hardened distribution.** Out of scope by design. Vulngraph recommends and does not
  ship images.

## Amendment (2026-10-09) — root-cause findings are the alerting unit

Outbound finding alerts fire on an urgency **transition**, not on every enrich. A finding is
*alertable* in the page band, in the `must_fix` class, or in the high band when a
reach-independent act-now floor lifted it there — an active-threat detection (GuardDuty
C&C/Backdoor/Exfiltration/PrivilegeEscalation/Persistence/Impact, GCP SCC high/critical), a live
leaked credential, a dangling-DNS takeover (`enrich.UrgentRegardlessOfReach`). Those floors only
ever reach the high band, so a page-only bar would have silenced them. Raw scanner severity no
longer alerts on its own. GuardDuty threats that no family marker names (AttackSequence:*,
Trojan:*, Execution:Runtime/ReverseShell, …) floor by GuardDuty's own severity — critical to page,
high to the high band — so they are alertable too. `Policy:*` types are excluded (standing
configuration such as root-credential use, not a live compromise); Recon and TorClient stay in.
Such a severity-floored GuardDuty finding also corroborates a lone `!DNS` observation on the same
host, as any independently floored threat does. `principal_class` (a human able to self-escalate)
and `identity_hygiene` (an SSO admin grant) also floor to High but are deliberately not alertable:
they describe standing posture, not a live compromise.

An alertable finding alerts when it first becomes alertable in an episode, enters `must_fix`, or
rises above the band it already alerted at — a per-finding high-water mark in
`finding_alert_state` (Postgres) that the store only ever raises. Re-enriching the same state (a
correlate sweep, the freshness backstop, a flapping graph read) sends nothing; a finding that falls
back and re-enters an urgency it already alerted at stays quiet.

- **Only a delivered alert is recorded.** If no channel delivered it — the channel list
  unreadable, every send failing, no channel accepting it — nothing is recorded and the finding's
  input fingerprint is cleared, so its next enrich (not the freshness backstop) tries again. The
  no-recipient warning is rate-limited; `GraphFindingAlertsReachNoChannel` pages on a sustained
  rate. With no channel configured at all nothing is retried (that would disable the
  change-gate). A finding resolved while its enrich runs records nothing and does not alert.
- **Resolving ends the episode.** `finding.Service.Resolve` tells `enrichcache` which findings it
  closed: their alert state is deleted and their fingerprint cleared, so a regression (the same
  deterministic id reopened by a later observation) is re-enriched on its first visit and pages
  again. Alert state for findings gone without a resolve (aged out by TTL) is pruned once no
  enrich has touched them for 30 days. Resolved findings are never enriched or alerted on.
- **The ledger is never seeded.** It is not derived from `enrich_cache.score_band`: "was in
  the page band" does not mean "was announced", so seeding could silence a page that never
  went out. A finding with no ledger row alerts on its first alertable enrich.

A per-CVE package finding that an open root cause carries stays open and visible but does not
alert itself (`enrich.SupplyChainExposure.AlertCarrier`), and only while the carrier
**currently holds at least the member's band** — a carrier below it never raised that page:

- **Base image.** Only container images run the package, it is a base-layer (distribution)
  package, and every one of those images is listed on an open `base-image-root-cause` finding at
  or above the member's band. A root cause whose image listing is capped (`running_images` above
  the listed count) carries nothing, nor does an image on an unidentified base. A root cause whose
  base layer carries a KEV floors to the page band (`RootCauseKEV`). Its membership counts
  (`base_layer_kev`, `base_layer_cves`, `running_images`, `exposed_workloads`) are part of its
  enrich fingerprint, so a base that gains a KEV member is re-scored as soon as the base-image job
  recounts it. Until then the newly-KEV member pages on its own (its carrier is below page), and
  the base pages too once re-scored: one duplicate, never a miss. A second KEV on a base that
  already paged stays silent — the base is still paging for the same rebuild.
- **VM fleet.** The package is fleet-canonical (only inventoried VMs run it and the `vm_vuln`
  fleets cover them) and the lowest-banded covering fleet is at or above the member's band. Its score
  is also capped below page even over its KEV floor (`Factor.RootCause`, the one cap a page floor
  does not beat), so ten fleets page ten times, not eleven. A changed fleet finding clears its
  package finding's enrich fingerprint so the regroup's re-enqueue is not skipped by the change-gate;
  a fleet's instance counts are part of its own fingerprint.

Suppressing a carrier silences its members too: a suppressed root cause raises no alert, and its
members stay carried while it holds their band. Suppress the members as well, or un-suppress the
carrier, if they must alert.

Every doubt answers "alert": a failed root-cause lookup, an application-layer package, a repo or
VM also running the package, a never-enriched carrier.
