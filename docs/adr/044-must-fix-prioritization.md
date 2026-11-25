# ADR 044 — Evidence-backed "must fix" prioritization

**Status:** accepted (implemented 2026-07-07; amended 2026-07-10, 2026-07-15, 2026-07-30) · amended 2026-10-23 (storage superseded by ADR 075; containment moved to the critical tier)

> **Amendment (2026-10-23) — storage superseded by ADR 075.** These outputs live in
> `finding_enrichment` (ClickHouse), written by enrichment writers (enrich and the
> KEV refresh) and LEFT JOINed on read; `findings` has no enrichment columns.

> **Amendment (2026-10-23) — containment moved to the critical tier.** `runs_package`,
> `runs_image` and `runs_container` are in the uncapped critical tier, enforced by
> `graphschema.TestReachAndInheritTypesAreCritical`, because the bulk tier's shared row cap
> starved alphabetically-late types to zero and silently disabled the "contained" demotion.
> The "Deliberate divergence" section below is superseded: the 150k per-type cap and the
> "failed bulk pass reports reach incomplete" consequence no longer apply to containment. The
> bulk per-type cap is now 500k (`asset/repo.go` `syncBulkPerTypeLimit`).

## Context

The contextual score answers "how bad is this in the abstract", but operators need
"which of these many findings must I fix *now*, and which is longstanding hygiene I can
leave?". A hypothetical example of the failure: an IAM privilege-escalation finding,
open for years on a role that can only be assumed through an identity provider with MFA,
scores high — yet it is not urgent, because an external attacker cannot reach it and the
assumption path is gated by a real control. Three signals that decide real urgency were **present in the graph / the
collected data but never scored**: (1) whether an attacker can actually *reach* the
resource from the internet, (2) how *long* the finding has existed, and (3)
*compensating controls* (MFA-required / IdP-federated assumption) that neutralize
the path. So a high score was conflated with "must fix", and controlled/unreachable/
longstanding findings drowned out the few that matter.

## Decision

Two orthogonal, fail-open mechanisms, both mirroring the existing additive-scorer
(ADR 014/024) and the ADR-043 `safety_class` pattern:

1. **New enrich `Source`s adjust the score** with the missing evidence:
   - `InternetReach` — promotes transitively internet-reachable resources (+points
     by hop distance) and **strongly demotes definitively-unreachable** ones
     (negative points, *not* suppression — "strong demote, not silence": internal/
     lateral risk stays visible, just far lower).
   - `IdentityHygiene` — reads real IAM metadata (MFA, federation, key age,
     activity). **Demotes to monitor** (`Suppress`) a privesc path gated by a
     compensating control (MFA-required or SSO/SAML/OIDC federation); **elevates**
     genuinely weak identities (no-MFA console user, wildcard trust, un-MFA'd human
     who can federate in).
   - `FindingAge` — demotion-only nudge for findings present > 90d / > 1y.
2. **A persisted `must_fix_class` tier** (CH columns, like `safety_class`), computed
   at enrich by a pure classifier: **`must_fix` = internet-reachable AND exploitable
   (KEV or active privesc) AND real blast radius AND present AND uncontrolled**;
   `contained` (unreachable), `controlled` (compensating control), `elevated`
   (high-signal but not all conditions). A leaked secret (`ghas_secrets`) is graded
   on its own axis instead, since a working key works from anywhere once read. The
   only evidence that a key works is GitHub's validity check (the alert's
   `validity`: `active`, `inactive` or `unknown`, absent where validity checks are
   off); Vulngraph runs no check of its own. A non-test-mode credential in a
   public repository is `must_fix` when validity is `active` or unknown (unknown
   is never treated as safe, but its reason says "validity unknown" rather than
   that the key works); in a private or `internal` repository it is `elevated`;
   a test-mode credential or one GitHub reports `inactive` is `contained`
   (`assessGHASSecretsMustFix`). A `must_fix_reason` string carries the
   evidence ("internet-reachable (2 hops) · KEV · blast 42"), surfaced on the list
   and a "Must fix" Findings view (the default landing).

**Reachability is computed once per graph rebuild as a Ladybug node signal**
(`internet_hops`, a bounded attacker-movement BFS from internet-exposed seeds —
`graphstore/reach.go`), read per-finding for free via the cached `TryNodeSignals`
(exactly how `exposed`/`privesc_count` already work). NO per-finding reverse BFS —
that is the cost ADR 024 exists to avoid. The BFS deliberately traverses only
attacker-movement edges (`executes_as`/`has_role`/`can_assume`/`can_escalate_to`/
`accesses_secret`) and **excludes `federated_access`** — an SSO-only admin role is
reachable via the federated identity (Okta + MFA), NOT from the raw internet, so it
correctly lands `contained`+`controlled`. Adding the column bumped the Ladybug
`SchemaVersion`.

### Guardrails (the design's load-bearing invariant)

**Absence of evidence never demotes.** Unknown reachability, missing identity
metadata, a nil provider, or a graph read error contribute *nothing* — a demotion
requires *positive* evidence of a control or of unreachability, and a must-fix
promotion requires positive reachable+present evidence. **KEV is never demoted** by
any source (central `score.go` Page floor + a per-source self-check). This is what
prevents the noise-reduction from ever hiding real risk.

The enrich fingerprint version is bumped (one-time global re-enrich so the new scoring
takes effect) and gains a `ReachBucket` input so a topology change that makes a
resource reachable re-scores it. `enrich` does not import `graphstore`/`respond`
(ADR 010) — small classifier helpers and the reachability sentinels are duplicated
with tests, as ADR 043 did.

## Consequences

- The "Must fix" view is a small, defensible, evidence-backed set from day one; the
  years-old-privesc-behind-SSO class is demoted out of it with the reason shown.
- Advisory only — `must_fix_class` does not gate the OPA policy (ADR 030); it labels
  and filters. Demotions cap/reduce the score; the reasoned `respond` verdict remains
  authoritative.
- Orthogonal to `safety_class` (ADR 043): "must I fix it?" vs "will fixing it break
  something?" — a must-fix finding is often `risky` to fix; together they are the
  full triage matrix.
- One-time re-enrich sweep on deploy and a full Ladybug rebuild — both normal,
  expected, and self-healing.
- The compensating-control demotion depends on trust-policy metadata from the
  collector; where that metadata is absent the demotion simply does not fire (fail-open).

Cites ADR 043 (the safety_class pattern it mirrors), 024 (change-driven enrich +
fingerprint), 025/026 (the graph + node signals), 014 (the additive scorer), 030/005
(the reasoner it complements), 031 (human-identity federation), 010 (layering).

## Amendment (2026-07-10) — reach edges are uncapped and truncation fails open

Two gaps in the original implementation undercut the "absence of evidence
never demotes" invariant:

1. `has_role` — listed here as a reachability edge — actually sat in the CAPPED
   bulk sync tier (combined 500k-row limit) with no `ORDER BY`, so on a large graph
   truncation was nondeterministic per rebuild. Reach paths through instance profiles
   could silently vanish.
2. A node present in Ladybug but missing its reach edges read `ReachNone`
   ("definitively unreachable"), which classified its findings `contained` —
   demoted with the missing edges as the only evidence. A transient bulk-pass
   failure did the same to the whole graph generation.

Changes (with a `SchemaVersion` bump): every `Reach` edge type must be in the critical
(uncapped) tier — enforced by `TestRegistryConsistency` in `internal/graphschema`;
the bulk fetch is per-type capped (`LIMIT n BY edge_type`) and deterministic
(`ORDER BY` before the caps); and the sync carries truncation accounting
(`asset.EdgeSyncResult`) so an incomplete reach fetch degrades not-reached nodes
to `ReachUnknown` — must-fix runs fail-open instead of demoting. The
`graph_ladybug_reach_complete` and `graph_ladybug_edge_cap_hit` gauges alert on it.

## Amendment (2026-07-15) — supply-chain + image reachability lineage

The must-fix reachability traversal now also walks the container-image supply-chain
lineage `package ← runs_package ← container_image ← runs_image ← k8s_pod → internet`
(alongside the existing repo lineage), so an image-vuln finding on an internet-exposed
pod reaches `must_fix`/`elevated`. See ADR 057 for the image→package→CVE scanner and
the `runs_package` edge that lineage rides on. The enrich gate that decides *when* the
reachability BFS runs was also widened to network-addressable resource types — see
ADR 060.

## Amendment (2026-07-30) — containment inheritance; the 2026-07-15 lineage was never implemented

The 2026-07-15 amendment described the image lineage as working, but no code walked
it and no end-to-end test covered it. Once image scanning (ADR 057) produced findings,
image package findings — including critical and high severity ones — carried an
**empty** `must_fix_class` and fell to the `monitor` band. Two independent gaps, either
one sufficient:

1. **The BFS could not walk containment.** `runs_image` and `runs_package` were never
   `Reach` edge types, and `internetHops` traverses only `ReachEdgeTypes()`. Even had
   they been, `maxReachDepth = 3` is one hop short of a package:
   internet→ingress(0)→service(1)→pod(2)→image(3)→**package(4)**.
2. **The classifier never asked.** `assessSupplyChainMustFix` consulted only
   `PackageDeployExposure` (the repo/`deploys_to` lineage) and returned blank on
   `!anyDeployed`. An OS package inside a base image has no dependent repo and no SBOM
   entry, so that path can *never* resolve for the apk/deb findings image scanning
   exists to produce.

### Decision: containment is inherited, not traversed

Containment (`runs_container`, `runs_image`, `runs_package`) is declared `Inherit` in
`internal/graphschema`, and `internetHops` runs a post-BFS closure that copies a
reached node's hop count to everything inside it **without incrementing depth**.

A package inside an image on a pod is not three hops further from the internet than
that pod — it *is* that pod's attack surface. Modelling it as inheritance is both more
truthful and cheaper than the alternative of raising `maxReachDepth` to 5, which would
have loosened every identity chain (`can_assume` → `can_escalate_to` → …) at the same
time and inflated reachability corpus-wide. Containment therefore stays out of
`ReachEdgeTypes()`, which remains strictly attacker *movement*.

`assessSupplyChainMustFix` now weighs both lineages independently: exposure found by
either earns `elevated`; `contained` requires that at least one positively resolved and
neither found exposure; neither resolving still leaves the class blank (fail-open).

### Deliberate divergence from "every reach type is critical-tier" (superseded — see the 2026-10-23 amendment)

The 2026-07-10 fix above put every `Reach` type in the uncapped critical tier so a row
cap can never hide a path. The `Inherit` types are **bulk** tier and stay there: the
three are high-cardinality, and moving them into an uncapped fetch would remove the
runaway guard that bounds worker memory.

Truncation safety comes from `EdgeSyncResult.ReachComplete()` instead, which now covers
`Inherit` types as well as `Reach` types — a truncated `runs_image` degrades reach to
`ReachUnknown` (fail-open), never `ReachNone`. One consequence is intentional: because
containment lives in the bulk tier, a *failed bulk pass* now reports reach incomplete
where it previously did not. Losing demotions during a bulk outage is the safe
direction; silently marking image CVEs "contained" is not.

The per-type bulk cap (150k) applies to `runs_container`, `runs_image`, and
`runs_package`; exceeding it degrades reach to `ReachUnknown` as above. A `LogicVersion` bump forces
the one-time full re-enrichment that makes this apply to the standing corpus (ADR 069).
