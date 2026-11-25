# ADR 081 — Deletion authority: shadow mode by default, enforcement per operator-named type

**Status:** accepted — amended 2026-08-25 (twice) and 2026-10-23 (see Amendments). Six types are
audited (`ec2_instance`, `security_group`, `vpc`, `elastic_ip`, `subnet`, `gce_instance`), but only
two can be enforced: `security_group` and `vpc` (`forget.TombstoneEligibleTypes`). Under
`FORGET_MODE=enforce` a type is tombstoned only if it is named in `FORGET_ENFORCE_TYPES`, and an
unset list enforces nothing. Any other value in `FORGET_ENFORCE_TYPES`, including an audited type
such as `ec2_instance`, fails worker startup. The other audited types stay shadow-only until
`EnumerationShrinkFraction` is calibrated for them and the allow-list is widened in code.

## Context

Nothing in this platform is ever authoritatively forgotten: no code path deletes an asset on
absence alone. The observe-only per-scope completeness signal from ADR 054's 2026-08-21
amendment (`collect.Result.CompletedEnumerations` / `MarkComplete`) proves which collector
scopes enumerate completely enough to make absence meaningful, and stops there — its own doc
comment sketches, but does not implement, the refusal thresholds an enforce mode would need.

Without forgetting, stored compute ids that their own connector's most recent sweep no longer
observes accumulate indefinitely, and attack paths are computed over all of them. Connectors
that never complete a full enumeration make this worse.

Acting on absence is dangerous in the other direction. A scope-blind deletion can drop live
resources from the graph and wrongly auto-resolve their findings, and there is no undo for that
class of mistake: a resolved finding and a graph node that silently stopped existing both look
like success until someone goes looking.

## Decision

Ship the decision engine (`internal/app/forget`) with two modes, `shadow` (default) and
`enforce`.

**In both modes**, `forget.Service.Evaluate` runs at the end of every sync sweep, for every
scope the sweep proved complete, and:

1. Reads the scope's stored population from ClickHouse (`asset.ScopeStaleness`) — total rows,
   rows not re-observed by this sweep, rows absent longer than `ConfirmWindow`.
2. Applies every refusal below, in the fixed order in `Decide` (cheapest and most categorical
   first — the order is for the RECORD, not the outcome, since every path either refuses or
   returns a count).
3. Writes the verdict to Postgres (`forget_scope_state`) and publishes it as
   Prometheus gauges (`internal/obs/metrics_deletion.go`).

**Only in `enforce` mode**, a scope that survives every refusal gets its confirmed-absent ids
fetched (`asset.ScopeCandidateIDs`, bounded by `MaxForgetPerSweep`) and written to
`forget_tombstones` — see "Tombstone, never delete" below.

### Enforcement scope: six audited families, and nothing else

`forget.enforceableFamilies` is a second, hand-audited gate in front of the collector's own
completeness claim — a family appearing in `CompletedEnumerations` gains no deletion authority
until someone reads its pagination and error handling end-to-end and adds it here:

| family | types | region-scoped |
|---|---|---|
| `ec2:instances` | `ec2_instance` | yes |
| `ec2:security-groups` | `security_group` | yes |
| `ec2:vpcs` | `vpc` | yes |
| `ec2:addresses` | `elastic_ip` | yes |
| `ec2:subnets` | `subnet` | yes |
| `compute.instances` | `gce_instance` | no (GCP `aggregatedList` covers every zone) |

**Deliberately excluded, with reasons, so widening this list is a conscious ADR edit:**

- **GitHub** (`listRepos` pages out early by design), **Kubernetes** (RBAC `Forbidden` on some
  lists is *expected*, not a completeness failure), **Azure** (no audited collector family), and
  every other AWS/GCP family that declares nothing. Auditing each pagination loop is separate
  work; a family with no `MarkComplete` call reaching it has no claim to evaluate.
- **Everything downstream of a node** — findings, edges, belief rows. See "Tombstone, never
  delete" below; this ADR governs node (asset) forgetting only.

`TestEnforceableFamiliesAreDeclaredByACollector` pins the allow-list textually against the two
collector source files, and is mutation-verified (see "Guards").

### Thresholds

Every constant lives in `internal/app/forget/domain.go` next to its rationale; summarized here
because ADR review is where they get revisited.

| threshold | value | rationale |
|---|---|---|
| `RelativeRefusalFraction` | 1/3 of stored population | conservative cap; known not to separate truncation from churn (below) |
| `MinScopePopulation` | 10 | small scopes give ratios too noisy to act on |
| `MaxForgetPerSweep` | 500 | sized to be reviewable by a human, not merely to tolerate normal churn |
| `ConfirmWindow` | 2 hours | spans several completed enumerations at normal sync cadence |
| `EnumerationShrinkFraction` | 0.5 | **not calibrated** — placeholder, shipped saying so |
| `HighWaterTTL` | 7 days | longer than `ConfirmWindow`, short enough that a genuine account shrink drains promptly; a design choice |

**The relative cap does not separate the two cases it exists to separate.** Spot and autoscaled
fleets can turn over a large fraction of their population within a sweep interval, so the tail
of legitimate hourly disappearance per scope reaches and can exceed the cap; in the extreme,
churn backfills a listing that returned almost nothing. No ratio threshold distinguishes a
truncated listing from a bad hour, because a threshold loose enough to tolerate the churn tail
would also admit a listing returning nothing at all.

It is kept at 1/3 anyway because the two failure modes are not symmetric: a too-tight cap
refuses to forget, which is the status quo and costs nothing new; a too-loose one wrongly drops
live resources. The intended separator — `EnumerationShrinkFraction`, which reads the listing's
own returned count against its high-water rather than the candidate count against stored
population — is the test that can tell "10 instances terminated" (births balance deaths, size
holds) from "the listing silently returned half the fleet" (size moves, nothing else does).
**It is not calibrated.** The series it needs — one enumerated count per scope per sweep, over
weeks — was not available before this change: the Prometheus gauges from ADR 054's amendment are
process-lifetime (the worker restarts on every deploy), and ClickHouse's `assets` table cannot
supply it because `ReplacingMergeTree` merges collapse the per-sweep rows. `forget_scope_state`
exists specifically to start accumulating it. **0.5 is a placeholder bound, and enforcement for
a type must not turn on until it has been calibrated for that type.**

### Tombstone, never delete

`ModeEnforce` writes to `forget_tombstones` (`asset_id PRIMARY KEY`, `believed_gone_at`,
`ON CONFLICT DO NOTHING` — the first belief is kept, not the latest, because the column answers
"since when" and a re-stamping write would turn an audit trail into a clock). **It never issues
a `DELETE` against ClickHouse, never resolves a finding, and never removes a graph edge.**

This is a deliberately narrower claim than "deletion authority" suggests:

- A tombstone is a recoverable, auditable record a later, SEPARATE decision can act on, discard,
  or override. A ClickHouse `DELETE` is not recoverable at all, and an auto-resolved finding is
  recoverable only by re-detecting the same issue from scratch.
- **What consumes a tombstone is explicitly out of scope for this ADR.** ADR 054 already governs
  finding resolution on asset deletion (`findDeletedAssets`, gated on `!Result.Partial`) — a
  tombstone is not wired to it, and doing so is a separate, later decision with its own review.
  Until then, a tombstoned asset keeps behaving exactly as before: present in Ladybug, present in
  the graph, present in every read.
- Graph edges keep their own liveness discipline (ADR 049: re-stamp + freshness filter, no
  deletes) independently of this mechanism — unreferenced edges already age out on their own
  schedule.

### Refusing on unknown edge health, not just partial sweeps

`RefusalEdgeHealthUnknown` and `RefusalEdgeTruncated` extend ADR 054's `Partial` gate to the
graph's own last edge fetch (ADR 049's `TruncatedEdgeTypes`, ADR 077's fidelity gate). Edges are
re-stamped rather than deleted and every reader filters on freshness, so a truncated edge fetch
already *looks like* mass edge deletion to anything reading the graph — taking a node-deletion
decision on top of a known-partial topology compounds exactly the failure ADR 077 was written to
stop. A `nil` `EdgeHealth` (a pod without Ladybug) is **not** read as healthy: every scope then
refuses with `edge_health_unknown`. This costs nothing in shadow mode — the counts are still
recorded — and is the fail-closed answer for a pod that cannot say.

### Second gate re-derived from the key, not trusted from the caller

`Decide` re-runs `ParseScope(in.Scope.Key)` itself rather than trusting a `Scope.Family` a
caller already attached. `ParseScope` is the *one* predicate for "may this scope forget
anything"; a caller that hand-built a `Scope` — or parsed a key one character off an audited
family — must not be able to hand `Decide` an already-blessed family. This defends against a
recurring bug class in this codebase (label/type drift across a layering seam): a one-character
typo in a scope key must fail loudly as `not_enforceable`, not silently disable enforcement for
the scope while the allow-list still claims to cover it.

### Guards

Two rows in the `internal/guardmutation` catalogue (mutation-verified structural guards):

- `TestForgetNeverActsWithoutProvenCompleteness` — the mutation disables the `ParseScope`
  enforceability check in `Decide` (`if false` in place of `if _, ok := ParseScope(...); !ok`).
  With the check gone, every population/candidate computation runs for an unaudited or
  malformed scope key exactly as it would for `ec2:instances`; the guard asserts the specific
  refusal reason (`not_enforceable`), not merely "was refused", so a different refusal reason
  reaching the same zero-forgettable outcome still trips it.
- `TestEnforceableFamiliesAreDeclaredByACollector` — the mutation renames the `MarkComplete`
  family key AWS's EC2-instance collector declares (`"ec2:instances"` → `"ec2:instance"`),
  reproducing the drift class the allow-list is built to catch: a family stays allow-listed
  while the collector has silently stopped proving it complete.

Both are exercised by `go test -tags=guardmutation ./internal/guardmutation -run TestGuardsBite`,
which applies each mutation, confirms the guard fails, and restores the tree byte-for-byte.

## Out of scope

- **Any family beyond the six above**, including every GCP/Azure/K8s/GitHub family that is not
  `compute.instances`. Widening this list is a future ADR amendment, made after auditing the new
  family's pagination loop the same way these six were.
- **Enforcement for a type whose `EnumerationShrinkFraction` is uncalibrated.** This is a
  recommendation to operators, not a code check: `FORGET_ENFORCE_TYPES` accepts any audited
  type. The recommended setting enforces `security_group`/`vpc` only.
- **Anything that consumes a tombstone.** Finding resolution, edge removal, graph pruning — all
  unchanged.
- **Findings, edges, or any non-asset row.** This ADR is about forgetting *asset nodes* only.

## Consequences

- In shadow mode the gauges `graph_forget_shadow_candidates`, `graph_forget_would_forget` and
  `graph_forget_refusals_total` populate once sweeps complete with `forget_scope_state` behind
  them. A unit fixture in `domain_test.go` reproduces the shape of a large stale backlog — nearly
  the whole stored population confirmed-absent — and refuses on `relative_cap`, which is the
  correct answer: near-total absence is not distinguishable from a broken listing until
  `EnumerationShrinkFraction` is calibrated, so shadow mode's honest output on such a corpus is
  "nothing yet forgettable".
- `GraphForgetTombstonesInShadowMode` (`deploy/helm-chart/graph/alerts/rules.yaml`, severity
  warning) fires if any tombstone is ever written while `graph_forget_enforcing` reads 0 — a
  combination that should be structurally impossible (`ModeEnforce` is the only writer) and
  therefore means the mode gate itself was bypassed in code, not a threshold tuning problem.
- `graph_forget_enforcing` is a boot-time gauge; changing `FORGET_MODE` requires a pod restart,
  which is the correct friction for a deployment-time switch with no live toggle.
- The mechanism composes with, and does not replace, ADR 054's connector-level `Partial` gate or
  ADR 077's rebuild fidelity gate — it adds a third, narrower gate (per scope, per type) in front
  of node deletion specifically.

## Runbook

**Shadow mode (default):** nothing to do. `FORGET_MODE` unset or `shadow` records verdicts and
writes zero tombstones. Confirm with `graph_forget_enforcing == 0` and watch
`graph_forget_would_forget` / `graph_forget_refusals_total` for at least the `HighWaterTTL`
window (7 days) before trusting a shrink-refusal reading.

**Before enabling enforcement for a type:**
1. Let shadow mode accumulate `forget_scope_state` history (the Postgres table shadow mode
   writes) for `EnumerationShrinkFraction` calibration — weeks, not days.
2. Recompute the fraction against that history and amend this ADR with the number before
   enabling the type anywhere, including staging.
3. `FORGET_MODE` is process-wide, not per-connector: enable on a single non-production
   deployment first and watch `forget_tombstones` row counts against `MaxForgetPerSweep` for
   several sweeps before enabling it on a production worker.

**To roll back:** set `FORGET_MODE=shadow` (or unset it) and restart the affected pod(s).
Existing rows in `forget_tombstones` are left in place — they are a historical record, and
nothing currently reads that table. If `GraphForgetTombstonesInShadowMode` fires, treat it as a
code defect (the mode gate was bypassed), not a data problem: no tombstone forces any downstream
action by itself.

**To widen enforcement beyond the six audited types:** this is not a config change. It requires
reading the new family's pagination and error handling end-to-end, adding it to
`forget.enforceableFamilies`, and amending this ADR.

Amends ADR 054 (extends its per-scope completeness signal into the enforce-mode design that
signal's doc comment sketched) and ADR 022 (the diff-sync deletion path this eventually feeds).
Builds on ADR 049 and ADR 077 for the edge-health refusal.

## Amendments

### 2026-08-25: `FORGET_ENFORCE_TYPES` — enforcement scoped per asset type

`FORGET_MODE` was a single all-or-nothing switch: `enforce` armed tombstoning for every audited
type at once. That was too coarse: evidence for `security_group`/`vpc` deletions can be
verified independently, while `ec2_instance`/`gce_instance` depend on `EnumerationShrinkFraction`,
the one guard that would catch a truncated listing on those types and which remains a
placeholder. There was no way to enable the former without also arming the latter.

**Mechanism:** `FORGET_ENFORCE_TYPES` (comma-separated asset types, `forget.ParseEnforceTypes`)
is a second, additive filter checked alongside `enforceableFamilies` before a tombstone is
written. `Service.enforceScoped(assetType)` is `mode == ModeEnforce && enforceTypes[assetType]`
— both halves required:

- Under `FORGET_MODE=shadow`, `FORGET_ENFORCE_TYPES` has **no effect**, regardless of its value.
- Under `FORGET_MODE=enforce`, only named types get a tombstone written. Every other audited type
  is still evaluated and recorded (`forget_scope_state`, `graph_forget_shadow_candidates`,
  `graph_forget_would_forget`); it simply never reaches `tombstonesFor`. Evaluation is never
  skipped by this filter; only the write is.
- **`FORGET_ENFORCE_TYPES` unset while `FORGET_MODE=enforce` enforces NOTHING** (fails closed),
  per ADR 080's principle that the safe value is the zero value. Defaulting unset to "every
  audited type" would let a bare `FORGET_MODE=enforce` re-arm `ec2_instance`/`gce_instance` by
  accident.
- Only `security_group` and `vpc` may be named (`forget.TombstoneEligibleTypes`). Any other
  name, a typo or an audited type such as `ec2_instance`, is an error and the worker does not
  start. `Service.enforceScoped` also checks that set, so widening it is a code change.

**New metric — `graph_forget_would_enforce`** (`internal/obs/metrics_deletion.go`), same labels
as `graph_forget_would_forget`, which is deliberately unchanged: it still reports what `Decide()`
permits, independent of operator configuration. `graph_forget_would_enforce` is the
`FORGET_ENFORCE_TYPES`-scoped subset; the difference between the two reads as "would forget, but
this type is not in the enforce scope". It is a new series rather than a new label, so nothing
already summing `graph_forget_would_forget` changes shape.

**Deployment wiring:** both env vars are templated in the shared `graph.podEnv` block
(`deploy/helm-chart/graph/templates/_helpers.tpl`), included by the worker, serve and scanner
deployments; only the worker constructs a `forget.Service`, so the vars are inert elsewhere.
Values `forget.mode` / `forget.enforceTypes` default to `shadow` / empty, preserving prior
behaviour.

### 2026-08-25: enforcement recommended for `security_group`/`vpc`

The recommended values override is `forget.mode: enforce` and `forget.enforceTypes:
"security_group,vpc"`. These two types were chosen because their deletions can be confirmed
independently of the uncalibrated shrink guard. With that setting the other audited types are
still evaluated every sweep and get no tombstone; an operator who names them gets them enforced.

**Verifying a correctly enabled worker:** `FORGET_MODE=enforce`,
`FORGET_ENFORCE_TYPES=security_group,vpc`, `graph_forget_enforcing 1`. On a fresh enablement
`graph_forget_tombstones_written_total 0` is expected — a scope must survive every refusal in
`Decide` (population floor, relative/absolute cap, confirm window, edge health) before its first
candidate can be tombstoned.

**What to watch:**

- `graph_forget_tombstones_written_total` — should stay small and explainable (an actual
  `security_group`/`vpc` teardown), never a sustained climb. Correlate a jump against the
  originating connector/account before treating it as expected churn.
- `graph_forget_would_enforce` against `graph_forget_would_forget` for the same types — a
  divergence means the allow-list and `Decide`'s verdict disagree unexpectedly.
- `GraphForgetTombstonesRunawayVolume` (`deploy/helm-chart/graph/alerts/rules.yaml`, severity
  warning) — fires if tombstone writes exceed 2,000/hour while `graph_forget_enforcing == 1`.
  `GraphForgetTombstonesInShadowMode` stays live as the "mode gate bypassed" guard.
- `graph_forget_enforcing` reading 0 after enablement means the pod did not pick up the new env
  var (restart required) or the values file regressed.

Widening enforcement to `ec2_instance`/`gce_instance` means adding them to
`forget.TombstoneEligibleTypes`, governed by the Runbook's "Before enabling enforcement for a
type" steps.

### 2026-10-23: `ec2:subnets` is audited

`ec2:subnets` was excluded because a subnet's stored `region` column held its availability zone
(`eu-west-1b`), not the region its scope key carries, so the scope's population could not be
selected exactly. `collectSubnets` (`internal/collect/aws/network.go`) now stores the region and moves
the AZ to `Metadata["availability_zone"]`, and `ec2:subnets` (type `subnet`) is in
`forget.enforceableFamilies`, so it is audited in shadow mode. It is not in
`forget.TombstoneEligibleTypes`, so it cannot be enforced without a code change.
