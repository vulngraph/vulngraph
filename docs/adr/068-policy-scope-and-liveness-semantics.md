# ADR 068: Policy scope/deny semantics, and liveness vs row-presence

**Status:** accepted (2026-07-25) · amended 2026-07-31 (liveness applies to the graph's input), 2026-08-02 (`last_seen` was never a liveness signal)

## Context

ADR 066 gave the CIEM evaluator real boundary/SCP intersection, and a follow-up consolidated
the AWS collector's `isAdminish`, the `allows_action` correlator and the secret-access
correlator onto that evaluator. An audit of what that consolidation did not reach found the
same bug class in further places, plus defects inside the shared evaluator. Separately, a
finding-lifecycle bug of a different kind kept findings on deleted resources open
indefinitely.

Each item below is covered by a regression test that fails when the fix is reverted.

### The recurring bug class: a narrower re-implementation of policy semantics

Several hand-rolled parsers answered "is this allowed?" by scanning `Effect == "Allow"` one
document at a time. Trust policies were the last surface doing so, across four parsers (three
in the AWS collector, one duplicated in `internal/app/correlate`). Two common hardening idioms
were therefore invisible:

- `Allow AWS:*` + `Deny unless aws:PrincipalOrgID` — the standard organization-confined
  cross-account trust — was graded a **public** trust.
- `Allow` + `Deny unless aws:MultiFactorAuthPresent` — how MFA on assumption is actually
  written — was read as **no MFA**, discarding a compensating control.

Both errors inflate severity and propagate: `trust_entry`, `PublicEntry` and `RequiresMFA`
drive a privesc score cap (`ciem.entryCap`), a hard enrich suppression, must-fix demotion,
belief evidence, a graph column and the assistant's prompt.

### Defects inside the shared evaluator

1. A Deny expressed with `NotAction` expanded to zero targets and vanished — `Deny
   NotAction:[s3:*]`, the standard service-restriction SCP, permitted everything.
2. Boundary/SCP presence was recorded only inside the `Allow` branch, so a boundary consisting
   only of Denies was never intersected. A boundary that allows nothing must permit nothing.
3. `narrowerPattern` recognised only containment, so `ec2:Describe*` capped by a boundary
   allowing `ec2:*Instances` — both admitting `ec2:DescribeInstances` — was dropped as
   non-overlapping, erasing the grant.
4. Deny matching ignored resource scope: a single `Deny iam:PassRole on role/break-glass`
   suppressed the whole privesc path.
5. The first fix for (4) introduced a worse bug: `CoversResource` fed an Allow's resource
   *pattern* into a value matcher, so `Deny …Resource:"?"` (matching only one-character ARNs)
   was judged to cover `Allow …Resource:"*"`, because the string `*` matches the pattern `?`.
   One decoy statement could erase a Critical.

### Liveness is not row presence

`internal/jobs/dangling.go` resolved findings whose resource was gone by calling `ExistingIDs`
(`SELECT id FROM assets WHERE id IN (…)`). Asset rows are never deleted from the
ReplacingMergeTree; they stop being refreshed. A pod deleted long ago therefore read as live,
and the k8s lifecycle sweep could never resolve a finding. The sweep also paged newest-first
from a cursor that reset every tick, so the per-check ceiling (`danglingScanMax`) re-examined
the same newest findings — all on live pods — forever. The sweep's spec comment had always
described the criterion in terms of `last_seen`; only the implementation disagreed.

## Decision

**One evaluator per question.** `ciem.EvaluateTrustPolicy` joins
`EffectivePermissionsForPolicies` as the second and last authority on AWS policy. All four
collector helpers and the duplicated correlator parser delegate to it; the duplicate is
deleted.

**Trust evaluation is Action-aware and IfExists-aware.** A trust policy's Action names which
assumption method a statement governs, so each Allow is judged only against Denies that reach
its method. Only `BoolIfExists`/`Null` MFA denies and `...IfExists` negated scoping operators
are credited as protection: a bare `Bool` or `StringNotEquals` does not match an absent
condition key, so the Deny never fires for a caller who presents none. Reporting the weak form
as protected was the bug; the resulting finding correctly signals a miswritten guardrail.

**Unprovable suppression is refused.** `patternCoversPattern` proves glob containment only for
shapes that occur in practice and returns false otherwise. An unproven suppression hides a
privilege; an unproven retention is at worst noise. The same asymmetry justifies the opposite
choice in `narrowerPattern`: overlapping patterns without containment keep the grant,
over-approximating the cap.

**Liveness is `last_seen`, anchored to the provider's own high-water mark.** Never wall-clock,
which would mass-resolve the estate the moment a collector broke. `ProviderHighWater` freezes
when collection for the whole provider stops, so a provider-wide outage is not mistaken for mass
deletion, and a 72h grace (`resourceGoneGrace`) absorbs missed ticks. The mark is per provider
(per type for the k8s_pod ephemeral sweep), not per connector: one broken connector among several
of the same provider does not freeze it, so that connector's resources are judged gone after the
grace. The sweep pages `OldestFirst` with
`DetectedBefore`. The ceiling is retained — it guards ClickHouse query load and the River job
timeout, not memory — as is the per-phase budget split.

**Noise is calibrated against typical clusters.** Unfiltered, the new
`k8s-cluster-role-dangerous-permissions` check (since split into the per-capability `k8s-rbac-*` checks) fires heavily on Kubernetes bootstrap
defaults and provider-managed roles, which are dangerous by design and not user-changeable;
platform-managed roles are excluded. `lease-hijack` was removed outright: leader election is
how every controller works.

**The graph schema** adds `BindsK8sWorkload` (`K8sWorkload→Asset`) and sets `Reach`/`Expand`
on `binds`. `k8s_service_account` is `K8sWorkload`-labelled while `Binds` was
`Asset→Asset` with no reroute, so `ServiceAccount → ClusterRoleBinding` rows were discarded at
COPY — the identity half of every RBAC chain. This is the fourth instance of this
label-mismatch class (after `executes_as`, `defined_in` and `targets`).

## Consequences

Finding counts move in both directions, deliberately:

- **More** AWS privesc/admin/secret findings survive — narrow guardrail Denies, decoy patterns
  and `NotAction` SCPs no longer suppress them wholesale.
- **Fewer** Lambda public-access findings — `Effect` was never read, so Deny lockdown
  statements were counted as grants.
- **Fewer** false public-trust and lost-MFA verdicts.
- K8s RBAC findings leave the `monitor` band: High RBAC findings had been sitting below
  `ThresholdPipeline` (50) with an empty `must_fix_class`. The `SignalFloor` addition keys on
  type, so it deliberately also rescues pre-existing checks, not only the new one.
- `CIS-AWS-5.1` can fail for the first time: it mapped to a nonexistent check ID and so
  reported Passing unconditionally.
- The lifecycle fix drains findings on deleted pods; expect a step change.

Deploying the `SchemaVersion` bump forces a full Ladybug rebuild from ClickHouse, the established pattern.

One extra `GetRole` per role is issued so the permission boundary is present for every
principal, not just admin-ish ones — previously the boundary-capping path was inert for most
principals, which is where privesc rules fire. For admin roles the net cost is lower:
`roleDetails` returns the boundary and last-used date from one call, and `roleUsage` no longer
calls `GetRole`.

`TrustEvaluation.ConfinedBy` is computed but deliberately not surfaced; a metadata key with no
reader is how dead signals accumulate.

## Known gaps, not addressed here

- Namespaced `Role`/`RoleBinding` are collected cluster-wide (`internal/collect/kubernetes`
  `Collect`; ADR 049 amendment 2026-08-21), best-effort: if the collector's ClusterRole lacks
  `list` on roles/rolebindings they are skipped with a warning, and a permission error does
  not mark the sync partial (the scope is just not marked complete).
- Clusters without a configured k8s connector are not covered at all; this is a configuration
  gap rather than a code gap.
- `aws-ebs-unencrypted` has no lifecycle coverage — the same bug class as the k8s sweep.
- GCP IAM Deny Policies, org/folder bindings and `RequestedPolicyVersion: 3`; Azure
  `denyAssignments` and assignment scope. All unmodelled.
- A Deny gated by any Condition is skipped wholesale, which over-reports when the condition is
  effectively always true.

## Amendment 2026-07-31 — liveness applies to the graph's input, not just the finding sweep

The liveness decision was applied to `internal/jobs/dangling.go` and stopped there. The two
queries that decide what the graph contains — `asset.listAllForSyncQ` (Ladybug bulk sync) and
`correlate.loadView` (every rule's input) — still selected on row presence. Pods are recreated
on every deploy and nothing prunes their rows, so dead `k8s_pod` rows accumulate and can
outnumber live ones. Correlate
re-stamps its output every sweep while collectors stop refreshing dead pods, which produced an
asymmetry:

- Fresh `exposed_to_internet` edges were mostly attached to pods that no longer existed,
  inflating reported pod internet exposure.
- A dead pod's `runs_image` containment edge correctly aged out while its exposure edge was
  recomputed, so traversals from an "exposed" pod dead-ended and "which package version is
  internet-exposed" returned nothing.

`asset.EphemeralLivenessCond` is now applied by both queries, anchored to the ephemeral type's
own high-water mark (`max(last_seen)`), never wall-clock, with the same 72h grace.

**Scoped deliberately to `k8s_pod`.** Many assets legitimately go unrefreshed because of slow
or broken collection rather than deletion; a blanket filter would delete much of the graph. An
EC2 instance that stopped being collected may still exist; a pod that stopped being collected
does not. Only add a type when absence genuinely means the resource is gone.

Guard tests pin both queries, mirroring `TestGraphEdgesReadersApplyFreshness`.

### Also: containment inheritance was nondeterministic

`graphstore.internetHops` closed containment (pod→container→image→package) with a
first-writer-wins visited check seeded from map iteration. An image shared by a directly
exposed pod and a distant one took whichever was walked first, so the same topology produced
`hops=0` or `hops=2` between runs, flapping must-fix classification. It now relaxes to the
minimum with a sorted seed and terminates because a node is re-enqueued only when its distance
strictly decreases. This surfaced as an intermittently failing test, unrelated to the liveness
change.

## Amendment 2026-08-02 — last_seen was never actually a liveness signal

"Liveness is `last_seen`" was true of the readers and false of the writer. ADR 022's per-asset
content diff wrote only assets whose `asset.ContentHash` changed, and `ContentHash` excludes
`LastSeen`, so a resource that exists but does not change never had `last_seen` refreshed. The
column meant "last changed", and every consumer reading it as "last observed" was wrong about
stable infrastructure. Consequences:

- `EphemeralLivenessCond` excluded running pods as dead while retaining genuinely dead ones.
- `resourceLifecycleSpecs` in `jobs/dangling.go` resolved some findings as `resource_gone` on
  running long-lived pods (for example `kube-system` DaemonSet pods) — a systematic bias, if a
  small one.
- The table TTL `last_seen + INTERVAL 180 DAY` would have deleted any resource stable for half
  a year (latent, not yet reached).
- Assets read as stale while their connectors were succeeding, distorting staleness reporting.

It did not materially suppress must-fix: privesc lands on `gcp_service_account`, which CIEM
re-ingests with a bumped `RiskScore` every sweep, so its hash always changes.

**Fix.** `jobs/sync.go` writes every collected asset each sweep with `restampLastSeen`, on both
the no-change short-circuit and the per-asset diff path. The diff still gates the expensive half
— which assets get re-checked and re-enriched (`changedAssetIDs`) — so ADR 022's purpose is
preserved. This decouples what is re-observed from what is re-evaluated, the same trade already
accepted for `graph_edges` re-stamping. Asset rows compress small, so the extra parts per sweep
are modest; watch merge pressure on `graph.assets`. The existing post-correlate
`OPTIMIZE TABLE assets FINAL` is the compaction path.

Related: `assetArgMaxSelect` now reads `min(discovered_at)` and `max(last_seen)` rather than
`argMax(…, synced_at)`. Both are monotonic facts about a row's whole history; the argMax form
made `respond.ageBucket` call long-established resources "new" whenever anything changed.
