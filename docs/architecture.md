# Architecture

An overview of how Vulngraph fits together. Each section names the Go package that
implements it; if this doc and the code disagree, the code wins and this doc is wrong.

---

## Overview

Vulngraph builds one security graph of an estate, enriches findings with context from that
graph, asks an LLM for a proposed action on the findings that matter, and routes every
state-changing proposal to a person. It never remediates on its own (ADR 087).

```
AWS + GCP + Azure + GitHub + Kubernetes (+ Okta / Google Workspace identity)
  → asset inventory → ClickHouse + LadybugDB graph (Cypher)
    → CSPM checks + CIEM techniques + Nuclei scanner + CISA-KEV/EPSS/OSV intel
      → LLM reasoning (graph-enriched) → human approval queue → audit trail
```

Check counts change as the registry grows; the authoritative count is
`checks.Default().Len()` (`internal/checks/`), and per-benchmark coverage is in
[`cspm-coverage.md`](cspm-coverage.md).

The pipeline has four stages: **collect → correlate → decide → learn**. They run over three
stores.

---

## Storage: three stores, one source of truth

| Store | Role | Why |
|---|---|---|
| **Postgres** | Transactional state: users, connectors, River jobs, governance decisions, the verdict ledger | Mutable, relational, ACID |
| **ClickHouse** | **Source of truth**: assets, every graph edge, findings, signals, audit, change log | Columnar, append-only writes; `ReplacingMergeTree` + TTL on every state table (the audit tables `audit_events` and `asset_change_log` are plain MergeTree with a 7-year TTL) |
| **LadybugDB** | In-memory property graph for multi-hop Cypher traversal | Attack-path queries the other two cannot do efficiently |

**LadybugDB is a disposable projection, never a store of record**
([ADR-003](adr/003-postgres-clickhouse.md),
[ADR-074](adr/074-ladybug-rebuild-gate-is-a-content-digest.md)). It is rebuilt from
ClickHouse on correlate sweeps, gated by a content digest of the load set.
`graph_ladybug_rebuild_phase_seconds{phase}` exposes the read/build/risk-BFS/snapshot split.
A pod restart warm-loads its PVC snapshot in seconds, and deleting the PVC is safe because
ClickHouse can reproduce it (`internal/app/graphstore`).

**Rebuilds do not interrupt reads.** The new graph is built in a fresh in-memory database.
Only once it is fully populated does `SyncFromSources` take the write lock, drain in-flight
reads and swap databases. Readiness is `synced AND nodeCount > 0`, so the serve path never
queries an empty or half-built graph. If LadybugDB is unavailable, traversal reads fall back
to a ClickHouse BFS (`explore/tiered_repo.go`, `explore/fallback_repo.go`); raw Cypher returns
an error.

**A degraded rebuild is refused, not published.** `SyncFromSources` measures the candidate
load set before building and abandons it (`ErrRebuildRefused`) if it is incomplete, for
example after a ClickHouse memory error partway through the edge fetch. It fails toward a
stale graph rather than an incomplete one, because the risk score and `InternetHops` this
graph serves feed proposals a person approves (`graphstore/fidelity.go`, ADR 077).

---

## 1. Collect: inventory and change history

Collectors cover AWS most deeply, with narrower GCP, Azure, GitHub and Kubernetes coverage,
plus Okta and Google Workspace identity. Sync combines periodic full reconciliation with
optional event/webhook freshness. Every sync collects and re-stamps every asset; a content-hash
diff skips re-checking and re-enriching the ones that did not change.

Every per-field change is written to an append-only `graph.asset_change_log`
(`asset_id, field, old_value, new_value, connector_id, changed_at`) at the sync diff
chokepoint. Drift is modelled as events (`new_asset`, `new_exposure`, `removed_exposure`,
`changed`), so "what changed since the last sync?" has a direct answer
(`internal/app/asset/drift.go`, `drift_handler.go`).

Evidence comes from several independent sources: collected config, graph structure, the
change log and CloudTrail, intel feeds, Nuclei and read-only live AWS describe calls. A claim's
confidence scales with how many independent sources corroborate it. Config alone asserting
"public" or "privileged" is a `possible` candidate; a second source makes it `confirmed`. This
applies today to exposure and IAM inbound-assumability (`public_access` tiers, `trust_entry`)
and to DNS-resolution confirmation of dangling CNAMEs (ADR 050, ADR 051).

> **Code:** `internal/app/asset`, `internal/graphschema`

## 2. Correlate: inventory into graph structure

Correlation rules turn flat metadata into a property graph: `ExposedToInternet`,
`CanAssume`, `Accesses`, `RunsPackage`, `DeploysTo`, `ConnectedViaSG` and the other edge types
declared in `graphschema.EdgeTypes`. This includes the SSO access graph
(`AssignedTo`/`GrantsAccessTo`/`GrantsAdmin`) from the AWS Identity Center API, and IaC
ownership (`defined_in`, resource → declaring repo) joined from k8s manifests, Terraform state
and identifiers harvested from repo text by deterministic keys.

- **Exposure is derived.** `exposed_to_internet` is an edge to a singleton `internet` node,
  re-derived every sweep (`correlate/reachability.go`). VMs need a public IP plus a world-open
  SG/NSG/firewall rule. AWS EC2 is judged per address family: a public IPv4 address needs a rule
  spanning `0.0.0.0/0`, a global IPv6 address a rule spanning `::/0` and an IPv6
  internet-gateway route. EC2 is skipped only when its subnet has been read and found private
  for that family, so an unread route table keeps the exposure. An Azure NIC with no NSG is
  exposed on a Basic-SKU public IP and closed on a Standard one; an NSG or SKU that could not be
  read gives the `possible` tier, not silence. Managed services whose config marks them public
  count as reachable without a network-path check.
- **Risk propagates by directed BFS.** CIEM privilege escalation is detected inline (66
  documented techniques across AWS, GCP and Azure). Detection is action-based: it ignores the
  resource scope an action is granted on (the scopes are kept on the result for triage) and
  skips an AWS Deny that has a Condition, so it over-reports by design rather than miss a
  scoped-but-admin target (`ciem/privesc.go`, `ciem/evaluator.go`). An asset's score is raised by its
  neighbours' risk, attenuating by 0.7 × the edge type's registry weight per hop, over at most
  4 hops and 20 nodes per walk, adding at most 30 points. Each
  edge type declares its direction in the `graphschema` registry (`EdgeType.Dir`): forward for
  attacker movement, reverse where the danger starts at the destination. The BFS follows only
  the declared direction (`graphstore/bfs.go`).
- **Data-sensitivity tagging.** Storage assets get a likely data class (`ContainsData` →
  `DataClass`, with confidence) from a name/tag heuristic, alongside `encrypted` and `public`
  signals, so "sensitive data that is exposed or unencrypted" is a graph query. Content is not
  scanned.

> **Code:** `internal/app/correlate`, `internal/app/graphstore/bfs.go`

## 3. Decide: reason in context, a person approves

Steps, in order:

1. **Enrich.** Each finding gets a 0–100 contextual score from about 20 sources and a band:
   `monitor` (0–49), `pipeline` (50–60), `high` (61–80), `page` (≥81). Inputs include blast
   radius, KEV, EPSS, supply chain and provenance (`internal/app/enrich`).
2. **Propose.** For `pipeline` and above, `respond.Decide` sends the LLM a `ContextPack`
   (blast radius, exposure, provenance, score breakdown, peers, EPSS/KEV, identity chain,
   supply-chain path). The model returns `Plan{action_class, summary, rationale}` with
   `action_class ∈ {observe, remediate, modify, isolate, destroy}`. The prompt asks the model to
   cite graph signals in the rationale; the code requires only a valid `action_class` and a
   non-empty summary and rationale (`internal/reason`). An AWS resource ID or ARN the rationale
   cites that is not in the ContextPack escalates the decision to a person
   (`internal/app/respond/grounding.go`).
3. **Govern.** The plan passes the policy gate (`policy.Decide`); the remediation policy only changes how the
   approval queue displays it (hidden, parked or escalated). Only read-only
   `observe` plans skip the approval queue (`internal/app/govern`, ADR 087).
4. **Execute.** Only when a person runs an approved fix through the executor (admin HTTP, or
   MCP with a second admin's grant), synchronously and audited. Nothing in the pipeline
   executes.

Underneath the score is a **severity belief** (`internal/app/belief`). On every enrich a
deterministic `BeliefFormer` forms a claim about the finding's real severity, backed only by
cited facts, with a confidence. It is persisted in ClickHouse and re-examined when its evidence
changes. `Reconcile` resolves findings whose high score disagrees with a not-urgent must-fix
class. An LLM adjudication layer that tries to refute high severities exists but is off by
default (`ADJUDICATOR_ENABLED`).

**Unknown is never zero.** An unmeasured internet-hop count is represented as unknown, never
as 0-hop. An enrich-time consistency gate strips any factor that violates this before persist,
and the adjudicator corroborates a reachability claim against an independent
`exposed_to_internet` lookup rather than the cached signal (ADR 067, ADR 080).

**Cost scales with change, not volume.** A sha256 fingerprint over the inputs that change the
answer lets a sweep over stable findings reuse the cached plan without calling the LLM
(`internal/app/enrichcache`).

> **Code:** `enrich`, `respond`, `reason`, `govern`, `enrichcache`, `belief`

## 4. Learn: confidence from human verdicts

Governor verdicts on proposals (`approved`, `risk_accepted`, `denied`) are recorded in a
Postgres ledger. Confidence for an `(action class, asset context)` pair is an
exponentially decayed approval rate over those verdicts:

```
confidence = Σ wᵢ·approvedᵢ / Σ wᵢ     where wᵢ = e^(−λ·age(i))
```

- Default 30-day half-life, so recent verdicts dominate.
- A minimum-sample threshold stops a short streak from reading as high confidence.
- Confidence sets how a proposal is raised (high or medium: park for approval; low or
  insufficient: escalate). It never decides whether a person is asked: every state-changing
  action still needs one (ADR 087).

The result carries its own evidence: a score, the effective sample size, the raw sample count
(over the most recent 500 outcomes) and a band (`high`, `medium`, `low` or `insufficient`)
(`internal/app/memory`, `internal/app/govern`).

> **Code:** `internal/app/memory`

---

## Deployed vs installed

A critical CVE on an internet-exposed host is not automatically urgent. The graph separates
**installed**, **deployed** and **reachable**:

- **Installed ≠ deployed.** A package is a graph node (id = purl). `depends_on` (Repo →
  Package) means it is in the SBOM; `runs_package` (Asset → Package) means it is running on a
  workload (`internal/intel/osv`).
- **Deployed ≠ reachable.** `exposed_to_internet` is a computed edge. `protected_by` links an
  instance or load balancer to its security group (AWS) or an Azure VM to its NSG. It is a
  traversable hop that raises the risk of what it guards when the control is permissive; it
  does not end a path. WAFs are not modelled in the path.
- **"No meaningful risk" is a valid answer.** The `observe` action class and the suppress/floor
  score factors let the reasoner return a graph-grounded verdict that cites the missing edge.

`internal/app/findingctx` assembles this in one call: the ContextPack, the reasoning decision
(action class, rationale, confidence, verification concerns, safe-to-fix band) and the
per-source score breakdown. It backs both the finding-detail UI and the MCP
`get_finding_context` tool. The explicit edge chain is not returned as its own artifact.

---

## Trust and audit

- **Every distinct decision, including `observe`, is an audit event.** A repeat that reaches
  the same outcome, action class, confidence band and verification-concern set as the cached
  reasoning is not re-audited or re-notified; it increments the reasoning cache's
  `repeat_count`, which the escalation-hotspot panel reads (`respond/service.go`,
  `skipRecord`). Notifiers skip a plain `observe` decision that is not waiting for a person
  (`Decision.Notifiable`).
- **Cypher exposed to agents and the API is read-only.** `graphquery.IsReadOnly` allows only
  known read starters and rejects write and IO keywords (ADR 036), and the engine rejects any
  prepared statement that is not read-only (`graphstore/repo_cypher.go`).
- **No autonomous remediation.** The policy gate decides how a proposal reaches a person (the
  remediation policy only changes its queue display); no setting lets a state-changing
  action run without one (ADR 087). The
  destructive subset needs a second admin's grant.
- **Verification guardrails** force escalation when the verification step raises a concern.
- **API keys use the same surface as people.** External agents authenticate with
  `Authorization: Bearer gph_<key>` (scopes `read`/`write`/`admin`) against the same REST and
  MCP endpoints (`internal/app/apikey`, `internal/app/mcp`). Live cloud reads over MCP and
  from chat (`chat.live_read`, `internal/app/chat/live_gate.go`), executor actions and
  suppressions are written to `audit_events`; other reads are not, and a
  key records only `last_used_at`.

## Current state

| Capability | State |
|---|---|
| Collection, drift, change log | Live |
| Correlation, computed exposure, BFS risk | Live |
| Enrich → reason → govern → audit | Live |
| Confidence from human verdicts | Live |
| MCP with scoped keys | Live |
| Cloud execution (AWS security-group, instance, access-key and S3 changes; GCP service-account key disable and firewall-rule removal; Azure NSG rule removal) | Human-initiated only (executor HTTP/MCP), never automatic |
| Deployed-vs-installed verdict | Live (`findingctx`, MCP `get_finding_context`) |
| Agentless disk scanning | Opt-in per connector, off by default: VM packages come from SSM / OS Config inventory, or from a disk snapshot (AWS, Azure) where an admin enabled it ([capabilities](capabilities.md#vm-disk-scanning)) |
| Bulk edge coverage | Known gap: bulk (non-critical) edge types share one combined load cap that a large estate can exceed (`asset/repo.go`); attack-path edges are in the uncapped critical tier |
| Edges that cannot be loaded | Counted per edge type as `endpoint_expired` (the endpoint no longer exists) or `endpoint_absent` (a dangling reference), the latter against a budget each edge type declares in `internal/graphschema` |
