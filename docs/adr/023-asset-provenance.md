# ADR 023 — Asset provenance

**Status:** accepted

## Context

ADR 021 gave the reasoner the connected graph — blast radius, attack paths, peer findings, exposure — and explicitly deferred one thing: an asset's *origin*. Its deferral named exactly what was missing — collectors stamping the source connector on each asset (assets carried no connector link), supply-chain `github_repo --deploys_to--> workload` lineage edges, and ownership signal — so the reasoner could weigh "who shipped this, who owns it, where it came from" when separating real findings from low-risk noise. A finding on an owned, production, internet-facing resource is a real risk; the same finding on an orphaned, unowned, isolated resource usually is not. Without provenance the reasoner can't tell them apart.

At the time, the `Asset` struct and the ClickHouse `assets` table carried no connector link; no `deploys_to` edge was produced (the type was named in comments only); and the `ContextPack` had no origin field.

## Decision

**1. Stamp the connector at the single sync chokepoint.** `jobs.SyncWorker.Work` already holds the `Connector` and the collected assets; before `Ingest` it writes `prov_connector_id` / `prov_connector_type` into each asset's existing `Metadata` map. No collector change, no schema migration, no read-path change — `Metadata` already round-trips through ClickHouse. (A first-class `connector_id` column is deferred until UI filtering needs it; reasoning does not.)

**2. Provenance in the ContextPack → prompt → fingerprint.** `ContextPack.Provenance` carries connector, account, region, owner, environment, an age bucket, and (once `deploys_to` lineage exists) the source repo. It is derived from the **seed asset already in the blast radius** (`br.Assets[0]`), so there is no extra read for the source/ownership/age fields — owner/environment reuse the tag reader generalized out of `cove.go`; age is bucketed (`new`/`established`/`stale`), never a raw timestamp. `reason.buildPrompt` renders a `- Provenance:` line and the system prompt instructs the model to weigh it — owned+prod+exposed is real risk, orphaned+isolated is likely low risk, and "stale" is *not* a synonym for safe. The bucketed/owner/env/repo signals fold into ADR 021's change fingerprint so an ownership or lifecycle change re-reasons while a timestamp tick does not.

**3. `deploys_to` correlation rule.** A new `correlate.DeploysTo` rule (pure, deterministic, registered alongside `DNSPointsTo`/`IAMCanAssume`) links a `github_repo` to the k8s workloads it ships, with the match confidence recorded on the edge:
- **high** — a container image is `ghcr.io/<org>/<repo>...`, which *is* the repo's full name (exact identity).
- **medium** — the workload's `app.kubernetes.io/name`/`part-of` label matches a repo's short name (strong convention, but names collide).

The correlation view loads `github_repo` + `k8s_pod`/`k8s_deployment` and their tags. The source repo is surfaced into reasoning via a new `EdgesInto(dstID, edgeType)` lookup (the blast-radius walk is outgoing-only and never sees an inbound `deploys_to`), preferring the high-confidence link.

## Consequences

- The reasoner sees where a resource came from and who owns it, and re-reasons when that changes — closing ADR 021's deferral with the instrumentation it specified.
- `deploys_to` edges enrich the graph for everyone (blast radius from the repo side, future UI lineage), not just reasoning.
- **Metadata-not-column** keeps this change migration-free at the cost of queryability; the promotion path is a `connector_id` column when filtering needs it.
- **False lineage links** are bounded: the confidence is on the edge, the prompt treats medium as a hint not a fact, and the policy gate never auto-acts on a medium link alone. ECR/GCR images are deliberately not name-matched (would be low-confidence noise).
- Provenance adds one keyed read per `Decide` (the `EdgesInto` lookup) only on a cache miss — ADR 021's gate already eliminates most `Decide` LLM calls.
- New seam `respond.Lineage` (and `asset.EdgesInto`) defined as a narrow interface in `respond`, satisfied by the existing `asset.Service` — no new cross-domain coupling (ADR 010).

## Not built

- **True config drift** ("what changed since last sync") needs the per-asset content-hash from ADR 022 — building a second drift mechanism would duplicate that infrastructure. The `AgeBucket` is the coarse interim signal (newly-appeared vs long-lived vs going-stale). ADR 022's content hash is now implemented; a `drifted_recently` flag built on it has not been added.
- ECR/GCR → repo lineage: needs an image→repo mapping, which does not exist.
- A first-class `connector_id` column: not needed while nothing in the UI filters by connector.

Cites ADR 021 (the deferral this closes), 013 (sync), 014 (enrichment), 012 (supply-chain first-class), 010 (layering), 005 (decaying memory).
