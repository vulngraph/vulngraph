# Comparing Vulngraph and Cartography

Cartography inspired Vulngraph's inventory graph. Both projects collect infrastructure and model its
relationships. Vulngraph adds an integrated workflow for prioritising findings, investigating with
people or agents, and reviewing proposed changes. Both are open source; choose based on the work you
need to do and the systems you need to connect.

This comparison was checked on 2026-11-26 against Cartography's current code and documentation.
It describes the projects as shipped, not every application someone could build on their graphs.

## Where Vulngraph helps

- **Investigation is part of the application.** Findings, graph exploration, risk context, chat,
  proposed fixes and approval share a web UI. An investigator can follow a package finding to its
  workload, exposure and identity relationships without building a separate application.
- **Agents use the same evidence.** MCP and scoped API keys expose inventory and investigation tools.
  An agent can request a change, but it cannot grant its own approval. Hosted and local LLMs are
  optional; deterministic inventory, checks and scoring work without one.
- **Work is separated by purpose.** Bounded River queues separate collection, enrichment, graph work
  and model calls. Content diffs avoid repeating unchanged checks and enrichment. The graph's content
  digest avoids a rebuild when the loaded topology is unchanged.
- **Storage has distinct jobs.** Postgres holds transactional state, ClickHouse holds inventory,
  findings and history, and LadybugDB serves graph traversal. The graph can be rebuilt from the
  retained source data. This also means more components to operate.

See [capabilities](capabilities.md), [LLM providers](llm-providers.md),
[architecture](architecture.md) and [security controls](security-hardening.md) for implementation
details and limits. AI integration is not evidence of decision accuracy: the current model
evaluations are small, manually triggered regression sets.

## Where Cartography is strong

Cartography has a broader connector ecosystem, an established contributor community and publicly
listed users. Its graph can support custom applications, Cypher investigations and security rules.
It also inventories AI infrastructure, including model providers and agents. Those capabilities
should be considered alongside Vulngraph's built-in analyst and agent workflow.

Sources: [project overview](https://github.com/cartography-cncf/cartography),
[rules](https://docs.cartography.dev/usage/rules.html),
[building applications](https://docs.cartography.dev/usage/applications.html).

## What we can say about sync performance

Cartography's standard AWS account loop is sequential. Its operations guide also documents parallel
jobs under an external orchestrator, with cleanup-scope constraints; some collectors use async I/O.
The guide reports 20–30% sync improvements from its Rust Neo4j driver extension, included in its
published container. These are Cartography's figures, not measurements made by Vulngraph.

Vulngraph's sync workers run concurrently, but provider quotas, pagination, data volume and downstream
work still matter. Each sync collects and re-stamps the asset set, even when content is unchanged.
Graph sync reads its load set to compute the digest, and changing topology can require a full rebuild.
An in-memory query engine does not by itself make cloud collection faster.

There is no published, matched end-to-end benchmark establishing a Vulngraph speed advantage or a
supported fleet-size ceiling. The LadybugDB multi-hop bug above one storage node group is fixed in
the pinned v0.22.3 engine and covered by a regression test with 131,112 nodes. That is correctness
evidence for that bug, not a fleet-scale performance benchmark.

Sources: [Cartography AWS sync](https://github.com/cartography-cncf/cartography/blob/master/cartography/intel/aws/__init__.py),
[Cartography operations](https://docs.cartography.dev/ops.html),
[Vulngraph sync](../internal/jobs/sync.go),
[diff design and amendments](adr/022-incremental-diff-sync.md),
[graph rebuild design](adr/074-ladybug-rebuild-gate-is-a-content-digest.md),
[engine regression](../internal/graphdb/ladybug/multihop_regression_test.go).

## How to compare on your environment

1. **Match coverage first.** Use the same accounts, regions, resource families and permissions. Record
   exact versions, configuration, hardware and cloud quotas. Verify expected resource and relationship
   counts; faster collection with missing data is not a win.
2. **Measure three cases.** A cold full sync, an unchanged repeat, and a controlled set of additions,
   changes and deletions. Repeat runs and report variation rather than selecting the fastest result.
3. **Measure the complete path.** Record collection time and time until the changed data is available
   in graph queries, plus API requests, retries, throttles, CPU, peak memory and database growth.
   Compare equivalent collection/query work separately from extra checks or LLM reasoning.
4. **Check failure and recovery.** Interrupt a sync, deny one service permission, and retry. Confirm
   partial collection is visible and does not erase live resources or invent a clean result.
5. **Test investigations as well as ingestion.** Use known exposure and identity paths to check the
   answers. Record whether a person can find the relevant evidence and safely review a proposed fix.

Publish the configurations, coverage, raw measurements and missed relationships with any speed claim.
Vulngraph remains pre-1.0; [project evaluation](evaluating.md) and
[known limitations](known-limitations.md) describe the current maturity and coverage gaps.
