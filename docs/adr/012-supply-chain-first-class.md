# ADR 012 — Supply chain is a first-class domain

**Status:** accepted

## Context

Software supply-chain compromise is a major risk class for any organisation that builds
software. Well-understood building blocks exist for it: OSV/GHSA/CISA-KEV feed pipelines,
GitHub dependency/Dependabot/Actions-workflow scanners, multi-stage package vetting
(typosquat, provenance, reputation, OpenSSF Scorecard), per-asset supply-chain risk
context, and toxic-combination scoring ("internet-exposed + critical CVE + admin IAM").

## Decision

Treat supply chain as a pillar, not an afterthought:

- **Graph model:** dependencies become graph nodes; `repo → package → workload` become
  edges, so Explore can answer "what is reachable from this compromised package?" natively.
  *Implemented:* the GitHub collector reads each repo's dependency-graph SBOM; every
  dependency is a `package` asset (ID = purl) with a `repo →(depends_on)→ package` edge.
- **Intel feeds:** `internal/intel/` — OSV, GHSA, and CISA KEV feeds; the vet pipeline
  emits findings with `source=supply_chain`.
  *Implemented (OSV + KEV):* `internal/intel/osv` batch-queries api.osv.dev for the
  package inventory daily (`osvInterval = 24h`; a daily cadence keeps the batch query well
  inside its timeout on large inventories) and records one `supply_chain` finding per
  affected package×advisory, preferring the CVE alias as CheckID so the KEV refresh
  escalates them too. GHSA needs no feed of its own — GitHub publishes its advisory
  database natively into OSV, and the GHSA GraphQL API would add auth + rate limits for
  the same data. The package-vetting pipeline (typosquat, provenance, reputation) is
  still open.
- **Enrichment and scoring:** `SupplyChainContext` enrichment, KEV-presence boost (a
  KEV-listed CVE on an internet-exposed asset pages, full stop), toxic-combination
  multipliers.
  *Implemented:* supply-chain exposure scoring is `enrich.SupplyChainExposure`
  (`sources_supply_chain.go`), and KEV and toxic-combination scoring are in
  `internal/app/enrich`. No separate `SupplyChainContext` type exists.
- **MCP exposure:** package-vetting and supply-chain queries exposed as MCP tools.
  *Not built:* there are no dedicated supply-chain or package-vetting MCP tools. Supply-chain
  exposure is reachable through `run_cypher`, and in Explore through the named query
  `supply_chain_exposure`. Package vetting is still open (see Intel feeds).

Boundary: Vulngraph is the **context layer** (where a package lives, how exposed, what blast
radius). An external vulnerability manager owns the **lifecycle** (SLA, tickets, fix PRs).

## Consequences

- Supply-chain findings ride the same scoring/reasoning/approval pipeline as everything
  else — no parallel system to maintain.
