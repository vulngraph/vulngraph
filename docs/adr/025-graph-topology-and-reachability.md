# ADR 025 — Graph topology and computed reachability

**Status:** accepted

## Context

A comparison with established inventory graphs identified three gaps in Vulngraph's topology model:

- **Topology lives as metadata, not edges.** Collectors stamp `vpc_id`, `subnet_id`,
  `security_groups`, `network` into an asset's `Metadata` map. They are strings, not nodes/edges, so
  the blast-radius walk (`asset.Service.BlastRadius`, outgoing `EdgesFrom`) has almost nothing to
  traverse. Inventory graphs typically model VPC/subnet/SG membership as a real graph and walk it.
- **Exposure is asserted, never computed.** We emit `gcp-firewall-open-ingress` and
  `aws-ec2-public-ip` as *findings*, but never connect a permissive rule to the instances it
  actually exposes. Exposure can instead be computed by traversing ingress rules to targets.
- **No cross-cloud DNS chaining.** `DNSPointsTo` resolves a record's values to IP/domain-bearing
  assets but does not follow a CNAME whose value is itself another record.

These are inventory/topology gaps, not reasoning gaps; closing them gives the reasoning layer
(scored findings, KEV, GuardDuty, SBOM→CVE) real structure to work over.

## Decision

**1. Network topology and supply-chain lineage are first-class `graph_edges`.** No schema migration:
`graph_edges.edge_type` is an open `LowCardinality(String)` and `Properties` is a JSON map. New
edge types (`in_vpc`, `sg_allows_from`, `applies_to`, `exposed_to_internet`, plus the existing
`deploys_to`) ride the same ReplacingMergeTree lifecycle as collector and correlation edges.

**2. Membership edges are emitted by collectors** (the data is already local at collection time):
`in_vpc` for ec2/subnet/sg, and the existing `protected_by`/`runs_in`. Security-group **ingress
rules** (ports, protocol, CIDRs, referenced SG IDs) are serialized into the SG asset's `Metadata`
as JSON so the reachability rule has them without a second API call.

**3. Internet reachability is a *computed* correlate rule, not a per-asset boolean.** A new
`InternetReachability` rule emits `<asset> -[exposed_to_internet]-> internet` (a singleton sentinel
node, `id="internet" type="internet"`) only when an asset has a public IP/endpoint **and** a
permissive path to it: an AWS SG that allows `0.0.0.0/0` on a port (via the `sg_allows_from` graph
the `SecurityGroupAllows` rule builds), a GCP firewall with `open_to_internet` that `applies_to`
the instance (the `GCPFirewallApplies` rule), or a public managed service (CloudSQL/CloudRun).
Modelling exposure as an edge (not a column) keeps it re-derivable each correlation sweep and lets
blast-radius and checks traverse it. The analysis is implemented independently in the correlate layer
(no third-party code reused).

All new rules are pure/deterministic and registered in the `[]correlate.Rule{…}` slice in
`cmd/graph/worker.go`; the correlation view (`correlate.repo.correlationTypes`) is widened to load
`security_group`, `subnet`, `vpc`, and `gcp_firewall`. (`subnet` and `vpc` were later removed from
the view because no rule reads them — see ADR 024's 2026-08-11 amendment.)

## Consequences

- Blast radius and attack-path reasoning gain real structure to walk: an `exposed_to_internet`
  asset now reaches a non-trivial frontier instead of a near-empty one.
- The security-group exposure findings (`aws-security-group-world-open-admin-port`,
  `aws-sg-open-all-ports`, `aws-sg-open-database-ports`) are config rules over SG ingress in
  `internal/checks`, not derived from the computed graph. The supply-chain exposure enrichment (ADR 012 lineage) can
  answer "is this CVE internet-exposed?".
- **Computed-not-collected exposure** keeps the firewall/SG metadata as the single source of truth;
  the edge is a derived view re-built every sweep, so a rule change re-exposes correctly without a
  re-sync. Reachability is intentionally conservative (public IP/endpoint required) to avoid marking
  internal-only assets as exposed.
- The `internet` sentinel keeps "everything exposed" a single `EdgesInto("internet", …)` query and
  avoids a boolean column that would drift from the rules that set it.

## Not built

- **NACL / route-table precision.** Reachability uses SG/firewall ingress + public IP; subnet route
  tables and NACLs (and AWS ENI as a node) are not modelled.
- **Per-asset content-hash diffing** (ADR 022) still governs when re-sync happens; this ADR only
  changes what edges a sweep produces, not the sync cadence.
- **Cross-cloud DNS CNAME chaining.** `DNSPointsTo` resolves a record's values to
  IP/domain-bearing assets but does not follow a CNAME whose value is another record's name —
  the correlation view loads no record `name`, so chaining needs that field plumbed through first.
  Chaining needs the DNS-record name in the view; the single-hop resolution already covers the
  common dangling-record case.

Cites ADR 021 (connected-graph reasoning this feeds), 023 (provenance/`deploys_to`, same edge
lifecycle), 012 (supply-chain first-class), 013 (sync), 010 (layering), 007 (AWS/GCP/GitHub scope).
