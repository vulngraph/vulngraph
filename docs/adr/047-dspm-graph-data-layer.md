# ADR 047 — DSPM is a data layer of the attack graph

**Status:** accepted (implemented 2026-07-10; amended 2026-08-09)

## Context

The platform classifies storage assets by data sensitivity (`DataClassification`
correlator → `contains_data` edges to synthetic `DataClass` nodes) and ships a DSPM
page at `/investigate/dspm`. But the page rendered empty: `contains_data` was
excluded from Ladybug by the A3 filter (`ladybugRelSpec` — the rule that keeps high-volume topology edges out of the in-memory engine), so `MATCH (a)-[:ContainsData]->(dc)`
over the graph RPC returned nothing. The classification was also shallow — name/tag
heuristics into five classes — and ignored security signals the collectors already
capture (S3 `public`/`encryption`, RDS `publicly_accessible`/`storage_encrypted`,
CloudSQL `public`). There was no *toxic-combination* view — the core value of DSPM:
"sensitive data that is also exposed, unencrypted, or reachable by a
privileged identity."

The unified graph is exactly the right substrate for that view — data sensitivity is
one more node/edge property to correlate against exposure, IAM reachability, and
findings. It was simply not wired through.

## Decision

Treat data classification as a first-class **layer of the graph**, not a side table.

1. **Load `contains_data` into Ladybug** (`ladybugRelSpec`). This revises the A3 exclusion
   for this one edge: A3 keeps *high-volume topology* edges out of the in-memory
   engine, but `contains_data` is low-volume (bounded by data-store count × a handful
   of `DataClass` sentinels) and is directly queried by a product surface, so it
   belongs in Ladybug. `TestBuildEdgeRowsAppliesA3` now pins it as loaded.

2. **Signal-aware classification** (`correlate/data_classification.go`). Each
   `ContainsData` edge carries a **confidence** — `high` (explicit
   data-classification/sensitivity/compliance tag), `medium` (resource-name pattern),
   `low` (the `internal` floor). Added a **PCI** class.

3. **Store-security node signals** (`encrypted`, `public` on the `Asset` node,
   with a `SchemaVersion` bump). Read straight from collector metadata (`assetEncrypted`,
   `assetPublic`) at graph build — no new collection. `public` (config-level public
   accessibility) is deliberately distinct from `exposed` (a graph `ExposedToInternet`
   path). At the time a `publicly_accessible` RDS emitted no exposure edge, so DSPM
   needed the config signal to flag it; since the 2026-08-09 amendment RDS/CloudSQL also
   seed `ExposedToInternet`, and `public` remains an independent second signal. Both
   surface on `explore.Node` and in the API.

4. **Toxic-combination surface.** Named queries (`sensitive_data_exposed`,
   `unencrypted_sensitive_data`, `sensitive_data_reachable_by_escalating_role`)
   plus a rebuilt DSPM dashboard: headline tiles for exposed / public / unencrypted
   sensitive stores, and a worklist ranked by a data-risk score
   (sensitivity × exposure × public × unencrypted × finding score).

## Consequences

- DSPM leads with risk, not a flat inventory — the highest-risk data-store
  combinations surface first.
- Loading `contains_data` grows the Ladybug graph by a bounded, low-volume edge set;
  the SchemaVersion bump forces one clean rebuild on deploy. `contains_data` volume
  should be checked before enabling this on a large graph (the A3/OOM guard rail).
- `encrypted`/`public` are computed from already-collected metadata, so no collector
  or agentless-scan work was needed to ship this.

## Boundary — what this is *not*

Classification remains **heuristic** (names, tags, and collected config metadata),
not content-based. True DSPM accuracy needs **content scanning** — sampling object
contents, AWS Macie, or agentless side-scan of storage snapshots — which requires
agentless-scan infrastructure the platform does not yet have. That is the explicit
next phase, tracked separately; this ADR covers the graph-native layer that makes
the data we *can* infer actionable.

**Amendment (2026-08-09):** Decision 3 and the paragraph above originally said a publicly-
accessible RDS/CloudSQL does not yet emit an `ExposedToInternet` edge and that
only S3 does — that is no longer true. `correlate/
reachability.go`'s `InternetReachability` rule now seeds exposure from
`rds_instance`/`cloudsql_instance` (and `s3_bucket`/`gcs_bucket`/`eks_cluster`/
`gke_cluster`) alongside S3, closing the recommended follow-up this paragraph
used to point at. The DSPM bridge via the `public` signal described here is
still accurate as a *second*, independent signal path — it just isn't the only
one anymore.
