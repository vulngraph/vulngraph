# ADR 032 — DSPM: heuristic data classification

**Status:** accepted · amended 2026-07-18 (`contains_data` moved to the bulk fetch tier)

## Context

"Which exposed asset holds sensitive data" is the question that turns a misconfiguration into
a business risk — a public bucket named `prod-logs` and one named `customer-pii-exports` are
not the same risk. The graph had storage assets (S3/GCS/RDS/etc.) but no notion of *what
kind of data* they hold, so exposure and sensitivity couldn't be combined. A full DSPM
side-scans object contents — heavy, and out of scope for a control-plane-first platform.

## Decision

A heuristic data-classification correlator that bootstraps DSPM from signals we already have,
emitting `ContainsData` edges to synthetic `DataClass` nodes.

- **`DataClassification` correlator** classifies storage/database assets by name patterns and
  resource tags into `DataClass:PII | Financial | Credentials | Health | Internal`
  (sentinel node IDs `dataclass:*`, synthetic — not collected). Emits
  `Asset -[ContainsData]-> DataClass`.
- **Indexing:** the correlate `Graph` indexes storage/database/secret types into a
  dedicated `dataStoreAssets` slice — the classifier iterates that, not workloads (iterating
  workloads such as k8s pods yields no classifiable data stores).
- **`contains_data` is loaded into Ladybug** (bulk fetch tier — see Amendment below) so the
  DSPM queries resolve. Surface: an Investigate → Data (DSPM) tab + the GDPR-style power
  query "exposed assets containing PII" (`ExposedToInternet` ∩ `ContainsData`).

## Consequences

- Exposure × sensitivity is now one query: the public bucket that holds PII ranks above the
  one that holds logs — bootstrapped from naming/tags.
- **Trade-off:** this is a *heuristic* — name- and tag-based, not content inspection. It
  estimates likely sensitivity; it does not prove a bucket contains PII. A bucket with an
  innocuous name holding real PII is missed; a misnamed empty bucket is a false positive. It
  is a prioritisation signal, not a data inventory. True content classification (object
  side-scan) is deliberately out of scope (same reasoning as agentless disk scanning,
  ADR 034 — the control-plane graph already carries most of the practical value).
- `DataClass` nodes are synthetic sentinels seeded in Ladybug, mirroring the `internet` sentinel
  (ADR 025) — no collector produces them.

Cites ADR 025 (sentinel-node pattern + reachability for the exposure∩data query), 026 (graph
schema), 034 (why content side-scan is out of scope).

## Amendment (2026-07-18) — `contains_data` moved to the bulk fetch tier

`contains_data` was originally described as a critical-tier edge that always loads regardless
of volume. Loading it uncapped can exhaust ClickHouse memory on large datasets, so it now sits
in the **bulk** fetch tier (see ADR 047 and `internal/app/asset/repo.go`) and is subject to
bulk-cap truncation like other high-volume edges.
