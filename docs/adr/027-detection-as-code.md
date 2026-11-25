# ADR 027 — Detection-as-code (saved, scheduled, alerting Cypher)

**Status:** accepted

## Context

The Ladybug graph (ADR 025/026) and the Cypher surface (REST `/api/graph/cypher`, NL→Cypher,
MCP `run_cypher`) answer security questions on demand — but only on demand. Every query was
ephemeral: run it, read the result, lose it. A common capability in graph-based security
tools is turning queries into *standing detections* ("alert me the moment a new
internet-exposed admin role appears"); Vulngraph could not. The graph was an investigation
tool, not a continuous control. Closing this gap converts an open, queryable graph into
ongoing value with almost no new infrastructure — the alerting
backbone (`notify`, ADR 033) and the scheduler (River periodic jobs, ADR 002) already exist.

## Decision

A saved query is a first-class, persisted, optionally-scheduled detection.

- **`internal/app/savedquery/`** (domain/repo/service/handler; raw-pgx repo mirroring
  `notify`). `SavedQuery{Name, Cypher, Schedule (cron), AlertChannelIDs, AlertOnChange,
  Enabled, …}` + `saved_query_runs` history. Read-only validation
  (`graphquery.IsReadOnly`) rejects write Cypher at save time —
  a saved detection can never mutate the graph.
- **Change detection by result hash.** Each run hashes the sorted (node IDs + edge keys); a
  run is "changed" when the hash differs from the prior run. This is the detection signal —
  not "query returned rows" (which fires forever) but "the result set *changed*."
- **Scheduling** reuses River: a per-minute `SavedQueryWorker` tick evaluates each enabled
  query's cron via a self-contained 5-field matcher (`cronexpr.Due` in `pkg/cronexpr`, no new dependency) and runs
  the due ones. The Ladybug primary lives in the worker pod, so the worker executes directly;
  serve wires the tiered runner for manual "run now."
- **Alerting** reuses `notify` (ADR 033): on a changed scheduled run with `AlertOnChange`,
  build a `notify.Notification{EventType: EventQueryMatch}` and `Dispatch`. Only the
  notification builder is new — the channel routing/delivery is the existing path.
- **Surfaces:** REST `/api/saved-queries` (+ `/run`, `/runs`; writes admin-gated), a
  "Detections" panel in the Vulngraph UI, and A2A agents create detections via the same REST
  with a `gph_` key (ADR 011) — detection-as-code authored by agents.

## Consequences

- The graph becomes a continuous control surface: any Cypher pattern can be a standing,
  alerting detection — version-controllable, agent-authorable, no code change to add one.
- Reuses three existing systems (Ladybug Cypher, River periodic, notify) — the only new
  persistence is two tables; the feature is small precisely because the platform is composable.
- **Trade-off:** change detection is result-set-hash granularity (something entered/left
  the set), not per-row diffs. "Which specific node is new" is derivable by the operator from
  the query but isn't surfaced as a structured diff — not built.
- Cron evaluation is a hand-rolled 5-field matcher (minute granularity); good enough for the
  daily/weekly/hourly presets and standard expressions. No second-level or `@reboot` syntax.

Cites ADR 025/026 (the graph + Cypher this stands on), 002 (River periodic scheduling), 033
(notify — the alerting backbone), 011 (A2A authoring via key-auth), 010 (layering — savedquery
depends on narrow CypherRunner/Alerter interfaces, not graphstore/notify directly).
