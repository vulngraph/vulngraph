import type { GraphStatus } from "./api";

// Copy for the graph engine's state, keyed on what GET /api/graph/status
// measured. `ready` is a completed, non-empty build, not merely a configured
// engine; an unread status is unknown, never ready.

// graphNotReadyNotice is the Explore banner text, or null while a built graph
// is serving.
export function graphNotReadyNotice(status: GraphStatus | undefined): string | null {
  if (!status || status.ready) return null;
  switch (status.state) {
    case "not_configured":
      return "No graph engine configured — Cypher queries are unavailable on this deployment.";
    case "unknown":
      return "Graph engine state unknown — its build state could not be read, so results may be empty or queries may fail.";
    default:
      return "Graph engine not ready — on restart Ladybug restores its saved snapshot, and rebuilds from ClickHouse only when the snapshot is missing or stale. Until a graph with nodes is loaded, queries return empty or fail.";
  }
}

// graphMultiHopNotice is the Explore warning while a node table of the loaded
// graph is above one engine node group (ladybug#1341), or null. Absent means
// unmeasured, which says nothing either way, so it shows no warning and no
// all-clear.
export function graphMultiHopNotice(status: GraphStatus | undefined): string | null {
  if (!status?.multi_hop_may_be_incomplete) return null;
  const tables = (status.oversized_node_tables ?? [])
    .map((t) => `${t.label} (${t.rows.toLocaleString("en-US")} rows)`)
    .join(", ");
  return (
    `Multi-hop results may be incomplete: ${tables || "a graph node table"} holds more than 131,072 rows, ` +
    "and the graph engine can then miss relationships in multi-hop and variable-length queries " +
    "(attack paths, blast_radius_deep, saved queries, detections, raw Cypher), returning fewer paths than exist. " +
    "Single-hop results and risk scores are not affected."
  );
}

// graphStateLabel is the short form for the Home footer.
export function graphStateLabel(status: GraphStatus | undefined): string {
  switch (status?.state) {
    case "ready":
      return "graph ready";
    case "not_ready":
      return "graph not ready";
    case "not_configured":
      return "graph engine not configured";
    default:
      return "graph status unknown";
  }
}
