import { http, HttpResponse } from "msw";

// meHandler mocks GET /api/auth/me with a session of the given role — the gate
// AppShell and the admin-action UI read through useMe/useIsAdmin.
export function meHandler(role: "admin" | "analyst" | "viewer" = "viewer") {
  return http.get("/api/auth/me", () =>
    HttpResponse.json({ id: "u1", email: `${role}@example.com`, role }),
  );
}

// Default handlers always registered — endpoints every page hits on mount.
// Tests can override these with their own handler before the default.
export const defaultHandlers = [
  http.get("/api/graph/status", () =>
    HttpResponse.json({ ready: true, state: "ready", multi_hop_may_be_incomplete: false }),
  ),
  http.get("/api/graph/stats", () =>
    HttpResponse.json({
      nodes: { assets: 0, roles: 0, repos: 0 }, last_rebuilt: null, ready: true,
      multi_hop_may_be_incomplete: false, oversized_node_tables: [],
    }),
  ),
  http.get("/api/drift/analyses", () => HttpResponse.json({ enabled: false, analyses: [] })),
  http.get("/api/assets/:id/disk-scan", ({ params }) =>
    HttpResponse.json({ asset_id: params.id, state: "none", volumes: [] }),
  ),
  http.get("/api/connectors/:id/disk-scan", ({ params }) =>
    HttpResponse.json({
      connector_id: params.id, type: "aws", mode: "off", modes: ["off", "existing_snapshots", "create_snapshots"],
      confirmation: "I accept the snapshot cost and the snapshot permissions", warning: "Disk scanning reads your VMs' disks from cloud snapshots.",
    }),
  ),
  http.get("/api/queue", () => HttpResponse.json({ items: [] })),
  // The Findings "Start here" view (default) fetches ?safe=true on mount; empty by
  // default so pages mount cleanly. Tests override with their own /api/findings.
  http.get("/api/findings", () => HttpResponse.json({ items: [], next_cursor: "" })),
  http.get("/api/findings/:id", () =>
    HttpResponse.json({ id: "f1", title: "test", severity: "high", score: 72, check_id: "test-01", resource_id: "r1", source: "cspm" }),
  ),
  http.post("/api/graph/cypher", () => HttpResponse.json({ nodes: [], edges: [], truncated: false })),
  http.get("/api/policy", () => HttpResponse.json({ id: "default", suggest_threshold: 70, action_rules: {}, updated_at: "2026-01-01T00:00:00Z", updated_by: "system" })),
  http.get("/api/decisions", () => HttpResponse.json({ items: [], next_cursor: "" })),
  http.get("/api/assets/summary", () => HttpResponse.json({ total: 0, by_provider: {}, by_type: {} })),
];
