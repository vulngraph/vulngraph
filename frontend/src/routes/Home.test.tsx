import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const summaryData = { total: 100, by_severity: { critical: 7, high: 31 }, by_band: { page: 4, high: 20, pipeline: 50, monitor: 26 } };
const complianceData = { total: 28, passing: 10, controls: [] };
const connectorData = [
  { id: "c1", type: "aws", name: "aws-1", sync_status: "ok", last_synced_at: "2026-06-15T00:00:00Z" },
  { id: "c2", type: "aws", name: "aws-2", sync_status: "pending", last_synced_at: null },
];
const decisionData = { items: [], next_cursor: "" };
const clusterData = {
  items: [
    { check_id: "CVE-2023-44487", title: "HTTP/2 Stream Cancellation Attack", severity: "critical",
      source: "supply_chain", max_score: 81, worst_band: "page", instances: 10, resources: 10,
      known_exploited: true, last_detected: "2026-06-10T00:00:00Z" },
  ],
};
const assetSummaryData = { total: 4000, by_provider: { aws: 3000, gcp: 1000 }, by_type: {} };
const driftData = {
  events: [
    { kind: "new_exposure", asset_id: "arn:aws:ec2:::i-0abc", asset_name: "prod-api-gw",
      asset_type: "ec2_instance", provider: "aws", account_id: "111122223333",
      detected_at: "2026-06-26T08:00:00Z", findings_count: 2, max_score: 84, findings_known: true,
      why: "Security group 0.0.0.0/0 added on port 22" },
  ],
};

function baseHandlers() {
  return [
    meHandler("viewer"),
    http.get("/api/findings/summary", () => HttpResponse.json(summaryData)),
    http.get("/api/compliance", () => HttpResponse.json(complianceData)),
    http.get("/api/connectors", () => HttpResponse.json(connectorData)),
    http.get("/api/decisions", () => HttpResponse.json(decisionData)),
    http.get("/api/findings/clusters", () => HttpResponse.json(clusterData)),
    http.get("/api/assets/summary", () => HttpResponse.json(assetSummaryData)),
    http.get("/api/drift/events", () => HttpResponse.json(driftData)),
    http.get("/api/queue", () => HttpResponse.json({ items: [] })),
    // The must-fix worklist behind the "Fix now" action card.
    http.get("/api/findings", () =>
      HttpResponse.json({ items: [{ id: "mf1" }, { id: "mf2" }], next_cursor: "" })),
  ];
}

test("renders the posture snapshot with key metrics", async () => {
  server.use(...baseHandlers());
  renderApp("/");

  // Tiles carry one number + one plain-language label each.
  expect(await screen.findByText("compliance controls passing")).toBeInTheDocument();
  expect(await screen.findByText("10 of 28")).toBeInTheDocument();
  expect(await screen.findByText("findings scored below the pipeline threshold")).toBeInTheDocument();
  expect(await screen.findByText("connectors synced")).toBeInTheDocument();

  // Top risks section with the cluster
  expect(await screen.findByText("HTTP/2 Stream Cancellation Attack")).toBeInTheDocument();
  expect(screen.getByText("KEV")).toBeInTheDocument();
});

test("action cards lead with the page-band count and a quiet decide state", async () => {
  server.use(...baseHandlers());
  renderApp("/");

  // The hero headline is the page band (4), not the page+high aggregate (24).
  expect(await screen.findByText("findings need a fix now")).toBeInTheDocument();
  expect(await screen.findByText("4")).toBeInTheDocument();
  expect(screen.queryByText("24")).not.toBeInTheDocument();
  // Empty queue → the verdicts card is in its quiet zero state.
  expect(await screen.findByText(/nothing parked for you/)).toBeInTheDocument();
});

test("shows compliance failing count", async () => {
  server.use(...baseHandlers());
  renderApp("/");
  expect(await screen.findByText("18 failing")).toBeInTheDocument();
});

test("shows connectors with pending count", async () => {
  server.use(...baseHandlers());
  renderApp("/");
  // 1 ok, 1 pending → "1/2" in the metric card
  expect(await screen.findByText("1/2")).toBeInTheDocument();
});

test("shows empty top risks message when all findings are monitor band", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings/summary", () => HttpResponse.json(summaryData)),
    http.get("/api/compliance", () => HttpResponse.json(complianceData)),
    // All connectors synced (no pending) so we get the happy-path empty state.
    http.get("/api/connectors", () => HttpResponse.json([
      { id: "c1", type: "aws", name: "aws-1", sync_status: "ok", last_synced_at: "2026-06-15T00:00:00Z" },
    ])),
    http.get("/api/decisions", () => HttpResponse.json(decisionData)),
    http.get("/api/findings/clusters", () => HttpResponse.json({ items: [
      { check_id: "aws-privesc-01", title: "IAM expected", severity: "critical",
        source: "cspm", max_score: 20, worst_band: "monitor", instances: 5, resources: 5,
        known_exploited: false, last_detected: "2026-06-10T00:00:00Z" },
    ]})),
    http.get("/api/assets/summary", () => HttpResponse.json(assetSummaryData)),
    http.get("/api/drift/events", () => HttpResponse.json({ events: [] })),
  );
  renderApp("/");
  expect(await screen.findByText((content) => content.includes("No actionable findings right now"))).toBeInTheDocument();
});

test("surfaces the loops footer and recent drift", async () => {
  server.use(...baseHandlers());
  renderApp("/");

  // The four loops survive as a single quiet footer line of links.
  expect(await screen.findByText("Sense")).toBeInTheDocument();
  expect(screen.getByText("Learn")).toBeInTheDocument();
  // Recent changes (drift) section with the new exposure.
  expect(await screen.findByText("Recent changes")).toBeInTheDocument();
  expect(screen.getByText("prod-api-gw", { exact: false })).toBeInTheDocument();
  expect(screen.getByText("Now exposed")).toBeInTheDocument();
});

// The Correlate fact reads the measured build state: a wired engine with no
// loaded graph used to show "graph ready", and its zero counts "0 nodes".
test("footer shows graph not ready, not 0 nodes, while no build is loaded", async () => {
  server.use(
    ...baseHandlers(),
    http.get("/api/graph/status", () => HttpResponse.json({ ready: false, state: "not_ready", node_count: 0 })),
    http.get("/api/graph/stats", () =>
      HttpResponse.json({ nodes: { assets: 0, roles: 0, repos: 0 }, last_rebuilt: null, ready: false })),
  );
  renderApp("/");
  expect(await screen.findByText("graph not ready")).toBeInTheDocument();
  expect(screen.queryByText(/^0 nodes/)).not.toBeInTheDocument();
});

test("footer shows the node count once the graph is ready", async () => {
  server.use(
    ...baseHandlers(),
    http.get("/api/graph/stats", () =>
      HttpResponse.json({ nodes: { assets: 1200, roles: 300, repos: 0 }, last_rebuilt: "2026-10-01T12:00:00Z", ready: true })),
  );
  renderApp("/");
  expect(await screen.findByText(/^1\.5k nodes/)).toBeInTheDocument();
});

test("with no connectors it prompts for a first source instead of reading as all clear", async () => {
  server.use(
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.get("/api/findings/clusters", () => HttpResponse.json({ items: [] })),
    ...baseHandlers(),
  );
  renderApp("/");

  expect(await screen.findByText("Connect your first source")).toBeInTheDocument();
  expect(await screen.findByText("connect a source to evaluate controls")).toBeInTheDocument();
  expect(screen.queryByText(/No actionable findings right now/)).not.toBeInTheDocument();
});

test("with connectors configured it does not show the first-run prompt", async () => {
  server.use(...baseHandlers());
  renderApp("/");

  expect(await screen.findByText("connectors synced")).toBeInTheDocument();
  expect(screen.queryByText("Connect your first source")).not.toBeInTheDocument();
});
