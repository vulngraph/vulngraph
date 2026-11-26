import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const ev = {
  kind: "new_asset" as const,
  asset_id: "i-1",
  asset_name: "web",
  asset_type: "ec2_instance",
  provider: "aws",
  account_id: "123456789012",
  detected_at: "2026-06-14T00:00:00Z",
  findings_count: 0,
  max_score: 0,
  findings_known: true,
};

const asset = {
  id: "i-1",
  name: "web",
  type: "ec2_instance",
  provider: "aws",
  region: "eu-west-1",
  risk_score: 0,
  last_seen: "2026-06-14T00:00:00Z",
  environment: "unknown",
  environment_source: "",
};

test("clicking a drift row opens the asset slide-over instead of navigating away", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/drift/events", () => HttpResponse.json({ events: [ev] })),
    http.get("/api/assets/i-1", () => HttpResponse.json(asset)),
    http.get("/api/assets/i-1/blast-radius", () =>
      HttpResponse.json({ seed_id: "i-1", max_depth: 2, truncated: false, assets: [asset], edges: [] }),
    ),
    http.get("/api/assets/i-1/changes", () => HttpResponse.json({ changes: [] })),
    http.get("/api/findings", () => HttpResponse.json({ items: [], next_cursor: "" })),
  );

  renderApp("/investigate/drift");

  expect(await screen.findByText("web")).toBeInTheDocument();
  fireEvent.click(screen.getByText("web"));

  // The slide-over opens ("Asset detail" panel chrome) while the Drift page
  // itself stays mounted underneath — proving this was not a full-page
  // navigation to /investigate/assets/$id. The asset name now renders twice:
  // once in the drift row, once inside the opened panel.
  expect(await screen.findByLabelText("Asset detail")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Drift" })).toBeInTheDocument();
  await waitFor(() => expect(screen.getAllByText("web").length).toBeGreaterThan(1));
});

test("a full page of drift events reads as capped, not a total", async () => {
  const many = Array.from({ length: 200 }, (_, i) => ({ ...ev, asset_id: `i-${i}`, asset_name: `host-${i}` }));
  server.use(
    meHandler("viewer"),
    http.get("/api/drift/events", () => HttpResponse.json({ events: many })),
  );

  renderApp("/investigate/drift");

  expect(await screen.findByText("200+ changes (capped)")).toBeInTheDocument();
});

test("a failed findings lookup reads as unknown, not as no findings", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/drift/events", () =>
      HttpResponse.json({ events: [ev, { ...ev, asset_id: "i-2", asset_name: "db", findings_known: false }] }),
    ),
  );

  renderApp("/investigate/drift");

  expect(await screen.findByText("Findings unknown")).toBeInTheDocument();
  expect(screen.getAllByText("No findings")).toHaveLength(1);
});

test("the drift page shows the analysis panel above the events, labelled advisory", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/drift/events", () => HttpResponse.json({ events: [ev] })),
    http.get("/api/drift/analyses", () =>
      HttpResponse.json({
        enabled: true,
        analyses: [{
          batch_id: "b1", connector_id: "c1", window_start: "2026-06-14T00:00:00Z", window_end: "2026-06-14T01:00:00Z",
          status: "unknown", unknown_reason: "llm_error", summary: "", changes: [], exposure_judgement: "",
          scan_recommendation: "unknown", reason: "",
          confidence: "low", evidence: [], truncated: false, source: "llm", advisory: true,
        }],
      }),
    ),
  );

  renderApp("/investigate/drift");

  expect(await screen.findByText("Scan unknown")).toBeInTheDocument();
  expect(screen.getByText("AI-derived, advisory")).toBeInTheDocument();
  expect(await screen.findByText("web")).toBeInTheDocument();
});

test("with drift analysis off the drift page says so", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/drift/events", () => HttpResponse.json({ events: [ev] })),
  );

  renderApp("/investigate/drift");

  expect(await screen.findByText("DRIFT_ANALYSIS_ENABLED=true")).toBeInTheDocument();
});
