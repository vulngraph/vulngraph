import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { renderWithClient } from "../test/render";
import type { SavedQuery } from "../lib/queries";
import { SavedDetections, baselineLabel } from "./SavedDetections";

const base: SavedQuery = {
  id: "q1",
  name: "Public buckets",
  description: "",
  cypher: "MATCH (n) RETURN n",
  schedule: "0 * * * *",
  alert_channel_ids: [],
  alert_on_change: true,
  enabled: true,
  last_result_count: 0,
};

function serve(queries: SavedQuery[]) {
  server.use(http.get("/api/saved-queries", () => HttpResponse.json({ queries })));
  renderWithClient(<SavedDetections onClose={() => {}} onLoad={() => {}} />);
}

test("a scheduled query whose latest run failed shows the failure, not the old baseline as healthy", async () => {
  serve([
    {
      ...base,
      last_run_at: "2026-10-01T00:00:00Z",
      last_result_count: 12,
      last_attempt_at: "2026-10-20T00:00:00Z",
      last_attempt_status: "failed",
      last_attempt_error: "graph engine timeout",
      last_attempt_trigger: "schedule",
    },
  ]);
  const status = await screen.findByRole("status");
  expect(status).toHaveTextContent(/failed: graph engine timeout/);
  expect(status).toHaveClass("text-red");
  expect(screen.getByText(/^Baseline: 12 results as of/)).toBeInTheDocument();
});

test("a truncated latest run is flagged as incomplete", async () => {
  serve([{ ...base, last_attempt_at: "2026-10-20T00:00:00Z", last_attempt_status: "truncated", last_attempt_trigger: "schedule" }]);
  expect(await screen.findByRole("status")).toHaveTextContent(/truncated, result incomplete/);
  expect(screen.getByText("No baseline yet: no scheduled run has completed")).toBeInTheDocument();
});

test("a run on an oversized graph is flagged as possibly incomplete, never ok", async () => {
  serve([
    {
      ...base,
      last_attempt_at: "2026-10-20T00:00:00Z",
      last_attempt_status: "incomplete",
      last_attempt_error: "savedquery: multi-hop results may be incomplete",
      last_attempt_trigger: "schedule",
    },
  ]);
  const status = await screen.findByRole("status");
  expect(status).toHaveTextContent(/may be incomplete: savedquery: multi-hop results may be incomplete/);
  expect(status).not.toHaveTextContent(/: ok/);
});

test("a manual-only query that ran shows its latest run instead of 'never run'", async () => {
  serve([
    { ...base, schedule: "", last_attempt_at: "2026-10-20T00:00:00Z", last_attempt_status: "ok", last_attempt_trigger: "manual" },
  ]);
  expect(await screen.findByText(/Last run .* \(manual\): ok/)).toBeInTheDocument();
  expect(screen.queryByText("Never run")).not.toBeInTheDocument();
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
  expect(screen.getByText("Manual only: no change-detection baseline")).toBeInTheDocument();
});

test("a query that never ran says so", async () => {
  serve([base]);
  expect(await screen.findByText("Never run")).toBeInTheDocument();
});

test("baselineLabel never calls the baseline the last run", () => {
  expect(baselineLabel({ ...base, last_run_at: "2026-10-01T00:00:00Z", last_result_count: 3 })).toMatch(/^Baseline: 3 results/);
  expect(baselineLabel({ ...base, schedule: "" })).toBe("Manual only: no change-detection baseline");
});
