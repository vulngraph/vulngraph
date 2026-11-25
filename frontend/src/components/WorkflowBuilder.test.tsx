import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { renderWithClient } from "../test/render";
import type { ScanProfile } from "../lib/api";
import { WorkflowBuilder, submittedTargetQuery } from "./WorkflowBuilder";

const driftProfile: ScanProfile = {
  id: "p1",
  name: "Drift watch",
  description: "",
  target_query: "",
  scanner_type: "nuclei",
  template_strategy: "all",
  template_tags: [],
  schedule: "",
  drift_enabled: true,
  enabled: true,
  created_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
};

function open(profile: ScanProfile) {
  server.use(http.get("/api/workflows/presets", () => HttpResponse.json({ targets: [], triggers: [] })));
  renderWithClient(<WorkflowBuilder profile={profile} onClose={() => {}} />);
}

test("an unscoped drift profile says asset changes start it", () => {
  open(driftProfile);
  expect(screen.getByText(/runs automatically when a connector sync reports a change/)).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

// The server drift-triggers only profiles with no target query, so the form
// must not promise drift scans for a profile scoped by a WHO filter.
test("a scoped drift profile warns that asset changes will not start it", () => {
  open({
    ...driftProfile,
    target_query: "MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})\nWHERE a.provider = 'aws'\nRETURN a\nLIMIT 500",
  });
  expect(screen.getByRole("alert")).toHaveTextContent(/will not start it/);
  expect(screen.queryByText(/runs automatically when a connector sync/)).not.toBeInTheDocument();
});

// A blank query must be sent as "": the server drift-triggers only
// target_query = '', and the form shows a blank query as unscoped.
test("a blank or default target query is sent as no query", () => {
  expect(submittedTargetQuery("  \n\t ")).toBe("");
  expect(submittedTargetQuery("")).toBe("");
  const scoped = "MATCH (a:Asset) RETURN a LIMIT 5";
  expect(submittedTargetQuery(scoped)).toBe(scoped);
});
