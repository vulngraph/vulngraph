import { http, HttpResponse } from "msw";
import { fireEvent, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const run = {
  id: "s1",
  status: "completed",
  target_count: 5,
  finding_count: 2,
  started_at: "2026-06-10T00:00:00Z",
};

test("a viewer sees scan runs but no trigger button", async () => {
  server.use(meHandler("viewer"), http.get("/api/scans", () => HttpResponse.json([run])));

  renderApp("/scans");

  expect(await screen.findByText("completed")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Create scan/ })).not.toBeInTheDocument();
});

test("an admin sees the create scan button", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/scans", () => HttpResponse.json([run])),
  );

  renderApp("/scans");

  expect(await screen.findByRole("button", { name: /Create scan/ })).toBeInTheDocument();
});

// The old bespoke CreateScanModal is gone — "Create scan" now opens the single
// shared WorkflowBuilder in run-once mode.
test("create scan opens the workflow builder in run-once mode", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/scans", () => HttpResponse.json([run])),
    // WorkflowBuilder loads the preset catalog; it falls back to built-ins, but
    // stub it so the request doesn't log as unhandled.
    http.get("/api/workflows/presets", () =>
      HttpResponse.json({ targets: [], triggers: [] }),
    ),
  );

  renderApp("/scans");

  fireEvent.click(await screen.findByRole("button", { name: /Create scan/ }));

  // WorkflowBuilder chrome, run-once flavour.
  expect(await screen.findByText("Run a scan")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Run scan/ })).toBeInTheDocument();
  expect(screen.getByText("Run once")).toBeInTheDocument();
  // Shared builder sections are present…
  expect(screen.getByText("WHO")).toBeInTheDocument();
  expect(screen.getByText("DO")).toBeInTheDocument();
  // …and the run-once form never offers a schedule or an "Enabled" toggle.
  expect(screen.queryByLabelText("Enabled")).not.toBeInTheDocument();
  expect(screen.queryByPlaceholderText(/Cron expression/)).not.toBeInTheDocument();
});
