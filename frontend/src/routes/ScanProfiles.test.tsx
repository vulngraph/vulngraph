import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

test("a stored invalid profile schedule is shown, not silently idle", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/scan-profiles", () =>
      HttpResponse.json([
        {
          id: "p1",
          name: "Nightly external",
          scanner_type: "nuclei",
          template_strategy: "all",
          schedule: "0 2,x * * *",
          schedule_error: "scan: invalid schedule: hour value \"x\" must be * or a number in 0-23",
          drift_enabled: false,
          enabled: true,
          created_at: "2026-06-10T00:00:00Z",
          updated_at: "2026-06-10T00:00:00Z",
        },
      ]),
    ),
  );

  renderApp("/scans/profiles");

  expect(await screen.findByText(/Schedule is invalid and never runs/)).toBeInTheDocument();
});
