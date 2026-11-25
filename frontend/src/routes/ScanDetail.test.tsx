import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";
import { SCORE_THRESHOLDS } from "../lib/format";

const run = {
  id: "s1-aabbccdd", status: "completed", target_count: 12, finding_count: 3,
  started_at: "2026-06-10T00:00:00Z", finished_at: "2026-06-10T00:05:00Z",
  template_tags: ["exposure", "misconfig"], template_count: 2, scanner_name: "nuclei",
  target_urls: ["https://example.com", "https://api.example.com"],
};

test("renders a scan run's detail", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/scans/s1-aabbccdd", () => HttpResponse.json(run)),
    http.get("/api/scans/s1-aabbccdd/findings", () =>
      HttpResponse.json({ scan_id: "s1-aabbccdd", findings: [], count: 0 }),
    ),
  );

  renderApp("/scans/s1-aabbccdd");

  // Header shows scan id slice
  expect(await screen.findByText(/Scan #/)).toBeInTheDocument();
  // Stats
  expect(screen.getByText("12")).toBeInTheDocument(); // target count
  expect(screen.getByText("3")).toBeInTheDocument();  // finding count
  expect(screen.getByText("2")).toBeInTheDocument();  // template count
  // Template tags rendered
  expect(screen.getByText("exposure")).toBeInTheDocument();
  expect(screen.getByText("misconfig")).toBeInTheDocument();
  // Target URLs shown
  expect(screen.getByText("https://example.com")).toBeInTheDocument();
});

test("shows a truncation banner sized off the scan's finding_count, not the clamped batch's own count", async () => {
  // The backend sets count = len(rows) after clamping to 200, so count is
  // always <= findings.length and the old `count > findings.length` check
  // could never fire. The banner must instead compare against the scan's own
  // finding_count (1000), already shown in the stat card.
  const bigRun = { ...run, finding_count: 1000 };
  const findings = Array.from({ length: 200 }, (_, i) => ({
    id: `f${i}`, source: "cspm", type: "exposure", severity: "high",
    score: 80, score_band: "page", title: `Finding ${i}`, check_id: "aws-x",
    detected_at: "2026-06-10T00:00:00Z",
  }));

  server.use(
    meHandler("viewer"),
    http.get("/api/scans/s1-aabbccdd", () => HttpResponse.json(bigRun)),
    http.get("/api/scans/s1-aabbccdd/findings", () =>
      HttpResponse.json({ scan_id: "s1-aabbccdd", findings, count: 200 }),
    ),
  );

  renderApp("/scans/s1-aabbccdd");

  expect(await screen.findByText(/Showing 200 of 1000/)).toBeInTheDocument();
});

test("a scan finding's badge shows the band the server assigned, not one derived from the score", async () => {
  // scoreToBand(SCORE_THRESHOLDS.high) is "high"; the server says "pipeline".
  const score = SCORE_THRESHOLDS.high;
  const findings = [{
    id: "f1", severity: "medium", score, score_band: "pipeline", title: "Banded finding",
    resource_id: "r1", resource_type: "host", check_id: "nuclei-x", detected_at: "2026-06-10T00:00:00Z",
  }];
  server.use(
    meHandler("viewer"),
    http.get("/api/scans/s1-aabbccdd", () => HttpResponse.json(run)),
    http.get("/api/scans/s1-aabbccdd/findings", () =>
      HttpResponse.json({ scan_id: "s1-aabbccdd", findings, count: 1 }),
    ),
  );

  renderApp("/scans/s1-aabbccdd");

  expect(await screen.findByTitle(`Risk score ${score} — medium`)).toBeInTheDocument();
});
