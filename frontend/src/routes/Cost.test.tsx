import { http, HttpResponse } from "msw";
import { screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";
import { SCORE_THRESHOLDS } from "../lib/format";

// A representative shape: thousands of cost-bearing resources in the high band or above, of which the API
// returns a bounded page. The headline must be the TOTAL, never the page size —
// the pre-fix page printed the row count of a LIMIT 100 query as the population,
// so it read "100" forever.
function costAtRiskHandler(total = 7000, returned = 2) {
  return http.get("/api/findings/cost-at-risk", () =>
    HttpResponse.json({
      min_score: SCORE_THRESHOLDS.high,
      total,
      returned,
      by_type: { cloud_function: 5500, ec2_instance: 700 },
      by_provider: { gcp: 6000, aws: 1000 },
      cost_bearing_types: ["ec2_instance", "cloud_function"],
      items: [
        { id: "i-1", name: "payments-api", type: "ec2_instance", provider: "aws", region: "eu-west-1", max_score: 95, finding_count: 6 },
        { id: "fn-1", name: "invoice-fn", type: "cloud_function", provider: "gcp", region: "europe-west4", max_score: 90, finding_count: 2 },
      ].slice(0, returned),
    }),
  );
}

function costStatusHandler(collected: boolean) {
  return http.get("/api/cost/status", () =>
    HttpResponse.json({
      connectors: collected
        ? [{ connector_id: "c-1", account_id: "1234", outcome: "ok", snapshots_stored: 120, last_collected_at: "2026-08-21T00:00:00Z" }]
        : [{ connector_id: "c-1", account_id: "1234", outcome: "permission_denied", detail: "AccessDeniedException", snapshots_stored: 0, attempt_at: "2026-08-21T00:00:00Z" }],
      snapshots_total: collected ? 120 : 0,
      collected,
      required_iam_permission: "ce:GetCostAndUsage",
    }),
  );
}

const connectorsHandler = http.get("/api/connectors", () =>
  HttpResponse.json([{ id: "c-1", name: "aws-prod", type: "aws", enabled: true }]),
);

test("the at-risk headline is the server-side total, not the page size", async () => {
  server.use(meHandler("viewer"), costAtRiskHandler(), costStatusHandler(false), connectorsHandler);

  renderApp("/investigate/cost");

  // 7,000 — not "2" (the rows returned) and not "100" (the old limit clamp).
  expect(await screen.findByText("7,000")).toBeInTheDocument();
  // "100" was the old limit clamp masquerading as a count; nothing on the page
  // may print it as a population figure.
  expect(screen.queryByText("100")).not.toBeInTheDocument();

  // Provider chip counts come from by_provider, not from the sliced chip array.
  await waitFor(() => {
    expect(screen.getByText(`6,000 billed resources at score ≥ ${SCORE_THRESHOLDS.high}`, { exact: false })).toBeInTheDocument();
  });
  expect(screen.getByText(`1,000 billed resources at score ≥ ${SCORE_THRESHOLDS.high}`, { exact: false })).toBeInTheDocument();

  // The composition is published, so the number is auditable.
  expect(screen.getByText("cloud_function")).toBeInTheDocument();
  expect(screen.getByText("5,500")).toBeInTheDocument();
});

test("a permission denial is reported as a denial, never as 'no anomalies'", async () => {
  server.use(meHandler("viewer"), costAtRiskHandler(), costStatusHandler(false), connectorsHandler);

  renderApp("/investigate/cost");

  expect(await screen.findByText("No billing data collected")).toBeInTheDocument();
  expect(screen.getAllByText(/ce:GetCostAndUsage/).length).toBeGreaterThan(0);
  expect(screen.getByText(/AWS denied the Cost Explorer call/)).toBeInTheDocument();
  // The old copy claimed health, and the old advice could not be acted on.
  expect(screen.queryByText(/No cost anomalies/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Run a CSPM scan/)).not.toBeInTheDocument();
});

test("the dead waste estimator and the stale-asset tautology are gone", async () => {
  server.use(meHandler("viewer"), costAtRiskHandler(), costStatusHandler(true), connectorsHandler);

  renderApp("/investigate/cost");

  await screen.findByText("7,000");
  // No check emits the check_ids the price table matched, so the tile could
  // only ever render "—" over a false advice string.
  expect(screen.queryByText("Estimated monthly waste")).not.toBeInTheDocument();
  // The stale filter was applied to a set selected because it HAS findings.
  expect(screen.queryByText("All assets recently seen")).not.toBeInTheDocument();
  expect(screen.queryByText("Stale assets")).not.toBeInTheDocument();
});

test("an empty billed-risk population reads as zero, and a failure reads as a failure", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings/cost-at-risk", () =>
      HttpResponse.json({
        min_score: SCORE_THRESHOLDS.high, total: 0, returned: 0, by_type: {}, by_provider: {},
        cost_bearing_types: ["ec2_instance"], items: [],
      }),
    ),
    costStatusHandler(true),
    connectorsHandler,
  );

  renderApp("/investigate/cost");

  expect(
    await screen.findByText(`No billed resource currently carries a finding at score ≥ ${SCORE_THRESHOLDS.high}`, { exact: false }),
  ).toBeInTheDocument();
});

test("a failed rollup says so instead of showing a clean zero", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings/cost-at-risk", () => HttpResponse.json({ error: "boom" }, { status: 500 })),
    costStatusHandler(true),
    connectorsHandler,
  );

  renderApp("/investigate/cost");

  expect(await screen.findByText(/rollup failed/)).toBeInTheDocument();
  expect(screen.getByText("?")).toBeInTheDocument();
});
