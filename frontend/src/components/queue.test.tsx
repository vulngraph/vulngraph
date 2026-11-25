import { http, HttpResponse } from "msw";
import { fireEvent, screen, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";
import type { QueueItem } from "../lib/api";

function item(over: Partial<QueueItem>): QueueItem {
  return {
    cluster_key: "ck",
    title: "t",
    action_class: "remediate",
    outcome: "escalated",
    worst_score: 50,
    blast_radius: 0,
    count: 1,
    resources: 1,
    finding_ids: ["f"],
    decided_at: "2026-07-09T00:00:00Z",
    safety_band: "risky",
    ...over,
  } as QueueItem;
}

// Switches the Decisions page over to the live-queue tab, where QueueCard
// actually renders (the "needs action" outcome filter).
async function openQueueTab() {
  const select = await screen.findByLabelText("Show:");
  fireEvent.change(select, { target: { value: "needs_action" } });
}

// Decisions.tsx always fetches the whole-trail summary on mount; stub it so
// tests that only care about the live queue don't trip the MSW
// unhandled-request warning.
const emptySummaryHandler = http.get("/api/decisions/summary", () =>
  HttpResponse.json({
    total: 0,
    observed: 0,
    escalated: 0,
    parked_for_approval: 0,
    quick_wins: 0,
    unique_resources: 0,
    action_classes: {},
    confidence_bands: {},
    escalation_reasons: {},
    hotspots: [],
  }),
);

test("confidence_known=false renders no numeric gap — a failed lookup is not a measurement", async () => {
  server.use(
    meHandler("admin"),
    emptySummaryHandler,
    http.get("/api/queue", () =>
      HttpResponse.json({
        items: [
          item({
            cluster_key: "unknown-1",
            title: "Unknown-confidence cluster",
            confidence_known: false,
            confidence_gap: 0,
            confidence_effective_n: 0,
            unlocks: 0,
          }),
        ],
      }),
    ),
  );

  renderApp("/decisions");
  await openQueueTab();

  expect(await screen.findByText("Unknown-confidence cluster")).toBeInTheDocument();
  // Never render "gap 0" (or any gap text) when the lookup is not known-good.
  expect(screen.queryByText(/more evidence to high confidence/)).not.toBeInTheDocument();
  expect(screen.queryByText(/advances \d+ similar decision/)).not.toBeInTheDocument();
});

// blast_radius is a MAX across a cluster's findings while blast_radius_known
// is an AND (govern's clusterQueue) — a cluster with one measured finding and
// one failed walk reads as a nonzero blast_radius with known=false. The card
// must still show the caveat, not just when blast_radius is exactly 0.
test("a nonzero blast_radius with blast_radius_known=false still shows the unmeasured caveat", async () => {
  server.use(
    meHandler("admin"),
    emptySummaryHandler,
    http.get("/api/queue", () =>
      HttpResponse.json({
        items: [
          item({
            cluster_key: "partial-blast-1",
            title: "Partially-measured cluster",
            blast_radius: 12,
            blast_radius_known: false,
          }),
        ],
      }),
    ),
  );

  renderApp("/decisions");
  await openQueueTab();

  expect(await screen.findByText("Partially-measured cluster")).toBeInTheDocument();
  expect(screen.getByText(/blast radius: 12/)).toBeInTheDocument();
  expect(screen.getByText(/partially unmeasured/)).toBeInTheDocument();
});

test("shows the unlocks affordance and a meaningful confidence gap when known", async () => {
  server.use(
    meHandler("admin"),
    emptySummaryHandler,
    http.get("/api/queue", () =>
      HttpResponse.json({
        items: [
          item({
            cluster_key: "known-1",
            title: "Known-confidence cluster",
            confidence_known: true,
            confidence_gap: 4,
            unlocks: 3,
          }),
        ],
      }),
    ),
  );

  renderApp("/decisions");
  await openQueueTab();

  expect(await screen.findByText("Known-confidence cluster")).toBeInTheDocument();
  expect(screen.getByText(/4 more evidence to high confidence/)).toBeInTheDocument();
  expect(screen.getByText(/approving this also advances 3 similar decisions/)).toBeInTheDocument();
});

test("a known confidence_gap of 0 (already sufficient) renders no gap text", async () => {
  server.use(
    meHandler("admin"),
    emptySummaryHandler,
    http.get("/api/queue", () =>
      HttpResponse.json({
        items: [
          item({
            cluster_key: "sufficient-1",
            title: "Sufficient-confidence cluster",
            confidence_known: true,
            confidence_gap: 0,
            unlocks: 0,
          }),
        ],
      }),
    ),
  );

  renderApp("/decisions");
  await openQueueTab();

  expect(await screen.findByText("Sufficient-confidence cluster")).toBeInTheDocument();
  expect(screen.queryByText(/more evidence to high confidence/)).not.toBeInTheDocument();
});

test("preserves the server's order within a tier instead of re-sorting by score", async () => {
  server.use(
    meHandler("admin"),
    emptySummaryHandler,
    http.get("/api/queue", () =>
      HttpResponse.json({
        items: [
          item({ cluster_key: "c1", title: "Low score first", worst_score: 10 }),
          item({ cluster_key: "c2", title: "High score second", worst_score: 99 }),
        ],
      }),
    ),
  );

  renderApp("/decisions");
  await openQueueTab();

  const tier = await screen.findByText("Handle with care");
  const section = tier.closest("div")!.parentElement!;
  const text = within(section).getByText("Low score first").compareDocumentPosition(
    within(section).getByText("High score second"),
  );
  // Node.DOCUMENT_POSITION_FOLLOWING (4): "Low score first" comes before
  // "High score second" in the DOM, matching server order — a worst-score
  // sort would have put the 99-score item first.
  expect(text & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});
