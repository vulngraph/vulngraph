import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const decision = {
  id: "d1",
  ts: "2026-06-14T00:00:00Z",
  actor: "agent",
  action: "decision",
  target_type: "finding",
  target_id: "f1",
  target_title: "SSH brute force",
  target_resource: "arn:aws:ec2::1:instance/i-1",
  details: JSON.stringify({
    action_class: "isolate",
    summary: "cut the host off",
    confidence_band: "high",
    blast_radius: 7,
    cove_concerns: ["destructive action on a production asset"],
    outcome: "escalated",
  }),
};

test("renders decision detail from the audit JSON and expands concerns", async () => {
  server.use(meHandler("viewer"), http.get("/api/decisions", () => HttpResponse.json({ items: [decision], next_cursor: "" })));

  renderApp("/decisions");

  // Decisions now renders glass cards instead of a table. The plan summary,
  // action class, confidence band, and outcome are all shown on the card.
  // "Isolate" also appears as an action-class filter pill, so wait for that
  // to render (proves the page loaded) then assert at least one match exists.
  await screen.findByText("high");
  expect(screen.getAllByText("Isolate").length).toBeGreaterThan(0);
  expect(screen.getByText("high")).toBeInTheDocument();

  // "escalated" appears as both a filter button and an outcome badge on the card;
  // use getAllByText and assert at least one match exists.
  expect(screen.getAllByText("Escalated").length).toBeGreaterThan(0);

  // Summary is shown prominently — visible without any interaction.
  expect(screen.getByText("cut the host off")).toBeInTheDocument();

  // The target title links to the finding detail.
  const link = screen.getByRole("link", { name: "SSH brute force" });
  expect(link).toHaveAttribute("href", "/investigate/findings/f1");

  // Clicking "Review →" opens the DecisionDetailPanel slide-in.
  // Use exact text match to avoid the "escalated — review & approve →" banner button.
  const reviewBtn = screen.getByRole("button", { name: /^review →$/i });
  fireEvent.click(reviewBtn);

  // CoVe concerns are always visible (no toggle) — check directly.
  expect(await screen.findByText(/destructive action on a production asset/)).toBeInTheDocument();
});

// decisionsFixture has one decision per outcome/action_class combo exercised
// by the filter tests below — enough spread that a filter which does nothing
// (or filters the wrong axis) is distinguishable from one that works.
const decisionsFixture = [
  {
    id: "esc-remediate",
    ts: "2026-06-14T00:00:03Z",
    actor: "agent",
    action: "decision",
    target_type: "finding",
    target_id: "f-esc",
    target_title: "Escalated remediate",
    details: JSON.stringify({ action_class: "remediate", outcome: "escalated", safety_band: "caution" }),
  },
  {
    id: "parked-isolate",
    ts: "2026-06-14T00:00:02Z",
    actor: "agent",
    action: "decision",
    target_type: "finding",
    target_id: "f-parked",
    target_title: "Parked isolate",
    details: JSON.stringify({ action_class: "isolate", outcome: "parked_for_approval", safety_band: "risky" }),
  },
  {
    id: "parked-remediate-safe",
    ts: "2026-06-14T00:00:01Z",
    actor: "agent",
    action: "decision",
    target_type: "finding",
    target_id: "f-parked-safe",
    target_title: "Parked safe remediate",
    details: JSON.stringify({ action_class: "remediate", outcome: "parked_for_approval", safety_band: "safe" }),
  },
];

// decisionsHandler mimics the backend's outcome/action_class filtering (the
// same predicates as internal/app/respond/repo.go's selectDecisions) over the
// fixture above, so a test asserting "clicking a filter narrows the visible
// rows" is exercising real query-param plumbing end to end, not a client-side
// fold that would pass even if the frontend never sent the params.
function decisionsHandler() {
  return http.get("/api/decisions", ({ request }) => {
    const url = new URL(request.url);
    const outcome = url.searchParams.get("outcome");
    const actionClass = url.searchParams.get("action_class");
    let items = decisionsFixture;
    if (outcome === "needs_action") {
      items = items.filter((d) => {
        const o = JSON.parse(d.details).outcome;
        return o === "escalated" || o === "parked_for_approval";
      });
    } else if (outcome === "safe_to_fix") {
      items = items.filter((d) => {
        const detail = JSON.parse(d.details);
        return detail.safety_band === "safe" && detail.action_class !== "observe" && detail.outcome !== "suppressed_by_verdict";
      });
    } else if (outcome) {
      items = items.filter((d) => JSON.parse(d.details).outcome === outcome);
    }
    if (actionClass) {
      items = items.filter((d) => JSON.parse(d.details).action_class === actionClass);
    }
    return HttpResponse.json({ items, next_cursor: "" });
  });
}

test("outcome filter narrows the list via the outcome query param, not client-side folding", async () => {
  server.use(meHandler("viewer"), decisionsHandler());

  renderApp("/decisions");

  // Unfiltered: all three fixture rows render.
  await screen.findByText("Escalated remediate");
  expect(screen.getByText("Parked isolate")).toBeInTheDocument();
  expect(screen.getByText("Parked safe remediate")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Show:"), { target: { value: "escalated" } });

  await screen.findByText("Escalated remediate");
  await waitFor(() => expect(screen.queryByText("Parked isolate")).not.toBeInTheDocument());
  expect(screen.queryByText("Parked safe remediate")).not.toBeInTheDocument();
});

test("action-class filter narrows the list via the action_class query param", async () => {
  // Action-class pills only render for classes with a non-zero summary count,
  // so mock a summary matching the fixture's classes.
  server.use(
    meHandler("viewer"),
    decisionsHandler(),
    http.get("/api/decisions/summary", () =>
      HttpResponse.json({
        total: 3,
        observed: 0,
        escalated: 1,
        parked_for_approval: 1,
        quick_wins: 1,
        unique_resources: 3,
        action_classes: { remediate: 2, isolate: 1 },
        confidence_bands: {},
        suppressed_by_verdict: 0,
        escalation_reasons: {},
        hotspots: [],
      }),
    ),
  );

  renderApp("/decisions");

  await screen.findByText("Escalated remediate");
  expect(screen.getByText("Parked isolate")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Isolate 1/ }));

  await screen.findByText("Parked isolate");
  expect(screen.queryByText("Escalated remediate")).not.toBeInTheDocument();
  expect(screen.queryByText("Parked safe remediate")).not.toBeInTheDocument();
});

test("needs_action and safe_to_fix map to the backend's derived filter values", async () => {
  server.use(meHandler("viewer"), decisionsHandler());

  renderApp("/decisions");
  await screen.findByText("Escalated remediate");

  // needs_action switches the page to the live queue tab (not the audit
  // trail), so assert safe_to_fix instead, which stays on the trail view and
  // exercises the derived-value mapping end to end.
  fireEvent.change(screen.getByLabelText("Show:"), { target: { value: "safe_to_fix" } });

  await screen.findByText("Parked safe remediate");
  expect(screen.queryByText("Escalated remediate")).not.toBeInTheDocument();
  expect(screen.queryByText("Parked isolate")).not.toBeInTheDocument();
});

test("splits the escalation-reasons banner honestly and renders an unknown reason key gracefully", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/decisions", () => HttpResponse.json({ items: [decision], next_cursor: "" })),
    http.get("/api/decisions/summary", () =>
      HttpResponse.json({
        total: 20,
        observed: 0,
        escalated: 20,
        parked_for_approval: 0,
        quick_wins: 0,
        unique_resources: 5,
        action_classes: {},
        confidence_bands: {},
        suppressed_by_verdict: 2,
        escalation_reasons: {
          policy_blocked: 6,
          insufficient_confidence: 9,
          verification_concern: 3,
          pattern_denied: 2,
          some_future_reason: 1,
        },
        hotspots: [],
      }),
    ),
  );

  renderApp("/decisions");

  // Policy-blocked decisions (destructive, gate-escalated) must read as
  // its own distinct reason, not folded into "needs more evidence".
  expect(await screen.findByText(/6 destructive, low confidence/)).toBeInTheDocument();
  expect(screen.getByText(/9 need more evidence/)).toBeInTheDocument();
  expect(screen.getByText(/3 failed verification/)).toBeInTheDocument();
  // An unrecognized key still renders (humanized), never silently dropped.
  expect(screen.getByText(/1 some future reason/)).toBeInTheDocument();

  // pattern_denied rides on suppressed_by_verdict decisions, which are the
  // OPPOSITE of "needs a human" — a human already ruled. It must not appear in
  // the escalation-reason list, and its own count reads as answered.
  expect(screen.queryByText(/pattern denied/)).not.toBeInTheDocument();
  expect(screen.getByText(/2 already answered/)).toBeInTheDocument();

  // When the reasons cover only part of the trail, the banner says how much
  // instead of implying a full breakdown of all 20 escalations: 6 + 9 + 3 + 1 = 19.
  expect(screen.getByText(/why \(19 of 20\):/)).toBeInTheDocument();

  // The old blanket message must be gone.
  expect(screen.queryByText(/Most escalations:/)).not.toBeInTheDocument();
});
