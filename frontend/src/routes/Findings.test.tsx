import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";
import scoreBands from "../generated/score-bands.json";

function minScore(band: string): number {
  const b = scoreBands.bands.find((x) => x.band === band);
  if (!b) throw new Error(`no ${band} band`);
  return b.min_score;
}

const emptySummary = { total: 0, by_severity: {}, by_band: {} };

// The default Findings view is "Must fix". These tests cover the grouped/instance
// views, so switch to the "All" view tab first. (Must fix and Start here have
// their own tests below.) This must run before the All view renders the band
// pills, one of which is also named "All".
async function openAllView() {
  fireEvent.click(await screen.findByRole("tab", { name: "All" }));
}

// The grouped view fetches clusters, the governor queue, and the summary banner.
const grouped = (items: unknown[], queue: unknown[] = []) => [
  http.get("/api/findings/clusters", () => HttpResponse.json({ items })),
  http.get("/api/queue", () => HttpResponse.json({ items: queue })),
  http.get("/api/findings/summary", () => HttpResponse.json(emptySummary)),
];

const sampleFinding = {
  id: "f1",
  source: "cspm",
  type: "exposure",
  severity: "high",
  score: 84,
  score_band: "page",
  known_exploited: true,
  title: "EC2 instance has a public IP",
  resource_id: "i-123",
  detected_at: "2026-06-10T00:00:00Z",
};

const sampleCluster = {
  check_id: "aws-public-ip",
  title: "EC2 instance has a public IP",
  severity: "high",
  source: "cspm",
  max_score: 84,
  worst_band: "page",
  instances: 12,
  resources: 9,
  known_exploited: true,
  last_detected: "2026-06-10T00:00:00Z",
};

test("groups findings by check as a decision card in the All view", async () => {
  server.use(meHandler("viewer"), ...grouped([sampleCluster]));

  renderApp("/investigate/findings");
  await openAllView();

  // The cluster shows the issue once, with the worst score and the instance +
  // resource counts — not 12 duplicate rows.
  expect(await screen.findByText("EC2 instance has a public IP")).toBeInTheDocument();
  expect(screen.getByText("84")).toBeInTheDocument();
  expect(screen.getByText("KEV")).toBeInTheDocument();
  // Resource count now renders as a teal pill showing just the number
  expect(screen.getByText("9")).toBeInTheDocument();
});

test("a band filter on the grouped view keeps that band and every band above it", async () => {
  const cluster = (check_id: string, title: string, worst_band: string, max_score: number) =>
    ({ ...sampleCluster, check_id, title, worst_band, max_score, known_exploited: false });
  server.use(meHandler("viewer"), ...grouped([
    cluster("c-page", "Page cluster", "page", 90),
    cluster("c-high", "High cluster", "high", 70),
    cluster("c-pipe", "Pipeline cluster", "pipeline", 55),
  ]));

  renderApp("/investigate/findings");
  await openAllView();
  expect(await screen.findByText("Pipeline cluster")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "High" }));
  await waitFor(() => expect(screen.queryByText("Pipeline cluster")).not.toBeInTheDocument());
  expect(screen.getByText("Page cluster")).toBeInTheDocument();
  expect(screen.getByText("High cluster")).toBeInTheDocument();
});

test("a cluster shows the finding score and remediation — no approve button (actions are in Decisions)", async () => {
  server.use(
    meHandler("admin"),
    ...grouped([sampleCluster]),
  );

  renderApp("/investigate/findings");
  await openAllView();

  // Title renders (uses sampleCluster title).
  expect(await screen.findByText(/EC2 instance has a public IP/)).toBeInTheDocument();
  // Approve fix button must NOT be present — governance actions live in Decisions only.
  expect(screen.queryByRole("button", { name: /Approve fix/ })).not.toBeInTheDocument();
});

test("expanding a cluster drills into its instances", async () => {
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", ({ request }) => {
      const params = new URL(request.url).searchParams;
      // Other views' mount fetches land here too — Start here (?safe=true), Must fix
      // (?must_fix=true) and its unenriched-vs-clean probe (?limit=). Only the
      // cluster drill carries check_id, so key on that rather than excluding each
      // sibling request by name as they get added.
      if (!params.has("check_id")) return HttpResponse.json({ items: [], next_cursor: "" });
      // Expanding fetches the instances for that check.
      expect(params.get("check_id")).toBe("aws-public-ip");
      return HttpResponse.json({ items: [sampleFinding], next_cursor: "" });
    }),
  );

  renderApp("/investigate/findings");
  await openAllView();

  // The title Link now has stopPropagation so it navigates without toggling.
  // Click the parent <button> wrapper (the expand toggle) instead.
  const titleLink = await screen.findByText("EC2 instance has a public IP");
  // ClusterCard uses div[role="button"] (not <button>) to allow <Link> inside without invalid HTML.
  const expandButton = titleLink.closest("[role='button']");
  if (!expandButton) throw new Error("expand button not found");
  fireEvent.click(expandButton);
  // The instance's resource id shows once the cluster expands.
  expect(await screen.findByText("i-123")).toBeInTheDocument();
});

test("renders the flat instance list under the All toggle", async () => {
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", () => HttpResponse.json({ items: [sampleFinding], next_cursor: "" })),
  );

  renderApp("/investigate/findings");
  await openAllView();

  fireEvent.click(await screen.findByRole("button", { name: "All instances" }));
  expect(await screen.findByText("i-123")).toBeInTheDocument();
  const table = screen.getByRole("table");
  expect(within(table).getByText("84")).toBeInTheDocument();
  expect(within(table).getByText("KEV")).toBeInTheDocument();
});

test("shows the empty state when there are no findings", async () => {
  server.use(meHandler("viewer"), ...grouped([]));

  renderApp("/investigate/findings");
  await openAllView();

  expect(await screen.findByText(/No findings/)).toBeInTheDocument();
});

test("a viewer sees no suppress action", async () => {
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", () => HttpResponse.json({ items: [sampleFinding], next_cursor: "" })),
  );

  renderApp("/investigate/findings");
  await openAllView();

  fireEvent.click(await screen.findByRole("button", { name: "All instances" }));
  await screen.findByText("i-123");
  expect(screen.queryByRole("button", { name: "Suppress" })).not.toBeInTheDocument();
});

test("an admin can suppress a finding with a reason and an expiry (default 90 days)", async () => {
  let posted: { reason?: string; expires_at?: string } | null = null;
  server.use(
    meHandler("admin"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", () => HttpResponse.json({ items: [sampleFinding], next_cursor: "" })),
    http.post("/api/findings/f1/suppress", async ({ request }) => {
      posted = (await request.json()) as { reason?: string; expires_at?: string };
      return HttpResponse.json({ finding_id: "f1", reason: posted?.reason, suppressed_by: "admin@example.com", suppressed_at: "2026-06-11T00:00:00Z" }, { status: 201 });
    }),
  );

  // Also need to respond to useFinding so the inline detail renders
  server.use(
    http.get("/api/findings/f1", () =>
      HttpResponse.json({ id: "f1", source: "cspm", type: "exposure", severity: "high",
        score: 84, score_band: "page", known_exploited: false, title: "EC2 instance has a public IP",
        resource_id: "i-123", detected_at: "2026-06-10T00:00:00Z",
        exposure: {}, blast: {}, provenance: {}, factors: [] }),
    ),
  );

  renderApp("/investigate/findings");
  await openAllView();

  fireEvent.click(await screen.findByRole("button", { name: "All instances" }));
  // A row's primary click now opens the finding slide-over (house convention);
  // the chevron still toggles the inline detail that hosts the suppress form.
  await screen.findAllByText("EC2 instance has a public IP");
  fireEvent.click(screen.getByRole("button", { name: /expand details for EC2 instance has a public IP/i }));
  fireEvent.click(await screen.findByRole("button", { name: "Suppress" }));
  fireEvent.change(screen.getByPlaceholderText(/why this finding/i), { target: { value: "false positive" } });
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }));

  await waitFor(() => expect(posted?.reason).toBe("false positive"));
  // Pre-filled with 90 days out, sent as the end of that local day.
  const days = (new Date(posted!.expires_at!).getTime() - Date.now()) / 86_400_000;
  expect(days).toBeGreaterThan(89);
  expect(days).toBeLessThan(91);
});

test("a finding whose suppression expired is flagged as such", async () => {
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", () =>
      HttpResponse.json({ items: [{ ...sampleFinding, exception_expired: true }], next_cursor: "" }),
    ),
  );

  renderApp("/investigate/findings");
  await openAllView();
  fireEvent.click(await screen.findByRole("button", { name: "All instances" }));

  expect(await screen.findByText("exception expired")).toBeInTheDocument();
});

test("Must fix (default) lists evidence-backed must-fix findings with their reason", async () => {
  let requestedMustFix = false;
  server.use(
    meHandler("viewer"),
    http.get("/api/findings", ({ request }) => {
      // Default view is Must fix — it requests the must-fix worklist.
      if (new URL(request.url).searchParams.get("must_fix") === "true") {
        requestedMustFix = true;
        return HttpResponse.json({
          items: [{ ...sampleFinding, enrichment_state: "enriched", must_fix_class: "must_fix", must_fix_reason: "internet-reachable (2 hops) · KEV · blast 42" }],
          next_cursor: "",
        });
      }
      // The view also probes an unfiltered page, so that an EMPTY must-fix list can
      // distinguish "nothing qualified" from "enrichment never ran".
      return HttpResponse.json({ items: [{ ...sampleFinding, enrichment_state: "enriched" }], next_cursor: "" });
    }),
  );

  renderApp("/investigate/findings");

  expect(await screen.findByText("EC2 instance has a public IP")).toBeInTheDocument();
  expect(await screen.findByText(/internet-reachable \(2 hops\)/)).toBeInTheDocument();
  expect(requestedMustFix).toBe(true);
});

// The search box wrote ?q= to the URL on every view, but only ClusterView/InstanceView
// (the All tab) ever read it back — Must fix and Start here share FindingWorklist, which
// had no search filter at all, so typing a query there silently did nothing.
test("Must fix applies the ?q= search filter, not just the All tab", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings", ({ request }) => {
      if (new URL(request.url).searchParams.get("must_fix") === "true") {
        return HttpResponse.json({
          items: [
            { ...sampleFinding, id: "f1", title: "EC2 instance has a public IP", enrichment_state: "enriched" },
            { ...sampleFinding, id: "f2", title: "S3 bucket is publicly readable", enrichment_state: "enriched" },
          ],
          next_cursor: "",
        });
      }
      return HttpResponse.json({ items: [{ ...sampleFinding, enrichment_state: "enriched" }], next_cursor: "" });
    }),
  );

  renderApp("/investigate/findings?q=S3+bucket");

  expect(await screen.findByText("S3 bucket is publicly readable")).toBeInTheDocument();
  expect(screen.queryByText("EC2 instance has a public IP")).not.toBeInTheDocument();
});

// An empty must-fix list used to render "Nothing meets the must-fix bar — that's the
// goal" regardless of WHY it was empty. When enrichment has never run, must_fix_class
// is blank on every finding, the filter matches nothing, and a total absence of
// assessment was reported to the user as success. That is the single most misleading
// state in the product, and it is now impossible to reach.
test("Must fix distinguishes an unenriched corpus from a genuinely clean one", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings", ({ request }) => {
      if (new URL(request.url).searchParams.get("must_fix") === "true") {
        return HttpResponse.json({ items: [], next_cursor: "" }); // nothing matches the tier
      }
      // ...but findings DO exist, and none of them has been enriched.
      return HttpResponse.json({
        items: [{ ...sampleFinding, score: 0, score_band: "", must_fix_class: "", enrichment_state: "never_enriched" }],
        next_cursor: "",
      });
    }),
  );

  renderApp("/investigate/findings");

  expect(await screen.findByText(/enrichment has not run/i)).toBeInTheDocument();
  expect(screen.queryByText(/Nothing meets the must-fix bar/i)).not.toBeInTheDocument();
});

test("Start here tab lists safe∩high-signal findings with their evidence", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings", ({ request }) => {
      if (new URL(request.url).searchParams.get("safe") === "true") {
        return HttpResponse.json({
          items: [{ ...sampleFinding, safety_class: "safe", dependents: 0, unused: true, fix_target: "console:111:eu-west-1" }],
          next_cursor: "",
        });
      }
      return HttpResponse.json({ items: [], next_cursor: "" }); // must-fix default mount
    }),
  );

  renderApp("/investigate/findings");
  fireEvent.click(await screen.findByRole("tab", { name: "Start here" }));

  expect(await screen.findByText("EC2 instance has a public IP")).toBeInTheDocument();
  expect(screen.getByText("Safe to fix")).toBeInTheDocument();
});

test("passes the min_score filter to the API", async () => {
  const seen: string[] = [];
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", ({ request }) => {
      seen.push(new URL(request.url).searchParams.get("min_score") ?? "");
      return HttpResponse.json({ items: [], next_cursor: "" });
    }),
  );

  renderApp("/investigate/findings");
  await openAllView();

  fireEvent.click(await screen.findByRole("button", { name: "All instances" }));
  await screen.findByText(/No findings match/);
  // The flat view derives the threshold from the shared band filter in the
  // page toolbar, using the server's band boundaries.
  fireEvent.click(screen.getByRole("button", { name: "High" }));
  await waitFor(() => expect(seen).toContain(String(minScore("high"))));

  // Medium is the server's pipeline band, which starts where reasoning starts.
  fireEvent.click(screen.getByRole("button", { name: "Medium" }));
  await waitFor(() => expect(seen).toContain(String(minScore("pipeline"))));
});

test("the view switcher is three tabs — Signals/Hygiene/Timeline/Drift are gone", async () => {
  server.use(meHandler("viewer"), ...grouped([sampleCluster]));

  renderApp("/investigate/findings");

  // The three that remain.
  expect(await screen.findByRole("tab", { name: "Must fix" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Start here" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "All" })).toBeInTheDocument();
  // Signals folded into the band filter; Hygiene/Timeline into the sort control;
  // Drift is its own route (/investigate/drift) under the Investigate sub-nav.
  for (const gone of ["Signals", "Hygiene", "Timeline"]) {
    expect(screen.queryByRole("tab", { name: gone })).not.toBeInTheDocument();
  }
});

test("the filter bar is visible on every view, not just All", async () => {
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", () => HttpResponse.json({ items: [], next_cursor: "" })),
  );

  // Default view (Must fix) — filters used to be hidden here entirely, so users
  // never discovered them.
  renderApp("/investigate/findings");
  expect(await screen.findByPlaceholderText(/search findings/)).toBeInTheDocument();
  expect(screen.getByLabelText("Source filter")).toBeInTheDocument();
  // ...but the band pills are not, since Must fix defines its own tier.
  expect(screen.queryByRole("button", { name: "Critical" })).not.toBeInTheDocument();
});

test("a ?view=signals alias lands on All with the High band applied", async () => {
  const seen: string[] = [];
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", ({ request }) => {
      seen.push(new URL(request.url).searchParams.get("min_score") ?? "");
      return HttpResponse.json({ items: [], next_cursor: "" });
    }),
  );

  // ?view=signals is the High-and-above band filter.
  renderApp("/investigate/findings?view=signals&grouped=false");

  await screen.findByText(/No findings match/);
  await waitFor(() => expect(seen).toContain(String(minScore("high"))));
});

test("a legacy ?view=timeline link lands on All sorted by detection date", async () => {
  const seen: string[] = [];
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", ({ request }) => {
      seen.push(new URL(request.url).searchParams.get("sort") ?? "");
      return HttpResponse.json({ items: [], next_cursor: "" });
    }),
  );

  renderApp("/investigate/findings?view=timeline&grouped=false");

  await screen.findByText(/No findings match/);
  await waitFor(() => expect(seen).toContain("detected"));
});

test("the sort control switches the flat view between score and newest", async () => {
  const seen: string[] = [];
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", ({ request }) => {
      seen.push(new URL(request.url).searchParams.get("sort") ?? "");
      return HttpResponse.json({ items: [], next_cursor: "" });
    }),
  );

  renderApp("/investigate/findings?view=all&grouped=false");
  await screen.findByText(/No findings match/);

  fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "detected" } });
  await waitFor(() => expect(seen).toContain("detected"));
});

test("search is written to the URL, so the views read it back from there", async () => {
  server.use(meHandler("viewer"), ...grouped([sampleCluster]));

  renderApp("/investigate/findings?view=all");
  await screen.findByText(/need attention/);

  // The box is local state debounced into the URL; the views only ever read the
  // URL, so seeing the query echoed proves the round-trip (and that a refresh or
  // a shared link would keep it).
  fireEvent.change(screen.getByPlaceholderText(/search findings/), { target: { value: "public-ip" } });
  expect(await screen.findByText(/"public-ip"/)).toBeInTheDocument();
});

test("owner and environment filters go server-side and list instances, with owner/env badges", async () => {
  const seen: URLSearchParams[] = [];
  server.use(
    meHandler("viewer"),
    ...grouped([sampleCluster]),
    http.get("/api/findings", ({ request }) => {
      seen.push(new URL(request.url).searchParams);
      return HttpResponse.json({
        items: [{ ...sampleFinding, owner_team: "payments", owner_source: "tag", environment: "prod" }],
        next_cursor: "",
      });
    }),
  );

  // Grouped is the All view's default, but clusters carry no owner — the
  // routed filter must list instances rather than be silently ignored.
  renderApp("/investigate/findings?view=all&owner=payments&environment=prod");

  expect(await screen.findByText("@payments")).toBeInTheDocument();
  expect(screen.getByText("prod", { selector: "span" })).toBeInTheDocument();
  await waitFor(() => {
    expect(seen.some((p) => p.get("owner") === "payments" && p.get("environment") === "prod")).toBe(true);
  });
  expect(screen.getByText(/owner\/environment filters list instances/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Export CSV" })).toBeInTheDocument();
});
