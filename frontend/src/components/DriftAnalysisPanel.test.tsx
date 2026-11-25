import { http, HttpResponse } from "msw";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { expect, test, vi } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { DriftAnalysisPanel } from "./DriftAnalysisPanel";

const base = {
  batch_id: "b1",
  connector_id: "c1",
  window_start: "2026-06-14T00:00:00Z",
  window_end: "2026-06-14T01:00:00Z",
  status: "analysed",
  unknown_reason: "",
  summary: "One host became internet reachable.",
  changes: [{ kind: "new_exposure", asset_id: "i-1", note: "public IP added" }],
  exposure_judgement: "increased",
  scan_recommendation: "recommended",
  reason: "New exposure on a host",
  suggested_profile_id: "p1",
  suggested_template_tags: [],
  confidence: "medium",
  evidence: [{ source: "asset", ref: "i-1", fact: "public_ip set" }],
  auto_scan_profile_ids: [],
  truncated: false,
  source: "llm",
  advisory: true,
};

function serve(analysis: object | null, role: "admin" | "viewer" = "viewer", enabled = true) {
  server.use(
    meHandler(role),
    http.get("/api/drift/analyses", () =>
      HttpResponse.json({ enabled, analyses: analysis ? [analysis] : [] }),
    ),
  );
}

function renderPanel(onOpenAsset = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DriftAnalysisPanel since="24h" onOpenAsset={onOpenAsset} />
    </QueryClientProvider>,
  );
  return onOpenAsset;
}

test("an unknown analysis reads as unknown, never as no scan needed", async () => {
  serve({
    ...base, status: "unknown", unknown_reason: "budget", summary: "", changes: [], evidence: [],
    exposure_judgement: "", scan_recommendation: "unknown", suggested_profile_id: "",
  });
  renderPanel();

  expect(await screen.findByText("Scan unknown")).toBeInTheDocument();
  expect(screen.queryByText("Scan not needed")).not.toBeInTheDocument();
  expect(screen.getByText("AI-derived, advisory")).toBeInTheDocument();
});

test("a recommended analysis shows summary, exposure and links evidence to the asset", async () => {
  serve(base);
  const open = renderPanel();

  expect(await screen.findByText("Scan recommended")).toBeInTheDocument();
  expect(screen.getByText("Exposure increased")).toBeInTheDocument();
  expect(screen.getByText("One host became internet reachable.")).toBeInTheDocument();
  fireEvent.click(screen.getAllByText("i-1")[1]);
  expect(open).toHaveBeenCalledWith("i-1");
});

test("an admin confirms before the suggested profile scan starts", async () => {
  let triggered = 0;
  serve(base, "admin");
  server.use(
    http.post("/api/scan-profiles/p1/trigger", () => {
      triggered++;
      return HttpResponse.json({ run_id: "r1" });
    }),
  );
  renderPanel();

  fireEvent.click(await screen.findByText("Start profile scan"));
  expect(triggered).toBe(0);
  fireEvent.click(screen.getByText("Confirm"));
  expect(await screen.findByText(/Scan started/)).toBeInTheDocument();
  expect(triggered).toBe(1);
});

test("cancelling the confirm step starts nothing", async () => {
  serve(base, "admin");
  renderPanel();

  fireEvent.click(await screen.findByText("Start profile scan"));
  fireEvent.click(screen.getByText("Cancel"));
  expect(screen.getByText("Start profile scan")).toBeInTheDocument();
});

test("a non-admin does not see the start button", async () => {
  serve(base, "viewer");
  renderPanel();

  await screen.findByText("Scan recommended");
  expect(screen.queryByText("Start profile scan")).not.toBeInTheDocument();
});

test("an admin sees no start button without a suggested profile", async () => {
  serve({ ...base, suggested_profile_id: "" }, "admin");
  renderPanel();

  await screen.findByText("Scan recommended");
  await waitFor(() => expect(screen.queryByText("Start profile scan")).not.toBeInTheDocument());
});

test("not needed reads as not needed", async () => {
  serve({ ...base, scan_recommendation: "not_needed", exposure_judgement: "unchanged", suggested_profile_id: "" }, "admin");
  renderPanel();

  expect(await screen.findByText("Scan not needed")).toBeInTheDocument();
  expect(screen.queryByText("Start profile scan")).not.toBeInTheDocument();
});

test("disabled analysis reads Not analysed and says how to turn it on", async () => {
  serve(null, "viewer", false);
  renderPanel();

  expect(await screen.findByText("Not analysed")).toBeInTheDocument();
  expect(screen.getByText("DRIFT_ANALYSIS_ENABLED=true")).toBeInTheDocument();
  expect(screen.queryByText("Scan not needed")).not.toBeInTheDocument();
});

test("a failed fetch reads Not analysed", async () => {
  server.use(meHandler("viewer"), http.get("/api/drift/analyses", () => HttpResponse.json({}, { status: 500 })));
  renderPanel();

  expect(await screen.findByText("Not analysed")).toBeInTheDocument();
});

test("a truncated batch says the rest was not analysed", async () => {
  serve({ ...base, truncated: true });
  renderPanel();

  expect(await screen.findByText(/Truncated: more assets changed/)).toBeInTheDocument();
});
