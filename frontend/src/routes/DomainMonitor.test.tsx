import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import { DomainMonitor } from "./DomainMonitor";

const BASE = {
  monitored_domain: "zeta.test",
  source: "crt_sh",
  similarity_score: 0.88,
  issuer: "Let's Encrypt",
  not_before: "2026-08-01",
  not_after: "2026-11-01",
  status: "pending",
  ai_is_phishing: true,
  ai_confidence: 0.98,
  detected_at: "2026-08-20T00:00:00Z",
};

test("a heuristic verdict is labelled Heuristic, never AI", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/intel/domains", () => HttpResponse.json({ domains: [] })),
    http.get("/api/intel/phishing", ({ request }) => {
      if (new URL(request.url).searchParams.get("status") !== "pending") {
        return HttpResponse.json({ candidates: [], total: 0 });
      }
      return HttpResponse.json({
        candidates: [
          { ...BASE, id: "h", domain: "zeta-login.test", triage_source: "heuristic",
            ai_reasoning: "heuristic: similarity score + free certificate issuer" },
          { ...BASE, id: "l", domain: "z3ta.test", triage_source: "llm", ai_reasoning: "homoglyph of zeta.test" },
        ],
        total: 2,
      });
    }),
  );

  renderWithClient(<DomainMonitor />);

  expect(await screen.findByText("Heuristic: High (98%)")).toBeInTheDocument();
  expect(screen.getByText("AI: High (98%)")).toBeInTheDocument();
  expect(screen.getAllByText(/^AI:/)).toHaveLength(1);
  expect(screen.queryByText(/triaged by Claude/)).not.toBeInTheDocument();
});

test("an auto-dismissed row is labelled by why it was cleared", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/intel/domains", () => HttpResponse.json({ domains: [] })),
    http.get("/api/intel/phishing", ({ request }) => {
      if (new URL(request.url).searchParams.get("status") !== "pending") {
        return HttpResponse.json({ candidates: [], total: 0 });
      }
      // Served on the default tab so the badges render without a click; the
      // label must come from cleared_by, not from the status alone.
      return HttpResponse.json({
        candidates: [
          { ...BASE, id: "t", domain: "zeta-box.test", status: "auto_dismissed", triage_source: "llm",
            cleared_by: "triage", ai_reasoning: "unrelated product name" },
          { ...BASE, id: "r", domain: "www.northwind.example", status: "auto_dismissed", triage_source: "heuristic",
            cleared_by: "rescore",
            ai_reasoning: "heuristic: similarity score [auto: re-scored 0.40, below the 0.65 detection threshold]" },
        ],
        total: 2,
      });
    }),
  );

  renderWithClient(<DomainMonitor />);

  expect(await screen.findByText("Cleared by AI")).toBeInTheDocument();
  expect(screen.getByText("Cleared by re-score")).toBeInTheDocument();
  expect(screen.getAllByText("Cleared by AI")).toHaveLength(1);
});
