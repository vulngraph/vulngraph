import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const summary = {
  total: 3,
  by_provider: { aws: 2, github: 1 },
  by_type: { ec2_instance: 2, github_repo: 1 },
};
const ec2 = { id: "i-1", name: "web", type: "ec2_instance", provider: "aws", region: "eu-west-1", public_ip: "203.0.113.3", account_id: "123456789012", risk_score: 0, finding_count: 4, max_score: 86, risk_band: "page", last_seen: "2026-06-14T00:00:00Z" };
const repo = { id: "org/app", name: "app", type: "github_repo", provider: "github", region: "global", risk_score: 0, finding_count: 0, max_score: 0, last_seen: "2026-06-14T00:00:00Z" };

test("filters assets by provider via the summary chips", async () => {
  const seen: string[] = [];
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/summary", () => HttpResponse.json(summary)),
    http.get("/api/assets", ({ request }) => {
      const p = new URL(request.url).searchParams.get("provider") ?? "";
      seen.push(p);
      const items = p === "github" ? [repo] : p === "aws" ? [ec2] : [ec2, repo];
      return HttpResponse.json({ items, next_cursor: "" });
    }),
  );

  renderApp("/investigate/assets");

  // Both assets show initially; provider chips render with counts.
  expect(await screen.findByText("web")).toBeInTheDocument();
  expect(await screen.findByText("app")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "github (1)" })).toBeInTheDocument();
  // The network column surfaces the public IP — the whole point of the richer row.
  expect(screen.getByText("203.0.113.3")).toBeInTheDocument();

  // The risk rollup shows on the row: the worst finding score + the count.
  expect(screen.getByText("86")).toBeInTheDocument();

  // Clicking the github chip scopes the list (and the request).
  fireEvent.click(screen.getByRole("button", { name: "github (1)" }));
  await waitFor(() => expect(seen).toContain("github"));
  expect(await screen.findByText("app")).toBeInTheDocument();
});

test("the searchable type dropdown scopes the list", async () => {
  const seen: string[] = [];
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/summary", () => HttpResponse.json(summary)),
    http.get("/api/assets", ({ request }) => {
      const t = new URL(request.url).searchParams.get("type") ?? "";
      seen.push(t);
      return HttpResponse.json({ items: t === "github_repo" ? [repo] : [ec2, repo], next_cursor: "" });
    }),
  );

  renderApp("/investigate/assets");

  await screen.findByText("web"); // wait for the summary counts to land
  // Types live behind one dropdown now — no pill row, no "more…" select.
  const trigger = await screen.findByRole("button", { name: /Type filter: all/ });
  fireEvent.click(trigger);

  // The search box filters items; the raw type id is matched as a keyword.
  fireEvent.change(screen.getByPlaceholderText("search types…"), { target: { value: "github_repo" } });
  const opts = screen.getAllByRole("menuitemradio");
  expect(opts).toHaveLength(1);
  fireEvent.click(opts[0]!);

  await waitFor(() => expect(seen).toContain("github_repo"));
  // Trigger reflects the active type and the menu closed.
  expect(await screen.findByRole("button", { name: /Type filter: Repo/ })).toBeInTheDocument();
});

test("row actions are reachable from a keyboard-focusable menu", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/summary", () => HttpResponse.json(summary)),
    http.get("/api/assets", () => HttpResponse.json({ items: [ec2], next_cursor: "" })),
  );

  renderApp("/investigate/assets");

  await screen.findByText("web");
  // The ⋯ trigger is a real button (was an opacity-0 hover-only div before).
  const actions = screen.getByRole("button", { name: "Actions for web" });
  expect(actions).toHaveAttribute("aria-expanded", "false");
  fireEvent.click(actions);
  expect(actions).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("menuitemradio", { name: /Detail/ })).toBeInTheDocument();
  expect(screen.getByRole("menuitemradio", { name: /Ask AI/ })).toBeInTheDocument();
});

test("the Riskiest toggle requests the risk-sorted inventory", async () => {
  const sorts: string[] = [];
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/summary", () => HttpResponse.json(summary)),
    http.get("/api/assets", ({ request }) => {
      sorts.push(new URL(request.url).searchParams.get("sort") ?? "");
      return HttpResponse.json({ items: [ec2], next_cursor: "" });
    }),
  );

  renderApp("/investigate/assets");

  await screen.findByText("web");
  fireEvent.click(screen.getByRole("button", { name: "Riskiest" }));
  await waitFor(() => expect(sorts).toContain("risk"));
});

test("Riskiest mode disables the provider pills instead of leaving them clickable-but-ignored", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/summary", () => HttpResponse.json(summary)),
    http.get("/api/assets", () => HttpResponse.json({ items: [ec2], next_cursor: "" })),
  );

  renderApp("/investigate/assets");

  await screen.findByText("web");
  const githubPill = screen.getByRole("button", { name: "github (1)" });
  expect(githubPill).not.toBeDisabled();

  fireEvent.click(screen.getByRole("button", { name: "Riskiest" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Riskiest" })).toHaveAttribute("aria-pressed", "true"));

  expect(screen.getByRole("button", { name: "github (1)" })).toBeDisabled();
  expect(screen.getByText(/provider filter doesn't apply to Riskiest/)).toBeInTheDocument();
});
