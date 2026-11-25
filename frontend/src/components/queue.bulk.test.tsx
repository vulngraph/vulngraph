import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { server } from "../test/setup";
import { renderWithClient, testClient } from "../test/render";
import type { QueueItem } from "../lib/api";
import { PatternGroupCard, QueueCard } from "./queue";

function item(key: string): QueueItem {
  return {
    cluster_key: key,
    title: "IAM privilege escalation: " + key,
    check_id: "",
    action_class: "remediate",
    outcome: "escalated",
    worst_score: 50,
    blast_radius: 0,
    count: 1,
    resources: 1,
    finding_ids: [`f-${key}`],
    decided_at: "2026-07-09T00:00:00Z",
    safety_band: "safe",
  } as QueueItem;
}

const group = [item("a"), item("b"), item("c")];

function confirmBulk(label: string) {
  fireEvent.click(screen.getByRole("button", { name: label }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
}

test("a partly failed bulk verdict reports counts, re-enables the buttons and refetches the queue", async () => {
  const seen: string[] = [];
  server.use(
    http.post("/api/queue/resolve", async ({ request }) => {
      const body = (await request.json()) as { cluster_key: string };
      seen.push(body.cluster_key);
      if (body.cluster_key === "b") return HttpResponse.json({ detail: "boom" }, { status: 500 });
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const client = testClient();
  const invalidate = vi.spyOn(client, "invalidateQueries");

  renderWithClient(<PatternGroupCard group={group} isAdmin />, client);
  confirmBulk("Approve all");

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Resolved 2 of 3 clusters — 1 failed: boom");
  // Every cluster was attempted — one failure doesn't abort the rest.
  expect(seen).toEqual(["a", "b", "c"]);
  // Buttons are back (not stuck on "resolving…").
  expect(screen.getByRole("button", { name: "Approve all" })).toBeEnabled();
  expect(screen.queryByText(/resolving/)).not.toBeInTheDocument();
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["queue"] });
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["decisions"] });
});

test("retrying a partly failed bulk verdict only resolves the clusters that failed", async () => {
  const seen: string[] = [];
  let failB = true;
  server.use(
    http.post("/api/queue/resolve", async ({ request }) => {
      const body = (await request.json()) as { cluster_key: string };
      seen.push(body.cluster_key);
      if (body.cluster_key === "b" && failB) return HttpResponse.json({ detail: "boom" }, { status: 500 });
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<PatternGroupCard group={group} isAdmin />);
  confirmBulk("Deny all");
  await screen.findByRole("alert");

  failB = false;
  seen.length = 0;
  confirmBulk("Deny all");

  await waitFor(() => expect(seen).toEqual(["b"]));
  await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
});

test("a 401 mid-bulk stops the run instead of failing every remaining cluster", async () => {
  const seen: string[] = [];
  server.use(
    http.post("/api/queue/resolve", async ({ request }) => {
      const body = (await request.json()) as { cluster_key: string };
      seen.push(body.cluster_key);
      return HttpResponse.json({ detail: "unauthorized" }, { status: 401 });
    }),
    http.get("/api/auth/me", () => HttpResponse.json({ detail: "unauthorized" }, { status: 401 })),
  );

  renderWithClient(<PatternGroupCard group={group} isAdmin />);
  confirmBulk("Approve all");

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Resolved 0 of 3 clusters — 1 failed, 2 not attempted");
  expect(seen).toEqual(["a"]);
});

test("a failed single verdict shows an error instead of failing silently", async () => {
  server.use(
    http.post("/api/queue/resolve", () => HttpResponse.json({ detail: "forbidden" }, { status: 403 })),
  );

  renderWithClient(<QueueCard item={item("solo")} isAdmin />);
  fireEvent.click(screen.getByRole("button", { name: /Approve/ }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/Couldn't record the verdict: You don't have permission/);
  expect(screen.getByRole("button", { name: /Approve/ })).toBeEnabled();
});
