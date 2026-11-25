import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();

const suppression = {
  finding_id: "finding-abc123",
  reason: "Accepted risk — compensating control in place",
  suppressed_by: "alice@example.com",
  suppressed_at: "2026-08-01T00:00:00Z",
  expires_at: inDays(60),
  expired: false,
  last_reviewed_at: null,
  reviewed_by: "",
};

test("a failed suppressions fetch renders an error, not an empty state", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/suppressions", () => new HttpResponse(null, { status: 500 })),
  );

  renderApp("/settings?sub=suppressions");

  expect(await screen.findByText(/Could not load suppressions|error/i)).toBeInTheDocument();
  expect(screen.queryByText(/No suppressions/)).not.toBeInTheDocument();
});

test("unsuppress requires a confirm step", async () => {
  let unsuppressed = false;
  server.use(
    meHandler("admin"),
    http.get("/api/suppressions", () => HttpResponse.json([suppression])),
    http.delete("/api/findings/finding-abc123/suppress", () => {
      unsuppressed = true;
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderApp("/settings?sub=suppressions");

  const unsuppressButton = await screen.findByRole("button", { name: "unsuppress" });
  fireEvent.click(unsuppressButton);
  expect(unsuppressed).toBe(false); // first click only arms the confirm

  fireEvent.click(screen.getByRole("button", { name: "Confirm unsuppress?" }));
  await waitFor(() => expect(unsuppressed).toBe(true));
});

test("renders the count and a link to the finding", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/suppressions", () => HttpResponse.json([suppression])),
  );

  renderApp("/settings?sub=suppressions");

  expect(await screen.findByText("Suppressed findings")).toBeInTheDocument();
  expect(await screen.findByText("(1)")).toBeInTheDocument();

  const link = await screen.findByRole("link", { name: /finding-abc123|abc123/ });
  expect(link).toHaveAttribute("title", "finding-abc123");
});

test("shows each suppression's expiry and flags expired ones", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/suppressions", () =>
      HttpResponse.json([
        { ...suppression, expires_at: inDays(10.7) },
        {
          ...suppression, finding_id: "finding-old", expires_at: inDays(-3.7), expired: true,
          last_reviewed_at: "2026-08-02T00:00:00Z", reviewed_by: "carol@example.com",
        },
      ]),
    ),
  );

  renderApp("/settings?sub=suppressions");

  expect(await screen.findByText("expires in 11d")).toBeInTheDocument();
  expect(screen.getByText("expired 4d ago")).toBeInTheDocument();
  expect(screen.getByText(/1 expired — those findings are back in the pipeline/)).toBeInTheDocument();
  expect(screen.getByText(/reviewed by carol@example.com/)).toBeInTheDocument();
  // Viewers can read but not renew.
  expect(screen.queryByRole("button", { name: "renew" })).not.toBeInTheDocument();
});

test("an admin renews a suppression with a new expiry", async () => {
  let posted: { expires_at?: string } | null = null;
  server.use(
    meHandler("admin"),
    http.get("/api/suppressions", () => HttpResponse.json([{ ...suppression, expires_at: inDays(-1), expired: true }])),
    http.post("/api/findings/finding-abc123/suppress/review", async ({ request }) => {
      posted = (await request.json()) as { expires_at?: string };
      return HttpResponse.json({ ...suppression, expires_at: posted.expires_at, reviewed_by: "admin@example.com", last_reviewed_at: inDays(0) });
    }),
  );

  renderApp("/settings?sub=suppressions");

  fireEvent.click(await screen.findByRole("button", { name: "renew" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm renew" }));

  await waitFor(() => expect(posted).not.toBeNull());
  const days = (new Date(posted!.expires_at!).getTime() - Date.now()) / 86_400_000;
  expect(days).toBeGreaterThan(89);
  expect(days).toBeLessThan(91);
});
