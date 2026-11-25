import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const ORIGINAL_CLIPBOARD = navigator.clipboard;

afterEach(() => {
  Object.defineProperty(navigator, "clipboard", { value: ORIGINAL_CLIPBOARD, configurable: true });
});

test("copying the revealed key with no navigator.clipboard shows a manual fallback instead of throwing", async () => {
  // Plain HTTP (kubectl port-forward) leaves navigator.clipboard undefined.
  Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });

  server.use(
    meHandler("admin"),
    http.get("/api/keys", () => HttpResponse.json([])),
    http.post("/api/keys", () =>
      HttpResponse.json(
        {
          id: "k1",
          name: "CI pipeline",
          prefix: "gph_a1b2",
          scopes: "read",
          last_used_at: null,
          expires_at: null,
          created_at: "2026-08-20T00:00:00Z",
          key: "gph_example",
        },
        { status: 201 },
      ),
    ),
  );

  renderApp("/settings?sub=apikeys");

  fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "CI pipeline" } });
  fireEvent.click(screen.getByRole("button", { name: "Create key" }));

  const revealBox = await screen.findByDisplayValue("gph_example");
  expect(revealBox).toBeInTheDocument();

  // Clicking copy must not throw even though navigator.clipboard is undefined.
  expect(() => fireEvent.click(screen.getByRole("button", { name: "copy" }))).not.toThrow();

  expect(await screen.findByText(/copy failed/)).toBeInTheDocument();
});

test("copying the revealed key succeeds and flashes 'copied' when clipboard is available", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

  server.use(
    meHandler("admin"),
    http.get("/api/keys", () => HttpResponse.json([])),
    http.post("/api/keys", () =>
      HttpResponse.json(
        {
          id: "k1",
          name: "CI pipeline",
          prefix: "gph_a1b2",
          scopes: "read",
          last_used_at: null,
          expires_at: null,
          created_at: "2026-08-20T00:00:00Z",
          key: "gph_secret",
        },
        { status: 201 },
      ),
    ),
  );

  renderApp("/settings?sub=apikeys");

  fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "CI pipeline" } });
  fireEvent.click(screen.getByRole("button", { name: "Create key" }));
  await screen.findByDisplayValue("gph_secret");

  fireEvent.click(screen.getByRole("button", { name: "copy" }));

  await waitFor(() => expect(writeText).toHaveBeenCalledWith("gph_secret"));
  expect(await screen.findByRole("button", { name: "copied" })).toBeInTheDocument();
});

test("an expired key shows an expired badge and the date; a live key shows its expiry date without one", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/keys", () =>
      HttpResponse.json([
        {
          id: "k-expired",
          name: "Old integration",
          prefix: "gph_dead",
          scopes: "write",
          last_used_at: null,
          expires_at: "2020-01-01T00:00:00Z",
          created_at: "2019-01-01T00:00:00Z",
        },
        {
          id: "k-live",
          name: "Live integration",
          prefix: "gph_live",
          scopes: "read",
          last_used_at: null,
          expires_at: "2099-01-01T00:00:00Z",
          created_at: "2026-01-01T00:00:00Z",
        },
      ]),
    ),
  );

  renderApp("/settings?sub=apikeys");

  await screen.findByText("Old integration");
  expect(screen.getByText("expired")).toBeInTheDocument();

  const liveRow = screen.getByText("Live integration").closest("div")!.parentElement!;
  expect(liveRow.textContent).toContain("expires");
  // Only the expired key gets the "expired" badge.
  expect(screen.getAllByText("expired")).toHaveLength(1);
});

test("a non-admin analyst can delete their own key even though they cannot create one", async () => {
  let deleted = false;
  server.use(
    meHandler("analyst"),
    http.get("/api/keys", () =>
      HttpResponse.json(
        deleted
          ? []
          : [
              {
                id: "k1",
                name: "Leaked key",
                prefix: "gph_leak",
                scopes: "read",
                last_used_at: null,
                expires_at: null,
                created_at: "2026-08-01T00:00:00Z",
              },
            ],
      ),
    ),
    http.delete("/api/keys/k1", () => {
      deleted = true;
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderApp("/settings?sub=apikeys");

  await screen.findByText("Leaked key");
  // The backend's Create endpoint has no admin gate — it only clamps scopes to
  // the caller's privilege (apikey/handler.go) — so a non-admin analyst still
  // sees the create form, just without the admin-only "admin" scope option.
  expect(screen.getByRole("button", { name: "Create key" })).toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "admin" })).not.toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "inventory" })).not.toBeInTheDocument();

  const deleteButton = screen.getByRole("button", { name: "delete" });
  fireEvent.click(deleteButton);
  fireEvent.click(screen.getByRole("button", { name: "Confirm delete?" }));

  await waitFor(() => expect(screen.queryByText("Leaked key")).not.toBeInTheDocument());
});

test("only an admin is offered the inventory scope, with what it can do", async () => {
  server.use(meHandler("admin"), http.get("/api/keys", () => HttpResponse.json([])));

  renderApp("/settings?sub=apikeys");

  const option = await screen.findByRole("option", { name: "inventory" });
  expect(screen.queryByText(/bring-your-own scanning agent/)).not.toBeInTheDocument();
  fireEvent.change(option.closest("select")!, { target: { value: "inventory" } });
  expect(screen.getByText(/bring-your-own scanning agent/)).toBeInTheDocument();
});
