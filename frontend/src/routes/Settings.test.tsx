import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

test("the active sidebar section is marked aria-current and the others aren't", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/connectors", () => HttpResponse.json([])),
  );

  renderApp("/settings?sub=connectors");

  const connectorsLink = await screen.findByRole("link", { name: /Connectors/ });
  expect(connectorsLink).toHaveAttribute("aria-current", "page");

  const alertsLink = screen.getByRole("link", { name: /Alerts/ });
  expect(alertsLink).not.toHaveAttribute("aria-current");
});

test("switching ?sub renders the matching section, not a stale or blank one", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.get("/api/alerts/channels", () => HttpResponse.json({ channels: [] })),
  );

  renderApp("/settings?sub=connectors");
  expect(await screen.findByText("No connectors configured.")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: /Alerts/ })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("link", { name: /Alerts/ }));

  expect(await screen.findByRole("heading", { name: /Alerts/ })).toBeInTheDocument();
  expect(screen.queryByText("No connectors configured.")).not.toBeInTheDocument();
});

test("a viewer is told admin access is required", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.get("/api/suppressions", () => HttpResponse.json([])),
    http.get("/api/keys", () => HttpResponse.json([])),
  );

  renderApp("/settings?sub=users");

  // Viewer sees "Admin access required" on the users section.
  const adminMsgs = await screen.findAllByText(/Admin access required/);
  expect(adminMsgs.length).toBeGreaterThan(0);
  expect(screen.queryByRole("button", { name: "Create user" })).not.toBeInTheDocument();
});

test("an admin can create a user", async () => {
  let body: { email?: string; role?: string } | null = null;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.get("/api/suppressions", () => HttpResponse.json([])),
    http.get("/api/keys", () => HttpResponse.json([])),
    http.get("/api/users", () => HttpResponse.json({ items: [{ id: "u1", email: "admin@example.com", role: "admin", totp_enabled: true, created_at: "2026-06-10T00:00:00Z" }] })),
    http.post("/api/users", async ({ request }) => {
      body = (await request.json()) as typeof body;
      return HttpResponse.json({ id: "u9", email: body?.email, role: body?.role }, { status: 201 });
    }),
  );

  renderApp("/settings?sub=users");

  // The existing users are listed alongside the create form.
  expect(await screen.findByText("admin@example.com")).toBeInTheDocument();
  fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "new@example.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2hunter2" } });
  fireEvent.change(screen.getByLabelText("Role"), { target: { value: "analyst" } });
  fireEvent.click(screen.getByRole("button", { name: "Create user" }));

  await waitFor(() => expect(body).toEqual({ email: "new@example.com", password: "hunter2hunter2", role: "analyst" }));
  expect(await screen.findByText(/User created/)).toBeInTheDocument();
});
