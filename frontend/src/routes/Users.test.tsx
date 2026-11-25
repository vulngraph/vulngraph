import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import { UsersSection } from "./Users";

test("a viewer is told admin access is required", async () => {
  server.use(meHandler("viewer"));

  renderWithClient(<UsersSection />);

  expect(await screen.findByText(/Admin access required/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Create user" })).not.toBeInTheDocument();
});

test("a failed users fetch shows an error, not an empty list", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/users", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
  );

  renderWithClient(<UsersSection />);

  expect(await screen.findByText(/boom/)).toBeInTheDocument();
  expect(screen.queryByText("No users.")).not.toBeInTheDocument();
});

test("both 2FA states render explicit text", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/users", () =>
      HttpResponse.json({
        items: [
          { id: "u1", email: "on@example.com", role: "admin", totp_enabled: true, created_at: "2026-06-10T00:00:00Z" },
          { id: "u2", email: "off@example.com", role: "viewer", totp_enabled: false, created_at: "2026-06-10T00:00:00Z" },
        ],
      }),
    ),
  );

  renderWithClient(<UsersSection />);

  expect(await screen.findByText(/2FA on/)).toBeInTheDocument();
  expect(await screen.findByText(/2FA off/)).toBeInTheDocument();
});

test("an admin can create a user", async () => {
  let body: { email?: string; role?: string } | null = null;
  server.use(
    meHandler("admin"),
    http.get("/api/users", () => HttpResponse.json({ items: [] })),
    http.post("/api/users", async ({ request }) => {
      body = (await request.json()) as typeof body;
      return HttpResponse.json({ id: "u9", email: body?.email, role: body?.role }, { status: 201 });
    }),
  );

  renderWithClient(<UsersSection />);

  fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "new@example.com" } });
  fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "hunter2hunter2" } });
  fireEvent.change(screen.getByLabelText("Role"), { target: { value: "analyst" } });
  fireEvent.click(screen.getByRole("button", { name: "Create user" }));

  await waitFor(() => expect(body).toEqual({ email: "new@example.com", password: "hunter2hunter2", role: "analyst" }));
  expect(await screen.findByText(/User created/)).toBeInTheDocument();
});
