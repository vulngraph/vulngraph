import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp, renderWithClient } from "../test/render";
import { UsersSection } from "./Users";

// meHandler("admin") is { id: "u1", email: "admin@example.com" }.
function usersList(over: Record<string, unknown> = {}) {
  return http.get("/api/users", () =>
    HttpResponse.json({
      items: [
        { id: "u1", email: "admin@example.com", role: "admin", totp_enabled: true, created_at: "2026-06-10T00:00:00Z", disabled: false, disabled_at: null },
        {
          id: "u2",
          email: "bob@example.com",
          role: "viewer",
          totp_enabled: false,
          created_at: "2026-06-10T00:00:00Z",
          disabled: false,
          disabled_at: null,
          ...over,
        },
      ],
    }),
  );
}

function row(email: string) {
  return within(screen.getByRole("listitem", { name: email }));
}

test("your own row has no actions; other rows do", async () => {
  server.use(meHandler("admin"), usersList());
  renderWithClient(<UsersSection />);

  await screen.findByText("bob@example.com");
  expect(row("admin@example.com").queryByRole("button")).not.toBeInTheDocument();
  expect(row("admin@example.com").queryByRole("combobox")).not.toBeInTheDocument();
  expect(row("bob@example.com").getByRole("button", { name: "Disable" })).toBeInTheDocument();
  expect(row("bob@example.com").getByRole("button", { name: "Revoke sessions" })).toBeInTheDocument();
  expect(row("bob@example.com").getByRole("button", { name: "Delete" })).toBeInTheDocument();
});

test("disable, role change, revoke and delete hit the user endpoints and refetch the list", async () => {
  const calls: string[] = [];
  let listFetches = 0;
  server.use(
    meHandler("admin"),
    http.get("/api/users", () => {
      listFetches++;
      return HttpResponse.json({
        items: [
          { id: "u2", email: "bob@example.com", role: "viewer", totp_enabled: false, created_at: "2026-06-10T00:00:00Z", disabled: false, disabled_at: null },
        ],
      });
    }),
    http.patch("/api/users/:id", async ({ params, request }) => {
      calls.push(`PATCH ${params.id} ${JSON.stringify(await request.json())}`);
      return HttpResponse.json({});
    }),
    http.post("/api/users/:id/revoke-sessions", ({ params }) => {
      calls.push(`REVOKE ${params.id}`);
      return new HttpResponse(null, { status: 204 });
    }),
    http.delete("/api/users/:id", ({ params }) => {
      calls.push(`DELETE ${params.id}`);
      return new HttpResponse(null, { status: 204 });
    }),
  );
  renderWithClient(<UsersSection />);
  await screen.findByText("bob@example.com");

  fireEvent.click(screen.getByRole("button", { name: "Disable" }));
  await waitFor(() => expect(calls).toContain('PATCH u2 {"disabled":true}'));
  await waitFor(() => expect(screen.getByRole("button", { name: "Disable" })).toBeEnabled());

  fireEvent.change(screen.getByLabelText("Role for bob@example.com"), { target: { value: "analyst" } });
  await waitFor(() => expect(calls).toContain('PATCH u2 {"role":"analyst"}'));
  await waitFor(() => expect(screen.getByRole("button", { name: "Revoke sessions" })).toBeEnabled());

  // Destructive actions are two-click.
  fireEvent.click(screen.getByRole("button", { name: "Revoke sessions" }));
  expect(calls).not.toContain("REVOKE u2");
  fireEvent.click(screen.getByRole("button", { name: "Confirm revoke?" }));
  await waitFor(() => expect(calls).toContain("REVOKE u2"));
  expect(await screen.findByText(/Sessions revoked/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm delete?" }));
  await waitFor(() => expect(calls).toContain("DELETE u2"));

  // One initial fetch plus a refetch after each of the four actions.
  await waitFor(() => expect(listFetches).toBeGreaterThanOrEqual(5));
});

test("a disabled user shows a badge and an Enable action", async () => {
  let body: unknown = null;
  server.use(
    meHandler("admin"),
    usersList({ disabled: true, disabled_at: "2026-06-11T00:00:00Z" }),
    http.patch("/api/users/:id", async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({});
    }),
  );
  renderWithClient(<UsersSection />);

  await screen.findByText("bob@example.com");
  expect(row("bob@example.com").getByText("disabled")).toBeInTheDocument();
  fireEvent.click(row("bob@example.com").getByRole("button", { name: "Enable" }));
  await waitFor(() => expect(body).toEqual({ disabled: false }));
});

test.each([
  [409, "cannot remove the last active admin"],
  [404, "user not found"],
  [403, "cannot modify your own account"],
])("a %i problem on delete shows its detail on the row and keeps the action", async (status, detail) => {
  server.use(
    meHandler("admin"),
    usersList(),
    http.delete("/api/users/:id", () => HttpResponse.json({ detail }, { status })),
  );
  renderWithClient(<UsersSection />);
  await screen.findByText("bob@example.com");

  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm delete?" }));

  expect(await row("bob@example.com").findByRole("alert")).toHaveTextContent(detail);
  expect(screen.getByRole("button", { name: "Delete" })).toBeEnabled();
});

test("a 409 on role change shows the problem detail", async () => {
  server.use(
    meHandler("admin"),
    usersList(),
    http.patch("/api/users/:id", () =>
      HttpResponse.json({ detail: "cannot demote the last active admin" }, { status: 409 }),
    ),
  );
  renderWithClient(<UsersSection />);
  await screen.findByText("bob@example.com");

  fireEvent.change(screen.getByLabelText("Role for bob@example.com"), { target: { value: "analyst" } });

  expect(await row("bob@example.com").findByRole("alert")).toHaveTextContent("cannot demote the last active admin");
});

test("the Users settings entry is shown to admins only", async () => {
  server.use(meHandler("viewer"), http.get("/api/connectors", () => HttpResponse.json([])));
  const viewer = renderApp("/settings");
  const nav = await screen.findByRole("navigation", { name: "Settings sections" });
  expect(within(nav).getByText("API Keys")).toBeInTheDocument();
  expect(within(nav).queryByText("Users")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  viewer.unmount();

  server.use(meHandler("admin"));
  renderApp("/settings");
  const adminNav = await screen.findByRole("navigation", { name: "Settings sections" });
  expect(within(adminNav).getByText("Users")).toBeInTheDocument();
  // Sidebar entry plus the header shortcut.
  expect(screen.getAllByRole("link", { name: "Users" })).toHaveLength(2);
});
