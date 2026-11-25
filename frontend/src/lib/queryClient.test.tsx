import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { server } from "../test/setup";
import { renderApp } from "../test/render";
import { APIError, FORBIDDEN_MESSAGE, RATE_LIMITED_MESSAGE, api, notifyUnauthorized } from "./api";
import { rememberReturnPath, takeReturnPath } from "./returnTo";

afterEach(() => sessionStorage.clear());

// A session that is valid for the first /api/auth/me and then expires: every
// later call (me included) answers 401.
function expiringSession() {
  let alive = true;
  return {
    expire: () => {
      alive = false;
    },
    handler: http.get("/api/auth/me", () =>
      alive
        ? HttpResponse.json({ id: "u1", email: "admin@example.com", role: "admin" })
        : HttpResponse.json({ detail: "unauthorized" }, { status: 401 }),
    ),
  };
}

test("a 401 from any query mid-session drops the shell back to the login screen", async () => {
  const session = expiringSession();
  server.use(
    session.handler,
    http.get("/api/keys", () => {
      session.expire();
      return HttpResponse.json({ detail: "unauthorized" }, { status: 401 });
    }),
    http.get("/api/auth/providers", () => HttpResponse.json([{ id: "password", name: "Email + password" }])),
  );

  const { client, router } = renderApp("/settings?sub=apikeys");

  expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
  expect(screen.queryByLabelText("Sign out")).not.toBeInTheDocument();
  expect(client.getQueryState(["me"])?.status).toBe("error");
  // The URL is untouched, so signing back in lands on the same page.
  expect(router.state.location.pathname).toBe("/settings");
});

test("a 401 from a mutation also resets the session", async () => {
  const session = expiringSession();
  server.use(
    session.handler,
    http.get("/api/keys", () => HttpResponse.json([])),
    http.post("/api/keys", () => {
      session.expire();
      return HttpResponse.json({ detail: "unauthorized" }, { status: 401 });
    }),
    http.get("/api/auth/providers", () => HttpResponse.json([{ id: "password", name: "Email + password" }])),
  );

  renderApp("/settings?sub=apikeys");

  fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "CI" } });
  fireEvent.click(screen.getByRole("button", { name: "Create key" }));

  expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
});

test("a raw-fetch 401 reported via notifyUnauthorized resets the session", async () => {
  const session = expiringSession();
  server.use(
    session.handler,
    http.get("/api/keys", () => HttpResponse.json([])),
    http.get("/api/auth/providers", () => HttpResponse.json([{ id: "password", name: "Email + password" }])),
  );

  renderApp("/settings?sub=apikeys");
  expect(await screen.findByLabelText("Sign out")).toBeInTheDocument();

  session.expire();
  notifyUnauthorized();

  expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
});

test("a 403 surfaces a clear permission message, not a bare 'Forbidden'", async () => {
  server.use(http.post("/api/thing", () => HttpResponse.json({ detail: "forbidden" }, { status: 403 })));

  const err = await api.post("/api/thing").catch((e: unknown) => e);
  expect(err).toBeInstanceOf(APIError);
  expect((err as APIError).status).toBe(403);
  expect((err as APIError).message).toBe(FORBIDDEN_MESSAGE);
  expect((err as APIError).detail).toBe("forbidden");
});

test("a 429 shows the server detail when there is one", async () => {
  server.use(http.post("/api/thing", () => HttpResponse.json({ detail: "llm budget exceeded" }, { status: 429 })));

  const err = await api.post("/api/thing").catch((e: unknown) => e);
  expect((err as APIError).status).toBe(429);
  expect((err as APIError).message).toBe("llm budget exceeded");
});

test("a 429 without a detail reads as rate limited", async () => {
  server.use(http.post("/api/thing", () => new HttpResponse(null, { status: 429 })));

  const err = await api.post("/api/thing").catch((e: unknown) => e);
  expect((err as APIError).status).toBe(429);
  expect((err as APIError).message).toBe(RATE_LIMITED_MESSAGE);
});

test("a 403 from a mutation shows the permission message in the page", async () => {
  server.use(
    http.get("/api/auth/me", () => HttpResponse.json({ id: "u1", email: "admin@example.com", role: "admin" })),
    http.get("/api/keys", () => HttpResponse.json([])),
    http.post("/api/keys", () => HttpResponse.json({ detail: "forbidden" }, { status: 403 })),
  );

  renderApp("/settings?sub=apikeys");
  fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "CI" } });
  fireEvent.click(screen.getByRole("button", { name: "Create key" }));

  expect(await screen.findByText(/don't have permission/)).toBeInTheDocument();
  // A 403 is not session expiry — the shell stays up.
  expect(screen.getByLabelText("Sign out")).toBeInTheDocument();
});

test("after an OAuth round trip the shell returns to the remembered path", async () => {
  server.use(
    http.get("/api/auth/me", () => HttpResponse.json({ id: "u1", email: "admin@example.com", role: "admin" })),
    http.get("/api/keys", () => HttpResponse.json([])),
  );
  rememberReturnPath("/settings?sub=policy");

  const { router } = renderApp("/settings?sub=apikeys");

  await waitFor(() => expect(router.state.location.search).toEqual({ sub: "policy" }));
  expect(takeReturnPath()).toBeNull();
});

test("return paths never leave the origin", () => {
  rememberReturnPath("//evil.example.com/x");
  expect(takeReturnPath()).toBeNull();
  rememberReturnPath("https://evil.example.com");
  expect(takeReturnPath()).toBeNull();
});

test("a session expiry clears every stored chat transcript", async () => {
  const session = expiringSession();
  server.use(
    session.handler,
    http.get("/api/keys", () => HttpResponse.json([])),
    http.get("/api/auth/providers", () => HttpResponse.json([{ id: "password", name: "Email + password" }])),
  );
  localStorage.setItem("graph.chat.u1.sessions", JSON.stringify([{ id: "s1", messages: [{ content: "live data" }] }]));
  localStorage.setItem("graph.chat.u1.active", "s1");

  renderApp("/settings?sub=apikeys");
  expect(await screen.findByLabelText("Sign out")).toBeInTheDocument();
  expect(localStorage.getItem("graph.chat.u1.sessions")).not.toBeNull();

  session.expire();
  notifyUnauthorized();

  expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
  expect(localStorage.getItem("graph.chat.u1.sessions")).toBeNull();
  expect(localStorage.getItem("graph.chat.u1.active")).toBeNull();
});

test("signing out clears every stored chat transcript, even when the server call fails", async () => {
  for (const status of [204, 500]) {
    localStorage.clear();
    let signedIn = true;
    server.use(
      http.get("/api/auth/me", () =>
        signedIn
          ? HttpResponse.json({ id: "u1", email: "admin@example.com", role: "admin" })
          : HttpResponse.json({ detail: "unauthorized" }, { status: 401 }),
      ),
      http.post("/api/auth/logout", () => {
        signedIn = false;
        return status === 204 ? new HttpResponse(null, { status }) : HttpResponse.json({ detail: "boom" }, { status });
      }),
      http.get("/api/keys", () => HttpResponse.json([])),
      http.get("/api/auth/providers", () => HttpResponse.json([{ id: "password", name: "Email + password" }])),
    );
    localStorage.setItem("graph.chat.u1.sessions", "[]");
    localStorage.setItem("graph.chat.u2.sessions", "[]");

    const { unmount } = renderApp("/settings?sub=apikeys");
    fireEvent.click(await screen.findByLabelText("Sign out"));

    await waitFor(() => expect(localStorage.getItem("graph.chat.u1.sessions")).toBeNull());
    expect(localStorage.getItem("graph.chat.u2.sessions")).toBeNull();
    unmount();
  }
});
