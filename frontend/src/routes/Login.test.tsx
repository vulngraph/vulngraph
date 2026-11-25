import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { server } from "../test/setup";
import { renderApp } from "../test/render";
import { browser } from "../lib/returnTo";

afterEach(() => {
  sessionStorage.clear();
  vi.restoreAllMocks();
});

const signedOut = http.get("/api/auth/me", () => HttpResponse.json({ detail: "unauthorized" }, { status: 401 }));

function providers(list: { id: string; name: string }[], onCall?: () => void) {
  return http.get("/api/auth/providers", () => {
    onCall?.();
    return HttpResponse.json(list);
  });
}

const PASSWORD = { id: "password", name: "Email + password" };

function fillAndSubmit(code = "") {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@example.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2hunter2" } });
  if (code) fireEvent.change(screen.getByLabelText(/Authenticator code/), { target: { value: code } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

test("an empty provider list (access proxy) explains itself and does not auto-redirect", async () => {
  const assign = vi.spyOn(browser, "assign").mockImplementation(() => {});
  let calls = 0;
  server.use(signedOut, providers([], () => calls++));

  renderApp("/home");

  expect(await screen.findByText(/Sign-in is handled by your access proxy/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
  expect(assign).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await waitFor(() => expect(calls).toBe(2));
});

test("Okta gets a sign-in button when configured, and the TOTP field is always visible", async () => {
  server.use(signedOut, providers([PASSWORD, { id: "okta", name: "Sign in with Okta" }]));

  renderApp("/home");

  const okta = await screen.findByRole("link", { name: "Sign in with Okta" });
  expect(okta).toHaveAttribute("href", "/api/auth/okta");
  expect(screen.queryByRole("link", { name: /Google/ })).not.toBeInTheDocument();
  expect(screen.getByLabelText(/Authenticator code/)).toBeInTheDocument();
});

test("clicking SSO remembers where the user was", async () => {
  server.use(signedOut, providers([PASSWORD, { id: "okta", name: "Sign in with Okta" }]));

  renderApp("/settings?sub=policy");

  const okta = await screen.findByRole("link", { name: "Sign in with Okta" });
  okta.addEventListener("click", (e) => e.preventDefault());
  fireEvent.click(okta);
  expect(sessionStorage.getItem("graph-return-to")).toBe("/settings?sub=policy");
});

test("the code is sent with the password, and a rejection names no factor", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(
    signedOut,
    providers([PASSWORD]),
    http.post("/api/auth/login", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ detail: "invalid credentials" }, { status: 401 });
    }),
  );

  renderApp("/home");
  await screen.findByLabelText("Email");
  fillAndSubmit("123456");

  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Sign-in failed. Check your email, password and authenticator code (if you use one).",
  );
  expect(body).toEqual({ email: "a@example.com", password: "hunter2hunter2", totp_code: "123456" });
  // A login 401 is an answer, not session expiry: still on the form, no loop.
  expect(screen.getByRole("button", { name: "Sign in" })).toBeEnabled();
});

test("a blank code is omitted from the request", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(
    signedOut,
    providers([PASSWORD]),
    http.post("/api/auth/login", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ detail: "invalid credentials" }, { status: 401 });
    }),
  );

  renderApp("/home");
  await screen.findByLabelText("Email");
  fillAndSubmit();

  await waitFor(() => expect(body).toEqual({ email: "a@example.com", password: "hunter2hunter2" }));
});

test("rate limiting gets its own message", async () => {
  server.use(
    signedOut,
    providers([PASSWORD]),
    http.post("/api/auth/login", () => HttpResponse.json({ detail: "slow down" }, { status: 429 })),
  );

  renderApp("/home");
  await screen.findByLabelText("Email");
  fillAndSubmit();

  expect(await screen.findByRole("alert")).toHaveTextContent(/Too many sign-in attempts/);
});

test("server errors are generic, never the raw detail", async () => {
  server.use(
    signedOut,
    providers([PASSWORD]),
    http.post("/api/auth/login", () => HttpResponse.json({ detail: "pq: connection refused" }, { status: 500 })),
  );

  renderApp("/home");
  await screen.findByLabelText("Email");
  fillAndSubmit();

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(/Sign-in is unavailable right now/);
  expect(alert).not.toHaveTextContent(/pq:/);
});

test("a 404 from login (no break-glass behind an access proxy) says password sign-in is unavailable", async () => {
  server.use(
    signedOut,
    providers([PASSWORD]),
    http.post("/api/auth/login", () => HttpResponse.json({ detail: "not found" }, { status: 404 })),
  );

  renderApp("/home");
  await screen.findByLabelText("Email");
  fillAndSubmit();

  expect(await screen.findByRole("alert")).toHaveTextContent(/Password sign-in isn't available/);
});

test("a wrong password or code gets the one generic failure message", async () => {
  server.use(
    signedOut,
    providers([PASSWORD]),
    http.post("/api/auth/login", () => HttpResponse.json({ detail: "invalid credentials" }, { status: 401 })),
  );

  renderApp("/home");
  await screen.findByLabelText("Email");
  fillAndSubmit();

  expect(await screen.findByRole("alert")).toHaveTextContent(/Sign-in failed/);
});

test("Google as the only method redirects once, then offers a button instead of looping", async () => {
  const assign = vi.spyOn(browser, "assign").mockImplementation(() => {});
  server.use(signedOut, providers([{ id: "google", name: "Sign in with Google" }]));

  const first = renderApp("/home");
  await waitFor(() => expect(assign).toHaveBeenCalledWith("/api/auth/google"));
  first.unmount();

  // Back from Google but still 401 (e.g. account not permitted).
  assign.mockClear();
  renderApp("/home");
  expect(await screen.findByRole("link", { name: /Sign in with Google/ })).toBeInTheDocument();
  expect(screen.getByText(/account may not be permitted/)).toBeInTheDocument();
  expect(assign).not.toHaveBeenCalled();
});

test("provider discovery failing still offers the password form", async () => {
  server.use(
    signedOut,
    http.get("/api/auth/providers", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
  );

  renderApp("/home");

  expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument();
});

test("after a mid-session 401 the login screen says the session ended", async () => {
  let alive = true;
  server.use(
    http.get("/api/auth/me", () =>
      alive
        ? HttpResponse.json({ id: "u1", email: "admin@example.com", role: "admin" })
        : HttpResponse.json({ detail: "unauthorized" }, { status: 401 }),
    ),
    http.get("/api/keys", () => {
      alive = false;
      return HttpResponse.json({ detail: "unauthorized" }, { status: 401 });
    }),
    providers([PASSWORD]),
  );

  renderApp("/settings?sub=apikeys");

  expect(await screen.findByText(/Your session has ended/)).toBeInTheDocument();
});
