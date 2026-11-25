import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import { AlertsSection } from "./AlertChannels";

const CHANNEL = {
  id: "ch1",
  type: "slack",
  name: "Security alerts",
  channel: "#security-alerts",
  enabled: true,
  event_types: [],
  severities: [],
  min_score: 0,
  last_status: "ok",
  last_delivered_at: "2026-08-20T00:00:00Z",
  has_token: true,
};

test("a successful test send shows a success message, a failed one shows a clear failure message", async () => {
  let testCalls = 0;
  server.use(
    meHandler("admin"),
    http.get("/api/alerts/channels", () => HttpResponse.json({ channels: [CHANNEL] })),
    http.post("/api/alerts/channels/:id/test", () => {
      testCalls += 1;
      // First send fails, second succeeds — both must be reflected accurately,
      // not a hardcoded "Test sent" regardless of outcome.
      return HttpResponse.json({ ok: testCalls !== 1 });
    }),
  );

  renderWithClient(<AlertsSection />);

  await screen.findByText("Security alerts");
  const testButton = screen.getByRole("button", { name: /Test/ });

  fireEvent.click(testButton);
  expect(await screen.findByText(/Test failed/)).toBeInTheDocument();
  expect(screen.queryByText("Test sent ✓")).not.toBeInTheDocument();

  fireEvent.click(testButton);
  expect(await screen.findByText("Test sent ✓")).toBeInTheDocument();
});

test("min_score is clamped to 0-100 before it is submitted", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(
    meHandler("admin"),
    http.get("/api/alerts/channels", () => HttpResponse.json({ channels: [] })),
    http.post("/api/alerts/channels", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...CHANNEL, id: "ch2" }, { status: 201 });
    }),
  );

  renderWithClient(<AlertsSection />);

  fireEvent.click(await screen.findByRole("button", { name: /Add channel/ }));
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Overflow test" } });
  fireEvent.change(screen.getByLabelText("Slack channel"), { target: { value: "#alerts" } });
  fireEvent.change(screen.getByLabelText(/Bot token/), { target: { value: "xoxb-test" } });

  const scoreInput = screen.getByLabelText(/Minimum score/);
  fireEvent.change(scoreInput, { target: { value: "500" } });
  expect(scoreInput).toHaveValue(100);

  fireEvent.change(scoreInput, { target: { value: "-40" } });
  expect(scoreInput).toHaveValue(0);

  fireEvent.change(scoreInput, { target: { value: "63" } });
  fireEvent.click(screen.getByRole("button", { name: "Create channel" }));

  await waitFor(() => expect(body).toMatchObject({ min_score: 63 }));
});

test("switching to edit resets any stale test result from before", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/alerts/channels", () => HttpResponse.json({ channels: [CHANNEL] })),
    http.post("/api/alerts/channels/:id/test", () => HttpResponse.json({ ok: false })),
  );

  renderWithClient(<AlertsSection />);

  fireEvent.click(await screen.findByRole("button", { name: /Test/ }));
  expect(await screen.findByText(/Test failed/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Edit" }));
  expect(screen.queryByText(/Test failed/)).not.toBeInTheDocument();
});

test("a webhook channel shows its own type and destination, not a Slack-shaped row", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/alerts/channels", () =>
      HttpResponse.json({
        channels: [{ ...CHANNEL, id: "ch3", type: "webhook", name: "Webhook out", channel: "", has_token: true }],
      }),
    ),
  );

  renderWithClient(<AlertsSection />);

  expect(await screen.findByText("Webhook out")).toBeInTheDocument();
  expect(screen.getByText("webhook")).toBeInTheDocument();
  expect(screen.getByText("Webhook configured")).toBeInTheDocument();
});

test("a channel can be scoped to owner teams, environments and the unowned default", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(
    meHandler("admin"),
    http.get("/api/alerts/channels", () =>
      HttpResponse.json({
        channels: [{ ...CHANNEL, owner_teams: ["identity"], environments: ["prod"], route_unowned: true }],
      }),
    ),
    http.post("/api/alerts/channels", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...CHANNEL, id: "ch2" }, { status: 201 });
    }),
  );

  renderWithClient(<AlertsSection />);

  // The row states its scope.
  expect(await screen.findByText(/scoped to @identity · unowned findings · prod/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Add channel/ }));
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Payments" } });
  fireEvent.change(screen.getByLabelText("Slack channel"), { target: { value: "#payments" } });
  fireEvent.change(screen.getByLabelText(/Bot token/), { target: { value: "xoxb-test" } });
  fireEvent.change(screen.getByLabelText("Owner teams"), { target: { value: "payments, @acme/billing, " } });
  fireEvent.click(screen.getByRole("button", { name: "staging" }));
  fireEvent.click(screen.getByRole("checkbox", { name: /Default channel for unowned findings/ }));
  fireEvent.click(screen.getByRole("button", { name: "Create channel" }));

  await waitFor(() =>
    expect(body).toMatchObject({
      owner_teams: ["payments", "@acme/billing"],
      environments: ["staging"],
      route_unowned: true,
    }),
  );
});

test("event types nothing emits yet are labelled, in the form and on channel rows", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/alerts/channels", () =>
      HttpResponse.json({
        channels: [
          { ...CHANNEL, id: "all", name: "All events", unwired_event_types: ["drift", "connector"] },
          {
            ...CHANNEL, id: "routed", name: "Routed", event_types: ["finding", "connector"],
            unwired_event_types: ["connector"],
          },
        ],
        unwired_event_types: ["drift", "connector"],
      }),
    ),
  );

  renderWithClient(<AlertsSection />);

  // An all-events channel names the events it will never receive.
  expect(
    await screen.findByText("Inventory drift, Connector failure: not emitted yet, so this channel never receives them."),
  ).toBeInTheDocument();
  // A routed channel marks only its unwired chip.
  expect(screen.getByText("Connector failure").textContent).toBe("Connector failure(not emitted yet)");
  expect(screen.getByText("New high/critical finding").textContent).toBe("New high/critical finding");

  // The form labels the choice before any channel routes it, and keeps it selectable.
  fireEvent.click(screen.getByRole("button", { name: /Add channel/ }));
  const connector = screen.getByRole("button", { name: "Connector failure (not emitted yet)" });
  expect(connector).toBeEnabled();
  expect(screen.getByRole("button", { name: "Inventory drift (not emitted yet)" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Confirmed phishing" })).toBeInTheDocument();
});
