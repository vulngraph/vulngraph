import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp, renderWithClient } from "../test/render";
import type { DecisionExecutionPlan, DecisionRun } from "../lib/api";
import { ApproveAndRun } from "./ApproveAndRun";

const PLAN = "/api/decisions/d1/execution";
const later = new Date(Date.now() + 10 * 60_000).toISOString();

function plan(over: Partial<DecisionExecutionPlan>): DecisionExecutionPlan {
  return {
    decision_id: "d1",
    state: "ready",
    action: "s3_block_public",
    connector_id: "c1",
    connector_name: "prod-aws",
    params: { bucket_name: "logs", region: "eu-west-1" },
    inputs: [],
    requires_second_admin: false,
    audit: [],
    audit_known: true,
    ...over,
  };
}

function run(over: Partial<DecisionRun>): DecisionRun {
  return {
    status: "succeeded",
    action: "s3_block_public",
    connector_id: "c1",
    params: {},
    plan: "block all public access on S3 bucket logs (eu-west-1)",
    requested_by: "alice@example.com",
    requested_by_you: false,
    updated_at: "2026-10-08T10:00:00Z",
    ...over,
  };
}

// servePlan answers the plan GET from a mutable holder, so a test can move the
// server's state forward the way a real run does.
function servePlan(initial: DecisionExecutionPlan) {
  const state = { current: initial };
  server.use(http.get(PLAN, () => HttpResponse.json(state.current)));
  return state;
}

test("a fix that cannot run from Vulngraph says why and offers no run button", async () => {
  servePlan(plan({ state: "guidance_only", reason: "2 connectors collect this resource (c1, c2). Vulngraph will not guess which one should change it." }));
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  expect(await screen.findByText("Guidance only")).toBeInTheDocument();
  expect(screen.getByText(/Vulngraph will not guess/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument();
});

test("a reversible fix: dry run, then one admin's click runs it and the result shows", async () => {
  const state = servePlan(plan({}));
  const bodies: unknown[] = [];
  server.use(
    http.post(`${PLAN}/dry-run`, () =>
      HttpResponse.json({
        action: "s3_block_public", connector_id: "c1", params: {}, destructive: false, confirm_text: "",
        detail: "DRY RUN — nothing was changed. Would block all public access on S3 bucket logs (eu-west-1)",
      }),
    ),
    http.post(`${PLAN}/run`, async ({ request }) => {
      bodies.push(await request.json());
      state.current = plan({
        run: run({ executed_by: "alice@example.com", detail: "blocked all public access on S3 bucket logs" }),
        audit: [
          { ts: "2026-10-08T10:00:00Z", actor: "alice@example.com", action: "executor.execute_intent", details: "{}" },
          { ts: "2026-10-08T10:00:01Z", actor: "alice@example.com", action: "executor.execute", details: "{}" },
        ],
      });
      return HttpResponse.json({ run: state.current.run, result: { connector_id: "c1", action: "s3_block_public", detail: "ok", dry_run: false, destructive: false } });
    }),
  );
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  expect(await screen.findByText(/through connector/)).toHaveTextContent("prod-aws");
  fireEvent.click(screen.getByRole("button", { name: "Approve & run…" }));
  expect(await screen.findByText(/DRY RUN — nothing was changed/)).toBeInTheDocument();
  expect(screen.queryByLabelText("Typed confirmation")).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Run now" }));
  expect(await screen.findByText("Fix ran")).toBeInTheDocument();
  expect(screen.getByText("blocked all public access on S3 bucket logs")).toBeInTheDocument();
  expect(screen.getByText("Audit trail")).toBeInTheDocument();
  expect(screen.getByText("Ran")).toBeInTheDocument();
  expect(bodies).toEqual([{ inputs: {}, confirm: "" }]);
});

test("parameters the finding lacks are typed before the dry run and sent as inputs", async () => {
  servePlan(plan({ state: "needs_input", action: "sg_rule_remove", inputs: ["cidr", "protocol"] }));
  let sent: unknown;
  server.use(
    http.post(`${PLAN}/dry-run`, async ({ request }) => {
      sent = await request.json();
      return HttpResponse.json({ action: "sg_rule_remove", connector_id: "c1", params: {}, destructive: false, confirm_text: "", detail: "DRY RUN — nothing was changed." });
    }),
  );
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  expect(await screen.findByText(/doesn't carry these/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("cidr"), { target: { value: "0.0.0.0/0" } });
  fireEvent.click(screen.getByRole("button", { name: "Approve & run…" }));
  await screen.findByText(/DRY RUN/);
  expect(sent).toEqual({ inputs: { cidr: "0.0.0.0/0" }, confirm: "" });
});

test("a destructive fix needs the typed confirmation, then waits for a second admin", async () => {
  const state = servePlan(plan({ action: "ec2_stop", requires_second_admin: true }));
  let requested: unknown;
  server.use(
    http.post(`${PLAN}/dry-run`, () =>
      HttpResponse.json({
        action: "ec2_stop", connector_id: "c1", params: {}, destructive: true, confirm_text: "i-abc",
        detail: "DRY RUN — nothing was changed. Would stop EC2 instance i-abc in eu-west-1 (the workload goes offline).",
      }),
    ),
    http.post(`${PLAN}/request`, async ({ request }) => {
      requested = await request.json();
      state.current = plan({
        action: "ec2_stop", requires_second_admin: true,
        run: run({ status: "awaiting_second_admin", requested_by_you: true, grant_expires_at: later, plan: "stop EC2 instance i-abc in eu-west-1 (the workload goes offline)" }),
      });
      return HttpResponse.json(state.current.run);
    }),
  );
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  fireEvent.click(await screen.findByRole("button", { name: "Approve & request a second admin…" }));
  const request = await screen.findByRole("button", { name: "Approve & request second admin" });
  expect(request).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Typed confirmation"), { target: { value: "i-wrong" } });
  expect(request).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Typed confirmation"), { target: { value: "i-abc" } });
  fireEvent.click(request);

  expect(await screen.findByText("Waiting for a second admin")).toBeInTheDocument();
  expect(screen.getByText(/You approved: stop EC2 instance i-abc/)).toBeInTheDocument();
  expect(requested).toEqual({ inputs: {}, confirm: "i-abc" });
  expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument();
});

test("the second admin reads the approved plan, types the confirmation and runs it", async () => {
  servePlan(plan({
    action: "ec2_stop", requires_second_admin: true,
    run: run({ status: "awaiting_second_admin", grant_expires_at: later, confirm_text: "i-abc", plan: "stop EC2 instance i-abc in eu-west-1 (the workload goes offline)" }),
  }));
  let confirmed: unknown;
  server.use(
    http.post(`${PLAN}/run`, async ({ request }) => {
      confirmed = await request.json();
      return HttpResponse.json({ type: "about:blank", title: "Forbidden", status: 403, detail: "approval expired" }, { status: 403 });
    }),
  );
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  expect(await screen.findByText("Needs a second admin")).toBeInTheDocument();
  expect(screen.getByText(/alice@example.com approved/)).toBeInTheDocument();
  const go = screen.getByRole("button", { name: "Confirm & run" });
  expect(go).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Typed confirmation"), { target: { value: "i-abc" } });
  fireEvent.click(go);

  await waitFor(() => expect(confirmed).toEqual({ confirm: "i-abc" }));
  expect(await screen.findByRole("alert")).toBeInTheDocument();
});

test("a failed run shows the executor's reason and can be tried again", async () => {
  servePlan(plan({ run: run({ status: "failed", error: "executor: connector has no distinct execution role" }) }));
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  expect(await screen.findByText(/The last attempt failed: executor: connector has no distinct execution role/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approve & run…" })).toBeEnabled();
});

test("audit rows that could not be read are said to be missing, not shown as none", async () => {
  servePlan(plan({ run: run({ status: "failed", error: "boom" }), audit_known: false }));
  renderWithClient(<ApproveAndRun decisionId="d1" />);
  expect(await screen.findByText(/audit rows for this run couldn't be loaded/)).toBeInTheDocument();
});

const pendingDecision = {
  id: "d1",
  ts: "2026-10-08T00:00:00Z",
  actor: "agent",
  action: "decision",
  target_type: "finding",
  target_id: "f1",
  target_title: "Public bucket",
  details: JSON.stringify({ action_class: "remediate", outcome: "parked_for_approval", summary: "block public access" }),
};

async function openPanel(role: "admin" | "viewer") {
  server.use(
    meHandler(role),
    http.get("/api/decisions", () => HttpResponse.json({ items: [pendingDecision], next_cursor: "" })),
    http.get("/api/decisions/summary", () =>
      HttpResponse.json({
        total: 1, observed: 0, escalated: 0, parked_for_approval: 1, suppressed_by_verdict: 0,
        quick_wins: 0, unique_resources: 1, action_classes: { remediate: 1 }, confidence_bands: {},
        escalation_reasons: {}, hotspots: [],
      }),
    ),
  );
  renderApp("/decisions");
  fireEvent.click(await screen.findByRole("button", { name: /^review →$/i }));
  expect(await screen.findByRole("dialog")).toBeInTheDocument();
}

test("the decision panel offers the run flow to an admin", async () => {
  servePlan(plan({}));
  await openPanel("admin");
  expect(await screen.findByRole("region", { name: "Run this fix" })).toBeInTheDocument();
});

test("the decision panel shows no run flow to a viewer", async () => {
  await openPanel("viewer");
  expect(screen.queryByRole("region", { name: "Run this fix" })).not.toBeInTheDocument();
});

test("a run whose result is unknown offers no run button and says to verify", async () => {
  servePlan(plan({ run: run({ status: "outcome_unknown", error: "result unknown — verify in the cloud console" }) }));
  renderWithClient(<ApproveAndRun decisionId="d1" />);

  expect(await screen.findByText("Result unknown")).toBeInTheDocument();
  expect(screen.getByText(/Check the resource in the cloud console/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument();
});
