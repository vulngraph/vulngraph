import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import { ConnectorsSection } from "./Connectors";
import { generateExternalId } from "./AwsOrg";

const org = {
  id: "o1",
  type: "aws_org",
  name: "acme",
  enabled: true,
  sync_status: "ok",
  stale: false,
  partially_stale: false,
  mode: "read_only",
};

test("generateExternalId is random and AWS-valid", () => {
  const a = generateExternalId();
  expect(a).toMatch(/^graph-[0-9a-f]{32}$/);
  expect(generateExternalId()).not.toBe(a);
});

test("creating an aws_org connector shows the setup guide and sends the generated ExternalId", async () => {
  let sent: { type: string; config: Record<string, string> } | undefined;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.post("/api/connectors", async ({ request }) => {
      sent = (await request.json()) as typeof sent;
      return HttpResponse.json({ ...org }, { status: 201 });
    }),
  );
  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Add connector" }));
  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "aws_org" } });

  expect(screen.getByText("Onboard a whole AWS Organization")).toBeInTheDocument();
  const shown = screen.getByTestId("external-id").textContent ?? "";
  expect(shown).toMatch(/^graph-/);
  expect(screen.getByRole("link", { name: "graph-org-stackset.yaml" })).toHaveAttribute(
    "href",
    "/api/aws-org/templates/graph-org-stackset.yaml",
  );

  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "acme" } });
  fireEvent.change(screen.getByLabelText("management_role_arn"), {
    target: { value: "arn:aws:iam::111111111111:role/GraphOrgDiscovery" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Create" }));

  await waitFor(() => expect(sent).toBeDefined());
  expect(sent?.type).toBe("aws_org");
  expect(sent?.config.external_id).toBe(shown);
  expect(sent?.config).not.toHaveProperty("aws_access_key_id");
});

test("an aws_org connector with a principal-trust hub sends hub_role_arn", async () => {
  let sent: { type: string; config: Record<string, string> } | undefined;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.post("/api/connectors", async ({ request }) => {
      sent = (await request.json()) as typeof sent;
      return HttpResponse.json({ ...org }, { status: 201 });
    }),
  );
  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Add connector" }));
  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "aws_org" } });
  expect(screen.getByText(/assumes the hub role/)).toHaveTextContent("HubRoleArn");

  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "acme" } });
  fireEvent.change(screen.getByLabelText("management_role_arn"), {
    target: { value: "arn:aws:iam::111111111111:role/GraphOrgDiscovery" },
  });
  fireEvent.change(screen.getByLabelText("hub_auth (optional)"), { target: { value: "access_key" } });
  fireEvent.change(screen.getByLabelText("hub_role_arn (optional)"), {
    target: { value: "arn:aws:iam::333333333333:role/GraphHub" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Create" }));

  await waitFor(() => expect(sent).toBeDefined());
  expect(sent?.config.hub_auth).toBe("access_key");
  expect(sent?.config.hub_role_arn).toBe("arn:aws:iam::333333333333:role/GraphHub");
});

test("an admin can test an aws_org connection and see per-account causes", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([org])),
    http.post("/api/connectors/o1/test", () =>
      HttpResponse.json({
        hub_ok: true,
        hub_identity: "arn:aws:sts::9:assumed-role/GraphHub/x",
        list_ran: true,
        list_ok: true,
        account_count: 2,
        members: [
          { account_id: "222222222222", ok: true, cause: "ok" },
          { account_id: "333333333333", ok: false, cause: "role_missing_or_untrusted", detail: "role not deployed" },
        ],
      }),
    ),
  );
  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Test connection" }));
  expect(await screen.findByText(/Listed 2 accounts/)).toBeInTheDocument();
  expect(screen.getByText(/333333333333 — role_missing_or_untrusted/)).toBeInTheDocument();
  expect(screen.getByText("role not deployed")).toBeInTheDocument();
});

test("the accounts list shows each account's status and child health; viewers cannot test", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/connectors", () => HttpResponse.json([org])),
    http.get("/api/connectors/o1/org-accounts", () =>
      HttpResponse.json([
        {
          account_id: "222222222222",
          name: "prod",
          email: "p@x",
          aws_state: "ACTIVE",
          status: "active",
          child_connector_id: "c2",
          child: { enabled: true, sync_status: "error", stale: false },
          first_seen_at: "2026-10-01T00:00:00Z",
          last_seen_at: "2026-10-09T00:00:00Z",
          status_changed_at: "2026-10-01T00:00:00Z",
        },
        {
          account_id: "333333333333",
          name: "old",
          email: "o@x",
          aws_state: "SUSPENDED",
          status: "suspended",
          status_detail: "suspended by AWS; its child connector is disabled and its data kept",
          child_connector_id: "c3",
          child: { enabled: false, sync_status: "ok", stale: false },
          first_seen_at: "2026-10-01T00:00:00Z",
          last_seen_at: "2026-10-09T00:00:00Z",
          status_changed_at: "2026-10-05T00:00:00Z",
        },
      ]),
    ),
  );
  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Accounts" }));
  expect(await screen.findByText("prod")).toBeInTheDocument();
  expect(screen.getByText("suspended")).toBeInTheDocument();
  expect(screen.getByText("disabled")).toBeInTheDocument();
  expect(screen.getByText(/its data kept/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Test connection" })).not.toBeInTheDocument();
});
