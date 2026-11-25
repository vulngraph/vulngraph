import { http, HttpResponse } from "msw";
import { fireEvent, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

// The census the backend returns for an estate. Representative fixture
// numbers exercising the shape: humans behind IAM console principal rows,
// account roots and key-only service users excluded, workload identities
// across multiple providers, and IAM roles split between workload identities
// and the human SSO federation surface.
function censusHandler(overrides: Record<string, unknown> = {}) {
  return http.get("/api/identity/summary", () =>
    HttpResponse.json({
      humans: {
        distinct: 150,
        with_corporate_email: 100,
        console_principals: 400,
        by_provider: { aws: 150 },
        excluded: {
          root_principals: 40,
          programmatic: 300,
          programmatic_distinct: 250,
          console_access_unknown: 0,
          inactive_principals: 50,
        },
        federation: {
          directory_identities: 0,
          directory_by_provider: {},
          sso_permission_sets: 250,
          sso_groups: 150,
          sso_group_assignments: 100,
          sso_user_assignments: 0,
          sso_federation_roles: 300,
        },
      },
      workloads: {
        total: 5000,
        by_provider: { aws: 3000, gcp: 1700, kubernetes: 280, azure: 20 },
        by_type: {
          iam_role: 3000,
          gcp_service_account: 1700,
          k8s_service_account: 280,
          azure_service_principal: 20,
        },
        gcp_default_service_accounts: 250,
        programmatic_iam_users: 250,
        roles_referenced_not_collected: 5,
      },
      roles: {
        total: 10000,
        by_class: { unattributed: 6000, workload: 3000, platform: 700, human_federation: 300 },
        stale_by_class: { unattributed: 1500, workload: 1000, platform: 100, human_federation: 20 },
      },
      staleness: {
        threshold_days: 30,
        stale_by_type: { iam_role: 2500, iam_user: 5 },
        total_by_type: { iam_role: 10000, iam_user: 800 },
        stale_accounts: [
          { account_id: "999900001111", provider: "aws", count: 2500, last_seen: "2026-06-19T19:50:53Z", age_days: 60 },
        ],
      },
      generated_at: "2026-08-21T12:00:00Z",
      ...overrides,
    }),
  );
}

// The page's list tabs page through /api/assets independently of the census.
// Stubbed empty so the tile assertions are about the census alone.
function emptyAssetsHandler() {
  return http.get("/api/assets", () => HttpResponse.json({ items: [], next_cursor: "" }));
}

// The three headline tiles must come from the census endpoint, not from
// arithmetic on /api/assets/summary. If they ever regress to by_type math the
// people tile shows 800 instead of 150 and this test fails.
test("Identity tiles report the backend census, not asset-row arithmetic", async () => {
  server.use(meHandler("viewer"), censusHandler(), emptyAssetsHandler());

  renderApp("/investigate/identity");

  // People: the deduplicated headcount, with the raw row count still visible.
  expect(await screen.findByText("150")).toBeInTheDocument();
  expect(screen.getByText("People with cloud access")).toBeInTheDocument();
  expect(screen.getByText(/400 IAM principals across accounts/)).toBeInTheDocument();

  // Every narrowed-away population is named rather than silently dropped.
  expect(screen.getByText(/40 account root/)).toBeInTheDocument();
  expect(screen.getByText(/250 programmatic \(key-only\)/)).toBeInTheDocument();

  // Workloads: cross-cloud, and it says which clouds.
  expect(screen.getByText("5,000")).toBeInTheDocument();
  expect(screen.getByText("Workload identities (all clouds)")).toBeInTheDocument();
  expect(screen.getByText(/3000 AWS · 1700 GCP · 280 K8s · 20 Azure/)).toBeInTheDocument();

  // Roles: the count was always right, the label wasn't.
  expect(screen.getByText("10,000")).toBeInTheDocument();
  expect(screen.getByText("AWS IAM roles by purpose")).toBeInTheDocument();
  expect(screen.getByText(/300 SSO \(human\)/)).toBeInTheDocument();
});

// A 60-day-stale account cannot silently inflate a figure the page calls current.
test("Identity warns that a stale account's identities are last-known state", async () => {
  server.use(meHandler("viewer"), censusHandler(), emptyAssetsHandler());

  renderApp("/investigate/identity");

  expect(await screen.findByText(/stopped being collected/)).toBeInTheDocument();
  expect(screen.getByText("999900001111")).toBeInTheDocument();
  expect(screen.getByText(/last seen 60d ago/)).toBeInTheDocument();
});

// Zero collected federated humans alongside 150 SSO groups is the
// understatement the old tile had no way to express.
test("Identity flags that federated humans are not collected", async () => {
  server.use(meHandler("viewer"), censusHandler(), emptyAssetsHandler());

  renderApp("/investigate/identity");

  expect(await screen.findByText(/Federated humans are not collected/)).toBeInTheDocument();
  expect(screen.getByText(/0 direct to a user/)).toBeInTheDocument();
});

// The tab badge must not add workload identities to the role total: a chunk of
// the roles ARE the AWS workload identities, so summing them double-counted every
// AWS workload.
test("Machine roles tab badge does not double-count overlapping populations", async () => {
  server.use(meHandler("viewer"), censusHandler(), emptyAssetsHandler());

  renderApp("/investigate/identity");

  expect(await screen.findByText("(5,000 workload identities)")).toBeInTheDocument();
  // The old badge summed gcp_service_account + iam_role = 11,700.
  expect(screen.queryByText(/11,?700/)).not.toBeInTheDocument();
});

// A root with no password has no console sign-in for MFA to protect; one
// whose credential report was not read is unknown, never shown as clean.
test("People rows tell no MFA, no console and unread console access apart", async () => {
  const iamUser = (id: string, name: string, metadata: Record<string, string>) => ({
    id, type: "iam_user", name, provider: "aws", account_id: "111122223333", metadata,
  });
  server.use(
    meHandler("viewer"),
    censusHandler(),
    http.get("/api/assets", ({ request }) => {
      if (new URL(request.url).searchParams.get("type") !== "iam_user") {
        return HttpResponse.json({ items: [], next_cursor: "" });
      }
      return HttpResponse.json({
        items: [
          iamUser("u:console", "console-user", { console_access: "true", mfa_enabled: "false" }),
          iamUser("u:root-nopw", "root-no-password", { root: "true", console_access: "false", mfa_enabled: "false" }),
          iamUser("u:root-unread", "root-unread", { root: "true", mfa_enabled: "false" }),
        ],
        next_cursor: "",
      });
    }),
  );

  renderApp("/investigate/identity");
  fireEvent.click(await screen.findByRole("button", { name: /People/ }));

  const row = async (name: string) => (await screen.findByText(name)).closest("button") as HTMLElement;
  expect(await row("console-user")).toHaveTextContent("no MFA");
  expect(await row("root-no-password")).not.toHaveTextContent(/MFA/);
  expect(await row("root-unread")).toHaveTextContent("MFA unknown");
  expect(await row("root-unread")).not.toHaveTextContent("no MFA");
});

// An EC2 instance reaches its role through HasRole, not ExecutesAs: both are
// machine edges, so the breakdown counts the instance profile too.
test("Identity graph counts HasRole edges as machine identities", async () => {
  const node = (id: string, type: string) => ({ id, type, name: id, provider: "aws", account_id: "111122223333" });
  server.use(
    meHandler("viewer"),
    censusHandler(),
    emptyAssetsHandler(),
    http.post("/api/graph/cypher", () =>
      HttpResponse.json({
        nodes: [node("fn", "lambda_function"), node("i-web", "ec2_instance"), node("repo", "github_repo"), node("role", "iam_role")],
        edges: [
          { src_id: "fn", dst_id: "role", edge_type: "ExecutesAs" },
          { src_id: "i-web", dst_id: "role", edge_type: "HasRole" },
          { src_id: "repo", dst_id: "role", edge_type: "FederatedAccess" },
        ],
        truncated: false,
      }),
    ),
  );

  renderApp("/investigate/identity");

  expect(await screen.findByText("1 human")).toBeInTheDocument();
  expect(screen.getByText("2 machine")).toBeInTheDocument();
});
