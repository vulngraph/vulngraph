import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

// frameworkOf() (the fake dash-prefix taxonomy the accordion groups by, as
// opposed to control.frameworks) needs a 3-segment id — "cis-1-1" and
// "cis-1-2" collapse to the same "cis-1" group, matching real check ids like
// "aws-privesc-1".
const CONTROLS = [
  {
    control: { id: "cis-1-1", title: "Root account has no access keys", check_ids: ["aws-privesc-1"], frameworks: ["CIS"] },
    state: "failing",
    passing: false,
  },
  {
    control: { id: "cis-1-2", title: "MFA enabled for root", check_ids: ["aws-privesc-2"], frameworks: ["CIS"] },
    state: "passing",
    passing: true,
  },
  {
    control: { id: "soc2-2-1", title: "Access logging enabled", check_ids: ["aws-privesc-3"], frameworks: ["SOC2"] },
    state: "passing",
    passing: true,
  },
  {
    control: { id: "soc2-3-1", title: "Audit trail retained", check_ids: ["aws-cloudtrail-1"], frameworks: ["HIPAA"] },
    state: "not_assessed",
    passing: false,
  },
  {
    control: { id: "soc2-4-1", title: "DNS records not dangling", check_ids: ["dns-a", "dns-b"], frameworks: ["HIPAA"] },
    state: "partial",
    passing: false,
  },
];

const COMPLIANCE = {
  total: 5,
  passing: 2,
  failing: 1,
  partial: 1,
  not_assessed: 1,
  controls: CONTROLS,
  frameworks: [
    { framework: "CIS", total: 2, passing: 1, failing: 1, partial: 0, not_assessed: 0 },
    { framework: "SOC2", total: 1, passing: 1, failing: 0, partial: 0, not_assessed: 0 },
    { framework: "HIPAA", total: 2, passing: 0, failing: 0, partial: 1, not_assessed: 1 },
  ],
};

const CLUSTERS = {
  items: [
    {
      check_id: "aws-privesc-1",
      title: "Root account has an active access key",
      severity: "critical",
      max_score: 92,
      worst_band: "high",
      instances: 3,
      resources: 2,
      known_exploited: false,
      last_detected: "2026-08-01T00:00:00Z",
      remediation: "Delete the root access key and use an IAM role instead.",
    },
  ],
};

function mockCompliance() {
  server.use(
    meHandler("admin"),
    http.get("/api/compliance", () => HttpResponse.json(COMPLIANCE)),
    http.get("/api/compliance/frameworks", () => HttpResponse.json({ frameworks: [] })),
    http.get("/api/connectors", () => HttpResponse.json([{ id: "c1", type: "aws", name: "aws-1", sync_status: "ok" }])),
    http.get("/api/findings/clusters", () => HttpResponse.json(CLUSTERS)),
  );
}

test("renders framework groups from real per-framework coverage, not the dash-prefix grouping", async () => {
  mockCompliance();
  renderApp("/compliance");

  // fullyCoveredFrameworks must come from data.frameworks (SOC2 is 1/1 →
  // fully covered; CIS is 1/2 → not), not from grouping raw controls by
  // frameworkOf(), which would report 0.
  const label = await screen.findByText(/fully covered/);
  expect(label.previousElementSibling?.textContent).toBe("1");
});

test("failing-only header count matches the rendered rows (no 'N failing, 0 rows' contradiction)", async () => {
  mockCompliance();
  renderApp("/compliance");

  await screen.findByText("cis-1", { selector: "span" });
  // Under the default "failing only" filter, the cis-1 group must show
  // exactly its one failing control's title, and a "1 failing" count (banner
  // badge + group header both say it — there's no "N failing, 0 rows" split).
  expect(screen.getAllByText("1 failing").length).toBe(2);
  expect(screen.getByText("Root account has no access keys")).toBeInTheDocument();
  expect(screen.queryByText("MFA enabled for root")).not.toBeInTheDocument();
  // soc2-2 is fully passing, so under "failing only" it has nothing to
  // triage and doesn't render as a group at all.
  expect(screen.queryByText("soc2-2", { selector: "span" })).not.toBeInTheDocument();
});

test("toggling failing-only off reveals passing controls", async () => {
  mockCompliance();
  renderApp("/compliance");

  await screen.findByText("Root account has no access keys");
  fireEvent.click(screen.getByRole("button", { name: "Failing only" }));

  // cis-1 was already open (it had a failing control); now that passing
  // controls are included it should show MFA too without needing another click.
  expect(await screen.findByText("MFA enabled for root")).toBeInTheDocument();

  // soc2-2 has just appeared as a new group and starts collapsed (same as
  // any group opened outside of failing-only triage) — expand it to see its row.
  fireEvent.click(screen.getByText("soc2-2", { selector: "span" }));
  expect(await screen.findByText("Access logging enabled")).toBeInTheDocument();
});

test("a never-assessed control reads 'not assessed', not passing or failing", async () => {
  mockCompliance();
  renderApp("/compliance");

  await screen.findByText("Root account has no access keys");
  // Not a failure: the banner's failing count is still 1, and the control is
  // hidden under "failing only".
  expect(screen.getByText("1 not assessed", { selector: "span.rounded" })).toBeInTheDocument();
  expect(screen.queryByText("Audit trail retained")).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Failing only" }));
  fireEvent.click(await screen.findByText("soc2-3", { selector: "span" }));
  expect(await screen.findByText("Audit trail retained")).toBeInTheDocument();
  expect(screen.getByText("not assessed")).toBeInTheDocument();
});

test("a control with some unevaluated checks reads 'partially assessed', never passing", async () => {
  mockCompliance();
  renderApp("/compliance");

  await screen.findByText("Root account has no access keys");
  expect(screen.getByText("1 partially assessed", { selector: "span.rounded" })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Failing only" }));
  fireEvent.click(await screen.findByText("soc2-4", { selector: "span" }));
  expect(await screen.findByText("DNS records not dangling")).toBeInTheDocument();
  expect(screen.getByText("partially assessed")).toBeInTheDocument();
});

test("search filters by check_id, not just title", async () => {
  mockCompliance();
  renderApp("/compliance");

  await screen.findByText("Root account has no access keys");
  fireEvent.change(screen.getByLabelText("Filter controls by name or ID"), { target: { value: "aws-privesc-1" } });

  // "aws-privesc-1" matches CIS-1.1's check_id, not its title — proves the
  // search haystack includes check_ids, not just title/control id.
  await waitFor(() => expect(screen.getByText("Root account has no access keys")).toBeInTheDocument());
});

test("worst-finding and view-all links route to the All findings view, not Must fix", async () => {
  mockCompliance();
  renderApp("/compliance");

  const links = await screen.findAllByRole("link", { name: /Root account has an active access key/ });
  expect(links.length).toBeGreaterThan(0);
  for (const link of links) {
    const url = new URL(link.getAttribute("href") ?? "", "http://localhost");
    expect(url.searchParams.get("view")).toBe("all");
    expect(url.searchParams.get("q")).toBe("aws-privesc-1");
  }
});

test("an error loading finding clusters is shown, not silently swallowed", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/compliance", () => HttpResponse.json(COMPLIANCE)),
    http.get("/api/compliance/frameworks", () => HttpResponse.json({ frameworks: [] })),
    http.get("/api/findings/clusters", () => HttpResponse.json({ message: "boom" }, { status: 500 })),
  );
  renderApp("/compliance");

  expect(await screen.findByText(/Could not load the finding data/)).toBeInTheDocument();
});

test("with no connectors the page says nothing has been evaluated", async () => {
  mockCompliance();
  server.use(http.get("/api/connectors", () => HttpResponse.json([])));
  renderApp("/compliance");

  expect(await screen.findByText("Nothing is connected yet.")).toBeInTheDocument();
});

test("with a connector configured there is no connect-a-source banner", async () => {
  mockCompliance();
  renderApp("/compliance");

  await screen.findByText(/fully covered/);
  expect(screen.queryByText("Nothing is connected yet.")).not.toBeInTheDocument();
});
