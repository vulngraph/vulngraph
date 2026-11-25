import { http, HttpResponse } from "msw";
import { fireEvent, screen, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const SUMMARY = { id: "pci-dss-4.0", name: "PCI DSS", version: "4.0.1", total: 3, passing: 1, failing: 1, unknown: 1, manual: 0 };
const NIST = { id: "nist-800-53-r5", name: "NIST SP 800-53", version: "Rev. 5", total: 1, passing: 0, failing: 0, unknown: 0, manual: 1 };

const req = (id: string, title: string, state: string, extra: Record<string, string[]> = {}) => ({
  id,
  title,
  state,
  controls: ["aws-fsbp/S3.1"],
  check_ids: ["aws-s3-public-bucket"],
  failing_checks: [],
  unevaluated_checks: [],
  gaps: [],
  out_of_scope: [],
  unjoined_source_checks: 0,
  partial_mapping: "",
  evidence_gaps: [] as string[],
  evidence_as_of: "2026-10-12T06:00:00Z" as string | null,
  ...extra,
});

const PCI = {
  clouds: [
    { provider: "aws", connectors: 2, has_inventory: true, evidence_as_of: "2026-10-12T06:00:00Z", stale: false },
    { provider: "azure", connectors: 1, has_inventory: false, evidence_as_of: null, stale: true },
  ],
  ...SUMMARY,
  requirements: [
    req("1.3.1", "Inbound traffic to the CDE restricted", "failing", { failing_checks: ["aws-sg-open-all-ports"] }),
    {
      ...req("3.5.1", "Stored PAN rendered unreadable", "unknown", { gaps: ["aws-fsbp/S3.4"] }),
      unjoined_source_checks: 2,
      partial_mapping: "partial mapping: 2 source checks without a graph control",
    },
    req("8.4.2", "MFA for all CDE access", "passing"),
  ],
};

function mock(role: "admin" | "analyst" | "viewer") {
  server.use(
    meHandler(role),
    http.get("/api/compliance", () =>
      HttpResponse.json({ total: 0, passing: 0, failing: 0, partial: 0, not_assessed: 0, controls: [], frameworks: [] }),
    ),
    http.get("/api/findings/clusters", () => HttpResponse.json({ items: [] })),
    http.get("/api/compliance/frameworks", () => HttpResponse.json({ frameworks: [SUMMARY, NIST] })),
    http.get("/api/compliance/frameworks/pci-dss-4.0", () => HttpResponse.json(PCI)),
    http.get("/api/compliance/frameworks/nist-800-53-r5", () =>
      HttpResponse.json({ ...NIST, clouds: [], requirements: [req("AC-1", "Policy and Procedures", "manual", { controls: [], check_ids: [] })] }),
    ),
  );
}

test("shows requirement-level state with the evidence behind it", async () => {
  mock("analyst");
  renderApp("/compliance");

  const section = await screen.findByRole("region", { name: "Framework requirements" });
  expect(await within(section).findByText("Inbound traffic to the CDE restricted")).toBeInTheDocument();
  expect(within(section).getByText("aws-sg-open-all-ports")).toBeInTheDocument();
  expect(within(section).getByText(/1 control without full checks/)).toBeInTheDocument();
  expect(within(section).getByText("partial mapping: 2 source checks without a graph control")).toBeInTheDocument();
  expect(within(section).getByText(/azure: stale or missing evidence · as of unknown/)).toBeInTheDocument();
  expect(within(section).getAllByText(/evidence as of 2026-10-12 06:00 UTC/).length).toBeGreaterThan(0);
  // Unknown is labelled as such, never folded into passing.
  expect(within(section).getByTitle(/evidence is incomplete — not a pass/)).toHaveTextContent("unknown");

  const exportLink = within(section).getByText("Export CSV for auditors");
  expect(exportLink.getAttribute("href")).toBe("/api/compliance/frameworks/pci-dss-4.0/export");
});

test("filters by state and switches framework", async () => {
  mock("admin");
  renderApp("/compliance");
  const section = await screen.findByRole("region", { name: "Framework requirements" });
  await within(section).findByText("MFA for all CDE access");

  fireEvent.click(within(section).getByRole("button", { name: "failing" }));
  expect(within(section).queryByText("MFA for all CDE access")).not.toBeInTheDocument();
  expect(within(section).getByText("Inbound traffic to the CDE restricted")).toBeInTheDocument();

  fireEvent.click(within(section).getByRole("button", { name: "all" }));
  fireEvent.click(within(section).getByRole("tab", { name: /NIST SP 800-53/ }));
  expect(await within(section).findByText("Policy and Procedures")).toBeInTheDocument();
});

test("viewers do not get an export link the server would refuse", async () => {
  mock("viewer");
  renderApp("/compliance");
  const section = await screen.findByRole("region", { name: "Framework requirements" });
  await within(section).findByText("Inbound traffic to the CDE restricted");
  expect(within(section).queryByText("Export CSV for auditors")).not.toBeInTheDocument();
});
