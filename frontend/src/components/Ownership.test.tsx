import { http, HttpResponse } from "msw";
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import type { Finding } from "../lib/api";
import { EnvironmentBadge, findingsToCSV, OwnerBadge, OwnerEnvFilters, ownerLabel } from "./Ownership";

const base = {
  id: "f1", source: "cspm", type: "exposure", severity: "high", score: 70, title: "Public bucket, really",
  detected_at: "2026-06-10T00:00:00Z", enrichment_state: "enriched", score_band: "high", safety_class: "",
  must_fix_class: "routine", owner_source: "", environment: "",
} as Finding;

test("owner badge keeps owned, unowned and unresolved apart", () => {
  const { rerender, container } = render(
    <OwnerBadge finding={{ ...base, owner_team: "payments", owner_source: "codeowners", owner_confidence: "high" }} />,
  );
  expect(screen.getByText("@payments")).toHaveAttribute("title", expect.stringMatching(/CODEOWNERS.*high confidence/));

  rerender(<OwnerBadge finding={{ ...base, owner_source: "none" }} />);
  expect(screen.getByText("unowned")).toBeInTheDocument();

  rerender(<OwnerBadge finding={base} />);
  expect(container).toBeEmptyDOMElement(); // unresolved: no guess

  expect(ownerLabel({ ...base, owner_source: "none" })).toBe("unowned");
  expect(ownerLabel(base)).toBe("");
});

test("environment badge renders the classified value and nothing when unstamped", () => {
  const { container, rerender } = render(<EnvironmentBadge env="prod" />);
  expect(screen.getByText("prod")).toBeInTheDocument();
  rerender(<EnvironmentBadge env="" />);
  expect(container).toBeEmptyDOMElement();
});

test("CSV export carries owner and environment and escapes cells", () => {
  const csv = findingsToCSV([
    { ...base, owner_team: "payments", owner_source: "tag", environment: "prod" },
    { ...base, id: "f2", owner_source: "none", environment: "unknown" },
  ]);
  const [header, row1, row2] = csv.split("\n");
  expect(header).toContain("owner,owner_source,environment");
  expect(row1).toContain('"Public bucket, really"');
  expect(row1).toContain(",payments,tag,prod,");
  expect(row2).toContain(",unowned,none,unknown,");
});

test("CSV export neutralises formula-leading cells from finding data", () => {
  const csv = findingsToCSV([{ ...base, title: "=HYPERLINK(\"https://evil.example\")", resource_id: "@SUM(A1)" }]);
  const row = csv.split("\n")[1];
  expect(row).toContain(`"'=HYPERLINK(""https://evil.example"")"`);
  expect(row).toContain(",'@SUM(A1),");
});

test("owner and environment filters list facet counts and report changes", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings/summary", () =>
      HttpResponse.json({
        total: 9, by_severity: {}, by_band: {},
        by_owner: { payments: 4, unowned: 2, "": 3 }, by_environment: { prod: 5, unknown: 4 },
      }),
    ),
  );
  const onChange = vi.fn();
  renderWithClient(<OwnerEnvFilters owner="" environment="" onChange={onChange} />);

  expect(await screen.findByRole("option", { name: "@payments (4)" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "Unowned (2)" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "All owners (3 unresolved)" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "prod (5)" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "staging (0)" })).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Owner filter"), { target: { value: "unowned" } });
  expect(onChange).toHaveBeenCalledWith("owner", "unowned");
  fireEvent.change(screen.getByLabelText("Environment filter"), { target: { value: "prod" } });
  expect(onChange).toHaveBeenCalledWith("environment", "prod");
});
