import { http, HttpResponse } from "msw";
import { screen, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const asset = {
  id: "i-1",
  name: "web-server",
  type: "ec2_instance",
  provider: "aws",
  region: "eu-west-1",
  public_ip: "203.0.113.7",
  private_ip: "10.0.1.5",
  risk_score: 72,
  last_seen: "2026-06-10T00:00:00Z",
  environment: "prod",
  environment_source: "tag:env",
};

test("renders an asset and its blast radius", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/i-1", () => HttpResponse.json(asset)),
    http.get("/api/assets/i-1/blast-radius", () =>
      HttpResponse.json({
        seed_id: "i-1",
        max_depth: 2,
        truncated: false,
        // The blast radius includes the seed (depth 0) plus reachable assets.
        assets: [asset, { ...asset, id: "i-2", name: "db", risk_score: 40 }],
        edges: [{ src_id: "i-1", dst_id: "i-2", edge_type: "runs_in" }],
      }),
    ),
    http.get("/api/findings", () =>
      HttpResponse.json({
        items: [{ id: "f1", source: "cspm", type: "exposure", severity: "high", score: 80, score_band: "page", title: "Public bucket", check_id: "aws-s3-public", detected_at: "2026-06-10T00:00:00Z" }],
        next_cursor: "",
      }),
    ),
  );

  renderApp("/investigate/assets/i-1");

  // The asset name appears in the page heading (and again as a graph node).
  expect(await screen.findByRole("heading", { name: "web-server" })).toBeInTheDocument();
  // Network addressing surfaces; a public IP marks the asset internet-facing.
  expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
  expect(screen.getByText("10.0.1.5")).toBeInTheDocument();
  expect(screen.getByText("internet-facing")).toBeInTheDocument();
  expect(screen.getByText("Production (tag:env)")).toBeInTheDocument();
  // The asset's findings are listed (its real risk), linkable to the finding detail.
  expect(await screen.findByText("Public bucket")).toBeInTheDocument();
  expect(screen.getByText("1 on this asset")).toBeInTheDocument();
  // The blast radius renders as a graph (1 connected besides the seed), not the
  // "Isolated" empty state, and offers the can-reach / reached-by toggle.
  expect(await screen.findByText("1 connected")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Reached by" })).toBeInTheDocument();
  expect(screen.queryByText(/Isolated/)).not.toBeInTheDocument();
});

function diskScanAsset(diskScan: Record<string, unknown>) {
  server.use(
    meHandler("viewer"),
    http.get("/api/assets/i-1", () => HttpResponse.json(asset)),
    http.get("/api/assets/i-1/blast-radius", () =>
      HttpResponse.json({ seed_id: "i-1", max_depth: 2, truncated: false, assets: [asset], edges: [] }),
    ),
    http.get("/api/assets/i-1/disk-scan", () => HttpResponse.json(diskScan)),
  );
}

test("disk scan panel: a scanned volume shows its source, time and package count", async () => {
  diskScanAsset({
    asset_id: "i-1", state: "scanned",
    volumes: [{ volume_ref: "vol-1", snapshot_source: "reused", encrypted: false, inventory_known: true, cve_matchable_known: true, package_count: 312, observed_at: "2026-06-10T00:00:00Z" }],
  });
  renderApp("/investigate/assets/i-1");

  const panel = await screen.findByRole("region", { name: "Disk scan" });
  expect(within(panel).getByText("Scanned")).toBeInTheDocument();
  expect(within(panel).getByText("vol-1")).toBeInTheDocument();
  expect(within(panel).getByText(/312 packages read from an existing snapshot/)).toBeInTheDocument();
  expect(within(panel).getByText(/observed/)).toBeInTheDocument();
});

test("disk scan panel: not enabled reads as unknown, never as clean", async () => {
  diskScanAsset({ asset_id: "i-1", state: "not_enabled", gap: "not_enabled", volumes: [] });
  renderApp("/investigate/assets/i-1");

  const panel = await screen.findByRole("region", { name: "Disk scan" });
  expect(within(panel).getByText("Not enabled")).toBeInTheDocument();
  expect(within(panel).getByText(/not a clean result/)).toBeInTheDocument();
  expect(within(panel).queryByText(/no vulnerabilities/i)).not.toBeInTheDocument();
});

test("disk scan panel: a gap is explained in plain English with the volume marked not read", async () => {
  diskScanAsset({
    asset_id: "i-1", state: "none", gap: "encrypted_no_key",
    volumes: [{ volume_ref: "vol-2", encrypted: true, inventory_known: false, cve_matchable_known: false, gap: "encrypted_no_key", package_count: 0, observed_at: "2026-06-10T00:00:00Z" }],
  });
  renderApp("/investigate/assets/i-1");

  const panel = await screen.findByRole("region", { name: "Disk scan" });
  expect(within(panel).getByText("Not scanned")).toBeInTheDocument();
  expect(within(panel).getAllByText(/encrypted and the scanner's role cannot use its key/).length).toBeGreaterThan(0);
  expect(within(panel).getByText(/Not read\./)).toBeInTheDocument();
  expect(within(panel).queryByText(/0 packages/)).not.toBeInTheDocument();
});
