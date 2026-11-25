import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import { ConnectorsSection } from "./Connectors";

const conn = {
  id: "c1",
  type: "aws",
  name: "prod",
  enabled: true,
  sync_status: "ok",
  last_synced_at: "2026-06-10T00:00:00Z",
  last_success_at: "2026-06-10T00:00:00Z",
  stale: false,
  partially_stale: false,
  mode: "read_only",
};

test("a viewer sees connectors but no write actions", async () => {
  server.use(meHandler("viewer"), http.get("/api/connectors", () => HttpResponse.json([conn])));

  renderWithClient(<ConnectorsSection />);

  expect(await screen.findByText("prod")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Add connector" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Sync now" })).not.toBeInTheDocument();
});

test("an admin can sync a connector and sees confirmation", async () => {
  let synced = false;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([conn])),
    http.post("/api/connectors/c1/sync", () => {
      synced = true;
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Sync now" }));
  await waitFor(() => expect(synced).toBe(true));
  expect(await screen.findByText("Sync queued.")).toBeInTheDocument();
});

test("a sync failure renders visibly instead of the button silently resetting", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([conn])),
    http.post("/api/connectors/c1/sync", () => HttpResponse.json({ detail: "rate limited by provider" }, { status: 429 })),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Sync now" }));
  expect(await screen.findByText(/rate limited by provider/)).toBeInTheDocument();
});

test("delete requires a confirm step that auto-disarms", async () => {
  let deleted = false;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([conn])),
    http.delete("/api/connectors/c1", () => {
      deleted = true;
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
  expect(deleted).toBe(false); // first click only arms the confirm
  fireEvent.click(screen.getByRole("button", { name: "Confirm delete?" }));
  await waitFor(() => expect(deleted).toBe(true));
});

test("an admin creates an aws connector with provider-specific fields", async () => {
  type CreateBody = { type?: string; config?: Record<string, string> };
  // Capture inside an object so TS doesn't narrow the closure-assigned var to null.
  const captured: { body: CreateBody | null } = { body: null };
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([])),
    http.post("/api/connectors", async ({ request }) => {
      captured.body = (await request.json()) as CreateBody;
      return HttpResponse.json({ ...conn, name: "new" }, { status: 201 });
    }),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Add connector" }));
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "new" } });
  // aws renders role_arn + region inputs (connectorConfigKeys).
  fireEvent.change(screen.getByLabelText("role_arn"), { target: { value: "arn:aws:iam::1:role/x" } });
  fireEvent.change(screen.getByLabelText("region"), { target: { value: "eu-west-1" } });
  fireEvent.click(screen.getByRole("button", { name: "Create" }));

  await waitFor(() => expect(captured.body?.type).toBe("aws"));
  expect(captured.body?.config).toEqual({ role_arn: "arn:aws:iam::1:role/x", region: "eu-west-1" });
});

test("okta's api_token renders masked, github's private_key_pem renders as a textarea", async () => {
  server.use(meHandler("admin"), http.get("/api/connectors", () => HttpResponse.json([])));

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Add connector" }));
  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "okta" } });
  expect(screen.getByLabelText("api_token")).toHaveAttribute("type", "password");

  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "github" } });
  expect(screen.getByLabelText("private_key_pem").tagName).toBe("TEXTAREA");
  // github's optional webhook_secret is also a sensitive field, masked like the token.
  expect(screen.getByLabelText("webhook_secret (optional)")).toHaveAttribute("type", "password");

  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "google_workspace" } });
  expect(screen.getByLabelText("service_account_json").tagName).toBe("TEXTAREA");
});

test("a disabled connector and a stale connector look visually distinct from a healthy one", async () => {
  const healthy = { ...conn, id: "c-healthy", name: "healthy" };
  const disabled = { ...conn, id: "c-disabled", name: "disabled-conn", enabled: false };
  const stale = { ...conn, id: "c-stale", name: "stale-conn", stale: true };
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([healthy, disabled, stale])),
  );

  renderWithClient(<ConnectorsSection />);

  expect(await screen.findByText("disabled-conn")).toBeInTheDocument();
  expect(screen.getByText("disabled")).toBeInTheDocument();
  expect(screen.getByText("stale")).toBeInTheDocument();
});

test("an active status filter chip stays mounted and clearable when the search text leaves it matching nothing", async () => {
  const healthy = { ...conn, id: "c-healthy", name: "healthy", sync_status: "ok" };
  server.use(meHandler("admin"), http.get("/api/connectors", () => HttpResponse.json([healthy])));

  renderWithClient(<ConnectorsSection />);

  const okChip = await screen.findByRole("button", { name: /ok \(1\)/ });
  fireEvent.click(okChip);
  expect(await screen.findByText("healthy")).toBeInTheDocument();

  // Narrow the search past what the filtered connector matches — the "ok"
  // chip (still the active filter, count now stale at 0 matches shown) must
  // stay mounted rather than vanish, and "all" must remain to clear both.
  fireEvent.change(screen.getByPlaceholderText("search connectors…"), { target: { value: "nomatch" } });
  expect(await screen.findByText(/No connectors currently match "ok"/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /ok \(/ })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /all \(/ }));
  fireEvent.change(screen.getByPlaceholderText("search connectors…"), { target: { value: "" } });
  expect(await screen.findByText("healthy")).toBeInTheDocument();
});

const SENTENCE = "I accept the snapshot cost and the snapshot permissions";

function diskScanDetail(over: Record<string, unknown> = {}) {
  return {
    connector_id: "c1", type: "aws", mode: "off", modes: ["off", "existing_snapshots", "create_snapshots"],
    confirmation: SENTENCE, warning: "Disk scanning reads your VMs' disks from cloud snapshots.", ...over,
  };
}

test("disk scan: a viewer sees the mode but no controls", async () => {
  server.use(meHandler("viewer"), http.get("/api/connectors", () => HttpResponse.json([{ ...conn, disk_scan_mode: "existing_snapshots" }])));

  renderWithClient(<ConnectorsSection />);

  const section = await screen.findByRole("region", { name: "Disk scan" });
  expect(within(section).getByText("existing snapshots")).toBeInTheDocument();
  expect(within(section).queryByRole("button")).not.toBeInTheDocument();
});

test("disk scan: an admin must type the confirmation sentence before enabling", async () => {
  let body: unknown = null;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([{ ...conn, disk_scan_mode: "off" }])),
    http.get("/api/connectors/c1/disk-scan", () => HttpResponse.json(diskScanDetail())),
    http.put("/api/connectors/c1/disk-scan", async ({ request }) => {
      body = await request.json();
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Configure disk scan" }));
  expect(await screen.findByText(/Disk scanning reads your VMs' disks/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "existing_snapshots" } });
  const save = screen.getByRole("button", { name: "Save disk scan mode" });
  expect(save).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Type this sentence to confirm"), { target: { value: "I accept" } });
  expect(save).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Type this sentence to confirm"), { target: { value: SENTENCE } });
  expect(save).toBeEnabled();
  fireEvent.click(save);
  await waitFor(() => expect(body).toEqual({ mode: "existing_snapshots", confirmation: SENTENCE }));
});

test("disk scan: turning it off needs no confirmation", async () => {
  let body: unknown = null;
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([{ ...conn, disk_scan_mode: "existing_snapshots" }])),
    http.get("/api/connectors/c1/disk-scan", () => HttpResponse.json(diskScanDetail({ mode: "existing_snapshots", role: "arn:aws:iam::1:role/GraphDiskScan" }))),
    http.put("/api/connectors/c1/disk-scan", async ({ request }) => {
      body = await request.json();
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Configure disk scan" }));
  expect(await screen.findByText("arn:aws:iam::1:role/GraphDiskScan")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "off" } });
  expect(screen.queryByLabelText("Type this sentence to confirm")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save disk scan mode" }));
  await waitFor(() => expect(body).toEqual({ mode: "off" }));
});

test("disk scan: GCP says existing snapshots only and offers no create mode", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([{ ...conn, id: "g1", type: "gcp", disk_scan_mode: "off" }])),
    http.get("/api/connectors/g1/disk-scan", () => HttpResponse.json(diskScanDetail({ connector_id: "g1", type: "gcp", modes: ["off", "existing_snapshots"] }))),
  );

  renderWithClient(<ConnectorsSection />);

  expect(await screen.findByText("GCP: existing snapshots only, creation not available yet.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Configure disk scan" }));
  await screen.findByLabelText("Mode");
  expect(screen.queryByRole("option", { name: /Create short-lived snapshots/ })).not.toBeInTheDocument();
});

test("disk scan: a server refusal renders visibly", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/connectors", () => HttpResponse.json([{ ...conn, disk_scan_mode: "off" }])),
    http.get("/api/connectors/c1/disk-scan", () => HttpResponse.json(diskScanDetail())),
    http.put("/api/connectors/c1/disk-scan", () =>
      HttpResponse.json({ title: "Conflict", status: 409, detail: "creating snapshots needs the dedicated disk scan role set on the connector" }, { status: 409, headers: { "Content-Type": "application/problem+json" } }),
    ),
  );

  renderWithClient(<ConnectorsSection />);

  fireEvent.click(await screen.findByRole("button", { name: "Configure disk scan" }));
  await screen.findByLabelText("Mode");
  fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "create_snapshots" } });
  fireEvent.change(screen.getByLabelText("Type this sentence to confirm"), { target: { value: SENTENCE } });
  fireEvent.click(screen.getByRole("button", { name: "Save disk scan mode" }));
  expect(await screen.findByText(/dedicated disk scan role/)).toBeInTheDocument();
});
