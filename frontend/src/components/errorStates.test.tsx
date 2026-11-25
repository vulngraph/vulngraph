// Regression tests for the "silent failure" sweep: mutations that failed
// without telling the user, async click handlers that leaked unhandled
// rejections, and mutations that didn't refetch what they changed.
import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp, renderWithClient, testClient } from "../test/render";
import type { Finding } from "../lib/api";
import { copyText } from "../lib/clipboard";
import { SuppressControl } from "./FindingDetailPanel";
import { SavedDetections } from "./SavedDetections";

const ORIGINAL_CLIPBOARD = navigator.clipboard;
afterEach(() => {
  Object.defineProperty(navigator, "clipboard", { value: ORIGINAL_CLIPBOARD, configurable: true });
});

const finding = {
  id: "f1",
  source: "cspm",
  type: "exposure",
  severity: "high",
  score: 84,
  title: "EC2 instance has a public IP",
  resource_id: "i-123",
  detected_at: "2026-06-10T00:00:00Z",
  is_suppressed: false,
} as unknown as Finding;

async function suppressWithReason() {
  fireEvent.click(await screen.findByRole("button", { name: "Suppress" }));
  fireEvent.change(screen.getByPlaceholderText(/Reason/), { target: { value: "false positive" } });
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
}

test("a failed suppress shows why instead of doing nothing", async () => {
  server.use(
    meHandler("admin"),
    http.post("/api/findings/f1/suppress", () => HttpResponse.json({ detail: "forbidden" }, { status: 403 })),
  );

  renderWithClient(<SuppressControl finding={finding} />);
  await suppressWithReason();

  expect(await screen.findByRole("alert")).toHaveTextContent(/don't have permission/);
  // Still armed so the user can retry.
  expect(screen.getByPlaceholderText(/Reason/)).toHaveValue("false positive");
});

test("a successful suppress closes the form and refetches the single finding", async () => {
  server.use(
    meHandler("admin"),
    http.post("/api/findings/f1/suppress", () => HttpResponse.json({}, { status: 201 })),
  );
  const client = testClient();
  const invalidate = vi.spyOn(client, "invalidateQueries");

  renderWithClient(<SuppressControl finding={finding} />, client);
  await suppressWithReason();

  await waitFor(() => expect(screen.queryByPlaceholderText(/Reason/)).not.toBeInTheDocument());
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["finding"] });
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["findings"] });
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["finding-summary"] });
});

test("the suppress toggle reflects the detail's real suppression standing", async () => {
  server.use(meHandler("admin"));
  const { unmount } = renderWithClient(
    <SuppressControl
      finding={{ id: "f1", is_suppressed: true, suppression_known: true, suppression_expires_at: "2026-12-01T00:00:00Z" }}
    />,
  );
  expect(await screen.findByRole("button", { name: /Unsuppress/ })).toBeInTheDocument();
  expect(screen.getByText(/suppressed until/)).toBeInTheDocument();
  unmount();

  // Unreadable standing: no toggle built on a guess.
  renderWithClient(<SuppressControl finding={{ id: "f1", is_suppressed: false, suppression_known: false }} />);
  expect(await screen.findByText("suppression status unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Suppress/ })).not.toBeInTheDocument();
});

test("a failed bulk suppress keeps the selection and shows the error (no unhandled rejection)", async () => {
  server.use(
    meHandler("admin"),
    http.get("/api/findings/clusters", () => HttpResponse.json({ items: [] })),
    http.get("/api/findings/summary", () => HttpResponse.json({ total: 0, by_severity: {}, by_band: {} })),
    http.get("/api/findings", () => HttpResponse.json({ items: [finding], next_cursor: "" })),
    http.post("/api/suppressions/bulk", () => HttpResponse.json({ detail: "bulk exploded" }, { status: 500 })),
  );

  renderApp("/investigate/findings");
  fireEvent.click(await screen.findByRole("tab", { name: "All" }));
  fireEvent.click(await screen.findByRole("button", { name: "All instances" }));
  fireEvent.click(await screen.findByLabelText("select EC2 instance has a public IP"));
  fireEvent.change(screen.getByPlaceholderText(/Suppression reason/), { target: { value: "noise" } });
  fireEvent.click(screen.getByRole("button", { name: "Suppress 1" }));

  expect(await screen.findByText("bulk exploded")).toBeInTheDocument();
  expect(screen.getByText("1 selected")).toBeInTheDocument();
  expect(screen.getByPlaceholderText(/Suppression reason/)).toHaveValue("noise");
});

test("saved detections: a failed list load is an error, not 'no detections yet'", async () => {
  server.use(http.get("/api/saved-queries", () => HttpResponse.json({ detail: "db down" }, { status: 500 })));

  renderWithClient(<SavedDetections onClose={() => {}} onLoad={() => {}} />);

  expect(await screen.findByText("db down")).toBeInTheDocument();
  expect(screen.queryByText(/No saved detections yet/)).not.toBeInTheDocument();
});

test("saved detections: a failed run is reported", async () => {
  server.use(
    http.get("/api/saved-queries", () =>
      HttpResponse.json({
        queries: [
          {
            id: "q1",
            name: "Public buckets",
            description: "",
            cypher: "MATCH (n) RETURN n",
            schedule: "",
            alert_channel_ids: [],
            alert_on_change: false,
            enabled: true,
            last_result_count: 0,
          },
        ],
      }),
    ),
    http.post("/api/saved-queries/q1/run", () => HttpResponse.json({ detail: "cypher timeout" }, { status: 504 })),
  );

  renderWithClient(<SavedDetections onClose={() => {}} onLoad={() => {}} />);
  fireEvent.click(await screen.findByTitle("Run now"));

  expect(await screen.findByRole("alert")).toHaveTextContent("Run failed: cypher timeout");
});

test("saved detections: a stored invalid schedule is shown, not silently idle", async () => {
  server.use(
    http.get("/api/saved-queries", () =>
      HttpResponse.json({
        queries: [
          {
            id: "q1",
            name: "Public buckets",
            description: "",
            cypher: "MATCH (n) RETURN n",
            schedule: "0 2 * *",
            schedule_error: "savedquery: invalid schedule: want 5 fields",
            alert_channel_ids: [],
            alert_on_change: false,
            alert_severity: "high",
            enabled: true,
            last_result_count: 0,
          },
        ],
      }),
    ),
  );

  renderWithClient(<SavedDetections onClose={() => {}} onLoad={() => {}} />);

  expect(await screen.findByText(/Schedule is invalid and never runs/)).toBeInTheDocument();
});

test("copyText never throws or rejects", async () => {
  Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
  await expect(copyText("x")).resolves.toBe(false);

  Object.defineProperty(navigator, "clipboard", {
    value: { writeText: () => Promise.reject(new Error("denied")) },
    configurable: true,
  });
  await expect(copyText("x")).resolves.toBe(false);

  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
  await expect(copyText("x")).resolves.toBe(true);
  expect(writeText).toHaveBeenCalledWith("x");
});
