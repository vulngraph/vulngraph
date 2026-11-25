import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  useCancelScan,
  useAssetSummary,
  useIsAdmin,
  useScans,
  useTriggerScan,
} from "../lib/queries";
import { Button, ErrorNote, Loading, PageHeader } from "../components/ui";
import { WorkflowBuilder } from "../components/WorkflowBuilder";
import { timeAgo as timeAgoBase, elapsed, elapsedRunning } from "../lib/format";

// ── helpers ──────────────────────────────────────────────────────────────────

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

// ── sub-components ────────────────────────────────────────────────────────────

// stallAfterMs mirrors the backend reaper window (scan job timeout 4h + margin):
// a run still "running" past this has almost certainly lost its worker and will
// be failed by the reaper on its next tick. Surface it as stalled immediately so
// the operator isn't misled by a healthy-looking pulse.
const stallAfterMs = 5 * 60 * 60 * 1000;

function isStalled(status: string, startedAt?: string): boolean {
  return status === "running" && !!startedAt && Date.now() - new Date(startedAt).getTime() > stallAfterMs;
}

function StatusBadge({ status, startedAt }: { status: string; startedAt?: string }) {
  if (isStalled(status, startedAt)) return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] text-amber"
      title="Running far longer than a scan should — the worker likely died; the reaper will fail this run shortly."
    >
      <span className="h-1.5 w-1.5 rounded-full bg-amber" />
      stalled?
    </span>
  );
  if (status === "running") return (
    <span className="inline-flex items-center gap-1.5 text-[11px] text-teal">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-teal" />
      running
    </span>
  );
  if (status === "completed") return (
    <span className="text-[11px] text-emerald">completed</span>
  );
  if (status === "failed") return (
    <span className="text-[11px] text-red">failed</span>
  );
  return <span className="text-[11px] text-text-3">{status}</span>;
}

// ── Scans page ────────────────────────────────────────────────────────────────

export function Scans() {
  const { data, isLoading, isError, error } = useScans();
  const isAdmin = useIsAdmin();
  const cancel = useCancelScan();
  const triggerScan = useTriggerScan();
  const summary = useAssetSummary();
  const [modalOpen, setModalOpen] = useState(false);
  // Cancelled runs stay visible by default: marking a run cancelled does not stop
  // its scan, so hiding it would hide a scan that may still be probing.
  const [hideCancelled, setHideCancelled] = useState(false);

  const scannableTypes = ["ec2_instance", "gce_instance", "load_balancer", "gcs_bucket", "s3_bucket"];
  const scannableCount = summary.data
    ? scannableTypes.reduce((n, t) => n + (summary.data?.by_type[t] ?? 0), 0)
    : null;

  const navigate = useNavigate();
  const scans = Array.isArray(data) ? data : [];
  const running = scans.filter((s) => s.status === "running");
  const done = scans
    .filter((s) => s.status !== "running")
    .filter((s) => !hideCancelled || s.status !== "cancelled");

  // Most recent completed scan for freshness banner
  const lastCompleted = done.find((s) => s.status === "completed");

  return (
    <div>
      <div className="flex items-start justify-between">
        <PageHeader
          title="Scans"
          subtitle={
            scannableCount != null
              ? `Active nuclei scan — ${scannableCount} internet-facing assets scannable.`
              : "Active nuclei scan runs over internet-facing assets."
          }
        />
        {isAdmin && (
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              onClick={() => triggerScan.mutate()}
              disabled={triggerScan.isPending}
              title="Run an ad-hoc scan now over all internet-facing assets, using the default templates"
            >
              {triggerScan.isPending ? "Starting…" : "Scan now"}
            </Button>
            <Button variant="primary" onClick={() => setModalOpen(true)}>
              Create scan
            </Button>
          </div>
        )}
      </div>

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}
      {triggerScan.isError && (
        <ErrorNote message={(triggerScan.error as Error).message ?? "Could not start scan."} />
      )}
      {cancel.isError && <ErrorNote message={`Could not cancel the scan: ${(cancel.error as Error).message}`} />}

      {/* Freshness banner — last completed scan */}
      {lastCompleted && running.length === 0 && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-border-subtle bg-surface px-4 py-2 text-[11px] text-text-3">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald" />
          Last scan completed{" "}
          <span
            className="text-text-2"
            title={new Date(lastCompleted.finished_at ?? lastCompleted.started_at).toISOString()}
          >
            {timeAgo(lastCompleted.finished_at ?? lastCompleted.started_at)}
          </span>
          {lastCompleted.finding_count > 0 ? (
            <>
              {" "}·{" "}
              <Link to="/investigate/findings" className="text-amber hover:underline">
                {lastCompleted.finding_count} finding{lastCompleted.finding_count !== 1 ? "s" : ""}
              </Link>
            </>
          ) : (
            <> · no findings</>
          )}
        </div>
      )}

      {/* Running scans — surface prominently */}
      {running.length > 0 && (
        <div className="mb-4 space-y-2">
          <div className="text-[11px] text-text-3">Active scans</div>
          {running.map((s) => (
            <div
              key={s.id}
              className={`glass flex flex-wrap items-center gap-3 rounded-lg border-l-2 px-4 py-3 ${
                isStalled(s.status, s.started_at) ? "border-l-amber" : "border-l-teal"
              }`}
            >
              <StatusBadge status={s.status} startedAt={s.started_at} />
              <Link
                to="/scans/$id"
                params={{ id: s.id }}
                className="text-sm font-medium text-text hover:text-teal"
              >
                Scan #{s.id.slice(-6)}
              </Link>
              <span className="text-[11px] text-text-3">
                {s.target_count} targets · {elapsedRunning(s.started_at)}
              </span>
              {s.finding_count > 0 && (
                <Link
                  to="/investigate/findings"
                  className="rounded border border-amber/30 bg-amber/10 px-2 py-0.5 text-[11px] text-amber tabular-nums hover:bg-amber/20"
                >
                  {s.finding_count} finding{s.finding_count !== 1 ? "s" : ""} so far →
                </Link>
              )}
              <span className="ml-auto text-[11px] text-text-3" title={new Date(s.started_at).toISOString()}>
                started {timeAgo(s.started_at)}
              </span>
              {isAdmin && (
                <Button
                  variant="danger"
                  onClick={() => cancel.mutate(s.id)}
                  disabled={cancel.isPending}
                  title="Marks the run cancelled. It does not stop the scan: a run already probing keeps going, and a queued run still executes when its job is picked up."
                >
                  Mark cancelled
                </Button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Completed scan history */}
      {done.length > 0 && (
        <div className="glass overflow-hidden rounded-lg">
          <div className="flex items-center justify-end border-b border-border-subtle px-3 py-1.5">
            <button
              onClick={() => setHideCancelled((v) => !v)}
              className={`rounded border px-2 py-1 text-[11px] transition-colors ${
                hideCancelled
                  ? "border-teal/40 bg-teal/10 text-teal"
                  : "border-border-subtle text-text-3"
              }`}
            >
              {hideCancelled ? "Hide cancelled" : "Show all"}
            </button>
          </div>
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border-subtle text-left text-[11px] uppercase tracking-wide text-text-3">
                <th className="px-3 py-2 font-medium">Scan</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Templates</th>
                <th className="px-3 py-2 font-medium">Targets</th>
                <th className="px-3 py-2 font-medium">Findings</th>
                <th className="px-3 py-2 font-medium">Duration</th>
                <th className="px-3 py-2 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {done.map((s) => (
                <tr
                  key={s.id}
                  className="card-hover cursor-pointer border-b border-border-subtle/40 last:border-0"
                  onClick={() => navigate({ to: "/scans/$id", params: { id: s.id } })}
                >
                  <td className="px-3 py-2">
                    <Link
                      to="/scans/$id"
                      params={{ id: s.id }}
                      className="font-mono text-[11px] text-teal hover:underline"
                    >
                      #{s.id.slice(-6)}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Link to="/scans/$id" params={{ id: s.id }}>
                      {s.status === "failed" && s.error ? (
                        <span className="text-[11px] text-red" title={s.error}>
                          failed
                        </span>
                      ) : (
                        <StatusBadge status={s.status} startedAt={s.started_at} />
                      )}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Link to="/scans/$id" params={{ id: s.id }}>
                      <div className="flex flex-wrap gap-1">
                        {(s.template_tags ?? []).slice(0, 3).map((t) => (
                          <span
                            key={t}
                            className="rounded border border-border-subtle bg-surface-2 px-1.5 py-0.5 text-[11px] text-text-3"
                          >
                            {t}
                          </span>
                        ))}
                        {(s.template_tags ?? []).length > 3 && (
                          <span className="text-[11px] text-text-3">
                            +{(s.template_tags ?? []).length - 3}
                          </span>
                        )}
                      </div>
                    </Link>
                  </td>
                  <td className="px-3 py-2 tabular-nums text-text-2">
                    <Link to="/scans/$id" params={{ id: s.id }} className="hover:text-teal">
                      {s.target_count}
                    </Link>
                  </td>
                  <td className="px-3 py-2 tabular-nums">
                    {s.finding_count > 0 ? (
                      <Link
                        to="/scans/$id"
                        params={{ id: s.id }}
                        className="text-[11px] text-amber hover:underline"
                      >
                        {s.finding_count} finding{s.finding_count !== 1 ? "s" : ""}
                      </Link>
                    ) : (
                      <span className="text-[11px] text-text-3">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 tabular-nums text-[11px] text-text-3">
                    <Link to="/scans/$id" params={{ id: s.id }} className="hover:text-text-2">
                      {s.finished_at ? elapsed(s.started_at, s.finished_at) : "—"}
                    </Link>
                  </td>
                  <td
                    className="px-3 py-2 text-[11px] text-text-3"
                    title={new Date(s.started_at).toISOString()}
                  >
                    <Link to="/scans/$id" params={{ id: s.id }} className="hover:text-text-2">
                      {timeAgo(s.started_at)}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {scans.length === 0 && !isLoading && (
        <div className="rounded-lg border border-border-subtle bg-surface p-5">
          <div className="mb-2 text-sm text-text">No scan runs yet.</div>
          {isAdmin ? (
            <div className="space-y-2 text-[11px] text-text-2">
              <p>
                <strong className="text-text">One-off scan:</strong> Click &quot;Create scan&quot; above to probe internet-facing assets immediately.
              </p>
              <p>
                <strong className="text-text">Automatic scanning:</strong> Set{" "}
                <code className="rounded bg-surface-3 px-1 py-0.5 font-mono text-teal">SCAN_INTERVAL</code>{" "}
                on the worker (e.g. <code className="rounded bg-surface-3 px-1 py-0.5 font-mono text-teal">SCAN_INTERVAL=6h</code>),
                or create a{" "}
                <Link to="/scans/profiles" className="text-teal hover:underline">
                  Workflow
                </Link>{" "}
                to configure a recurring schedule.
              </p>
            </div>
          ) : (
            <p className="text-[11px] text-text-3">Ask an admin to trigger a scan.</p>
          )}
        </div>
      )}

      {/* Create scan — the one-and-only scan-creation form, in run-once mode. */}
      {modalOpen && (
        <WorkflowBuilder
          mode="runOnce"
          onClose={() => setModalOpen(false)}
        />
      )}
    </div>
  );
}
