import { Clock, Play, Trash2, Bell, X } from "lucide-react";
import {
  useSavedQueries,
  useDeleteSavedQuery,
  useRunSavedQuery,
  type SavedQuery,
} from "../lib/queries";
import { Loading, Empty, ErrorNote } from "./ui";
import { errorMessage } from "../lib/api";

// Cron presets matching WorkflowBuilder's scan schedules, for consistency.
// Exported so the unified Save dialog offers the same set (one vocabulary).
export const SCHEDULES: { label: string; cron: string }[] = [
  { label: "Manual", cron: "" },
  { label: "Hourly", cron: "0 * * * *" },
  { label: "Daily", cron: "0 2 * * *" },
  { label: "Weekly", cron: "0 2 * * 1" },
];

function scheduleLabel(cron: string): string {
  return SCHEDULES.find((s) => s.cron === cron)?.label ?? cron;
}

// baselineLabel describes the change-detection baseline, which only a good
// scheduled run moves — so it is not "the last run".
export function baselineLabel(q: SavedQuery): string {
  if (q.last_run_at) {
    return `Baseline: ${q.last_result_count} results as of ${new Date(q.last_run_at).toLocaleString()}`;
  }
  return q.schedule ? "No baseline yet: no scheduled run has completed" : "Manual only: no change-detection baseline";
}

// LastAttempt shows the newest run whatever its outcome; a failed, truncated
// or possibly incomplete one is the detection's real health, so it is red.
function LastAttempt({ q }: { q: SavedQuery }) {
  if (!q.last_attempt_at) {
    return <div className="mt-0.5 text-[11px] text-text-3">Never run</div>;
  }
  const when = new Date(q.last_attempt_at).toLocaleString();
  const how = q.last_attempt_trigger === "manual" ? "manual" : "scheduled";
  if (q.last_attempt_status === "ok") {
    return (
      <div className="mt-0.5 text-[11px] text-text-3">
        Last run {when} ({how}): ok
      </div>
    );
  }
  const what =
    q.last_attempt_status === "truncated"
      ? "truncated, result incomplete"
      : q.last_attempt_status === "incomplete"
        ? "may be incomplete"
        : "failed";
  return (
    <div role="status" className="mt-0.5 text-[11px] font-medium text-red" title={q.last_attempt_error}>
      Last run {when} ({how}) {what}
      {q.last_attempt_error ? `: ${q.last_attempt_error}` : ""}
    </div>
  );
}

// SavedDetections is the detection-as-code management panel: it lists the
// server-persisted detections, runs them on demand, and deletes them. Creating
// one lives in the single Save dialog (SaveQueryDialog, "Monitor on a schedule")
// so the Graph toolbar has one save action, not two.
export function SavedDetections({
  onClose,
  onLoad,
}: {
  onClose: () => void;
  onLoad: (cypher: string) => void;
}) {
  const { data, isLoading, isError, error } = useSavedQueries();
  const del = useDeleteSavedQuery();
  const run = useRunSavedQuery();

  const queries = data?.queries ?? [];

  return (
    <div className="rounded-xl border border-border-subtle bg-surface p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="font-display text-sm font-semibold text-text">Saved detections</h3>
          <p className="text-[11px] text-text-3">
            Server-side, scheduled, alerting. Create one from Save → “Monitor on a schedule”.
          </p>
        </div>
        <button onClick={onClose} className="text-text-3 hover:text-text" aria-label="Close">
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* List */}
      {isLoading && <Loading />}
      {isError && <ErrorNote message={errorMessage(error)} />}
      {(run.isError || del.isError || run.data?.error) && (
        <p role="alert" className="mb-2 text-[11px] text-red">
          {run.isError
            ? `Run failed: ${errorMessage(run.error)}`
            : del.isError
              ? `Delete failed: ${errorMessage(del.error)}`
              : `Run failed: ${run.data?.error}`}
        </p>
      )}
      {!isLoading && !isError && queries.length === 0 && (
        <Empty message="No saved detections yet. Run a Cypher query, then Save it with “Monitor on a schedule” on to watch it continuously." />
      )}
      {queries.length > 0 && (
        <div className="divide-y divide-border-subtle/50">
          {queries.map((q) => (
            <div key={q.id} className="flex items-center gap-3 py-2.5">
              <button
                onClick={() => onLoad(q.cypher)}
                className="min-w-0 flex-1 text-left"
                title="Load into editor"
              >
                <div className="flex items-center gap-2">
                  <span className="truncate text-[13px] font-medium text-text">{q.name}</span>
                  {q.schedule && (
                    <span className="flex items-center gap-1 rounded border border-border-subtle px-1 py-0.5 text-[11px] text-text-3">
                      <Clock className="h-2.5 w-2.5" />
                      {scheduleLabel(q.schedule)}
                    </span>
                  )}
                  {q.alert_on_change && <Bell className="h-3 w-3 text-amber" />}
                </div>
                {q.schedule_error && (
                  <div className="mt-0.5 text-[11px] text-red" title={q.schedule_error}>
                    Schedule is invalid and never runs: {q.schedule_error}
                  </div>
                )}
                <LastAttempt q={q} />
                <div className="mt-0.5 text-[11px] text-text-3">{baselineLabel(q)}</div>
              </button>
              <button
                onClick={() => run.mutate(q.id)}
                disabled={run.isPending}
                title="Run now"
                className="flex h-7 w-7 items-center justify-center rounded border border-border-subtle text-text-3 hover:bg-surface hover:text-teal"
              >
                <Play className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={() => del.mutate(q.id)}
                disabled={del.isPending}
                title="Delete"
                className="flex h-7 w-7 items-center justify-center rounded border border-border-subtle text-text-3 hover:bg-surface hover:text-red"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
