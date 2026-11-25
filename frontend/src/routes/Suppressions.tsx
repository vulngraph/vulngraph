import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useBulkUnsuppress, useIsAdmin, useReviewSuppression, useSuppressions, useUnsuppressFinding } from "../lib/queries";
import type { Suppression } from "../lib/api";
import { Empty, ErrorNote, Loading } from "../components/ui";
import { ConfirmButton } from "../components/form";
import { ExpiryLabel, ExpiryPicker } from "../components/SuppressionExpiry";
import { expiryBounds, expiryToISO } from "../lib/expiry";
import { timeAgo, shortenId } from "../lib/format";

// RenewControl re-reviews a suppression: pick a new expiry (default 90 days) and
// confirm. Renewing an expired suppression re-instates it.
function RenewControl({ suppression: s }: { suppression: Suppression }) {
  const review = useReviewSuppression();
  const [open, setOpen] = useState(false);
  const [expiry, setExpiry] = useState(() => expiryBounds().initial);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="rounded border border-border-subtle px-2 py-1 text-[11px] text-text-2 hover:bg-surface-2"
      >
        renew
      </button>
    );
  }
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-1.5">
        <ExpiryPicker value={expiry} onChange={setExpiry} />
        <button
          onClick={() =>
            review.mutate({ id: s.finding_id, expiresAt: expiryToISO(expiry) }, { onSuccess: () => setOpen(false) })
          }
          disabled={!expiry || review.isPending}
          className="rounded border border-amber/30 bg-amber/10 px-2 py-1 text-[11px] font-medium text-amber hover:bg-amber/20 disabled:opacity-40"
        >
          {review.isPending ? "Renewing…" : "Confirm renew"}
        </button>
        <button onClick={() => setOpen(false)} className="px-1 text-[11px] text-text-3 hover:text-text-2">
          cancel
        </button>
      </div>
      {review.isError && <span role="alert" className="text-[11px] text-red">{(review.error as Error).message}</span>}
    </div>
  );
}

// Rendered as the Suppressions section inside Settings.
export function SuppressionsSection() {
  const isAdmin = useIsAdmin();
  const { data, isLoading, isError, error } = useSuppressions();
  const unsuppress = useUnsuppressFinding();
  const bulkUnsuppress = useBulkUnsuppress();
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const items = data ?? [];
  const expiredCount = items.filter((s) => s.expired).length;

  const filtered = filter.trim()
    ? items.filter((s) => {
        const q = filter.trim().toLowerCase();
        return s.finding_id.toLowerCase().includes(q) || s.reason.toLowerCase().includes(q) || s.suppressed_by.toLowerCase().includes(q);
      })
    : items;

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setSelected((prev) => (prev.size === filtered.length ? new Set() : new Set(filtered.map((s) => s.finding_id))));
  }

  function runBulkUnsuppress() {
    bulkUnsuppress.mutate([...selected], { onSuccess: () => setSelected(new Set()) });
  }

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-medium text-text">
          Suppressed findings <span className="text-text-3">({items.length})</span>
        </h2>
        {expiredCount > 0 && (
          <span className="text-[11px] text-red">
            {expiredCount} expired — those findings are back in the pipeline
          </span>
        )}
      </div>

      {(unsuppress.isError || bulkUnsuppress.isError) && (
        <div className="mb-3">
          <ErrorNote message={((unsuppress.error ?? bulkUnsuppress.error) as Error)?.message ?? "Could not unsuppress this finding."} />
        </div>
      )}

      {isError && (
        <div className="mb-3">
          <ErrorNote message={(error as Error)?.message ?? "Could not load suppressions."} />
        </div>
      )}

      {isLoading && <Loading />}

      {!isLoading && !isError && items.length === 0 && (
        <Empty message="No suppressions. Suppress findings from the Findings view." />
      )}

      {!isLoading && !isError && items.length > 0 && (
        <>
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by finding, reason, or who suppressed it…"
            className="mb-3 w-full rounded border border-border-subtle bg-surface px-2.5 py-1.5 text-xs text-text placeholder:text-text-3 focus:outline-none focus:ring-1 focus:ring-teal/50"
          />
          {filtered.length === 0 ? (
            <Empty message="No suppressions match this filter." />
          ) : (
            <>
              {isAdmin && (
                <div className="mb-2 flex items-center gap-2 text-[11px]">
                  <label className="flex items-center gap-1.5 text-text-3">
                    <input
                      type="checkbox"
                      checked={selected.size > 0 && selected.size === filtered.length}
                      onChange={toggleAll}
                      aria-label="select all suppressions"
                    />
                    select all
                  </label>
                  {selected.size > 0 && (
                    <div className="ml-auto flex items-center gap-2">
                      <span className="text-text-3">{selected.size} selected</span>
                      <ConfirmButton
                        label={`unsuppress ${selected.size}`}
                        verb="unsuppress"
                        onConfirm={runBulkUnsuppress}
                        isPending={bulkUnsuppress.isPending}
                      />
                    </div>
                  )}
                </div>
              )}
              <div className="glass overflow-hidden rounded-xl">
                {filtered.map((s) => (
                  <div
                    key={s.finding_id}
                    className="flex items-start justify-between gap-3 border-b border-border-subtle/40 px-4 py-3 last:border-0"
                  >
                    <div className="flex min-w-0 flex-1 items-start gap-2">
                      {isAdmin && (
                        <input
                          type="checkbox"
                          className="mt-0.5"
                          checked={selected.has(s.finding_id)}
                          onChange={() => toggle(s.finding_id)}
                          aria-label={`select ${s.finding_id}`}
                        />
                      )}
                      <div className="min-w-0 flex-1">
                        <Link
                          to="/investigate/findings/$id"
                          params={{ id: s.finding_id }}
                          title={s.finding_id}
                          className="truncate font-mono text-xs text-text hover:text-teal hover:underline"
                        >
                          {shortenId(s.finding_id)}
                        </Link>
                        <div className="mt-0.5 text-xs leading-relaxed text-text-2">{s.reason}</div>
                        <div className="mt-1 text-[11px] text-text-3">
                          by {s.suppressed_by} &middot; {timeAgo(s.suppressed_at)} &middot;{" "}
                          <ExpiryLabel expiresAt={s.expires_at} />
                          {s.last_reviewed_at && (
                            <> &middot; reviewed by {s.reviewed_by} {timeAgo(s.last_reviewed_at)}</>
                          )}
                        </div>
                      </div>
                    </div>
                    {isAdmin && (
                      <div className="flex flex-shrink-0 items-start gap-1.5">
                        <RenewControl suppression={s} />
                        <ConfirmButton
                          label="unsuppress"
                          verb="unsuppress"
                          onConfirm={() => unsuppress.mutate(s.finding_id)}
                          isPending={unsuppress.isPending}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
