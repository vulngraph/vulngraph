import { useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import type { Finding } from "../lib/api";
import { useBulkSuppress, useIsAdmin, type useFindings } from "../lib/queries";
import { useInfiniteSentinel } from "../lib/useInfiniteSentinel";
import { ErrorNote, KevBadge, Loading, ScoreBadge } from "./ui";
import { BulkSuppressBar, type BulkAccent } from "./BulkSuppressBar";
import { FindingDetailPanel } from "./FindingDetailPanel";
import { MustFixBadge } from "./MustFixBadge";
import { shortenId } from "../lib/format";

// FindingWorklist is the shared machinery behind the opinionated worklists
// ("Must fix" and "Start here"): selection state, infinite scroll, bulk
// suppression with a required reason, and the 5-column evidence table. The two
// views were ~85% identical line-for-line; everything that actually differed
// between them — the banner, the query, the "why" column, the empty state and
// the footer count — is a prop, so a fix to the machinery lands in both.
export type FindingsQuery = ReturnType<typeof useFindings>;

export interface FindingWorklistProps {
  // Coloured context banner above the list. Rendered unconditionally.
  banner: ReactNode;
  // The already-invoked useFindings result. The caller owns the filter so it can
  // also read the query state (e.g. for a probe-informed empty state).
  query: FindingsQuery;
  // Free-text search over title/check_id/resource_id, applied client-side over
  // the fetched page — same pattern as ClusterView/InstanceView on the All tab.
  search?: string;
  // Accent for the bulk-suppress toolbar.
  accent: BulkAccent;
  // Header text and per-row renderer for the evidence ("why") column.
  whyHeader: ReactNode;
  whyColumn: (f: Finding) => ReactNode;
  // Shown when the list is empty and neither loading nor errored. The caller
  // computes it, so a view with an extra probe (must-fix's "has enrichment run?")
  // can explain WHY the list is empty.
  emptyState: ReactNode;
  // Footer line once every page is loaded, e.g. "12 must-fix findings".
  footer: (count: number) => ReactNode;
}

export function FindingWorklist({
  banner, query, search = "", accent, whyHeader, whyColumn, emptyState, footer,
}: FindingWorklistProps) {
  const isAdmin = useIsAdmin();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState("");
  // Row click opens the finding in a slide-over so triage never leaves the
  // worklist; the explicit "Open ↗" link is the escape hatch to the full page.
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const bulk = useBulkSuppress();

  const { data, isLoading, isError, error, hasNextPage, isFetchingNextPage } = query;
  useInfiniteSentinel(sentinelRef, query);

  const sq = search.trim().toLowerCase();
  const items = useMemo(
    () =>
      (data?.pages.flatMap((p) => p.items) ?? [])
        .filter((f) => !f.is_suppressed)
        .filter(
          (f) =>
            !sq ||
            f.title.toLowerCase().includes(sq) ||
            (f.check_id ?? "").toLowerCase().includes(sq) ||
            (f.resource_id ?? "").toLowerCase().includes(sq),
        ),
    [data, sq],
  );
  const allSelected = items.length > 0 && items.every((f) => selected.has(f.id));

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }
  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(items.map((f) => f.id)));
  }
  // mutate (not mutateAsync): a failed bulk call surfaces via bulk.error in
  // the bar instead of an unhandled promise rejection, and keeps the selection.
  function suppressSelected(expiresAt: string) {
    const r = reason.trim();
    if (!r || selected.size === 0 || bulk.isPending) return;
    bulk.mutate(
      { ids: [...selected], reason: r, expiresAt },
      { onSuccess: () => { setSelected(new Set()); setReason(""); } },
    );
  }

  return (
    <>
      {banner}

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}
      {!isLoading && !isError && items.length === 0 && emptyState}

      {items.length > 0 && (
        <>
          {/* Sticky bulk-action toolbar — appears once a selection exists (admin only). */}
          {isAdmin && selected.size > 0 && (
            <BulkSuppressBar
              accent={accent}
              count={selected.size}
              reason={reason}
              onReasonChange={setReason}
              onSuppress={suppressSelected}
              onClear={() => setSelected(new Set())}
              isPending={bulk.isPending}
              errorMessage={bulk.isError ? (bulk.error as Error).message : undefined}
            />
          )}

          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border-subtle text-left text-[11px] uppercase text-text-3">
                {isAdmin && (
                  <th className="w-8 py-2">
                    <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="select all" />
                  </th>
                )}
                <th className="py-2 font-medium">Score</th>
                <th className="py-2 font-medium">Issue</th>
                <th className="py-2 font-medium">{whyHeader}</th>
                <th className="py-2 font-medium">Resource</th>
              </tr>
            </thead>
            <tbody>
              {items.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFindingId(f.id)}
                  className="group cursor-pointer border-b border-border-subtle/50 align-top hover:bg-surface-2/40"
                >
                  {isAdmin && (
                    <td className="py-2" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggle(f.id)} aria-label={`select ${f.title}`} />
                    </td>
                  )}
                  <td className="py-2"><ScoreBadge score={f.score} band={f.score_band} /></td>
                  <td className="py-2">
                    <span className="text-text transition-colors group-hover:text-teal">{f.title}</span>
                    <div className="mt-0.5 flex items-center gap-2 text-[11px] text-text-3">
                      {f.known_exploited && <KevBadge />}
                      <MustFixBadge cls={f.must_fix_class} state={f.enrichment_state} />
                      {f.check_id && <span className="font-mono">{f.check_id}</span>}
                      {/* Explicit full-page escape hatch — the row itself opens the panel. */}
                      <Link
                        to="/investigate/findings/$id"
                        params={{ id: f.id }}
                        onClick={(e) => e.stopPropagation()}
                        title="Open the full finding page"
                        className="text-[11px] text-text-3 hover:text-teal"
                      >
                        Open ↗
                      </Link>
                    </div>
                  </td>
                  <td className="py-2">{whyColumn(f)}</td>
                  <td className="max-w-[14rem] truncate py-2 font-mono text-[11px] text-text-2" title={f.resource_id}>{shortenId(f.resource_id)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div ref={sentinelRef} className="h-px" />
          {isFetchingNextPage && <div className="mt-3 text-center text-[11px] text-text-3">Loading…</div>}
          {!hasNextPage && (
            <div className="mt-3 flex items-center justify-center gap-1 text-[11px] text-text-3">
              {footer(items.length)}
            </div>
          )}
        </>
      )}

      <FindingDetailPanel findingId={selectedFindingId} onClose={() => setSelectedFindingId(null)} />
    </>
  );
}
