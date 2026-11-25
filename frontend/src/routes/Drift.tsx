import React, { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useDriftEvents, type DriftEvent } from "../lib/queries";
import { Empty, ErrorNote, Loading, PageHeader } from "../components/ui";
import { scoreTone } from "../lib/format";
import { AssetDetailPanel } from "../components/AssetDetailPanel";
import { DriftAnalysisPanel } from "../components/DriftAnalysisPanel";

// /api/drift/events is limit-capped server-side (default 200, max 500 —
// internal/app/asset/drift.go). When the response is exactly the requested
// page size, "N total changes" would misreport a clamp as a total.
const DRIFT_EVENTS_LIMIT = 200;

// ── Drift ─────────────────────────────────────────────────────────────────────
// Inventory drift is its own domain (what CHANGED in the estate), not a risk
// view, so it is a page of its own rather than a Findings tab behind a filter
// bar that does not apply to it.

// Real kinds are new_asset|new_exposure|removed_exposure|changed
// (internal/app/asset/drift.go:20-23).
const KIND_CONFIG: Record<string, { label: string; color: string; bg: string; icon: string }> = {
  new_asset:        { label: "First seen",     color: "text-teal",       bg: "bg-teal/10",       icon: "+" },
  new_exposure:     { label: "Now exposed",    color: "text-red",        bg: "bg-red/10",        icon: "⚠" },
  removed_exposure: { label: "No longer exposed", color: "text-emerald", bg: "bg-emerald/10", icon: "✓" },
  changed:          { label: "Changed",        color: "text-amber",      bg: "bg-amber/10",      icon: "~" },
};

function fieldLabel(f: string): string {
  const labels: Record<string, string> = {
    public_ip:  "\u{1F310} Public IP",
    private_ip: "Private IP",
    name:       "✏ Name",
    state:      "⚡ State",
    type:       "Type",
    region:     "Region",
  };
  return labels[f] ?? f;
}

const SINCE_OPTIONS = [
  { value: "1h",   label: "1h" },
  { value: "6h",   label: "6h" },
  { value: "24h",  label: "24h" },
  { value: "72h",  label: "3d" },
  { value: "168h", label: "7d" },
];

function providerColor(p: string): string {
  if (p === "aws") return "bg-orange/10 text-orange";
  if (p === "gcp") return "bg-sky/10 text-sky";
  if (p === "azure") return "bg-sky/10 text-sky";
  // github has no dedicated hue token (assetMeta.tsx treats it the same way —
  // a neutral icon, not a colored one); fall through to the neutral default.
  if (p === "kubernetes") return "bg-teal/10 text-teal";
  return "bg-surface-3 text-text-3";
}

type DriftKindFilter = "all" | "new_asset" | "changed" | "new_exposure" | "removed_exposure";

export function Drift() {
  const [since, setSince] = useState("24h");
  const [kindFilter, setKindFilter] = useState<DriftKindFilter>("all");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const navigate = useNavigate();
  const { data, isLoading, isError } = useDriftEvents(since);
  const events: DriftEvent[] = data?.events ?? [];

  const newCount     = events.filter(e => e.kind === "new_asset").length;
  const changedCount = events.filter(e => e.kind === "changed").length;
  const exposedCount = events.filter(e => e.kind === "new_exposure").length;
  const removedCount = events.filter(e => e.kind === "removed_exposure").length;

  const visibleEvents = kindFilter === "all" ? events : events.filter(e => e.kind === kindFilter);

  // House convention (see Assets.tsx): open the asset detail slide-over rather
  // than a full-page navigation, so drilling into a drift event doesn't leave
  // the drift feed.
  function goToAsset(ev: DriftEvent, e: React.MouseEvent) {
    e.preventDefault();
    setSelectedAssetId(ev.asset_id);
  }

  function goToFindings(ev: DriftEvent, e: React.MouseEvent) {
    e.stopPropagation();
    e.preventDefault();
    void navigate({ to: "/investigate/findings", search: { q: ev.asset_id } as Record<string, string> });
  }

  const KIND_FILTERS: { value: DriftKindFilter; label: string }[] = [
    { value: "all",              label: "All" },
    { value: "new_asset",        label: "+ New" },
    { value: "changed",          label: "~ Changed" },
    { value: "new_exposure",     label: "⚠ Exposed" },
    { value: "removed_exposure", label: "✓ Removed" },
  ];

  return (
    <div>
      <PageHeader
        title="Drift"
        subtitle="Inventory changes since the last sync sweep — new assets, new exposures, and exposures that were removed."
      />

      <DriftAnalysisPanel since={since} onOpenAsset={setSelectedAssetId} />

      {/* Summary strip */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {SINCE_OPTIONS.map((o) => (
            <button
              key={o.value}
              onClick={() => setSince(o.value)}
              className={`rounded px-2.5 py-1 text-[11px] transition-colors ${
                since === o.value ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
        {!isLoading && !isError && events.length > 0 && (
          <div className="flex gap-3 text-[11px] text-text-3">
            {newCount > 0 && <span><span className="text-teal font-medium">+{newCount}</span> new</span>}
            {changedCount > 0 && <span><span className="text-amber font-medium">~{changedCount}</span> changed</span>}
            {exposedCount > 0 && <span><span className="text-red font-medium">⚠{exposedCount}</span> exposed</span>}
            {removedCount > 0 && <span><span className="text-emerald font-medium">✓{removedCount}</span> removed</span>}
            <span className="text-text-3">
              {events.length >= DRIFT_EVENTS_LIMIT ? `${events.length}+ changes (capped)` : `${events.length} total changes`}
            </span>
          </div>
        )}
      </div>

      {/* Kind filter strip */}
      {!isLoading && !isError && events.length > 0 && (
        <div className="mb-3 flex gap-1">
          {KIND_FILTERS.map((kf) => (
            <button
              key={kf.value}
              onClick={() => setKindFilter(kf.value)}
              className={`rounded px-2.5 py-1 text-[11px] transition-colors ${
                kindFilter === kf.value ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"
              }`}
            >
              {kf.label}
            </button>
          ))}
        </div>
      )}

      {isLoading && <Loading />}
      {isError && <ErrorNote message="Could not load drift events." />}
      {!isLoading && !isError && events.length === 0 && (
        <Empty message="No inventory changes in this window. Connect a source and run a sync to start tracking drift." />
      )}

      <div className="space-y-2">
        {visibleEvents.map((ev, i) => {
          const cfg = KIND_CONFIG[ev.kind] ?? KIND_CONFIG.new_asset;
          const hasFindings = ev.findings_count > 0;
          return (
            <div
              key={`${ev.asset_id}-${ev.kind}-${i}`}
              className="glass rounded-xl overflow-hidden activity-shimmer-hover cursor-pointer"
              onClick={(e) => goToAsset(ev, e)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === "Enter") goToAsset(ev, e as unknown as React.MouseEvent); }}
            >
              <div className="flex items-start gap-3 px-4 py-3">
                {/* Kind badge */}
                <span className={`shrink-0 mt-0.5 rounded px-1.5 py-0.5 text-[11px] font-semibold ${cfg.color} ${cfg.bg}`}>
                  {cfg.icon} {cfg.label}
                </span>

                {/* Main content */}
                <div className="min-w-0 flex-1">
                  {/* Row 1: name + type chips */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-text text-[13px] truncate">
                      {ev.asset_name || ev.asset_id.split("/").pop() || ev.asset_id}
                    </span>
                    <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-text-3">
                      {ev.asset_type}
                    </span>
                    <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${providerColor(ev.provider)}`}>
                      {ev.provider?.toUpperCase()}
                    </span>
                    {ev.region && (
                      <span className="text-[11px] text-text-3">{ev.region}</span>
                    )}
                    {/* new_asset: public IP shown as "now exposed" */}
                    {ev.kind === "new_asset" && ev.public_ip && (
                      <span className="rounded bg-teal/10 px-1.5 py-0.5 font-mono text-[11px] text-teal">
                        now exposed: {ev.public_ip}
                      </span>
                    )}
                    {/* new_exposure: internet-reachable callout */}
                    {ev.kind === "new_exposure" && ev.public_ip && (
                      <span className="rounded bg-red/10 px-1.5 py-0.5 text-[11px] font-medium text-red">
                        ⚠ Now internet-reachable: <span className="font-mono text-teal">{ev.public_ip}</span>
                      </span>
                    )}
                    {/* other kinds: plain IP */}
                    {ev.kind !== "new_asset" && ev.kind !== "new_exposure" && ev.public_ip && (
                      <span className="font-mono text-[11px] text-teal">{ev.public_ip}</span>
                    )}
                  </div>

                  {/* Row 2: Why explanation */}
                  {ev.why && (
                    <p className="mt-1 text-[11px] text-text-3 leading-relaxed">
                      {ev.why}
                    </p>
                  )}

                  {/* Row 3: Old→New value (for changes) */}
                  {ev.field && (ev.old_value !== undefined || ev.new_value) && (
                    <div className="mt-1 flex items-center gap-1.5 text-[11px]">
                      <span className="text-text-3">{fieldLabel(ev.field)}:</span>
                      {ev.old_value && (
                        <span className="line-through text-text-3">{ev.old_value}</span>
                      )}
                      {ev.old_value && <span className="text-text-3">→</span>}
                      <span className={
                        ev.field === "public_ip"
                          ? "font-mono font-semibold text-teal"
                          : ev.field === "state" && ev.new_value === "running"
                          ? "font-semibold text-emerald"
                          : ev.field === "state" && ev.new_value !== "running"
                          ? "font-semibold text-amber"
                          : ev.kind === "new_exposure"
                          ? "font-medium text-red"
                          : "font-medium text-teal"
                      }>
                        {ev.new_value ?? "—"}
                      </span>
                    </div>
                  )}

                  {/* Row 4: ARN + account */}
                  <div className="mt-0.5 flex flex-wrap gap-x-3 text-[11px] text-text-3">
                    {ev.account_id && <span>acct: <span className="font-mono">{ev.account_id}</span></span>}
                    {ev.domain && <span className="font-mono">{ev.domain}</span>}
                    <span className="font-mono truncate max-w-xs" title={ev.asset_id}>{ev.asset_id}</span>
                  </div>
                </div>

                {/* Right: findings chip + score + time */}
                <div className="shrink-0 flex flex-col items-end gap-1">
                  {/* Findings count */}
                  {hasFindings ? (
                    <button
                      onClick={(e) => goToFindings(ev, e)}
                      className="rounded bg-red/10 px-2 py-0.5 text-[11px] font-medium text-red hover:bg-red/20 transition-colors"
                      title="View findings for this asset"
                    >
                      {ev.findings_count} finding{ev.findings_count !== 1 ? "s" : ""} →
                    </button>
                  ) : ev.findings_known ? (
                    <span className="text-[11px] text-text-3">No findings</span>
                  ) : (
                    <span className="text-[11px] text-amber" title="The findings lookup failed for this event">Findings unknown</span>
                  )}
                  {/* Score */}
                  {ev.max_score > 0 && (
                    <span className={`text-[11px] font-semibold tabular-nums ${scoreTone(ev.max_score)}`}>
                      {ev.max_score}
                    </span>
                  )}
                  {/* Time */}
                  <span className="text-[11px] text-text-3">
                    {new Date(ev.detected_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <AssetDetailPanel
        assetId={selectedAssetId}
        onClose={() => setSelectedAssetId(null)}
      />
    </div>
  );
}
