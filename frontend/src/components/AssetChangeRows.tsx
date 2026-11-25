import type { AssetChange } from "../lib/queries";
import { timeAgo as timeAgoBase } from "../lib/format";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

// Row rendering shared by AssetDetail.tsx's full-page "Change history" section
// and AssetDetailPanel.tsx's "Change history" disclosure — same per-field drift
// rows, each caller owns its own heading/collapse chrome.
export function AssetChangeRows({ changes }: { changes: AssetChange[] }) {
  return (
    <div className="space-y-px">
      {changes.map((c, i) => (
        <div key={i} className="flex items-center gap-3 rounded border border-border-subtle/50 bg-surface px-3 py-2">
          <span className="shrink-0 rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[11px] text-text-2">
            {c.field}
          </span>
          <div className="flex min-w-0 flex-1 items-center gap-2 text-[11px]">
            <span className="truncate text-text-3 line-through">{c.old_value || "∅"}</span>
            <span className="shrink-0 text-text-3">→</span>
            <span className="truncate text-text">{c.new_value || "∅"}</span>
          </div>
          <span className="shrink-0 text-[11px] text-text-3">{timeAgo(c.changed_at)}</span>
        </div>
      ))}
    </div>
  );
}
