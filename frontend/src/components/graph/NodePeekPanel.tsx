import type { GraphViewNode } from "../GraphView";
import { edgeLabel, shortenLabel, typeLabel } from "./labels";
import { openAssistant } from "../../lib/assistant";
import { KevBadge } from "../ui";
import { scoreTone } from "../../lib/format";

export type PeekNeighbour = { rel: string; dir: "out" | "in"; node: GraphViewNode };

// NodePeekPanel shows a selected node's key facts inline (no navigation), with
// its provenance, neighbours-by-relationship drill-down, and Expand / Open
// actions. Pure presentation; the parent owns selection.
export function NodePeekPanel({
  node,
  degree,
  neighbours = [],
  pathHighlighted,
  expanding,
  onNeighbourClick,
  onExpand,
  onOpen,
  onQueryFromNode,
  onClose,
}: {
  node: GraphViewNode;
  degree: number;
  neighbours?: PeekNeighbour[];
  pathHighlighted: boolean;
  expanding: boolean;
  onNeighbourClick?: (id: string) => void;
  onExpand?: () => void;
  onOpen?: () => void;
  onQueryFromNode?: () => void;
  onClose: () => void;
}) {
  return (
    <div className="absolute right-2 top-2 z-10 w-64 rounded-lg border border-border-strong bg-bg/95 p-3 shadow-lg backdrop-blur-sm">
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-xs font-medium text-text" title={node.label}>{node.label}</div>
          {node.sub && <div className="text-[11px] text-text-3">{typeLabel(node.sub)}</div>}
        </div>
        <button onClick={onClose} className="shrink-0 text-[11px] text-text-3 hover:text-text-2">✕</button>
      </div>
      {/* Full ID as copyable Cypher snippet — click to copy */}
      <button
        onClick={() => navigator.clipboard?.writeText(node.id)}
        title="Click to copy ID"
        className="mt-0.5 w-full rounded border border-border-subtle/50 bg-surface px-2 py-1 text-left font-mono text-[9.5px] text-text-3 hover:border-teal/30 hover:text-text-2 transition-colors break-all">
        {node.id.slice(0, 72)}{node.id.length > 72 ? "…" : ""}
      </button>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-text-3">
        <span><span className="text-text-2 tabular-nums">{degree}</span> connections</span>
        {node.findings != null && node.findings > 0 && (
          <span><span className="text-amber tabular-nums">{node.findings}</span> findings</span>
        )}
        {node.provider && <span className="uppercase text-text-2">{node.provider}</span>}
        {node.account && <span>acct <span className="text-text-2">{node.account}</span></span>}
      </div>
      {node.risk != null && node.risk > 0 && (
        <div className={`mt-2 text-[11px] font-medium ${scoreTone(node.risk)}`}>
          Risk score: {node.risk}
        </div>
      )}
      {(node.exposed || node.hasKev || node.exploitable || node.toxicCombo) && (
        <div className="mt-2 flex flex-wrap gap-1">
          {node.toxicCombo && <SignalBadge label="toxic combo" className="border-red/40 bg-red/15 text-red" />}
          {node.exposed && <SignalBadge label="internet-exposed" className="border-orange/40 bg-orange/10 text-orange" />}
          {node.exploitable && <SignalBadge label="exploitable" className="border-red/40 bg-red/10 text-red" />}
          {node.hasKev && <KevBadge />}
        </div>
      )}
      {pathHighlighted && (
        <div className="mt-2 rounded border border-fuchsia-400/30 bg-fuchsia-400/10 px-2 py-1 text-[11px] text-fuchsia-300">
          Path to internet/admin highlighted
        </div>
      )}
      {/* Neighbours by relationship — drill into what this asset connects to. */}
      {neighbours.length > 0 && (
        <div className="mt-2 border-t border-border-subtle pt-2">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">Relationships ({neighbours.length})</div>
          <div className="max-h-40 space-y-0.5 overflow-y-auto">
            {neighbours.slice(0, 20).map((nb, i) => (
              <button key={i} onClick={() => onNeighbourClick?.(nb.node.id)}
                className="flex w-full items-center gap-1 rounded px-1 py-0.5 text-left hover:bg-surface-3">
                <span className="shrink-0 text-text-3">{nb.dir === "out" ? "→" : "←"}</span>
                <span className="shrink-0 rounded bg-surface-3 px-1 text-[11px] text-text-3">{edgeLabel(nb.rel)}</span>
                <span className="truncate text-[11px] text-text-2" title={nb.node.label}>{shortenLabel(nb.node.label)}</span>
              </button>
            ))}
            {neighbours.length > 20 && <div className="px-1 text-[11px] text-text-3">… and {neighbours.length - 20} more</div>}
          </div>
        </div>
      )}
      <div className="mt-2 space-y-1.5">
        {/* Explore from here — generates a Cypher query in the workbench */}
        {onQueryFromNode && (
          <button onClick={onQueryFromNode}
            className="w-full rounded border border-teal/40 bg-teal/10 py-1.5 text-[11px] font-medium text-teal hover:bg-teal/20 transition-colors">
            ⤳ Explore from here
          </button>
        )}
        {/* Ask AI — opens ChatPanel with this node's signals prefilled */}
        <button
          onClick={() => {
            const facts = [`Type: ${node.sub ?? "unknown"}`];
            if (node.risk != null && node.risk > 0) facts.push(`Risk score: ${node.risk}`);
            if (node.exposed) facts.push("internet-exposed");
            if (node.hasKev) facts.push("KEV vulnerability");
            if (node.exploitable) facts.push("exploitable");
            if (node.toxicCombo) facts.push("toxic combo");
            if (node.findings != null && node.findings > 0) facts.push(`${node.findings} active finding${node.findings !== 1 ? "s" : ""}`);
            if (node.provider) facts.push(`provider: ${node.provider}`);
            openAssistant({
              subject: `Asset: ${node.label}`,
              facts,
              question: "What is the risk and what attack paths lead from or to this asset?",
            });
          }}
          className="w-full rounded border border-violet-400/30 bg-violet-400/10 py-1.5 text-[11px] font-medium text-violet-400 hover:bg-violet-400/20 transition-colors"
        >
          ✦ Ask AI about this node
        </button>
        <div className="flex gap-1.5">
          {onExpand && (
            <button onClick={onExpand} disabled={expanding}
              className="flex-1 rounded border border-sky/30 bg-sky/10 py-1 text-[11px] text-sky hover:bg-sky/20 disabled:opacity-50">
              {expanding ? "Expanding…" : "⊕ Expand"}
            </button>
          )}
          {onOpen && (
            <button onClick={onOpen}
              className="flex-1 rounded border border-border-subtle py-1 text-[11px] text-text-3 hover:border-teal/30 hover:text-text-2 transition-colors">
              Open asset →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// SignalBadge is a small pill for a projected security signal.
function SignalBadge({ label, className }: { label: string; className: string }) {
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ${className}`}>
      {label}
    </span>
  );
}
