import { pathSummary, type AttackPath } from "./attackPaths";
import { edgeLabel, shortenLabel, typeLabel } from "./labels";

// AttackPathPanel lists candidate internet→admin chains and walks one hop-by-hop.
// Pure presentation — the parent owns selection/step state and the fly-to.
export function AttackPathPanel({
  paths,
  activePath,
  stepIdx,
  eliminated = 0,
  baselineCount = 0,
  onSelect,
  onClear,
  onStep,
  onBreak,
  onRestore,
  onClose,
}: {
  paths: AttackPath[];
  activePath: AttackPath | null;
  stepIdx: number;
  eliminated?: number;
  baselineCount?: number;
  onSelect: (p: AttackPath) => void;
  onClear: () => void;
  onStep: (idx: number) => void;
  onBreak?: (id: string) => void;
  onRestore?: () => void;
  onClose: () => void;
}) {
  return (
    <div className="absolute left-2 top-2 z-10 flex max-h-[calc(100%-1rem)] w-72 flex-col rounded-lg border border-fuchsia-400/30 bg-bg/95 shadow-lg backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-border-subtle px-3 py-2">
        <span className="text-[11px] font-semibold text-fuchsia-300">⚡ Attack paths</span>
        <button onClick={onClose} className="text-[11px] text-text-3 hover:text-text-2">✕</button>
      </div>
      {/* Break-the-chain result — how many paths the hidden node(s) eliminated. */}
      {eliminated > 0 && (
        <div className="flex items-center justify-between gap-2 border-b border-emerald-400/20 bg-emerald-400/10 px-3 py-1.5 text-[11px] text-emerald-300">
          <span>✂ Eliminated {eliminated} of {baselineCount} path{baselineCount !== 1 ? "s" : ""}</span>
          {onRestore && <button onClick={onRestore} className="underline hover:text-emerald-200">restore</button>}
        </div>
      )}
      {!activePath ? (
        <div className="overflow-y-auto p-1.5">
          {paths.length === 0 && (
            <div className="px-2 py-3 text-center text-[11px] text-text-3">
              {eliminated > 0 ? "All paths broken 🎉" : "No attack paths in this view."}
            </div>
          )}
          {paths.map((p) => (
            <button key={p.id} onClick={() => onSelect(p)}
              className="mb-1 w-full rounded border border-border-subtle bg-surface-2 px-2 py-1.5 text-left hover:border-fuchsia-400/40 hover:bg-fuchsia-400/5">
              <div className="flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${p.severity === "critical" ? "bg-red" : p.severity === "high" ? "bg-orange" : "bg-amber"}`} />
                <span className="truncate text-[11px] text-text-2" title={pathSummary(p).map(shortenLabel).join(" → ")}>
                  {pathSummary(p).map(shortenLabel).join(" → ")}
                </span>
              </div>
              <div className="mt-0.5 pl-3 text-[11px] uppercase tracking-wide text-text-3">{p.severity} · {p.hops.length} hops</div>
            </button>
          ))}
        </div>
      ) : (
        <div className="flex flex-col overflow-hidden">
          <div className="overflow-y-auto p-2">
            <ol className="space-y-1">
              {activePath.hops.map((h, i) => (
                <li key={h.id}>
                  {h.via && <div className="pl-2 text-[11px] text-fuchsia-300/70">↓ {edgeLabel(h.via)}</div>}
                  <div className="flex items-center gap-1">
                    <button onClick={() => onStep(i)}
                      className={`flex flex-1 items-start gap-1.5 rounded px-1.5 py-1 text-left ${i === stepIdx ? "bg-fuchsia-400/15" : "hover:bg-surface-3"}`}>
                      <span className={`mt-0.5 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${i === stepIdx ? "bg-fuchsia-400 text-bg" : "bg-surface-3 text-text-3"}`}>{i + 1}</span>
                      <span className="min-w-0">
                        <span className="block truncate text-[11px] text-text-2" title={h.label}>{shortenLabel(h.label)}</span>
                        {h.sub && <span className="block text-[11px] text-text-3">{typeLabel(h.sub)}</span>}
                      </span>
                    </button>
                    {onBreak && (
                      <button onClick={() => onBreak(h.id)} title="Break the chain — hide this node and recompute"
                        className="shrink-0 rounded px-1 py-0.5 text-[11px] text-text-3 hover:bg-emerald-400/15 hover:text-emerald-300">✂</button>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </div>
          <div className="flex items-center justify-between gap-1 border-t border-border-subtle px-2 py-1.5">
            <button onClick={onClear} className="text-[11px] text-text-3 hover:text-text-2">‹ All paths</button>
            <div className="flex items-center gap-1">
              <button disabled={stepIdx === 0} onClick={() => onStep(stepIdx - 1)}
                className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] text-text-2 disabled:opacity-30 hover:bg-surface-3">Prev</button>
              <span className="text-[11px] tabular-nums text-text-3">{stepIdx + 1}/{activePath.hops.length}</span>
              <button disabled={stepIdx >= activePath.hops.length - 1} onClick={() => onStep(stepIdx + 1)}
                className="rounded border border-fuchsia-400/40 bg-fuchsia-400/10 px-1.5 py-0.5 text-[11px] text-fuchsia-300 disabled:opacity-30 hover:bg-fuchsia-400/20">Next</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
