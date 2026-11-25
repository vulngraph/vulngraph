import { Sparkles, Scale } from "lucide-react";
import type { Belief } from "../lib/api";
import { SeverityBadge } from "./ui";

// BeliefPanel renders the belief engine's grounded true-severity verdict for a
// finding: the reconciled severity, how confident/settled it is, how it
// was formed, and — the point — the cited evidence chain behind it. It leads the
// finding detail above the raw score breakdown, because it is the headline
// judgment ("is this REALLY this severe?") that the score factors then justify.
//
// Renders nothing when there is no belief yet (only enriched findings form one).

const CONFIDENCE_CLASS: Record<string, string> = {
  high: "text-emerald",
  medium: "text-amber",
  low: "text-text-3",
};

const STATUS_CLASS: Record<string, string> = {
  confirmed: "border-emerald/30 bg-emerald/10 text-emerald",
  proposed: "border-amber/30 bg-amber/10 text-amber",
  refuted: "border-border-subtle bg-surface-3 text-text-3",
  stale: "border-border-subtle bg-surface-3 text-text-3",
};

export function BeliefPanel({ belief }: { belief: Belief | null | undefined }) {
  if (!belief) return null;

  const adjudicated = belief.provenance === "adjudicator";
  // Same wording as the badge's title tooltip, but rendered inline — a hover-only
  // explanation is easy to miss (same lesson as the Decisions action-class legend).
  const provenanceDescription = adjudicated
    ? "Adjudicated: reached by full-context, multi-sample adversarial LLM reasoning on a disagreement case."
    : "Deterministic: reached by grounded rules reconciling the score with reachability, trust, and must-fix signals.";

  return (
    <div className="mb-4 rounded-lg border border-violet-500/25 bg-violet-500/[0.04] p-3">
      <div className="mb-2 flex items-center justify-between gap-3">
        <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-violet-300">
          <Scale className="h-3 w-3" /> True severity
        </span>
        <span
          title={provenanceDescription}
          className={`flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ${
            adjudicated
              ? "border-violet-500/30 bg-violet-500/10 text-violet-300"
              : "border-border-subtle bg-surface-3 text-text-3"
          }`}
        >
          {adjudicated && <Sparkles className="h-2.5 w-2.5" />}
          {adjudicated ? "adjudicated" : "deterministic"}
        </span>
      </div>
      <p className="mb-2 text-[11px] leading-relaxed text-text-3">{provenanceDescription}</p>

      {/* Verdict row: the reconciled severity + how settled/confident it is */}
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={belief.severity} />
        <span
          className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ${
            STATUS_CLASS[belief.status] ?? STATUS_CLASS.stale
          }`}
        >
          {belief.status}
        </span>
        <span className="text-[11px] text-text-3">
          confidence{" "}
          <span className={`font-medium ${CONFIDENCE_CLASS[belief.confidence] ?? "text-text-3"}`}>
            {belief.confidence}
          </span>
        </span>
      </div>

      {/* The claim — the plain-English verdict / re-frame */}
      {belief.claim && (
        <p className="mt-2 text-[13px] leading-relaxed text-text-1">{belief.claim}</p>
      )}

      {/* Grounded evidence — every clause cites a concrete organ fact */}
      {belief.evidence && belief.evidence.length > 0 && (
        <div className="mt-3">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">Grounded in</div>
          <ul className="space-y-1.5">
            {belief.evidence.map((e, i) => (
              <li key={`${e.source}-${i}`} className="flex items-start gap-2 text-[12px] text-text-2">
                <span className="mt-0.5 shrink-0 text-violet-300/70">·</span>
                <span className="min-w-0 flex-1">
                  {e.clause}
                  <span className="ml-1.5 whitespace-nowrap rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-text-3">
                    {e.source}
                    {e.fact ? `: ${e.fact}` : ""}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
