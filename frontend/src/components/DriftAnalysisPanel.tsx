import { useDriftAnalyses, type DriftAnalysis } from "../lib/queries";

const DOCS_URL = "https://github.com/vulngraph/vulngraph/blob/main/docs/configuration.md";

type ScanState = "recommended" | "not_needed" | "unknown" | "not_analysed";

const SCAN_BADGE: Record<ScanState, { label: string; cls: string }> = {
  recommended:  { label: "Scan recommended", cls: "bg-amber/10 text-amber" },
  not_needed:   { label: "Scan not needed",  cls: "bg-emerald/10 text-emerald" },
  unknown:      { label: "Scan unknown",     cls: "bg-surface-3 text-text-3" },
  not_analysed: { label: "Not analysed",     cls: "bg-surface-3 text-text-3" },
};

const EXPOSURE_BADGE: Record<string, { label: string; cls: string }> = {
  increased:  { label: "Exposure increased",  cls: "bg-red/10 text-red" },
  decreased:  { label: "Exposure decreased",  cls: "bg-emerald/10 text-emerald" },
  unchanged:  { label: "Exposure unchanged",  cls: "bg-surface-3 text-text-2" },
};

const UNKNOWN_REASONS: Record<string, string> = {
  budget: "the LLM budget was exhausted or could not be read",
  llm_error: "the LLM call failed",
  ungrounded: "the answer did not cite the changed assets, so it was discarded",
  no_changes: "no inventory changes were found",
};

function scanState(a: DriftAnalysis): ScanState {
  if (a.status !== "analysed") return "unknown";
  return a.scan_recommendation;
}

function AdvisoryLabel() {
  return (
    <span className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] text-text-3">
      AI-derived, advisory
    </span>
  );
}

export function DriftAnalysisPanel({ since, onOpenAsset }: { since: string; onOpenAsset: (id: string) => void }) {
  const { data, isLoading, isError } = useDriftAnalyses(since);

  if (isLoading) return null;

  const shell = (children: React.ReactNode) => (
    <section aria-label="Drift analysis" className="glass mb-4 rounded-xl px-4 py-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h2 className="text-[13px] font-semibold text-text">What changed, and do I need to scan?</h2>
        <AdvisoryLabel />
      </div>
      {children}
    </section>
  );

  if (isError || !data) {
    return shell(
      <div className="flex items-center gap-2 text-[11px] text-text-3">
        <span className={`rounded px-1.5 py-0.5 font-semibold ${SCAN_BADGE.not_analysed.cls}`}>{SCAN_BADGE.not_analysed.label}</span>
        Drift analysis is unavailable right now. That is not a verdict on any change.
      </div>,
    );
  }

  if (!data.enabled) {
    return shell(
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-text-3">
        <span className={`rounded px-1.5 py-0.5 font-semibold ${SCAN_BADGE.not_analysed.cls}`}>{SCAN_BADGE.not_analysed.label}</span>
        <span>
          Drift analysis is off, so changes are not assessed. Set <span className="font-mono">DRIFT_ANALYSIS_ENABLED=true</span> on the worker to turn it on (it spends LLM budget).{" "}
          <a href={DOCS_URL} target="_blank" rel="noreferrer" className="text-teal hover:underline">Configuration docs</a>
        </span>
      </div>,
    );
  }

  const latest = data.analyses.find((a) => a.status !== "baseline");
  if (!latest) {
    return shell(<p className="text-[11px] text-text-3">No analysed changes in this window.</p>);
  }

  const state = scanState(latest);
  const scan = SCAN_BADGE[state];
  const exposure = latest.status === "analysed" ? EXPOSURE_BADGE[latest.exposure_judgement] : undefined;

  return shell(
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${scan.cls}`}>{scan.label}</span>
        {exposure && (
          <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${exposure.cls}`}>{exposure.label}</span>
        )}
        {latest.status === "analysed" && latest.confidence && (
          <span className="text-[11px] text-text-3">{latest.confidence} confidence</span>
        )}
        {latest.truncated && (
          <span className="rounded bg-amber/10 px-1.5 py-0.5 text-[11px] text-amber">
            Truncated: more assets changed than one analysis holds; the rest were not analysed
          </span>
        )}
      </div>

      {latest.status === "analysed" ? (
        <>
          <p className="text-[12px] leading-relaxed text-text-2">{latest.summary}</p>
          {latest.reason && <p className="text-[11px] text-text-3">{latest.reason}</p>}
          {latest.changes.length > 0 && (
            <ul className="space-y-0.5 text-[11px] text-text-2">
              {latest.changes.map((c, i) => (
                <li key={`${c.asset_id}-${i}`}>
                  <span className="text-text-3">{c.kind}</span>{" "}
                  <button onClick={() => onOpenAsset(c.asset_id)} className="font-mono text-teal hover:underline">
                    {c.asset_id}
                  </button>{" "}
                  {c.note}
                </li>
              ))}
            </ul>
          )}
          {latest.evidence.length > 0 && (
            <div className="text-[11px] text-text-3">
              Evidence:
              <ul className="mt-0.5 space-y-0.5">
                {latest.evidence.map((e, i) => (
                  <li key={`${e.ref}-${i}`}>
                    {e.source === "asset" ? (
                      <button onClick={() => onOpenAsset(e.ref)} className="font-mono text-teal hover:underline">{e.ref}</button>
                    ) : (
                      <span className="font-mono">{e.ref}</span>
                    )}{" "}
                    {e.fact}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : (
        <p className="text-[11px] text-text-3">
          Not established{UNKNOWN_REASONS[latest.unknown_reason] ? `: ${UNKNOWN_REASONS[latest.unknown_reason]}` : ""}.
          Unknown is not "no scan needed".
        </p>
      )}

    </div>,
  );
}
