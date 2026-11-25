import { useState } from "react";
import { complianceExportURL, useComplianceFramework, useComplianceFrameworks, useMe } from "../lib/queries";
import type { ComplianceRequirement } from "../lib/api";
import { Empty, ErrorNote, Loading } from "../components/ui";

type State = ComplianceRequirement["state"];

const STATE_STYLE: Record<State, string> = {
  passing: "border-teal/30 bg-teal/10 text-teal",
  failing: "border-red/30 bg-red/10 text-red",
  unknown: "border-amber/30 bg-amber/10 text-amber",
  manual: "border-border-subtle text-text-3",
};

// STATE_HELP says what each state claims. Unknown is never a pass: some
// mapped check could not read its evidence, or a mapped control has no check.
const STATE_HELP: Record<State, string> = {
  passing: "every mapped control is checked and nothing fails",
  failing: "a mapped check has an open finding",
  unknown: "no finding, but the evidence is incomplete — not a pass",
  manual: "no automated mapping; needs human evidence",
};

const STATES: State[] = ["failing", "unknown", "passing", "manual"];

function StateBadge({ state }: { state: State }) {
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase ${STATE_STYLE[state]}`} title={STATE_HELP[state]}>
      {state}
    </span>
  );
}

// evidenceNote explains, in one line, why a requirement has its state.
function evidenceNote(r: ComplianceRequirement): string {
  if (r.state === "manual") return STATE_HELP.manual;
  const parts: string[] = [];
  if (r.failing_checks.length) parts.push(`${r.failing_checks.length} failing check${r.failing_checks.length > 1 ? "s" : ""}`);
  if (r.unevaluated_checks.length) parts.push(`${r.unevaluated_checks.length} check${r.unevaluated_checks.length > 1 ? "s" : ""} missing evidence`);
  if (r.gaps.length) parts.push(`${r.gaps.length} control${r.gaps.length > 1 ? "s" : ""} without full checks`);
  if (r.evidence_gaps.length)
    parts.push(`${r.evidence_gaps.length} control${r.evidence_gaps.length > 1 ? "s" : ""} on stale or missing cloud evidence`);
  if (!parts.length && r.check_ids.length === 0) parts.push("no in-scope controls");
  if (!parts.length) parts.push(`${r.check_ids.length} check${r.check_ids.length > 1 ? "s" : ""} evaluated`);
  parts.push(`evidence as of ${asOf(r.evidence_as_of)}`);
  return parts.join(" · ");
}

function asOf(t: string | null): string {
  return t ? new Date(t).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "unknown";
}

// ComplianceRequirements is the requirement-level view (ADR 093): pick a
// framework, see each requirement's pass / fail / unknown / manual state and
// the evidence behind it, and export the auditor CSV.
export function ComplianceRequirements() {
  const list = useComplianceFrameworks();
  const me = useMe();
  const [picked, setPicked] = useState<string | undefined>();
  const [stateFilter, setStateFilter] = useState<State | "all">("all");
  const frameworks = list.data?.frameworks ?? [];
  const selected = picked ?? frameworks[0]?.id;
  const detail = useComplianceFramework(selected);
  const canExport = me.data?.role === "admin" || me.data?.role === "analyst";

  const requirements = (detail.data?.requirements ?? []).filter((r) => stateFilter === "all" || r.state === stateFilter);

  return (
    <section className="mt-10" aria-label="Framework requirements">
      <h2 className="mb-1 font-display text-lg text-text">Framework requirements</h2>
      <p className="mb-4 text-xs text-text-3">
        NIST 800-53, PCI DSS, SOC 2, ISO 27001 and HIPAA requirements, each mapped to benchmark controls and the checks behind
        them. Unknown is never counted as passing.
      </p>
      {list.isLoading && <Loading />}
      {list.isError && <ErrorNote message={(list.error as Error).message} />}
      {list.data && frameworks.length === 0 && <Empty message="No frameworks mapped." />}
      {frameworks.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2" role="tablist">
          {frameworks.map((fw) => (
            <button
              key={fw.id}
              role="tab"
              aria-selected={fw.id === selected}
              onClick={() => setPicked(fw.id)}
              className={`rounded-lg border px-3 py-2 text-left text-xs ${
                fw.id === selected ? "border-teal bg-teal/10 text-text" : "border-border-subtle bg-surface text-text-2 hover:border-teal/50"
              }`}
            >
              <div className="font-medium">
                {fw.name} <span className="text-text-3">{fw.version}</span>
              </div>
              <div className="mt-0.5 tabular-nums text-[11px] text-text-3">
                {fw.passing} passing · {fw.failing} failing · {fw.unknown} unknown · {fw.manual} manual
              </div>
            </button>
          ))}
        </div>
      )}
      {detail.isLoading && selected && <Loading />}
      {detail.isError && <ErrorNote message={(detail.error as Error).message} />}
      {detail.data && (
        <div className="rounded-lg border border-border-subtle bg-surface">
          <div className="flex flex-wrap items-center gap-2 border-b border-border-subtle px-4 py-2">
            {(["all", ...STATES] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStateFilter(s)}
                aria-pressed={stateFilter === s}
                className={`rounded px-2 py-0.5 text-[11px] ${stateFilter === s ? "bg-teal/15 text-teal" : "text-text-3 hover:text-text"}`}
              >
                {s}
              </button>
            ))}
            {canExport && (
              <a href={complianceExportURL(detail.data.id)} download className="ml-auto text-[11px] text-teal underline decoration-dotted">
                Export CSV for auditors
              </a>
            )}
          </div>
          {detail.data.clouds.length > 0 && (
            <div className="flex flex-wrap gap-3 border-b border-border-subtle px-4 py-2 text-[11px] text-text-3" aria-label="Cloud evidence">
              {detail.data.clouds.map((c) => (
                <span key={c.provider} className={c.stale ? "text-amber" : undefined}>
                  {c.provider}: {c.stale ? "stale or missing evidence" : "fresh"} · as of {asOf(c.evidence_as_of)}
                </span>
              ))}
            </div>
          )}
          {requirements.length === 0 && <div className="p-4 text-xs text-text-3">No requirements in this state.</div>}
          <ul className="divide-y divide-border-subtle">
            {requirements.map((r) => (
              <li key={r.id} className="flex items-start gap-3 px-4 py-2 text-xs">
                <span className="w-28 shrink-0 font-mono text-text-2">{r.id}</span>
                <span className="flex-1">
                  <span className="text-text">{r.title}</span>
                  <span className="block text-[11px] text-text-3">{evidenceNote(r)}</span>
                  {r.partial_mapping && <span className="block text-[11px] text-amber">{r.partial_mapping}</span>}
                  {r.failing_checks.length > 0 && (
                    <span className="block font-mono text-[11px] text-red">{r.failing_checks.join(", ")}</span>
                  )}
                </span>
                <StateBadge state={r.state} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
