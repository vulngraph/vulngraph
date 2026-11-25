import type { FindingContext } from "../lib/api";
import { CONFIDENCE_BAND_TITLE, OUTCOME_META, describeAction, labelAction } from "../lib/actions";

// ReasoningTrace renders the 7-step layered decision pipeline respond.Decide runs for
// every finding: blast radius -> context -> reason -> confidence
// (decaying memory) -> policy gate -> CoVe verify -> outcome. The data is
// the cached decision snapshot on FindingContext.reasoning plus the blast summary;
// each step shows what that stage produced so the routing call is fully legible.

type Reasoning = NonNullable<FindingContext["reasoning"]>;

// Outcome tone/title come from lib/actions.ts's OUTCOME_META — the same table
// Decisions.tsx's OutcomeBadge and queue.tsx read, so this trace (the one
// place a human reads the decision justification in depth) can't drift from
// what the rest of the app calls the same outcome.
const bandTone: Record<string, string> = {
  high: "text-emerald",
  medium: "text-amber",
  low: "text-orange",
  insufficient: "text-red",
};

export function ReasoningTrace({ reasoning }: { reasoning: Reasoning }) {
  const r = reasoning;
  // r.blast_radius is the DECISION-TIME snapshot — deliberately never
  // substituted with a live count: a `?? liveCount` fallback would let an
  // unmeasured cached 0 read as measured, silently mixing a stale snapshot
  // with a live one.
  // known === false means the walk that produced it failed; render that
  // plainly instead of a bare "0 reachable assets".
  const blast = r.blast_radius ?? 0;
  const blastUnmeasured = r.blast_radius_known === false;
  const concerns = r.cove_concerns ?? [];
  const score = r.confidence_score != null ? Math.round(r.confidence_score * 100) : null;

  const steps: Step[] = [
    {
      n: 1,
      name: "Blast radius",
      detail: blastUnmeasured
        ? "Unmeasured — the blast-radius walk failed at decision time, so this action's reach was never sized."
        : `${blast} reachable asset${blast === 1 ? "" : "s"} — sizes the action and seeds the change fingerprint.`,
    },
    {
      n: 2,
      name: "Context",
      detail: "Connected-graph context assembled (peers, lineage, provenance, exposure) — the reasoner judges over the graph, not the finding alone.",
    },
    {
      n: 3,
      name: "Reason → plan",
      detail: r.summary || r.rationale || "Plan proposed.",
      sub: r.summary && r.rationale ? r.rationale : undefined,
      badge: {
        text: labelAction(r.action_class, "plan"),
        tone: "text-teal border-teal/30 bg-teal/10",
        title: describeAction(r.action_class),
      },
    },
    {
      n: 4,
      name: "Confidence",
      // An "insufficient" band means the ledger returned BEFORE computing a
      // rate, so confidence_score is an uncomputed zero — rendering it as
      // "0% decayed success rate" states a total-failure rate that was never
      // measured. Show the evidence weight, which IS measured, and
      // say the rate does not exist yet.
      detail:
        r.confidence_band === "insufficient"
          ? `Not enough evidence to compute a success rate — ${fmtN(r.effective_n)} weighted evidence (${r.sample_count ?? 0} outcome${r.sample_count === 1 ? "" : "s"}), threshold is 3.`
          : score != null
            ? `${score}% decayed success rate over ${fmtN(r.effective_n)} weighted evidence (${r.sample_count ?? 0} outcome${r.sample_count === 1 ? "" : "s"}).`
            : "Confidence from past human verdicts (decaying memory).",
      badge: r.confidence_band
        ? {
            text: r.confidence_band,
            tone: `border-current/30 bg-surface ${bandTone[r.confidence_band] ?? "text-text-2"}`,
            title: CONFIDENCE_BAND_TITLE[r.confidence_band],
          }
        : undefined,
    },
    {
      n: 5,
      name: "Policy gate",
      detail: gateDetail(r.outcome),
    },
    {
      n: 6,
      name: "CoVe verify",
      detail:
        concerns.length > 0
          ? "Chain-of-verification raised guardrail concerns — fail-closed, forces human escalation."
          : "Chain-of-verification found no structural guardrail concerns.",
      concerns,
    },
    {
      n: 7,
      name: "Outcome",
      detail: "Decision recorded to the audit trail, which Vulngraph only ever appends to. Nothing runs until a person approves it; their verdict is what feeds decaying memory.",
      badge: r.outcome
        ? {
            text: OUTCOME_META[r.outcome]?.label ?? r.outcome.replace(/_/g, " "),
            tone: OUTCOME_META[r.outcome]?.tone ?? "text-text-3 border-border-subtle bg-surface",
            title: OUTCOME_META[r.outcome]?.title,
          }
        : undefined,
    },
  ];

  return (
    <ol className="relative space-y-3 border-l border-border-subtle pl-5">
      {steps.map((s) => (
        <li key={s.n} className="relative">
          <span className="absolute -left-[26px] flex h-4 w-4 items-center justify-center rounded-full border border-border-strong bg-surface text-[11px] font-semibold tabular-nums text-text-2">
            {s.n}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wide text-text-2">{s.name}</span>
            {s.badge && (
              <span
                className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${s.badge.tone}`}
                title={s.badge.title}
              >
                {s.badge.text}
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] leading-relaxed text-text">{s.detail}</p>
          {s.sub && <p className="mt-0.5 text-[11px] leading-relaxed text-text-3">{s.sub}</p>}
          {s.concerns && s.concerns.length > 0 && (
            <ul className="mt-1 space-y-0.5">
              {s.concerns.map((c, i) => (
                <li key={i} className="text-[11px] text-red">
                  ⚠ {c}
                </li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ol>
  );
}

type Step = {
  n: number;
  name: string;
  detail: string;
  sub?: string;
  badge?: { text: string; tone: string; title?: string };
  concerns?: string[];
};

function gateDetail(outcome?: string): string {
  switch (outcome) {
    case "observed":
      return "Read-only plan — nothing to change, so no approval is needed.";
    case "parked_for_approval":
      return "Policy held the change for human approval. Vulngraph never runs a remediation on its own.";
    case "escalated":
      return "Policy escalated — there is not enough confidence to treat this as a routine approval.";
    default:
      return "Policy gate evaluated the action class against confidence.";
  }
}

function fmtN(n?: number): string {
  if (n == null) return "0";
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}
