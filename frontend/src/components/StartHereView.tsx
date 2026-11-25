import { ShieldCheck, GitBranch, Cloud } from "lucide-react";
import { useFindings } from "../lib/queries";
import { SCORE_THRESHOLDS } from "../lib/format";
import type { Finding } from "../lib/api";
import { Empty } from "./ui";
import { SafetyBadge } from "./SafetyBadge";
import { FindingWorklist } from "./FindingWorklist";

// StartHereView is the confident-action worklist: the intersection of HIGH SIGNAL
// (meaningful risk score / known-exploited) and STRUCTURALLY SAFE TO FIX (nothing
// depends on the resource and it looks unused — computed at enrich time from the
// graph, no LLM; see internal/app/enrich/safety.go). It answers the two questions
// a freshly-onboarded large environment can't otherwise answer: "what actually
// matters?" and "will fixing it break anything?" — with the evidence for both on
// every row, and one-click bulk suppression once you've decided.
//
// Selection, paging, the table and bulk suppression are shared with "Must fix"
// via FindingWorklist; the safety evidence column below is what's specific here.
const START_HERE_MIN_SCORE = SCORE_THRESHOLDS.pipeline;

// formatFixTarget turns the compact fix_target hint ("repo:org/name" |
// "console:acct:region") into a rendered "where to fix" line. The finding-detail
// view shows the richer FixLocation; this is the at-a-glance version.
function FixTargetLine({ target }: { target?: string }) {
  if (!target) return null;
  if (target.startsWith("repo:")) {
    const repo = target.slice("repo:".length).replace(/^[a-z_]+:/, "");
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-text-3">
        <GitBranch className="h-3 w-3 text-teal" />
        Fix in <span className="font-mono text-text-2">{repo}</span> → redeploy
      </span>
    );
  }
  if (target.startsWith("console:")) {
    const where = target.slice("console:".length).replace(":", " · ");
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-text-3">
        <Cloud className="h-3 w-3 text-text-3" />
        Apply in console <span className="font-mono text-text-2">{where}</span>
      </span>
    );
  }
  return null;
}

// WhySafe renders the "will it break anything?" evidence — the reason this finding
// is classed safe. Safe = "present and unreferenced": the resource is still live,
// nothing routes to or runs as it (0 dependents), and it's not prod/internet-facing.
// We state it explicitly because that is the confidence the analyst acts on.
function WhySafe({ f }: { f: Finding }) {
  return (
    <div className="flex flex-col gap-0.5">
      <SafetyBadge band={f.safety_class} />
      <span className="text-[11px] text-text-3">
        nothing routes to or runs as this resource{f.unused ? " · inactive" : ""}
      </span>
      <FixTargetLine target={f.fix_target} />
    </div>
  );
}

export function StartHereView({ search }: { search?: string }) {
  const query = useFindings({ safe: true, min_score: START_HERE_MIN_SCORE, sort: "score" });

  return (
    <FindingWorklist
      query={query}
      search={search}
      accent="teal"
      banner={
        <div className="mb-3 rounded border border-teal/20 bg-teal/5 px-3 py-2 text-[11px] text-teal">
          <span className="font-medium">Start here.</span> High-signal issues (score ≥ {START_HERE_MIN_SCORE} or known-exploited)
          that are <span className="font-medium">structurally safe to fix</span> — the resource is still live, nothing routes to or runs as it, and it&apos;s not production or internet-facing.
          Every row shows why it matters and why it won&apos;t break anything. Select and suppress in bulk once handled.
        </div>
      }
      whyHeader={<>Why it&apos;s safe to fix</>}
      whyColumn={(f) => <WhySafe f={f} />}
      emptyState={
        <Empty message="No safe quick wins yet. As enrichment scores your environment, high-signal findings that are safe to fix land here — check back after the first sync completes." />
      }
      footer={(n) => (
        <>
          <ShieldCheck className="h-3 w-3 text-teal" /> {n} safe quick win{n === 1 ? "" : "s"}
        </>
      )}
    />
  );
}
