import { ShieldAlert, Zap } from "lucide-react";
import { useFindings } from "../lib/queries";
import { Empty } from "./ui";
import { FindingWorklist } from "./FindingWorklist";
import { StalenessNote } from "./MustFixBadge";

// MustFixView is the evidence-backed "fix this NOW" worklist: the tier
// computed at enrich from what an attacker can ACTUALLY do — a real internet-
// reachable attack path to the resource, exploitability (KEV / active threat /
// privilege escalation), and a non-trivial blast radius; or a non-test-mode
// credential leaked in a public repository that GitHub has not found revoked. It is the counterpart to "Start
// here" (safe quick wins): this is the small, defensible set that is genuinely
// urgent, with the evidence for WHY on every row — and, crucially, it excludes the
// longstanding-but-controlled/unreachable noise (e.g. IAM privesc behind SSO)
// that a raw high score would otherwise surface.
//
// The selection/table/bulk-suppress/infinite-scroll machinery is shared with
// "Start here" via FindingWorklist; what is specific to must-fix is the query,
// the banner, the urgency evidence column, and the empty-state probe below.
export function MustFixView({ search }: { search?: string }) {
  const query = useFindings({ must_fix: true, sort: "score" });

  // An empty must-fix list has two very different causes, which must not both
  // read as "Nothing meets the must-fix bar — that's the goal": either the
  // pipeline assessed everything and nothing qualified (genuinely good news), or
  // enrichment never ran, so must_fix_class is blank everywhere and the filter
  // matches nothing (very bad news). A small unfiltered probe tells them apart:
  // if findings exist but none has been enriched, the bar was never applied.
  const probe = useFindings({ sort: "score", limit: 25 });
  const probed = probe.data?.pages[0]?.items ?? [];
  const pipelineHasNotRun =
    probed.length > 0 && probed.every((f) => f.enrichment_state === "never_enriched");

  return (
    <FindingWorklist
      query={query}
      search={search}
      accent="red"
      banner={
        <div className="mb-3 rounded border border-red/20 bg-red/5 px-3 py-2 text-[11px] text-red">
          <span className="font-medium">Must fix now.</span> Findings with a real, <span className="font-medium">internet-reachable</span> attack
          path that is <span className="font-medium">exploitable</span> (known-exploited, an active threat, or privilege escalation) with a
          blast radius of 5+ assets on a resource that still exists, and <span className="font-medium">credentials</span> leaked in a
          public repository that are not test-mode keys and that GitHub has not found revoked (its validity check reports them
          active, or has not checked). Well-controlled or unreachable issues (e.g. privesc gated by SSO/MFA) are deliberately excluded — this is the
          set that is genuinely urgent, with the evidence on every row.
        </div>
      }
      whyHeader="Why you must fix this now"
      whyColumn={(f) => (
        <span className="inline-flex flex-wrap items-center gap-1.5 text-[11px] text-red">
          <span className="inline-flex items-center gap-1">
            <ShieldAlert className="h-3 w-3" />
            {f.must_fix_reason || "evidence reason not recorded"}
          </span>
          <StalenessNote state={f.enrichment_state} />
        </span>
      )}
      emptyState={
        pipelineHasNotRun ? (
          <Empty message="This list is empty because enrichment has not run — not because nothing is urgent. Findings exist, but none has been assessed, so the must-fix bar has not been applied to anything yet. Treat this as unknown risk, not zero risk." />
        ) : (
          <Empty message="Nothing meets the must-fix bar right now — no finding is internet-reachable and exploitable with real blast radius, and no credential that may still work is leaked in a public repository. Check 'Start here' for safe quick wins." />
        )
      }
      footer={(n) => (
        <>
          <Zap className="h-3 w-3 text-red" /> {n} must-fix finding{n === 1 ? "" : "s"}
        </>
      )}
    />
  );
}
