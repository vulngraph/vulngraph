import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Bot } from "lucide-react";
import type { Decision } from "../lib/api";
import { useDecisionsInfinite, useDecisionsSummary, useIsAdmin, useQueue } from "../lib/queries";
import { Button, ErrorNote, Loading, PageHeader } from "../components/ui";
import { DecisionDetailPanel, parseAuditDetail } from "../components/DecisionDetailPanel";
import { SafetyBadge, FixLocationLine, type FixLocation } from "../components/SafetyBadge";
import {
  ACTION_CLASSES,
  ActionClassLegend,
  ActionIcon, PatternGroupCard, QueueCard, TIER_META, TONE_CLASSES, actionTone, labelAction, tierQueue,
} from "../components/queue";
import { timeAgo as timeAgoBase, shortenId } from "../lib/format";
import { OUTCOME_META } from "../lib/actions";

const timeAgo = (iso?: string) => timeAgoBase(iso, "ago");

// Copy for DecisionsSummary.escalation_reasons — an open set. A key not
// listed here still renders (humanized key), just without the extra title.
const ESCALATION_REASON_META: Record<string, { label: string; title?: string }> = {
  policy_blocked: {
    label: "destructive, low confidence",
    title: "A destroy/isolate proposal the gate escalated — review it directly",
  },
  verification_concern: {
    label: "failed verification",
    title: "CoVe raised a concern that forced escalation",
  },
  insufficient_confidence: {
    label: "need more evidence",
    title: "Deny these, or run their fixes, to teach the agent — more evidence makes similar proposals park for approval instead of escalating",
  },
};

// DecisionDetail is the shape of AuditEvent.Details JSON written by auditFor()
// in respond/service.go. Rationale is NOT written to the audit trail — it lives
// in reasoncache. This type matches what is actually on the wire.
type DecisionDetail = {
  action_class?: string;
  summary?: string;
  confidence_band?: string;
  blast_radius?: number;
  // blast_radius_known: false means the walk that produced blast_radius
  // failed, so the 0 in blast_radius is unknown, not a measurement.
  blast_radius_known?: boolean;
  cove_concerns?: string[];
  safety_band?: string;
  fix_location?: FixLocation;
  outcome?: string;
};

function parse(details?: string): DecisionDetail {
  return parseAuditDetail<DecisionDetail>(details);
}

export function Decisions() {
  const [outcome, setOutcome] = useState("");
  const [actionClass, setActionClass] = useState("");
  const [showLegend, setShowLegend] = useState(false);
  const [selectedDecision, setSelectedDecision] = useState<Decision | null>(null);
  const isAdmin = useIsAdmin();
  const queue = useQueue(actionClass);
  const queueItems = queue.data?.items ?? [];
  // outcome/actionClass are passed straight to the backend — needs_action and
  // safe_to_fix are not raw outcome values, but the backend accepts both as
  // derived groupings. They must not be computed client-side over whatever
  // page happens to be loaded: a filtered-but-truncated list is
  // indistinguishable from "there really are only N of these".
  // Action-class ANDs with outcome server-side too — "show me every
  // isolate/destroy decision regardless of how it resolved" is a different
  // question from "show me what's escalated".
  const { data, isLoading, isError, error, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useDecisionsInfinite({ outcome, actionClass });
  const items = data?.pages.flatMap((p) => p.items) ?? [];

  // Banner/hotspot numbers come from /api/decisions/summary — whole-trail
  // aggregates computed server-side. They must never be folded from `items`,
  // which only holds the pages the user happened to load.
  const summaryQuery = useDecisionsSummary();
  const summary = summaryQuery.data;
  const counts = {
    parked_for_approval: summary?.parked_for_approval ?? 0,
    escalated: summary?.escalated ?? 0,
  };
  const actionClassCounts = summary?.action_classes ?? {};
  const quickWins = summary?.quick_wins ?? 0;
  const uniqueResources = summary?.unique_resources ?? 0;
  const hotspots = (summary?.hotspots ?? []).map((h) => {
    const key = h.target_resource || h.target_id;
    return [key, { title: h.target_title || shortenArn(key), count: h.count, latest: h.latest }] as const;
  });
  // Escalation reasons — never collapse to one blanket "needs more evidence"
  // message. policy_blocked decisions (destroy/isolate the gate escalated)
  // need a direct review, so telling the user to approve-to-teach is
  // misleading for them; verification_concern and insufficient_confidence are genuinely
  // different failure modes too. Unknown keys still render (humanized),
  // never dropped.
  //
  // pattern_denied is deliberately NOT in this list: it is recorded on
  // suppressed_by_verdict decisions, which are the opposite of "needs a human"
  // — a human already ruled on that pattern. Folding it in here would file
  // answered questions under unanswered ones on a governance dashboard.
  const escalationReasons = Object.entries(summary?.escalation_reasons ?? {})
    .filter(([key, n]) => n > 0 && key !== "pattern_denied")
    .sort((a, b) => b[1] - a[1]);
  const escalationReasonParts = escalationReasons.map(([key, n]) => ({
    key,
    text: `${n} ${ESCALATION_REASON_META[key]?.label ?? key.replace(/_/g, " ")}`,
    title: ESCALATION_REASON_META[key]?.title,
  }));
  // Say how many escalations the reasons cover — if any escalation lacks a
  // reason, the counts would otherwise read as a breakdown of all N and
  // quietly fail to add up.
  const reasonsCovered = escalationReasons.reduce((n, [, count]) => n + count, 0);
  const alreadyRuled = summary?.suppressed_by_verdict ?? 0;
  const needsAction = counts.escalated + counts.parked_for_approval;

  return (
    <div>
      <PageHeader
        title="Decisions"
        subtitle="The agent's reasoning log — what it planned, why it escalated, and what happened."
      />

      {/* Summary banner — whole-trail aggregates, independent of loaded pages. */}
      {(summary?.total ?? 0) > 0 && (
        <div className="glass mb-4 flex flex-wrap items-center gap-x-6 gap-y-1 rounded-lg px-4 py-3 text-[11px]">
          {quickWins > 0 && (
            <button onClick={() => setOutcome("safe_to_fix")} className="font-medium text-teal hover:underline">
              {quickWins} safe to fix — start here →
            </button>
          )}
          {counts.escalated > 0 && (
            <button onClick={() => setOutcome("escalated")} className="font-medium text-red hover:underline">
              {counts.escalated} escalated — review &amp; approve →
            </button>
          )}
          {counts.parked_for_approval > 0 && (
            <button onClick={() => setOutcome("parked_for_approval")} className="text-amber hover:underline">
              {counts.parked_for_approval} parked for approval →
            </button>
          )}
          {uniqueResources > 0 && (
            <span className="text-text-3">{uniqueResources} unique assets affected</span>
          )}
          {alreadyRuled > 0 && (
            <span
              className="text-text-3"
              title="A human already ruled on these patterns, so the agent stopped re-asking"
            >
              {alreadyRuled} already answered
            </span>
          )}
          {escalationReasonParts.length > 0 && (
            <span className="text-text-3">
              <span title={`Reasons are recorded for ${reasonsCovered} of ${counts.escalated} escalations`}>
                why ({reasonsCovered} of {counts.escalated}):
              </span>
              {escalationReasonParts.map((p) => (
                <span key={p.key}>
                  <span className="mx-1 text-border-subtle">·</span>
                  <span title={p.title}>{p.text}</span>
                </span>
              ))}
            </span>
          )}
        </div>
      )}

      {/* Repeated-escalation hotspots */}
      {hotspots.length > 0 && (
        <div className="mb-4 rounded-lg border border-red/20 bg-red/5 p-3">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">
            Repeated escalations — same entity escalated multiple times
          </div>
          <div className="space-y-1.5">
            {hotspots.map(([key, v]) => (
              <div key={key} className="flex items-center gap-3 text-[11px]">
                <span className="shrink-0 rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] font-medium tabular-nums text-red">
                  {v.count}×
                </span>
                <span className="min-w-0 truncate font-medium text-text-2" title={v.title}>
                  {v.title}
                </span>
                <span className="shrink-0 font-mono text-[11px] text-text-3">{shortenArn(key)}</span>
                <div className="ml-auto flex shrink-0 items-center gap-2">
                  <Link
                    to="/investigate/assets/$id"
                    params={{ id: key }}
                    className="text-[11px] text-text-3 hover:text-teal"
                  >
                    asset →
                  </Link>
                  <Link
                    to="/investigate/findings"
                    search={{ q: v.title || shortenArn(key) } as Record<string, string>}
                    className="text-[11px] text-teal hover:underline"
                  >
                    findings →
                  </Link>
                </div>
              </div>
            ))}
          </div>
          <p className="mt-2 text-[11px] text-text-3">
            These entities keep triggering escalations — they likely need a direct fix rather than repeated approvals.
          </p>
        </div>
      )}

      {/* Filters. Outcome ("what happened") and action class ("what the agent
          proposed") are independent axes that AND together — "needs action"
          is a union filter (escalated + parked_for_approval); "safe to fix" is
          a computed quick-win filter — neither is a raw outcome value, so they
          live alongside the real outcomes here. */}
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-center gap-2">
          <label htmlFor="decisions-outcome-filter" className="text-[11px] text-text-3">
            Show:
          </label>
          <select
            id="decisions-outcome-filter"
            value={outcome}
            onChange={(e) => setOutcome(e.target.value)}
            className="rounded border border-border-subtle bg-surface-2 px-2 py-1 text-[12px] text-text-2"
          >
            <option value="">All</option>
            <option value="needs_action">Needs action{needsAction > 0 ? ` (${needsAction})` : ""}</option>
            <option value="safe_to_fix">Safe to fix{quickWins > 0 ? ` (${quickWins})` : ""}</option>
            <option value="observed">Observed (read-only)</option>
            <option value="escalated">Escalated</option>
            <option value="parked_for_approval">Needs approval</option>
          </select>
        </div>

        {/* Action-class pills — same 5 values as the legend, same order. */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => setActionClass("")}
            className={`rounded px-2 py-1 text-[11px] transition-colors ${
              actionClass === "" ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"
            }`}
          >
            Any action
          </button>
          {ACTION_CLASSES.map((a) => {
            const n = actionClassCounts[a.value] ?? 0;
            if (n === 0) return null;
            const active = actionClass === a.value;
            const t = TONE_CLASSES[a.tone];
            return (
              <button
                key={a.value}
                onClick={() => setActionClass(active ? "" : a.value)}
                title={a.description}
                className={`rounded px-2 py-1 text-[11px] font-medium transition-colors ${
                  active ? t.accent : "text-text-3 hover:text-text-2"
                }`}
              >
                {a.label} <span className="tabular-nums opacity-70">{n}</span>
              </button>
            );
          })}
        </div>

        <button
          onClick={() => setShowLegend((v) => !v)}
          className="text-[11px] text-text-3 underline decoration-dotted hover:text-teal"
        >
          {showLegend ? "hide" : "what do these mean?"}
        </button>
      </div>

      {showLegend && (
        <div className="mb-4">
          <ActionClassLegend />
        </div>
      )}

      {/* Queue — needs action tab shows live queue items with approve/deny.
          Repeated patterns are grouped so one verdict can teach the ledger N
          lessons at once instead of N identical clicks. */}
      {outcome === "needs_action" && (
        <div className="mb-6">
          {queue.isLoading && <Loading />}
          {queueItems.length === 0 && !queue.isLoading && (
            <div className="rounded-lg border border-border-subtle bg-surface p-6 text-center text-xs text-text-3">
              No decisions waiting for action. Nothing runs without an approval, so anything proposed will appear here.
            </div>
          )}
          {queueItems.length > 0 && (
            <div className="space-y-5">
              {tierQueue(queueItems).map(({ tier, grouped, singles }) => {
                const meta = TIER_META[tier];
                const n = grouped.reduce((s, g) => s + g.length, 0) + singles.length;
                return (
                  <div key={tier}>
                    <div className="mb-2 flex flex-wrap items-baseline gap-x-2 border-b border-border-subtle pb-2">
                      <span className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${meta.text}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                        {meta.label}
                        <span className="tabular-nums text-text-3">({n})</span>
                      </span>
                      <span className="text-[11px] text-text-3">{meta.sub}</span>
                    </div>
                    <div className="space-y-2">
                      {grouped.map((g) => (
                        <PatternGroupCard key={`${g[0].check_id || g[0].title}::${g[0].action_class}`} group={g} isAdmin={isAdmin} />
                      ))}
                      {singles.map((q) => (
                        <QueueCard key={q.cluster_key} item={q} isAdmin={isAdmin} />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Audit trail — all other filter tabs */}
      {outcome !== "needs_action" && (
        <>
          {isLoading && <Loading />}
          {isError && <ErrorNote message={(error as Error).message} />}
          {!isLoading && items.length === 0 && (
            <div className="rounded-lg border border-border-subtle bg-surface p-8 text-center space-y-2">
              <p className="text-xs text-text-3">No agent decisions yet.</p>
              <p className="text-[11px] text-text-3">
                Decisions appear here once the reasoning agent evaluates a finding above the pipeline threshold.
              </p>
              <Link to="/investigate/findings" className="inline-block mt-2 text-[11px] text-teal hover:underline">
                Review findings →
              </Link>
            </div>
          )}
          {items.length > 0 && (
            <>
              <div className="space-y-2">
                {items.map((d) => (
                  <DecisionCard key={d.id} decision={d} onSelect={setSelectedDecision} />
                ))}
              </div>
              {hasNextPage && (
                <div className="mt-4 flex justify-center">
                  <Button onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
                    {isFetchingNextPage ? "Loading…" : "Load more"}
                  </Button>
                </div>
              )}
            </>
          )}
        </>
      )}

      <DecisionDetailPanel
        decision={selectedDecision}
        onClose={() => setSelectedDecision(null)}
      />
    </div>
  );
}


function DecisionCard({ decision: d, onSelect }: { decision: Decision; onSelect: (d: Decision) => void }) {
  const detail = parse(d.details);
  const tone = actionTone(detail.action_class);
  const toneClasses = TONE_CLASSES[tone];

  const isCriticalEscalated = tone === 'red' && detail.outcome === 'escalated';

  return (
    <div
      role="button"
      tabIndex={0}
      className={`rounded-xl border bg-surface-2 overflow-hidden activity-shimmer-hover transition-colors cursor-pointer hover:bg-surface-3/50 ${toneClasses.border}${isCriticalEscalated ? ' activity-conic-border' : ''}`}
      style={{borderLeft: `3px solid ${tone === 'teal' ? 'var(--graph-teal)' : tone === 'amber' ? 'var(--graph-amber)' : tone === 'red' ? 'var(--graph-red)' : 'var(--graph-border)'}`}}
      onClick={() => onSelect(d)}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect(d)}
    >
      {/* Card header — action class accent strip + meta */}
      <div className="flex items-start gap-3 p-3">
        {/* Accent icon */}
        <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border ${toneClasses.accent}`}>
          <ActionIcon action_class={detail.action_class} />
        </div>

        {/* Main content */}
        <div className="min-w-0 flex-1">
          {/* Row 1: action label + badges */}
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-[12px] font-semibold ${toneClasses.text}`}>
              {labelAction(detail.action_class, d.action)}
            </span>

            {/* Confidence band badge */}
            {detail.confidence_band && (
              <span className="rounded border border-border-subtle bg-surface-3 px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide text-text-3">
                {detail.confidence_band}
              </span>
            )}

            {/* Blast radius badge */}
            {(detail.blast_radius ?? 0) > 0 && (
              <span className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium text-amber">
                ↔ {detail.blast_radius} {detail.blast_radius === 1 ? "asset" : "assets"} at risk
              </span>
            )}
            {(detail.blast_radius ?? 0) === 0 && detail.blast_radius_known === false && (
              <span
                className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium text-amber"
                title="The blast-radius walk failed at decision time — this is not evidence the action's reach is small."
              >
                blast radius unmeasured
              </span>
            )}

            {/* Safety band — how risky the fix is to apply */}
            <SafetyBadge band={detail.safety_band} />

            {/* Outcome badge */}
            <OutcomeBadge outcome={detail.outcome} />
          </div>

          {/* Row 2: plan summary — this IS the plan. Show it prominently, always visible. */}
          {detail.summary && (
            <p className="mt-1.5 text-[12px] leading-relaxed text-text">
              {detail.summary}
            </p>
          )}

          {/* Where to apply the fix */}
          <FixLocationLine fix={detail.fix_location} className="mt-1.5" />

          {/* Row 3: target + resource */}
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-text-3">
            {/* Actor */}
            <span className="flex items-center gap-1">
              {d.actor === "agent" ? (
                <>
                  <Bot className="h-3 w-3 text-teal" />
                  <span className="text-teal">agent</span>
                </>
              ) : (
                d.actor?.split("@")[0] ?? "—"
              )}
            </span>

            <span className="text-border-subtle">·</span>

            {/* Timestamp */}
            <span title={new Date(d.ts).toLocaleString()}>{timeAgo(d.ts)}</span>

            {/* Target finding link */}
            {d.target_type === "finding" && d.target_id && (
              <>
                <span className="text-border-subtle">·</span>
                <Link
                  to="/investigate/findings/$id"
                  params={{ id: d.target_id }}
                  className="text-teal hover:underline"
                  onClick={(e) => e.stopPropagation()}
                >
                  {d.target_title || d.target_id}
                </Link>
              </>
            )}

            {/* Target asset link */}
            {d.target_type === "asset" && d.target_id && (
              <>
                <span className="text-border-subtle">·</span>
                <Link
                  to="/investigate/assets/$id"
                  params={{ id: d.target_id }}
                  className="text-teal hover:underline"
                  onClick={(e) => e.stopPropagation()}
                >
                  {d.target_title || d.target_id}
                </Link>
              </>
            )}

            {/* Resource ARN */}
            {d.target_resource && (
              <>
                <span className="text-border-subtle">·</span>
                <span className="font-mono text-[11px]" title={d.target_resource}>
                  {shortenArn(d.target_resource)}
                </span>
                {d.target_type !== "asset" && (
                  <Link
                    to="/investigate/assets/$id"
                    params={{ id: d.target_resource }}
                    className="text-[11px] text-teal hover:underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    asset →
                  </Link>
                )}
              </>
            )}
          </div>
        </div>

        {/* Right side: CTA */}
        <div className="flex shrink-0 items-center gap-2" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={(e) => { e.stopPropagation(); onSelect(d); }}
            className="inline-flex items-center gap-1 rounded border border-teal/30 bg-teal/5 px-2 py-1 text-[11px] font-medium text-teal hover:bg-teal/10 transition-colors"
          >
            Review →
          </button>
        </div>
      </div>
    </div>
  );
}

function shortenArn(s: string): string {
  return shortenId(s, { keepArnType: true, maxLen: 60 });
}

function OutcomeBadge({ outcome }: { outcome?: string }) {
  if (!outcome) return null;
  const meta = OUTCOME_META[outcome];
  const tone = meta?.tone ?? "border-border-subtle bg-surface text-text-2";
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${tone}`}
      title={meta?.title}
    >
      {meta?.label ?? outcome.replace(/_/g, " ")}
    </span>
  );
}
