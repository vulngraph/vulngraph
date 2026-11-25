import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Check, ChevronDown, ChevronUp, Eye, Shield, Slash, Trash2, X, Zap } from "lucide-react";
import { errorMessage, isUnauthorized, notifyUnauthorized, type QueueItem } from "../lib/api";
import { invalidateQueue, resolveDecision, useResolveDecision } from "../lib/queries";
import { SafetyBadge } from "./SafetyBadge";
import { timeAgo as timeAgoBase } from "../lib/format";
import {
  ACTION_CLASSES,
  ACTION_LABELS,
  BORDER_COLORS,
  CONFIDENCE_BAND_TITLE,
  OUTCOME_META,
  TONE_CLASSES,
  actionTone,
  describeAction,
  labelAction,
  type ActionTone,
} from "../lib/actions";

// Shared presentation helpers for agent actions — used by the queue cards here
// and by the audit-trail cards in routes/Decisions.tsx. The label/tone tables
// themselves live in lib/actions.ts and are re-exported here.
export { ACTION_CLASSES, ACTION_LABELS, BORDER_COLORS, TONE_CLASSES, actionTone, describeAction, labelAction };
export type { ActionTone };

// ── Action-class legend — what observe/remediate/modify/isolate/destroy mean ───
// Collapsed by default so it doesn't add to page density; a "what do these
// mean?" toggle next to the filters expands it. Order mirrors ACTION_CLASSES
// (least- to most-invasive) so the ordering itself is legible.
export function ActionClassLegend() {
  return (
    <div className="grid gap-2 rounded-lg border border-border-subtle bg-surface-2 p-3 sm:grid-cols-2 lg:grid-cols-5">
      {ACTION_CLASSES.map((a) => {
        const t = TONE_CLASSES[a.tone];
        return (
          <div key={a.value} className="flex items-start gap-2">
            <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border ${t.accent}`}>
              <ActionIcon action_class={a.value} />
            </span>
            <div className="min-w-0">
              <div className={`text-[11px] font-semibold ${t.text}`}>{a.label}</div>
              <p className="text-[11px] leading-snug text-text-3">{a.description}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// Icon per action_class — mirrors ACTION_CLASSES in lib/actions.ts (5 real
// values). "modify" and any unrecognized value fall through to Shield.
export function ActionIcon({ action_class }: { action_class?: string }) {
  switch (action_class) {
    case "observe": return <Eye className="h-3.5 w-3.5" />;
    case "remediate": return <Zap className="h-3.5 w-3.5" />;
    case "isolate": return <Slash className="h-3.5 w-3.5" />;
    case "destroy": return <Trash2 className="h-3.5 w-3.5" />;
    default: return <Shield className="h-3.5 w-3.5" />;
  }
}

// timeAgo returns a relative time string for recency ("5m ago").
export function timeAgo(ts: string): string {
  return timeAgoBase(ts, "ago");
}

// ── Pattern groups — one verdict, N lessons ────────────────────────────────────

// family extracts the technique family from a cluster title: everything before
// the first ":" ("IAM privilege escalation: iam:PutRolePolicy" → "IAM privilege
// escalation"). The queue is already one cluster per check, so exact repeats are
// rare — the operational repetition is N techniques of one family, all carrying
// the same proposed action.
export function family(title: string): string {
  const i = title.indexOf(":");
  return i > 0 ? title.slice(0, i).trim() : title;
}

// Safety tiers, in governance order: what the graph says you can act on with
// confidence comes first, what needs a careful human eye comes last.
export const SAFETY_TIERS = ["safe", "caution", "risky", "unknown"] as const;
export type SafetyTier = (typeof SAFETY_TIERS)[number];

export function safetyTier(band?: string): SafetyTier {
  return band === "safe" || band === "caution" || band === "risky" ? band : "unknown";
}

// One tier of the queue: pattern groups (all members share the tier) plus
// ungrouped singletons, both sorted biggest/worst first.
export type QueueTier = { tier: SafetyTier; grouped: QueueItem[][]; singles: QueueItem[] };

// groupQueue splits one tier's items into governable pattern groups and
// singletons. Two passes: exact (same check + action, ≥2) then family (same
// title family + action, ≥3) — so 22 privesc techniques proposing the same
// right-sizing render as one verdict, not 22. Exported for the unit test.
//
// Ordering: the server sorts `items` by teaching value (closest-to-threshold
// first, unknown-confidence last) — strictly more useful than anything the
// client can invent from fields it only sees a slice of. Grouping is
// structural (which clusters get combined) and must stay; re-sorting the
// resulting groups/singletons is not our call to make, so both come out in
// server order (a group's position is its earliest member's position).
//
// Caveat worth knowing: tierQueue buckets by safety tier BEFORE calling this,
// so server order holds WITHIN a tier, not across the page — the top of the
// page is still the safest tier, not the highest teaching value. That tier
// split is deliberate (safety reads first) and predates this ordering.
export function groupQueue(items: QueueItem[]): { grouped: QueueItem[][]; singles: QueueItem[] } {
  const order = new Map(items.map((q, i) => [q.cluster_key, i]));
  const firstIndex = (g: QueueItem[]) => Math.min(...g.map((q) => order.get(q.cluster_key)!));

  const byPattern = new Map<string, QueueItem[]>();
  for (const q of items) {
    const key = `${q.check_id || q.title}::${q.action_class}`;
    byPattern.set(key, [...(byPattern.get(key) ?? []), q]);
  }
  const grouped: QueueItem[][] = [];
  let rest: QueueItem[] = [];
  for (const g of byPattern.values()) {
    if (g.length >= 2) grouped.push(g);
    else rest.push(g[0]);
  }

  // Second pass over the leftovers: family-level grouping.
  const byFamily = new Map<string, QueueItem[]>();
  for (const q of rest) {
    const key = `${family(q.title)}::${q.action_class}`;
    byFamily.set(key, [...(byFamily.get(key) ?? []), q]);
  }
  rest = [];
  for (const g of byFamily.values()) {
    if (g.length >= 3) grouped.push(g);
    else rest.push(...g);
  }

  grouped.sort((a, b) => firstIndex(a) - firstIndex(b));
  rest.sort((a, b) => order.get(a.cluster_key)! - order.get(b.cluster_key)!);
  return { grouped, singles: rest };
}

// tierQueue is the full queue shape: split by structural safety first (the
// graph's evidence about whether acting can break anything — unused principals
// and unreferenced resources land in "safe"), then pattern-grouped within each
// tier. Groups never mix tiers, so a bulk verdict is always homogeneous.
export function tierQueue(items: QueueItem[]): QueueTier[] {
  const byTier = new Map<SafetyTier, QueueItem[]>();
  for (const q of items) {
    const t = safetyTier(q.safety_band);
    byTier.set(t, [...(byTier.get(t) ?? []), q]);
  }
  return SAFETY_TIERS
    .filter((t) => (byTier.get(t)?.length ?? 0) > 0)
    .map((t) => ({ tier: t, ...groupQueue(byTier.get(t)!) }));
}

// Plain-language section headers per tier — the sub line states the graph
// evidence in the words a human governor actually thinks in.
export const TIER_META: Record<SafetyTier, { label: string; sub: string; dot: string; text: string }> = {
  safe: {
    label: "Act with confidence",
    sub: "unused or unreferenced — nothing routes to or runs as these; fixing shouldn't break anything",
    dot: "bg-emerald",
    text: "text-emerald",
  },
  caution: {
    label: "Verify first",
    sub: "stale or possibly-gone resources — worth a glance before approving",
    dot: "bg-amber",
    text: "text-amber",
  },
  risky: {
    label: "Handle with care",
    sub: "production, internet-facing, or other assets depend on these",
    dot: "bg-red",
    text: "text-red",
  },
  unknown: {
    label: "Not yet assessed",
    sub: "no structural safety signal yet — treat as verify-first",
    dot: "bg-border-subtle",
    text: "text-text-3",
  },
};

type Verdict = "approved" | "risk_accepted" | "denied";

// PatternGroupCard renders N same-pattern clusters as one governable unit.
// Bulk verdicts are two-step (arm → confirm) and resolve sequentially, writing
// one outcome per cluster into the confidence ledger — this is how the human
// teaches the agent at the pattern level instead of click-by-click.
// BulkResult is what a finished, partly failed bulk run reports back.
type BulkResult = { ok: number; failed: number; skipped: number; total: number; error: string };

export function PatternGroupCard({ group, isAdmin }: { group: QueueItem[]; isAdmin: boolean }) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [arming, setArming] = useState<Verdict | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [result, setResult] = useState<BulkResult | null>(null);
  // Clusters already resolved by an earlier (partly failed) run — a retry
  // must not resolve them twice before the queue refetch drops them.
  const resolvedKeys = useRef(new Set<string>());

  const head = group[0];
  const tone = actionTone(head.action_class);
  const toneClasses = TONE_CLASSES[tone];
  const findings = group.reduce((n, q) => n + q.count, 0);
  const resources = group.reduce((n, q) => n + q.resources, 0);
  const worst = Math.max(...group.map((q) => q.worst_score));
  const unused = group.reduce((n, q) => n + (q.unused_count ?? 0), 0);
  // Family groups hold distinct techniques — title by the family, not one member.
  const sameCheck = group.every((q) => (q.check_id || q.title) === (head.check_id || head.title));
  const groupTitle = sameCheck ? head.title : `${family(head.title)} — ${group.length} techniques`;

  // bulk resolves the clusters one by one. A failure doesn't abort the run
  // (other clusters may still succeed) unless the session is gone. Whatever
  // happens the buttons come back, a partial failure is reported with counts,
  // and the queue + decision trail are refetched once at the end (not per
  // cluster, which re-grouped the card out from under the loop).
  async function bulk(v: Verdict) {
    const pending = group.filter((q) => !resolvedKeys.current.has(q.cluster_key));
    setArming(null);
    setResult(null);
    setProgress({ done: 0, total: pending.length });
    let ok = 0;
    let failed = 0;
    let firstError = "";
    try {
      for (const q of pending) {
        try {
          await resolveDecision({
            finding_ids: q.finding_ids,
            cluster_key: q.cluster_key,
            action_class: q.action_class,
            verdict: v,
            note: `bulk verdict across ${group.length} clusters of ${sameCheck ? head.check_id || head.title : family(head.title)}`,
          });
          resolvedKeys.current.add(q.cluster_key);
          ok++;
        } catch (e) {
          failed++;
          firstError ||= errorMessage(e);
          if (isUnauthorized(e)) {
            notifyUnauthorized();
            break;
          }
        }
        setProgress((p) => (p ? { ...p, done: p.done + 1 } : p));
      }
    } finally {
      setProgress(null);
      if (failed > 0) {
        setResult({ ok, failed, skipped: pending.length - ok - failed, total: pending.length, error: firstError });
      }
      void invalidateQueue(qc);
    }
  }

  const VERDICTS: { v: Verdict; label: string; cls: string }[] = [
    { v: "approved", label: "Approve all", cls: "border-teal/30 bg-teal/10 text-teal hover:bg-teal/20" },
    { v: "risk_accepted", label: "Accept risk", cls: "border-amber/30 bg-amber/10 text-amber hover:bg-amber/20" },
    { v: "denied", label: "Deny all", cls: "border-red/30 bg-red/10 text-red hover:bg-red/20" },
  ];

  return (
    <div
      className={`overflow-hidden rounded-xl border bg-surface-2 ${toneClasses.border}`}
      style={{ borderLeft: `3px solid ${BORDER_COLORS[tone]}` }}
    >
      <div className="flex items-start gap-3 p-3">
        <div className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded ${toneClasses.accent}`}>
          <ActionIcon action_class={head.action_class} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-start gap-2">
            <span className="rounded border border-border-subtle bg-surface-3 px-1.5 py-0.5 text-[11px] font-medium tabular-nums text-text-2">
              {group.length}× same pattern
            </span>
            <span className="text-[13px] font-medium leading-snug text-text">{groupTitle}</span>
            <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${toneClasses.accent}`}>
              {labelAction(head.action_class)}
            </span>
            <SafetyBadge band={head.safety_band} className="shrink-0" />
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-text-3">
            <span>{group.length} clusters · {findings} findings · {resources} resources</span>
            {unused > 0 && (
              <span className="rounded border border-emerald/30 bg-emerald/10 px-1.5 py-0.5 font-medium text-emerald">
                {unused} of {findings} targets unused
              </span>
            )}
            <span>worst score <span className="tabular-nums text-text-2">{worst}</span></span>
            <span className="text-teal/80">one verdict teaches the ledger {group.length} lessons</span>
            <button
              className="flex items-center gap-1 text-text-3 hover:text-text-2"
              onClick={() => setExpanded((x) => !x)}
            >
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {expanded ? "hide" : "show"} clusters
            </button>
          </div>
          {progress && (
            <div className="mt-2 text-[11px] tabular-nums text-teal">
              resolving {progress.done}/{progress.total}…
            </div>
          )}
          {result && !progress && (
            <div role="alert" className="mt-2 rounded border border-red/30 bg-red/5 px-2.5 py-1.5 text-[11px] text-red">
              Resolved {result.ok} of {result.total} clusters — {result.failed} failed
              {result.skipped > 0 ? `, ${result.skipped} not attempted` : ""}: {result.error}
              {isAdmin && <span className="text-text-3"> · pick a verdict again to retry the rest</span>}
            </div>
          )}
          {arming && !progress && (
            <div className="mt-2 flex items-center gap-2 rounded border border-amber/30 bg-amber/5 px-2.5 py-1.5 text-[11px]">
              <span className="text-amber">
                {arming === "denied" ? "Deny" : arming === "approved" ? "Approve" : "Accept risk on"} all {group.length} clusters?
              </span>
              <button
                onClick={() => void bulk(arming)}
                className="rounded border border-amber/40 bg-amber/15 px-2 py-0.5 font-medium text-amber hover:bg-amber/25"
              >
                Confirm
              </button>
              <button onClick={() => setArming(null)} className="text-text-3 hover:text-text-2">cancel</button>
            </div>
          )}
        </div>
        {isAdmin && !progress && !arming && (
          <div className="flex shrink-0 flex-col gap-1.5 sm:flex-row sm:items-center">
            {VERDICTS.map(({ v, label, cls }) => (
              <button
                key={v}
                onClick={() => setArming(v)}
                className={`flex items-center gap-1 rounded border px-2.5 py-1.5 text-[11px] font-medium transition-colors disabled:opacity-40 ${cls}`}
              >
                {v === "approved" && <Check className="h-3 w-3" />}
                {v === "denied" && <X className="h-3 w-3" />}
                {label}
              </button>
            ))}
          </div>
        )}
      </div>
      {expanded && (
        <div className="space-y-2 border-t border-border-subtle/40 bg-surface/40 p-3">
          {group.map((q) => (
            <QueueCard key={q.cluster_key} item={q} isAdmin={isAdmin} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Queue card — one actionable cluster needing a human verdict ────────────────

export function QueueCard({ item: q, isAdmin }: { item: QueueItem; isAdmin: boolean }) {
  const resolve = useResolveDecision();
  const [expanded, setExpanded] = useState(false);
  const tone = actionTone(q.action_class);
  const toneClasses = TONE_CLASSES[tone];
  const hasConcerns = (q.cove_concerns?.length ?? 0) > 0;

  function verdict(v: Verdict) {
    resolve.mutate({
      finding_ids: q.finding_ids,
      cluster_key: q.cluster_key,
      action_class: q.action_class,
      verdict: v,
    });
  }

  return (
    <div className={`rounded-xl border bg-surface-2 overflow-hidden activity-shimmer-hover ${toneClasses.border} ${tone === 'red' ? 'card-critical' : ''}`}
         style={{ borderLeft: `3px solid ${BORDER_COLORS[tone]}` }}>
      <div className="flex items-start gap-3 p-3">
        {/* Accent icon */}
        <div className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded ${toneClasses.accent}`}>
          <ActionIcon action_class={q.action_class} />
        </div>
        <div className="flex-1 min-w-0">
          {/* Top row: title + action badge */}
          <div className="flex items-start gap-2 flex-wrap">
            <span className="text-[13px] font-medium text-text leading-snug">{q.title}</span>
            <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase shrink-0 ${toneClasses.accent}`}>
              {labelAction(q.action_class)}
            </span>
            {OUTCOME_META[q.outcome] && (
              <span
                className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase shrink-0 ${OUTCOME_META[q.outcome].tone}`}
                title={OUTCOME_META[q.outcome].title}
              >
                {OUTCOME_META[q.outcome].label}
              </span>
            )}
            <SafetyBadge band={q.safety_band} className="shrink-0" />
          </div>
          {/* Summary — always visible */}
          {q.summary && <p className="mt-1 text-[12px] leading-relaxed text-text">{q.summary}</p>}
          {/* Meta row */}
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-text-3">
            {q.confidence_band && (
              <span>confidence: <span className="text-text-2" title={CONFIDENCE_BAND_TITLE[q.confidence_band]}>{q.confidence_band}</span></span>
            )}
            {(q.unused_count ?? 0) > 0 && (
              <span className="rounded border border-emerald/30 bg-emerald/10 px-1.5 py-0.5 font-medium text-emerald">
                {q.unused_count} of {q.count} targets unused
              </span>
            )}
            {/* blast_radius is a MAX across the cluster's findings while
                blast_radius_known is an AND (govern/service.go's
                clusterQueue) — a cluster with one finding measuring 12 and
                three failed walks reads as blast_radius:12,
                blast_radius_known:false. Gating the caveat on
                blast_radius === 0 alone would miss exactly that case: it
                isn't 0, so it would never show the unmeasured note and
                would render a confident "blast radius: 12" instead. */}
            {q.blast_radius > 0 && (
              <span className="text-amber">
                blast radius: {q.blast_radius}
                {q.blast_radius_known === false && (
                  <span title="At least one OTHER finding in this cluster had a failed blast-radius walk — the true max may be higher than shown.">
                    {" "}(partially unmeasured)
                  </span>
                )}
              </span>
            )}
            {q.blast_radius === 0 && q.blast_radius_known === false && (
              <span className="text-amber" title="At least one finding in this cluster had a failed blast-radius walk — this is not evidence the cluster's reach is small.">
                blast radius unmeasured
              </span>
            )}
            {q.count > 1 && <span>{q.count} findings · {q.resources} resources</span>}
            {/* Teaching-value metadata — decision-support, kept subtle. A gap is
                only meaningful once the confidence lookup succeeded; a
                failed/unwired lookup (confidence_known !== true) is not a
                measurement and must never render as "gap 0". */}
            {q.confidence_known === true && (q.confidence_gap ?? 0) > 0 && (
              <span title="Evidence weight still needed before similar proposals count as high confidence — they still need approval">
                {q.confidence_gap} more evidence to high confidence
              </span>
            )}
            {(q.unlocks ?? 0) > 0 && (
              <span
                className="text-teal/80"
                title="Other pending decisions share this confidence key — resolving this one grows their evidence too"
              >
                approving this also advances {q.unlocks} similar decision{q.unlocks === 1 ? "" : "s"}
              </span>
            )}
            {/* decided_at is the most recent fresh-reasoning timestamp across the
                WHOLE cluster (the max over every finding it bundles), not when
                this specific card was created and not a per-finding value —
                labeled so it doesn't read as a narrower claim than it is. */}
            <span title="Most recent reasoning refresh across this cluster's findings">
              reasoning refreshed {timeAgo(q.decided_at)}
            </span>
            {q.check_id && (
              <Link to="/investigate/findings" search={{ q: q.check_id } as Record<string, string>} className="text-teal hover:underline">
                findings →
              </Link>
            )}
          </div>
          {/* CoVe concerns toggle */}
          {hasConcerns && (
            <button
              className="mt-1.5 flex items-center gap-1 text-[11px] text-text-3 hover:text-text-2"
              aria-label={expanded ? "Collapse" : "Expand"}
              onClick={(e) => { e.stopPropagation(); setExpanded((v) => !v); }}
            >
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {q.cove_concerns!.length} concern{q.cove_concerns!.length !== 1 ? "s" : ""}
            </button>
          )}
          {resolve.isError && (
            <p role="alert" className="mt-1.5 text-[11px] text-red">
              Couldn't record the verdict: {errorMessage(resolve.error)}
            </p>
          )}
          {expanded && hasConcerns && (
            <div className="mt-2 rounded border border-amber/20 bg-amber/5 px-2.5 py-2 text-[11px]">
              <div className="mb-1 font-medium text-amber uppercase text-[11px] tracking-wide">CoVe concerns</div>
              {q.cove_concerns!.map((c, i) => (
                <div key={i} className="mt-0.5 text-text-2">· {c}</div>
              ))}
            </div>
          )}
        </div>
        {/* Action buttons — admin only */}
        {isAdmin && (
          <div className="flex shrink-0 flex-col gap-1.5 sm:flex-row sm:items-center">
            <button
              onClick={() => verdict("approved")}
              disabled={resolve.isPending}
              className="flex items-center gap-1 rounded border border-teal/30 bg-teal/10 px-2.5 py-1.5 text-[11px] font-medium text-teal hover:bg-teal/20 disabled:opacity-40 transition-colors"
            >
              <Check className="h-3 w-3" /> Approve
            </button>
            <button
              onClick={() => verdict("risk_accepted")}
              disabled={resolve.isPending}
              className="flex items-center gap-1 rounded border border-amber/30 bg-amber/10 px-2.5 py-1.5 text-[11px] font-medium text-amber hover:bg-amber/20 disabled:opacity-40 transition-colors"
            >
              Accept risk
            </button>
            <button
              onClick={() => verdict("denied")}
              disabled={resolve.isPending}
              className="flex items-center gap-1 rounded border border-red/30 bg-red/10 px-2.5 py-1.5 text-[11px] font-medium text-red hover:bg-red/20 disabled:opacity-40 transition-colors"
            >
              <X className="h-3 w-3" /> Deny
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
