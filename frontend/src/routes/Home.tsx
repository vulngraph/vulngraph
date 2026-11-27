import { useState, type ElementType } from "react";
import { Link } from "@tanstack/react-router";
import {
  ShieldAlert, CheckCircle2, ShieldCheck, Plus, GitCompareArrows,
  MessageSquare, ChevronDown,
} from "lucide-react";
import {
  useAssetSummary,
  useCompliance,
  useConnectors,
  useDecisions,
  useDecisionsSummary,
  useDriftEvents,
  useFindingClusters,
  useFindingSummary,
  useGraphStats,
  useGraphStatus,
  useQueue,
  type DriftEvent,
} from "../lib/queries";
import { ErrorNote, Loading, ScoreBadge } from "../components/ui";
import { ConnectSourceNotice } from "../components/ConnectSourceNotice";
import { tierQueue } from "../components/queue";
import { OUTCOME_META } from "../lib/actions";
import { timeAgo as timeAgoBase, scoreToBand, SCORE_THRESHOLDS } from "../lib/format";
import { openAssistant } from "../lib/assistant";
import { graphStateLabel } from "../lib/graphStatus";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

// Every number on this page goes through fmt — an unseparated "12345" reads as
// noise, "12,345" reads as a quantity.
const fmt = (n: number) => n.toLocaleString("en-US");

// Home has exactly three levels, top to bottom, and nothing else:
//   1. What should I do right now?  → two action cards, one number each
//   2. Is the system healthy?       → four tiles, one number + one sentence each
//   3. What's new?                  → signals, changes, decisions
// The four-stage pipeline strip is a single quiet footer line: its numbers all
// live somewhere above, so as a grid of cells it was pure duplication.
export function Home() {
  const summary = useFindingSummary();
  const clusters = useFindingClusters();
  const compliance = useCompliance();
  const connectors = useConnectors();
  const decisions = useDecisions();
  const queue = useQueue();
  const graphStatus = useGraphStatus();
  const graphStats = useGraphStats();
  const assetSummary = useAssetSummary();
  const drift = useDriftEvents("24h");

  const bands = summary.data?.by_band ?? {};
  // The page band IS the "fix now" number. The high band is fix-soon, so
  // adding it would inflate the headline.
  const page = bands.page ?? 0;
  const high = bands.high ?? 0;
  const pipeline = bands.pipeline ?? 0;
  const monitor = bands.monitor ?? 0;
  // Unenriched = findings with no band (score=0, awaiting enrichment after sync)
  const bandTotal = page + high + pipeline + monitor;
  const unenriched = summary.data ? summary.data.total - bandTotal : 0;

  // A failed /api/connectors request must never collapse to the same 0/0 an
  // account with zero configured connectors would show — that reads as
  // "perfectly healthy" during an outage. connError is checked everywhere
  // okConn/totalConn/pendingConn feed a verdict below.
  const connError = connectors.isError;
  const okConn = connectors.data?.filter((c) => c.sync_status === "ok").length ?? 0;
  const totalConn = connectors.data?.length ?? 0;
  const pendingConn = totalConn - okConn;
  // Nothing connected yet: every zero on this page is "no data", not "all clear".
  const firstRun = connectors.isSuccess && totalConn === 0;

  const lastDecision = decisions.data?.items?.[0]?.ts;
  const lastSync = connectors.data
    ?.map((c) => c.last_synced_at).filter((x): x is string => !!x).sort().at(-1);

  const decItems = decisions.data?.items ?? [];
  // Whole-trail outcome tallies for the footer's Learn segment — server-side
  // aggregates, not a fold over the first page of the paginated list (that
  // badly undercounted once the trail outgrew one page).
  const decisionsSummary = useDecisionsSummary();
  const awaitingApproval = decisionsSummary.data?.parked_for_approval ?? 0;
  const escalatedTotal = decisionsSummary.data?.escalated ?? 0;

  const topClusters = (clusters.data?.items ?? [])
    .filter((c) => c.worst_band !== "monitor")
    .slice(0, 5);

  const failCount = (compliance.data?.total ?? 0) - (compliance.data?.passing ?? 0);

  // Latest decision, for the footer strip.
  const latestDec = decItems[0];

  // Queue — items awaiting human approval.
  const queueItems = queue.data?.items ?? [];

  // Recent decisions for the decisions section (last 5).
  const recentDecisions = decItems.slice(0, 5);

  // Distinct verdicts the queue actually needs (pattern groups count as one) —
  // "80 proposals" sounds like an afternoon; "5 verdicts" is the truth.
  const patternCount = tierQueue(queueItems).reduce(
    (n, t) => n + t.grouped.length + t.singles.length, 0,
  );

  const assetTotal = assetSummary.data?.total;

  // Drift — newest-first inventory/exposure changes in the last 24h; exposure
  // changes rank above benign new-asset noise so the worst change leads.
  const driftRank: Record<DriftEvent["kind"], number> = {
    new_exposure: 0, changed: 1, new_asset: 2, removed_exposure: 3,
  };
  const allDrift = drift.data?.events ?? [];
  const driftEvents = [...allDrift]
    .sort((a, b) =>
      driftRank[a.kind] - driftRank[b.kind] ||
      (b.detected_at > a.detected_at ? 1 : -1)
    )
    .slice(0, 6);
  // /api/drift/events hard-caps at 200 with no total field returned — a length
  // of exactly 200 is the cap being hit, not a true count, so it's disclosed
  // with a "+" rather than presented as an exact population.
  const driftTotal = allDrift.length;
  const driftAtCap = driftTotal >= 200;
  const newExposures = allDrift.filter((e) => e.kind === "new_exposure").length;

  // Graph size — feeds the footer's Correlate segment. Counts from a graph
  // that is not ready (never built, rebuilding) are not its size.
  const graphNodes = (() => {
    const stats = graphStats.data;
    if (!stats?.ready) return null;
    const total = stats.nodes.assets + stats.nodes.roles + stats.nodes.repos;
    return total >= 1000 ? `${Math.round(total / 100) / 10}k` : String(total);
  })();

  return (
    <div className="space-y-7">
      {/* Header — identity and freshness only; the action cards below are the verdict */}
      <div className="flex items-baseline justify-between gap-4">
        <h1 className="font-display text-2xl font-semibold tracking-tight text-text">Security posture</h1>
        <p className="shrink-0 text-right text-[12px] text-text-3 tabular-nums">
          synced {timeAgo(lastSync ?? undefined)} · last decision {timeAgo(lastDecision ?? undefined)}
        </p>
      </div>

      {firstRun && <ConnectSourceNotice variant="panel" />}

      {/* ── 1. What should I do right now? Exactly two doors. ── */}
      <div className="grid gap-3 sm:grid-cols-2">
        <ActionCard
          value={summary.data ? fmt(page) : "…"}
          headline={
            page === 1 ? "finding needs a fix now" : "findings need a fix now"
          }
          zero={summary.data != null && page === 0}
          zeroHeadline="Nothing needs a fix right now"
          sub={`Scored ${SCORE_THRESHOLDS.page} or above: the highest risk band.`}
          zeroSub={`No open finding scores ${SCORE_THRESHOLDS.page} or above.`}
          cta="Start fixing"
          href="/investigate/findings"
          icon={ShieldAlert}
        />
        <ActionCard
          value={fmt(patternCount)}
          headline={patternCount === 1 ? "verdict awaits you" : "verdicts await you"}
          zero={queueItems.length === 0}
          zeroHeadline="No verdicts waiting"
          sub={`Covering ${fmt(queueItems.length)} agent proposal${queueItems.length === 1 ? "" : "s"} — denials and the fixes you run teach it what to propose.`}
          zeroSub="The agent has nothing parked for you."
          cta="Give verdicts"
          href="/decisions"
          icon={CheckCircle2}
        />
      </div>

      {/* ── 2. Is the system healthy? One number, one sentence, per tile. ── */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <MetricCard
          value={compliance.data ? `${fmt(compliance.data.passing)} of ${fmt(compliance.data.total)}` : "—"}
          label="benchmark controls passing"
          sub={
            firstRun ? "connect a source to evaluate controls"
              : compliance.data ? (failCount > 0 ? `${fmt(failCount)} failing` : "all controls passing") : undefined
          }
          accent={compliance.data && failCount === 0 ? "emerald" : "amber"}
          error={compliance.isError}
          errorLabel="Could not load compliance status"
          href="/compliance"
        />
        <MetricCard
          value={`${fmt(okConn)}/${fmt(totalConn)}`}
          label="connectors synced"
          sub={pendingConn > 0 ? `${fmt(pendingConn)} pending sync` : `synced ${timeAgo(lastSync ?? undefined)}`}
          accent={pendingConn > 0 ? "amber" : "emerald"}
          error={connError}
          errorLabel="Could not verify connector status"
          href="/settings"
        />
        <MetricCard
          value={summary.data ? fmt(monitor) : "—"}
          label="findings scored below the pipeline threshold"
          sub={
            unenriched > 500
              ? `${fmt(unenriched)} still enriching`
              : `${fmt(pipeline)} more in the pipeline`
          }
          accent="text"
          error={summary.isError}
          errorLabel="Could not load findings"
          href="/investigate/findings"
        />
        <MetricCard
          value={drift.data ? `${fmt(driftTotal)}${driftAtCap ? "+" : ""}` : "—"}
          label="inventory changes in 24 hours"
          sub={!drift.data ? undefined : newExposures > 0 ? `${fmt(newExposures)} newly exposed` : "nothing newly exposed"}
          accent={newExposures > 0 ? "red" : "text"}
          error={drift.isError}
          errorLabel="Could not load drift events"
          href="/investigate/drift"
        />
      </div>

      {/* ── 3. What's new? ── */}

      {/* Signals */}
      {clusters.isLoading && <Loading />}
      {clusters.isError && <ErrorNote message="Could not load findings." />}
      {topClusters.length > 0 && (
        <section>
          <SectionHeader
            title="Signals"
            note="Highest-scored open findings"
            linkLabel="View all findings"
            href="/investigate/findings"
          />
          <div className="glass overflow-hidden rounded-xl">
            {topClusters.map((c) => (
              <ClusterRow key={c.check_id} cluster={c} />
            ))}
          </div>
        </section>
      )}

      {topClusters.length === 0 && !clusters.isLoading && !firstRun && (
        connError ? (
          // Connector status is unknown, not confirmed healthy — never let this
          // fall through to the emerald "everything's fine" copy below.
          <div className="rounded-lg border border-red/30 bg-red/10 px-4 py-3 text-[13px] text-red">
            No findings shown — connector status could not be loaded, so this may reflect an outage rather than a clean bill of health.{" "}
            <Link to="/settings" className="underline hover:text-red/80">Check connectors →</Link>
          </div>
        ) : pendingConn > 0 ? (
          <div className="rounded-lg border border-amber/30 bg-amber/5 px-4 py-3 text-[13px] text-amber">
            No findings shown — {fmt(pendingConn)} connector{pendingConn !== 1 ? "s" : ""} pending sync.{" "}
            <Link to="/settings" className="underline hover:text-amber/80">Check connectors →</Link>
          </div>
        ) : (
          <div className="rounded-lg border border-emerald/30 bg-emerald/10 px-4 py-3 text-[13px] text-emerald">
            No actionable findings right now.{" "}
            <Link to="/investigate/findings" className="underline hover:text-emerald/80">Review all findings →</Link>
          </div>
        )
      )}

      {/* Recent changes — drift in the last 24h */}
      {driftEvents.length > 0 && (
        <section>
          <SectionHeader
            title="Recent changes"
            note={`${fmt(driftTotal)}${driftAtCap ? "+" : ""} inventory and exposure change${driftTotal !== 1 ? "s" : ""} in the last 24 hours${driftAtCap ? " (capped at 200)" : ""}`}
            linkLabel="View all changes"
            href="/investigate/drift"
          />
          <div className="glass overflow-hidden rounded-xl">
            {driftEvents.map((e) => (
              <DriftRow key={`${e.kind}:${e.asset_id}:${e.detected_at}`} event={e} />
            ))}
          </div>
        </section>
      )}

      {/* Recent decisions */}
      {recentDecisions.length > 0 && (
        <section>
          <SectionHeader
            title="Recent decisions"
            note="What the agent and your team decided"
            linkLabel="View all decisions"
            href="/decisions"
          />
          <div className="glass overflow-hidden rounded-xl">
            {recentDecisions.map((d) => (
              <DecisionRow key={d.id} decision={d} />
            ))}
          </div>
        </section>
      )}

      {/* The four loops as one quiet line — the links still go somewhere
          useful, but the numbers do not compete with the tiles. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-border-subtle pt-3 text-[12px] text-text-3">
        <LoopLink
          name="Sense"
          fact={`synced ${timeAgo(lastSync ?? undefined)}`}
          href="/investigate/drift"
        />
        <LoopLink
          name="Correlate"
          fact={
            graphNodes
              ? `${graphNodes} nodes${assetTotal != null ? ` · ${fmt(assetTotal)} assets` : ""}`
              : graphStateLabel(graphStatus.data)
          }
          href="/investigate/graph"
        />
        <LoopLink
          name="Decide"
          fact={latestDec ? `${latestDec.actor} ${latestDec.action} · ${timeAgo(latestDec.ts)}` : "nothing decided yet"}
          href="/decisions"
        />
        <LoopLink
          name="Learn"
          fact={
            decisionsSummary.data
              ? `${fmt(awaitingApproval)} awaiting approval · ${fmt(escalatedTotal)} escalated`
              : "—"
          }
          href="/decisions"
        />
      </div>
    </div>
  );
}

// SectionHeader — one title, one plain-language note, one "view all" link. The
// previous version repeated the count in monospace uppercase micro-type.
function SectionHeader({
  title, note, linkLabel, href,
}: { title: string; note: string; linkLabel: string; href: string }) {
  return (
    <div className="mb-2.5 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 border-b border-border-subtle pb-2">
      <h2 className="text-[15px] font-semibold text-text">{title}</h2>
      <span className="text-[12px] text-text-3">{note}</span>
      <Link to={href} className="ml-auto shrink-0 text-[13px] text-teal hover:underline">
        {linkLabel} →
      </Link>
    </div>
  );
}

function ClusterRow({ cluster: c }: { cluster: import("../lib/api").FindingCluster }) {
  const [expanded, setExpanded] = useState(false);

  // Score is zero but findings exist — enrichment still pending.
  const enriching = c.max_score === 0 && c.instances > 0;

  // Build the inline factors line: KEV, blast radius, resources count.
  type Factor = { kind: "kev" } | { kind: "count"; count: number; label: string };
  const factors: Factor[] = [];
  if (c.known_exploited) factors.push({ kind: "kev" });
  if (c.resources > 1) factors.push({ kind: "count", count: c.resources, label: "resources" });
  if (c.instances > 1) factors.push({ kind: "count", count: c.instances, label: "instances" });

  // Truncated remediation for inline preview (first sentence, max 120 chars).
  const remediationPreview = c.remediation
    ? (() => {
        const first = c.remediation.split(/\.\s/)[0];
        return first.length > 120 ? first.slice(0, 118) + "…" : first;
      })()
    : undefined;

  return (
    <div className="border-b border-border-subtle/40 last:border-0">
      {/* One link target per row (the title) plus an expand toggle — the row used
          to offer three competing ways to reach the same findings page. */}
      <div className="flex items-center gap-3 px-4 py-3 hover:bg-surface/50">
        <div className="flex shrink-0 flex-col items-center gap-0.5">
          {enriching ? (
            <span className="animate-pulse text-[12px] text-text-3">enriching…</span>
          ) : (
            <ScoreBadge score={c.max_score} band={c.worst_band} />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <Link
            to="/investigate/findings"
            search={{ q: c.check_id } as Record<string, string>}
            className="block truncate text-sm text-text hover:text-teal hover:underline"
          >
            {c.title}
          </Link>
          <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
            {factors.map((f, i) =>
              f.kind === "kev" ? (
                <span key={i} title="Known exploited vulnerability" className="rounded border border-red/30 bg-red/10 px-1 py-0.5 text-[11px] font-medium uppercase text-red">
                  KEV
                </span>
              ) : (
                <span key={i} className="inline-flex items-center gap-1 text-[12px] text-text-3">
                  <span className="rounded bg-teal/10 px-1.5 py-0.5 text-[12px] font-medium tabular-nums text-teal">{fmt(f.count)}</span>
                  {f.label}
                </span>
              )
            )}
            {factors.length > 0 && <span className="text-[12px] text-text-3">·</span>}
            <span className="text-[12px] text-text-3">{timeAgo(c.last_detected)}</span>
          </div>
        </div>

        <button
          onClick={() => setExpanded((v) => !v)}
          className="shrink-0 text-text-2 transition-colors hover:text-text"
          title={expanded ? "Collapse" : "Expand"}
        >
          <ChevronDown
            style={{ width: "14px", height: "14px" }}
            className={`transition-transform duration-150 ${expanded ? "rotate-180" : ""}`}
          />
        </button>
      </div>

      {/* Inline preview */}
      {expanded && (remediationPreview || c.instances > 0) && (
        <div className="border-t border-border-subtle/30 bg-surface/40 px-4 py-2.5">
          {remediationPreview && (
            <p className="text-[13px] leading-relaxed text-text-2">
              <span className="font-medium text-teal">Fix: </span>
              {remediationPreview}
            </p>
          )}
          <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[12px] text-text-3">
            <Link
              to="/investigate/findings"
              search={{ q: c.check_id } as Record<string, string>}
              className="text-teal hover:underline"
            >
              View all {fmt(c.instances)} instance{c.instances !== 1 ? "s" : ""} →
            </Link>
            <button
              className="flex items-center gap-1 text-[12px] text-sky hover:underline"
              onClick={(e) => {
                e.stopPropagation();
                const facts = [`Check: ${c.check_id}`, `${c.instances} instance${c.instances !== 1 ? "s" : ""}`, `Score: ${c.max_score}`];
                if (c.known_exploited) facts.push("KEV: yes");
                if (c.remediation) facts.push(`Remediation: ${c.remediation.split(/\.\s/)[0]}`);
                openAssistant({ subject: `Finding: ${c.title}`, facts, question: "What is the risk and blast radius?" });
              }}
            >
              <MessageSquare style={{ width: "10px", height: "10px" }} />
              Ask AI →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function DecisionRow({ decision: d }: { decision: import("../lib/api").Decision }) {
  // Parse outcome from details JSON blob; fall back to action string.
  let outcome = "";
  try { outcome = (JSON.parse(d.details ?? "{}") as { outcome?: string }).outcome ?? ""; } catch { /* ignore */ }

  const meta = OUTCOME_META[outcome];
  const outcomeStyle = meta?.tone ?? "border-border-subtle bg-surface text-text-3";
  const outcomeLabel = meta?.label ?? d.action.slice(0, 12);

  const summary = d.target_title ? `${d.action} on ${d.target_title}` : d.action;
  const summaryShort = summary.length > 72 ? summary.slice(0, 70) + "…" : summary;

  return (
    <Link
      to="/decisions"
      className="flex items-center gap-3 border-b border-border-subtle/40 px-4 py-2.5 transition-colors last:border-0 hover:bg-surface/50"
    >
      <span className="w-16 shrink-0 truncate text-[12px] text-text-3">{d.actor}</span>
      <span className="min-w-0 flex-1 truncate text-[13px] text-text-2">{summaryShort}</span>
      <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[12px] font-medium ${outcomeStyle}`}>
        {outcomeLabel}
      </span>
      <span className="w-16 shrink-0 text-right text-[12px] tabular-nums text-text-3">{timeAgo(d.ts)}</span>
    </Link>
  );
}

// Drift kind presentation: icon + label + colour. new_exposure is the dangerous
// one (an asset just became reachable), removed_exposure is good news.
const DRIFT_KIND: Record<DriftEvent["kind"], { icon: ElementType; label: string; color: string }> = {
  new_exposure:     { icon: ShieldAlert,       label: "Now exposed",   color: "text-red" },
  removed_exposure: { icon: ShieldCheck,       label: "Exposure gone", color: "text-emerald" },
  new_asset:        { icon: Plus,              label: "New asset",     color: "text-teal" },
  changed:          { icon: GitCompareArrows,  label: "Changed",       color: "text-amber" },
};

const DRIFT_KIND_FALLBACK = { icon: ShieldAlert, label: "Changed", color: "text-text-3" };

function DriftRow({ event: e }: { event: DriftEvent }) {
  const kind = DRIFT_KIND[e.kind] ?? DRIFT_KIND_FALLBACK;
  const Icon = kind.icon;

  // Prefer the backend's human explanation; otherwise fall back to type ·
  // account context.
  const detail = e.why
    ? e.why
    : [e.asset_type, e.account_id].filter(Boolean).join(" · ");
  const detailShort = detail.length > 80 ? detail.slice(0, 78) + "…" : detail;
  const nameShort = e.asset_name.length > 40 ? e.asset_name.slice(0, 38) + "…" : e.asset_name;

  return (
    <Link
      to="/investigate/drift"
      className="flex items-center gap-3 border-b border-border-subtle/40 px-4 py-2.5 transition-colors last:border-0 hover:bg-surface/50"
    >
      <Icon className={`h-3.5 w-3.5 shrink-0 ${kind.color}`} />
      <span className={`w-[92px] shrink-0 text-[12px] font-medium ${kind.color}`}>{kind.label}</span>
      <span className="min-w-0 flex-1 truncate text-[13px] text-text">
        {nameShort}
        {detailShort && <span className="text-text-3"> — {detailShort}</span>}
      </span>
      {e.findings_count > 0 && e.max_score > 0 && (
        <span className="shrink-0"><ScoreBadge score={e.max_score} band={scoreToBand(e.max_score)} /></span>
      )}
      <span className="w-14 shrink-0 text-right text-[12px] tabular-nums text-text-3">{timeAgo(e.detected_at)}</span>
    </Link>
  );
}

// ActionCard is one of the two doors at the top of Home: one big number, one
// plain sentence, one call to action. Amber framing when work exists, quiet
// emerald when the answer is "nothing".
function ActionCard({
  value, headline, sub, zeroHeadline, zeroSub, cta, href, icon: Icon, zero,
}: {
  value: string;
  headline: string;
  sub: string;
  zeroHeadline: string;
  zeroSub: string;
  cta: string;
  href: string;
  icon: ElementType;
  zero: boolean;
}) {
  const frame = zero
    ? "border-emerald/25 hover:bg-emerald/5"
    : "border-amber/40 bg-amber/5 hover:bg-amber/10";
  const valueColor = zero ? "text-emerald" : "text-amber";
  return (
    <Link to={href} className={`flex items-center gap-4 rounded-xl border px-4 py-4 transition-colors ${frame}`}>
      <Icon className={`h-5 w-5 shrink-0 ${valueColor}`} />
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-baseline gap-x-2">
          {!zero && (
            <span className={`font-display text-3xl font-semibold leading-none tabular-nums ${valueColor}`}>{value}</span>
          )}
          <span className={`text-[15px] font-medium ${zero ? "text-emerald" : "text-text"}`}>
            {zero ? zeroHeadline : headline}
          </span>
        </span>
        <span className="mt-1 block text-[13px] leading-snug text-text-2">{zero ? zeroSub : sub}</span>
      </span>
      {!zero && <span className={`shrink-0 text-[13px] font-medium ${valueColor}`}>{cta} →</span>}
    </Link>
  );
}

// LoopLink — one segment of the Sense → Correlate → Decide → Learn footer.
function LoopLink({ name, fact, href }: { name: string; fact: string; href: string }) {
  return (
    <Link to={href} className="group inline-flex items-baseline gap-1.5 hover:text-text">
      <span className="font-medium text-text-2 group-hover:text-teal">{name}</span>
      <span className="tabular-nums">{fact}</span>
    </Link>
  );
}

// MetricCard — one number, one sentence-case label, one optional quiet sub-line.
// `error` renders a request failure — visually distinct from both a healthy
// value and the "still loading" placeholder ("—"), so a failed fetch never
// looks like a query that just hasn't returned yet. A red exclamation reads as
// "something is wrong" in a way "—" does not.
function MetricCard({
  value, label, sub, accent, href, error, errorLabel,
}: {
  value: string;
  label: string;
  sub?: string;
  accent: "red" | "amber" | "emerald" | "teal" | "text";
  href: string;
  error?: boolean;
  errorLabel?: string;
}) {
  const effectiveAccent = error ? "red" : accent;
  const valueColor = {
    red: "text-red", amber: "text-amber", emerald: "text-emerald",
    teal: "text-teal", text: "text-text",
  }[effectiveAccent];
  const accentBg = {
    red: "bg-red", amber: "bg-amber", emerald: "bg-emerald",
    teal: "bg-teal", text: "bg-border-subtle",
  }[effectiveAccent];
  return (
    <Link to={href} className="glass card-hover relative block overflow-hidden rounded-xl p-4">
      {/* Left accent bar */}
      <div className={`absolute bottom-3 left-0 top-3 w-0.5 rounded-full ${accentBg} opacity-70`} />
      <div className="pl-3">
        <div className={`font-display text-2xl font-semibold leading-none tabular-nums ${valueColor}`}>
          {error ? "!" : value}
        </div>
        <div className="mt-1.5 text-[13px] leading-snug text-text-2">{label}</div>
        {(error || sub) && (
          <div className="mt-1 text-[12px] text-text-3">
            {error ? <span className="text-red">{errorLabel ?? "Failed to load"}</span> : sub}
          </div>
        )}
      </div>
    </Link>
  );
}
