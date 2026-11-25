import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { BellOff, CheckCircle2, ExternalLink, ShieldCheck, Sparkles, Undo2, X } from "lucide-react";
import { errorMessage, type Finding, type FindingContext } from "../lib/api";
import {
  useBelief, useFinding, useIsAdmin, useResolveFinding, useSuppressFinding, useUnsuppressFinding,
} from "../lib/queries";
import { KevBadge, ScoreBadge, SeverityBadge } from "./ui";
import { MustFixBadge } from "./MustFixBadge";
import { openAssistant } from "../lib/assistant";
import { openVerify } from "../lib/verify";
import { SafetyBadge, FixLocationLine } from "./SafetyBadge";
import { BeliefPanel } from "./BeliefPanel";
import { SlideOver } from "./SlideOver";
import { shortenId } from "../lib/format";
import { expiryBounds, expiryToISO } from "../lib/expiry";
import { ExpiryPicker } from "./SuppressionExpiry";
import { EnvironmentBadge, OwnerBadge } from "./Ownership";

// FindingDetailPanel — the slide-over for the app's core object. Findings are the
// one entity that had no panel, so every worklist row (Must fix, Start here, the
// cluster drill-down, the flat instance list) had to full-page navigate and threw
// the analyst out of the list they were triaging. This is the condensed answer to
// "what is this and what do I do?": the risk story, why the score is what it is,
// the fix, the resource, and how safe the fix is — with Suppress and Ask AI in the
// footer so a row can be actioned without leaving the worklist.
//
// The heavy sections (AHC decision trace, blast-radius graph, background prose,
// peer CVEs) deliberately stay on the full detail page; the footer links there.
// Overlay/Escape/focus-trap/scroll-lock all live in SlideOver.

interface Props {
  findingId: string | null;
  onClose: () => void;
}

export function FindingDetailPanel({ findingId, onClose }: Props) {
  return (
    <SlideOver open={findingId !== null} onClose={onClose} title="Finding detail" width="560px">
      {findingId && <PanelBody findingId={findingId} onClose={onClose} />}
    </SlideOver>
  );
}

function PanelBody({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const q = useFinding(findingId);
  const belief = useBelief(findingId);
  const f = q.data;

  return (
    <>
      {/* Header */}
      <div className="flex shrink-0 items-start justify-between gap-3 border-b border-border-subtle px-[18px] pt-4 pb-3.5">
        <div className="min-w-0">
          {f ? (
            <>
              <div className="break-words font-display text-[14px] font-semibold leading-tight tracking-[-0.01em] text-text">
                {f.title}
              </div>
              <div className="mt-1 text-[11px] text-text-3">{f.source} · {f.check_id ?? f.type}</div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <ScoreBadge score={f.score} band={f.score_band} />
                <SeverityBadge severity={f.severity} />
                {f.known_exploited && <KevBadge />}
                <MustFixBadge cls={f.must_fix_class} state={f.enrichment_state} />
                <OwnerBadge finding={f} />
                <EnvironmentBadge env={f.environment} />
                {f.exposure?.internet_facing && <Pill label="internet-facing" className="border-amber/30 bg-amber/10 text-amber" />}
                {f.exposure?.privileged && <Pill label="privileged" className="border-amber/30 bg-amber/10 text-amber" />}
              </div>
            </>
          ) : q.isError ? (
            <span className="text-[13px] text-text-3">Could not load this finding.</span>
          ) : (
            <span className="text-[13px] text-text-3">Loading…</span>
          )}
        </div>
        <button
          onClick={onClose}
          aria-label="Close panel"
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border-subtle bg-transparent text-text-3 transition-colors hover:bg-surface-2 hover:text-text"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Body */}
      <div className="flex flex-1 flex-col gap-3 overflow-y-auto px-[18px] py-4">
        {f && (
          <>
            {/* True-severity belief — the headline "is this REALLY this severe?"
                verdict, same as the full detail page. Leads the body
                for the same reason it does there: it can re-frame the score
                below. */}
            <BeliefPanel belief={belief.data} />

            {/* Risk story — the plain-English "why this matters", leads the body */}
            {f.narrative && (
              <div className="rounded-lg border border-teal/30 bg-teal/5 p-3">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-teal">Risk story</div>
                <p className="text-[12px] leading-relaxed text-text-1">{f.narrative}</p>
              </div>
            )}

            <ScoreFactors finding={f} />

            {/* Fix */}
            {f.remediation && (
              <div className="rounded-lg border border-teal/20 bg-teal/5 px-3 py-2.5">
                <span className="text-[11px] uppercase tracking-wide text-teal">Fix: </span>
                <span className="text-[12px] text-text-2">{f.remediation}</span>
              </div>
            )}

            {/* Affected resource */}
            <div className="rounded-lg border border-border-subtle bg-surface p-3">
              <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">Affected resource</div>
              <dl className="space-y-1.5 text-[11px]">
                <div className="flex justify-between gap-4">
                  <dt className="shrink-0 text-text-3">Resource</dt>
                  <dd className="min-w-0 truncate text-right" title={f.resource_id}>
                    {f.resource_id ? (
                      <Link
                        to="/investigate/assets/$id"
                        params={{ id: f.resource_id }}
                        className="font-mono text-[11px] text-teal hover:underline"
                      >
                        {f.resource_name || shortenId(f.resource_id)}
                      </Link>
                    ) : (
                      <span className="text-text-2">—</span>
                    )}
                  </dd>
                </div>
                <PanelRow label="Type" value={f.resource_type ?? f.type} />
                <PanelRow label="Region" value={f.region ?? f.provenance?.region ?? "—"} />
                {f.provenance?.account_id && <PanelRow label="Account" value={f.provenance.account_id} mono />}
                <PanelRow label="Detected" value={new Date(f.detected_at).toLocaleString()} />
              </dl>
            </div>

            <SafeToFixSection finding={f} />

            {/* The big sections live on the full page — say so rather than half-render them. */}
            {(f.reasoning?.summary || (f.blast?.count ?? 0) > 0 || f.description) && (
              <Link
                to="/investigate/findings/$id"
                params={{ id: f.id }}
                className="rounded-lg border border-border-subtle bg-surface px-3 py-2 text-[11px] text-text-3 transition-colors hover:border-teal/30 hover:text-teal"
              >
                Decision trace, blast-radius graph and background are on the full detail page →
              </Link>
            )}
          </>
        )}
      </div>

      {/* Footer — the actions that close a triage loop without leaving the worklist */}
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-t border-border-subtle px-[18px] pt-3 pb-4">
        <Link
          to="/investigate/findings/$id"
          params={{ id: findingId }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-2.5 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/10"
        >
          <ExternalLink className="h-3 w-3" />
          Open full detail →
        </Link>
        {f?.resource_id && (
          <button
            onClick={() => openVerify(f)}
            title="Confirm or refute this finding against the live cloud state — read-only, agent-driven"
            className="inline-flex items-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/10 px-2.5 py-1.5 text-[11px] font-medium text-violet-300 transition-colors hover:bg-violet-500/20"
          >
            <ShieldCheck className="h-3 w-3" />
            Verify live →
          </button>
        )}
        <button
          onClick={() => {
            if (!f) return;
            askAIAboutFinding(f); // seed the chat before closing so the event isn't lost
            onClose(); // SlideOver's z-40 overlay would otherwise cover ChatPanel's z-39 drawer
          }}
          disabled={!f}
          className="inline-flex items-center gap-1.5 rounded-lg border border-teal/30 bg-teal/10 px-2.5 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20 disabled:opacity-40"
        >
          <Sparkles className="h-3 w-3" />
          Ask AI →
        </button>
        {f && <SuppressControl finding={f} />}
        {f && <ResolveControl finding={f} />}
      </div>
    </>
  );
}

// ── Shared pieces, also used by the full FindingDetail page ───────────────────

// askAIAboutFinding binds the chat session to a finding via `context` (kept across
// follow-ups) and seeds the first question. Shared so the panel and the full page
// hand the assistant an identical brief.
export function askAIAboutFinding(f: FindingContext): void {
  const ctxParts = [`Finding: ${f.title}`];
  if (f.resource_id) ctxParts.push(`resource: ${f.resource_id} (${f.resource_type ?? "?"})`);
  if (f.severity) ctxParts.push(`severity: ${f.severity}`);
  if ((f.score ?? 0) > 0) ctxParts.push(`score: ${f.score}`);
  if (f.source) ctxParts.push(`source: ${f.source}`);
  if (f.check_id) ctxParts.push(`check: ${f.check_id}`);
  if (f.narrative) ctxParts.push(`narrative: ${f.narrative}`);
  openAssistant({
    question: "What is the root cause and how should I remediate this?",
    context: ctxParts.join("; "),
  });
}

// ScoreFactors — the WHY behind the score. Each factor gets a contribution bar
// scaled to the largest one: red adds risk, emerald reduces it.
export function ScoreFactors({ finding: f, className = "" }: { finding: FindingContext; className?: string }) {
  if (!f.factors || f.factors.length === 0) return null;
  const maxAbs = Math.max(...f.factors.map((x) => Math.abs(x.points ?? 0)), 1);
  return (
    <div className={`rounded-lg border border-border-subtle bg-surface p-3 ${className}`}>
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <span className="text-[11px] uppercase tracking-wide text-text-3">Why score {f.score}</span>
        <span className="text-[11px] text-text-3">graph-grounded evidence</span>
      </div>
      <div className="space-y-1.5">
        {f.factors.map((factor, i) => {
          const points = factor.points ?? 0;
          const width = Math.max(Math.round((Math.abs(points) / maxAbs) * 100), points !== 0 ? 4 : 0);
          return (
            <div
              key={`${factor.source}-${i}`}
              className="grid grid-cols-[minmax(0,1fr)_96px_52px] items-center gap-3 text-xs sm:grid-cols-[minmax(0,1fr)_140px_52px]"
            >
              <span className="min-w-0 truncate">
                <span className="text-text-2 capitalize">{(factor.source ?? "").replace(/_/g, " ")}</span>
                {factor.detail && <span className="ml-2 text-text-3">{factor.detail}</span>}
              </span>
              <span className="h-1.5 overflow-hidden rounded-full bg-surface-2">
                <span
                  className={`block h-full rounded-full ${points >= 0 ? "bg-red/60" : "bg-emerald/60"}`}
                  style={{ width: `${width}%` }}
                />
              </span>
              <span className="shrink-0 text-right tabular-nums text-text">
                {factor.points != null && (points >= 0 ? `+${points}` : points)}
                {factor.floor ? <span className="ml-1 text-[11px] text-text-3">fl {factor.floor}</span> : null}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// SafeToFixSection — how risky the fix is, what to look for, and where to apply it.
// Pairs with ScoreFactors: why it's a risk + what to check + where to fix.
export function SafeToFixSection({ finding: f, className = "" }: { finding: FindingContext; className?: string }) {
  const has = f.reasoning?.safety_band || (f.impact?.signals?.length ?? 0) > 0 || f.impact?.fix_location?.kind;
  if (!has) return null;
  return (
    <div className={`rounded-lg border border-border-subtle bg-surface p-3 ${className}`}>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] uppercase tracking-wide text-text-3">Safe to fix</span>
        <SafetyBadge band={f.reasoning?.safety_band} />
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-2">
        {f.impact?.dependents_known === false ? (
          <span className="text-amber">dependents unknown</span>
        ) : (
          <span>
            <span className="tabular-nums text-text">{f.impact?.dependents ?? 0}</span> dependent
            {(f.impact?.dependents ?? 0) === 1 ? "" : "s"}
          </span>
        )}
        {f.impact?.unused && <span className="text-amber">appears unused</span>}
      </div>
      {f.impact?.signals && f.impact.signals.length > 0 && (
        <div className="mt-2">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">What to look for before you action this</div>
          <ul className="space-y-1">
            {f.impact.signals.map((s, i) => (
              <li key={i} className="flex items-start gap-2 text-[12px] text-text-2">
                <span className="mt-0.5 shrink-0 text-text-3">·</span>
                <span>{s}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {f.impact?.fix_location?.kind && (
        <div className="mt-2 border-t border-border-subtle pt-2">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">Where to apply the fix</div>
          <FixLocationLine fix={f.impact.fix_location} />
        </div>
      )}
    </div>
  );
}

// SuppressControl completes the triage loop wherever a finding is shown: from the
// panel or the full page you can act (suppress the noise), not only read.
// Admin-only, matching the write gate on the suppress endpoints. Suppress requires
// a reason and an expiry (default 90 days), captured inline with no blocking
// prompt; unsuppress is one click.
//
// The toggle reads the finding's real suppression standing; when the standing
// could not be read (suppression_known false) no toggle is offered at all rather
// than a guess, since a guessed "Suppress" on a suppressed finding is wrong.
type Suppressible = Pick<Finding, "id" | "is_suppressed"> & {
  suppression_known?: boolean;
  suppression_expires_at?: string;
};

export function SuppressControl({ finding: f }: { finding: Suppressible }) {
  const isAdmin = useIsAdmin();
  const suppress = useSuppressFinding();
  const unsuppress = useUnsuppressFinding();
  const [arming, setArming] = useState(false);
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState(() => expiryBounds().initial);

  if (!isAdmin) return null;

  const failed = suppress.isError ? suppress.error : unsuppress.isError ? unsuppress.error : null;
  const failNote = failed ? (
    <span role="alert" className="text-[11px] text-red">
      {errorMessage(failed)}
    </span>
  ) : null;
  const doSuppress = () =>
    suppress.mutate(
      { id: f.id, reason: reason.trim(), expiresAt: expiryToISO(expiry) },
      { onSuccess: () => { setArming(false); setReason(""); } },
    );

  if (f.suppression_known === false) {
    return (
      <span className="text-[11px] text-text-3" title="The suppression store could not be read — refresh to retry">
        suppression status unavailable
      </span>
    );
  }

  if (f.is_suppressed) {
    return (
      <span className="flex items-center gap-1.5">
      {f.suppression_expires_at && (
        <span className="text-[11px] text-text-3">
          suppressed until {new Date(f.suppression_expires_at).toLocaleDateString()}
        </span>
      )}
      <button
        onClick={() => unsuppress.mutate(f.id)}
        disabled={unsuppress.isPending}
        title="Lift the suppression — this finding returns to the active worklist"
        className="flex items-center gap-1 rounded-lg border border-border-subtle bg-surface px-3 py-1.5 text-[11px] font-medium text-text-2 transition-colors hover:bg-surface-2 disabled:opacity-40"
      >
        <Undo2 className="h-3.5 w-3.5" /> Unsuppress
      </button>
      {failNote}
      </span>
    );
  }

  if (!arming) {
    return (
      <button
        onClick={() => setArming(true)}
        title="Suppress this finding — hide it from the active worklist with an audited reason"
        className="flex items-center gap-1 rounded-lg border border-border-subtle bg-surface px-3 py-1.5 text-[11px] font-medium text-text-2 transition-colors hover:bg-surface-2"
      >
        <BellOff className="h-3.5 w-3.5" /> Suppress
      </button>
    );
  }

  return (
    <div className="flex items-center gap-1.5">
      <input
        autoFocus
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && reason.trim() && expiry && !suppress.isPending) doSuppress();
          if (e.key === "Escape") { setArming(false); setReason(""); }
        }}
        placeholder="Reason (required)…"
        className="w-44 rounded-lg border border-border-subtle bg-surface px-2 py-1.5 text-[11px] text-text placeholder:text-text-3 focus:border-amber/40 focus:outline-none"
      />
      <ExpiryPicker value={expiry} onChange={setExpiry} />
      <button
        onClick={doSuppress}
        disabled={!reason.trim() || !expiry || suppress.isPending}
        className="rounded-lg border border-amber/30 bg-amber/10 px-2.5 py-1.5 text-[11px] font-medium text-amber transition-colors hover:bg-amber/20 disabled:opacity-40"
      >
        Confirm
      </button>
      <button
        onClick={() => { setArming(false); setReason(""); }}
        className="px-1 text-[11px] text-text-3 hover:text-text-2"
      >
        cancel
      </button>
      {failNote}
    </div>
  );
}

// ResolveControl — the human-driven counterpart to sync-time auto-resolve:
// closes the loop after "Verify live" refutes a finding the
// emitting check hasn't re-synced away yet. Admin-only. Shared by the panel
// and the full page so both surfaces close the same triage loop.
export function ResolveControl({ finding: f }: { finding: Finding }) {
  const isAdmin = useIsAdmin();
  const resolve = useResolveFinding();
  const [arming, setArming] = useState(false);
  const [reason, setReason] = useState("");

  if (!isAdmin) return null;

  if (resolve.isSuccess) {
    return <span className="text-[11px] text-text-3">Resolved</span>;
  }

  if (!arming) {
    return (
      <button
        onClick={() => setArming(true)}
        title="Manually resolve this finding — e.g. after Verify live refutes it. Requires a reason."
        className="flex items-center gap-1 rounded-lg border border-border-subtle bg-surface px-3 py-1.5 text-[11px] font-medium text-text-2 transition-colors hover:bg-surface-2"
      >
        <CheckCircle2 className="h-3.5 w-3.5" /> Resolve
      </button>
    );
  }

  return (
    <div className="flex items-center gap-1.5">
      <input
        autoFocus
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && reason.trim() && !resolve.isPending) resolve.mutate({ id: f.id, reason: reason.trim() });
          if (e.key === "Escape") { setArming(false); setReason(""); }
        }}
        placeholder="Reason (required)…"
        className="w-56 rounded-lg border border-border-subtle bg-surface px-2 py-1.5 text-[11px] text-text placeholder:text-text-3 focus:border-teal/40 focus:outline-none"
      />
      <button
        onClick={() => resolve.mutate({ id: f.id, reason: reason.trim() })}
        disabled={!reason.trim() || resolve.isPending}
        className="rounded-lg border border-teal/30 bg-teal/10 px-2.5 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20 disabled:opacity-40"
      >
        Confirm
      </button>
      <button
        onClick={() => { setArming(false); setReason(""); }}
        className="px-1 text-[11px] text-text-3 hover:text-text-2"
      >
        cancel
      </button>
      {resolve.isError && (
        <span role="alert" className="text-[11px] text-red">
          {errorMessage(resolve.error)}
        </span>
      )}
    </div>
  );
}

function Pill({ label, className }: { label: string; className: string }) {
  return <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${className}`}>{label}</span>;
}

function PanelRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="shrink-0 text-text-3">{label}</dt>
      <dd className={`min-w-0 truncate text-right ${mono ? "font-mono text-text-2" : "text-text-2"}`} title={value}>{value}</dd>
    </div>
  );
}
