import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Bot, Check, ChevronDown, ChevronUp, Edit2, Send, X } from "lucide-react";
import { errorMessage, streamPost, type Decision } from "../lib/api";
import { useIsAdmin, useResolveDecision } from "../lib/queries";
import { type FixLocation } from "./SafetyBadge";
import { ProposedFix } from "./ProposedFix";
import { ApproveAndRun } from "./ApproveAndRun";
import { renderMarkdown } from "../lib/markdown";
import { readEventStream } from "../lib/sse";
import { SlideOver } from "./SlideOver";
import { OUTCOME_META, TONE_CLASSES, actionTone, describeAction, labelAction } from "../lib/actions";
import { timeAgo as timeAgoBase, shortenId } from "../lib/format";

const timeAgo = (iso?: string) => timeAgoBase(iso, "ago");
const shortenArn = (s: string) => shortenId(s, { keepArnType: true, maxLen: 60 });

// Re-use the same types and helpers as Decisions.tsx.
type DecisionDetail = {
  action_class?: string;
  summary?: string;
  rationale?: string;
  confidence_band?: string;
  effective_n?: number;
  sample_count?: number;
  blast_radius?: number;
  // blast_radius_known: false means the walk that produced blast_radius
  // failed, so the radius is unknown, not 0.
  blast_radius_known?: boolean;
  cove_concerns?: string[];
  safety_band?: string;
  fix_location?: FixLocation;
  outcome?: string;
};

// parseAuditDetail parses the JSON blob written by respond/service.go's
// auditFor() into whatever detail shape the caller expects — Decisions.tsx and
// this panel read overlapping but not identical subsets of the same wire
// shape (this panel additionally reads rationale/effective_n/sample_count).
// Malformed or absent JSON degrades to an empty object rather than throwing.
export function parseAuditDetail<T>(details?: string): T {
  if (!details) return {} as T;
  try {
    return JSON.parse(details) as T;
  } catch {
    return {} as T;
  }
}

function parse(details?: string): DecisionDetail {
  return parseAuditDetail<DecisionDetail>(details);
}

// action_class label/tone/description live in lib/actions.ts (one table for
// the 5 real respond.ActionClass values); TONE_BADGE derives from its shared
// accent classes rather than keeping a second copy of that table.
const TONE_BADGE = Object.fromEntries(
  Object.entries(TONE_CLASSES).map(([tone, c]) => [tone, c.accent]),
) as Record<keyof typeof TONE_CLASSES, string>;

// ── Refine chat hook ──────────────────────────────────────────────────────────

type ChatMessage = { role: "user" | "ai"; text: string };

function useRefineChat(decisionId: string) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [streaming, setStreaming] = useState(false);

  async function send(message: string) {
    setMessages(m => [...m, { role: "user", text: message }]);
    setStreaming(true);
    let aiText = "";
    setMessages(m => [...m, { role: "ai", text: "" }]);

    try {
      // A failed request (401/500/…) throws from streamPost, so the user never
      // sees a blank AI reply with no indication anything went wrong.
      const stream = await streamPost(`/api/decisions/${decisionId}/refine`, { message });

      // Resolves only on the server's done event: an error event or a stream
      // that just stops rejects instead of passing for a complete answer.
      await readEventStream(stream, (text) => {
        aiText += text;
        setMessages(m => [...m.slice(0, -1), { role: "ai", text: aiText }]);
      });
    } catch (err) {
      const detail = err instanceof Error && err.message ? err.message : "could not reach the server.";
      // Keep any partial answer visible above the error.
      const shown = aiText ? `${aiText}\n\n**Error:** ${detail}` : `**Error:** ${detail}`;
      setMessages(m => [...m.slice(0, -1), { role: "ai", text: shown }]);
    } finally {
      setStreaming(false);
    }
  }

  return { messages, streaming, send };
}

// ── Component ─────────────────────────────────────────────────────────────────

interface DecisionDetailPanelProps {
  decision: Decision | null;
  onClose: () => void;
}

export function DecisionDetailPanel({ decision, onClose }: DecisionDetailPanelProps) {
  const [editingSummary, setEditingSummary] = useState(false);
  const [editedSummary, setEditedSummary] = useState<string | undefined>(undefined);
  const [chatExpanded, setChatExpanded] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const isAdmin = useIsAdmin();
  const resolve = useResolveDecision();
  const chatEndRef = useRef<HTMLDivElement>(null);

  const { messages, streaming, send } = useRefineChat(decision?.id ?? "");

  // Reset state when decision changes.
  useEffect(() => {
    setEditingSummary(false);
    setEditedSummary(undefined);
    setChatExpanded(false);
    setChatInput("");
  }, [decision?.id]);

  // Scroll chat to bottom on new messages.
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Escape-to-close, scroll lock, overlay and focus trap all live in SlideOver.

  if (!decision) return null;

  const detail = parse(decision.details);
  const tone = actionTone(detail.action_class);
  const badgeCls = TONE_BADGE[tone];
  const hasConcerns = (detail.cove_concerns?.length ?? 0) > 0;
  // Every state-changing plan gets the full fix breakdown; observe changes nothing.
  const proposesChange = !!detail.action_class && detail.action_class !== "observe";
  const canAct =
    (detail.outcome === "escalated" || detail.outcome === "parked_for_approval") && isAdmin;

  const accentColor =
    tone === "teal" ? "var(--graph-teal)" :
    tone === "amber" ? "var(--graph-amber)" :
    tone === "red" ? "var(--graph-red)" :
    "var(--graph-panel-border)";

  // The displayed summary — may be overridden by local edit.
  const displayedSummary = editedSummary !== undefined ? editedSummary : detail.summary;

  function verdict(v: "approved" | "risk_accepted" | "denied") {
    if (!decision) return;
    const clusterKey = `${decision.target_id ?? decision.target_resource ?? ""}:${detail.action_class ?? decision.action}`;
    resolve.mutate({
      finding_ids: decision.target_id ? [decision.target_id] : [],
      cluster_key: clusterKey,
      action_class: detail.action_class ?? decision.action,
      verdict: v,
    });
  }

  function confidenceLabel(): string | null {
    if (!detail.confidence_band) return null;
    const n = detail.effective_n ?? detail.sample_count;
    if (n === undefined) return detail.confidence_band;
    const band = detail.confidence_band.charAt(0).toUpperCase() + detail.confidence_band.slice(1);
    if (detail.confidence_band === "insufficient") {
      return `${band} (${n.toFixed(1)} samples, need 3.0)`;
    }
    return `${band} (${n.toFixed(1)} samples)`;
  }

  function handleSendChat() {
    const msg = chatInput.trim();
    if (!msg || streaming) return;
    setChatInput("");
    send(msg);
  }

  const footer = canAct ? (
    <div className="shrink-0 space-y-2 border-t border-border-subtle px-4 py-3">
      <div className="text-[11px] uppercase tracking-wide text-text-3">
        Your decision
      </div>
      <p className="text-[11px] leading-relaxed text-text-3">
        Nothing runs until someone says yes. "Approve fix" records your yes and hands the fix to the
        configured remediation channel. To run it in Vulngraph, use "Run this fix" above: it dry-runs
        first, asks you to confirm, and needs a second admin for destructive actions.
      </p>
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => verdict("approved")}
          disabled={resolve.isPending}
          className="flex items-center gap-1.5 rounded border border-teal/30 bg-teal/10 px-3 py-1.5 text-[12px] font-medium text-teal hover:bg-teal/20 disabled:opacity-40 transition-colors"
        >
          <Check className="h-3.5 w-3.5" /> Approve fix
        </button>
        <button
          onClick={() => verdict("risk_accepted")}
          disabled={resolve.isPending}
          className="flex items-center gap-1.5 rounded border border-amber/30 bg-amber/10 px-3 py-1.5 text-[12px] font-medium text-amber hover:bg-amber/20 disabled:opacity-40 transition-colors"
        >
          Accept risk
        </button>
        <button
          onClick={() => verdict("denied")}
          disabled={resolve.isPending}
          className="flex items-center gap-1.5 rounded border border-red/30 bg-red/10 px-3 py-1.5 text-[12px] font-medium text-red hover:bg-red/20 disabled:opacity-40 transition-colors"
        >
          <X className="h-3.5 w-3.5" /> Deny
        </button>
      </div>
      {resolve.isError && (
        <p role="alert" className="text-[11px] text-red">
          Couldn't record the verdict: {errorMessage(resolve.error)}
        </p>
      )}
      {resolve.isSuccess && <p className="text-[11px] text-emerald">Verdict recorded.</p>}
    </div>
  ) : null;

  return (
    <SlideOver open onClose={onClose} title="Decision detail" width="480px" footer={footer}>
        {/* Header */}
        <div
          className="flex shrink-0 items-center gap-3 border-b border-border-subtle px-4 py-3"
          style={{ borderLeft: `3px solid ${accentColor}` }}
        >
          <span
            className={`rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${badgeCls}`}
            title={describeAction(detail.action_class)}
          >
            {labelAction(detail.action_class, decision.action)}
          </span>
          <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-text">
            {decision.target_title || shortenArn(decision.target_resource ?? decision.target_id ?? "Decision")}
          </span>
          <button
            onClick={onClose}
            className="ml-auto shrink-0 rounded p-1 text-text-3 transition-colors hover:bg-surface-3 hover:text-text"
            aria-label="Close panel"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body — scrollable */}
        <div className="flex-1 overflow-y-auto px-4 py-4 space-y-5">

          {/* Plan summary — with inline edit */}
          {(displayedSummary || detail.summary) && (
            <section>
              <div className="flex items-center gap-2 mb-1.5">
                <div className="text-[11px] uppercase tracking-wide text-text-3">Plan summary</div>
                {!editingSummary && (
                  <button
                    onClick={() => {
                      setEditedSummary(displayedSummary ?? "");
                      setEditingSummary(true);
                    }}
                    className="flex items-center gap-0.5 rounded px-1 py-0.5 text-[11px] text-text-3 hover:text-text-2 hover:bg-surface-3 transition-colors"
                    aria-label="Edit summary"
                  >
                    <Edit2 className="h-2.5 w-2.5" />
                    Edit
                  </button>
                )}
              </div>
              {editingSummary ? (
                <div className="space-y-2">
                  <textarea
                    value={editedSummary ?? ""}
                    onChange={(e) => setEditedSummary(e.target.value)}
                    rows={4}
                    className="w-full rounded border border-border-subtle bg-surface-3 px-3 py-2 text-[13px] leading-relaxed text-text resize-none focus:outline-none focus:border-teal/40"
                    autoFocus
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={() => setEditingSummary(false)}
                      className="rounded border border-teal/30 bg-teal/10 px-2.5 py-1 text-[11px] font-medium text-teal hover:bg-teal/20 transition-colors"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => {
                        setEditedSummary(undefined);
                        setEditingSummary(false);
                      }}
                      className="rounded border border-border-subtle bg-surface-3 px-2.5 py-1 text-[11px] text-text-3 hover:text-text-2 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <p className="text-[14px] leading-relaxed text-text">{displayedSummary}</p>
              )}
            </section>
          )}

          {/* Reasoning — full decision rationale */}
          {detail.rationale && (
            <section>
              <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">Reasoning</div>
              <p className="text-[13px] leading-relaxed text-text-2">{detail.rationale}</p>
            </section>
          )}

          {/* CoVe concerns — always visible when present */}
          {hasConcerns && (
            <section>
              <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">CoVe Concerns</div>
              <div className="rounded border border-amber/20 bg-amber/5 px-3 py-2.5">
                {detail.cove_concerns!.map((c, i) => (
                  <div key={i} className="flex items-start gap-2 text-[12px] mt-1 first:mt-0">
                    <span className="mt-0.5 shrink-0 text-amber">⚠</span>
                    <span className="text-text-2">{c}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Proposed fix — what changes, why, reach, undo, safe to run, run by hand */}
          {proposesChange && <ProposedFix decision={decision} detail={detail} />}

          {/* Approve & run — admins only, and only while the decision asks a person */}
          {proposesChange && canAct && <ApproveAndRun key={decision.id} decisionId={decision.id} />}

          {/* Metadata row */}
          <section>
            <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">Details</div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[12px]">
              {detail.confidence_band && (
                <div className="col-span-2">
                  <span className="block text-[11px] text-text-3">Confidence</span>
                  <span className="text-text-2 capitalize">{confidenceLabel()}</span>
                </div>
              )}
              <div>
                <span className="block text-[11px] text-text-3">When</span>
                <span className="text-text-2" title={new Date(decision.ts).toLocaleString()}>
                  {timeAgo(decision.ts)}
                </span>
              </div>
              <div>
                <span className="block text-[11px] text-text-3">Actor</span>
                {decision.actor === "agent" ? (
                  <span className="flex items-center gap-1 text-teal">
                    <Bot className="h-3 w-3" /> agent
                  </span>
                ) : (
                  <span className="text-text-2">{decision.actor?.split("@")[0] ?? "—"}</span>
                )}
              </div>
              {detail.outcome && (
                <div>
                  <span className="block text-[11px] text-text-3">Outcome</span>
                  <span
                    className={
                      detail.outcome === "escalated" ? "text-red" :
                      detail.outcome === "parked_for_approval" ? "text-amber" :
                      detail.outcome === "observed" ? "text-teal" :
                      "text-text-2"
                    }
                    title={OUTCOME_META[detail.outcome]?.title}
                  >
                    {OUTCOME_META[detail.outcome]?.label ?? detail.outcome.replace(/_/g, " ")}
                  </span>
                </div>
              )}
            </div>
          </section>

          {/* Target */}
          {(decision.target_id || decision.target_resource) && (
            <section>
              <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">Target</div>
              <div className="space-y-1.5">
                {decision.target_type === "finding" && decision.target_id && (
                  <div className="flex items-center gap-2 text-[12px]">
                    <span className="text-text-3 w-14 shrink-0">Finding</span>
                    <Link
                      to="/investigate/findings/$id"
                      params={{ id: decision.target_id }}
                      onClick={onClose}
                      className="min-w-0 truncate text-teal hover:underline"
                    >
                      {decision.target_title || decision.target_id}
                    </Link>
                  </div>
                )}
                {decision.target_type === "asset" && decision.target_id && (
                  <div className="flex items-center gap-2 text-[12px]">
                    <span className="text-text-3 w-14 shrink-0">Asset</span>
                    <Link
                      to="/investigate/assets/$id"
                      params={{ id: decision.target_id }}
                      onClick={onClose}
                      className="min-w-0 truncate text-teal hover:underline"
                    >
                      {decision.target_title || decision.target_id}
                    </Link>
                  </div>
                )}
                {decision.target_resource && (
                  <div className="flex items-center gap-2 text-[12px]">
                    <span className="text-text-3 w-14 shrink-0">Resource</span>
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="min-w-0 truncate font-mono text-[11px] text-text-2" title={decision.target_resource}>
                        {shortenArn(decision.target_resource)}
                      </span>
                      {decision.target_type !== "asset" && (
                        <Link
                          to="/investigate/assets/$id"
                          params={{ id: decision.target_resource }}
                          onClick={onClose}
                          className="shrink-0 text-[11px] text-teal hover:underline"
                        >
                          asset →
                        </Link>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Refine with AI — collapsible chat */}
          <section>
            <button
              className="flex w-full items-center gap-1.5 text-[11px] uppercase tracking-wide text-text-3 hover:text-text-2 transition-colors"
              onClick={() => setChatExpanded((v) => !v)}
              aria-expanded={chatExpanded}
            >
              {chatExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {chatExpanded ? "Hide AI chat" : "Refine with AI →"}
            </button>

            {chatExpanded && (
              <div className="mt-3 rounded border border-border-subtle bg-surface-2 flex flex-col" style={{ minHeight: "200px", maxHeight: "320px" }}>
                {/* Message list */}
                <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
                  {messages.length === 0 && (
                    <p className="text-[11px] text-text-3 text-center py-4">
                      Ask the AI to help refine or explain this decision.
                    </p>
                  )}
                  {messages.map((msg, i) => (
                    <div
                      key={i}
                      className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                    >
                      <div
                        className={`max-w-[85%] rounded px-2.5 py-1.5 text-[12px] leading-relaxed ${
                          msg.role === "user"
                            ? "bg-teal/15 text-teal border border-teal/20"
                            : "bg-surface-3 text-text-2 border border-border-subtle"
                        }`}
                      >
                        {msg.text ? (
                          msg.role === "user" ? msg.text : renderMarkdown(msg.text)
                        ) : streaming && msg.role === "ai" ? (
                          <span className="text-text-3 italic">Thinking…</span>
                        ) : ""}
                      </div>
                    </div>
                  ))}
                  <div ref={chatEndRef} />
                </div>

                {/* Input */}
                <div className="flex gap-2 border-t border-border-subtle px-3 py-2.5">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSendChat(); } }}
                    placeholder="Ask about this decision…"
                    disabled={streaming}
                    className="flex-1 rounded border border-border-subtle bg-surface-3 px-2.5 py-1.5 text-[12px] text-text placeholder:text-text-3 focus:outline-none focus:border-teal/40 disabled:opacity-50"
                  />
                  <button
                    onClick={handleSendChat}
                    disabled={!chatInput.trim() || streaming}
                    className="flex items-center gap-1 rounded border border-teal/30 bg-teal/10 px-2.5 py-1.5 text-[11px] font-medium text-teal hover:bg-teal/20 disabled:opacity-40 transition-colors"
                    aria-label="Send"
                  >
                    <Send className="h-3 w-3" />
                  </button>
                </div>
              </div>
            )}
          </section>

        </div>
    </SlideOver>
  );
}
