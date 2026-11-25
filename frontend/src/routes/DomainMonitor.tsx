import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import {
  ShieldAlert, Plus, Trash2, Check, X, ExternalLink, Globe, AlertTriangle, Radar, Network, MessageSquare,
} from "lucide-react";
import {
  useMonitoredDomains, useAddMonitoredDomain, useRemoveMonitoredDomain,
  usePhishingCandidates, useConfirmPhishing, useDismissPhishing,
  type PhishingCandidate,
} from "../lib/queries";
import { Empty, ErrorNote, Loading, PageHeader } from "../components/ui";
import { timeAgo as timeAgoBase, scoreTone, SCORE_THRESHOLDS } from "../lib/format";
import { openAssistant } from "../lib/assistant";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");
import { api, type GraphResult } from "../lib/api";
import { GraphView } from "../components/GraphView";
import { PresetPicker } from "../components/PresetPicker";

type Tab = "candidates" | "surface" | "domains";

// "pending" is the genuinely-suspected queue: the backend routes automatically
// cleared candidates to their own `auto_dismissed` status instead of
// parking them here. That bucket is a filter, not a hidden list — nothing is
// invisible, it is just not counted as awaiting a human.
const STATUS_TABS: { key: string; label: string; hint?: string }[] = [
  { key: "pending", label: "Pending", hint: "Suspected — awaiting your review" },
  { key: "confirmed", label: "Confirmed" },
  { key: "dismissed", label: "Dismissed", hint: "Dismissed by a person" },
  {
    key: "auto_dismissed",
    label: "Cleared",
    hint: "Cleared without human review — by a benign LLM verdict, or by a re-score below the detection threshold",
  },
];

function confidenceBadge(c: number): { label: string; cls: string } {
  if (c >= 0.8) return { label: "High", cls: "text-red border-red/30 bg-red/10" };
  if (c >= 0.5) return { label: "Medium", cls: "text-amber border-amber/30 bg-amber/10" };
  return { label: "Low", cls: "text-text-3 border-border-subtle bg-surface" };
}

// The verdict fields are named ai_*, but only triage_source "llm" is an AI
// verdict: "heuristic" is the similarity/issuer fallback used when no LLM is
// configured or the call failed, and must never be presented as AI.
const TRIAGE_SOURCE_LABEL: Record<PhishingCandidate["triage_source"], string> = {
  llm: "AI",
  heuristic: "Heuristic",
  "": "Triage",
};

// auto_dismissed has two causes, and only a triage clear on an LLM verdict
// is the AI's: a re-score clear applies to heuristic verdicts too.
function clearedLabel(c: PhishingCandidate): string {
  if (c.cleared_by === "rescore") return "Cleared by re-score";
  return c.triage_source === "llm" ? "Cleared by AI" : "Cleared by triage";
}

function CandidateCard({ c }: { c: PhishingCandidate }) {
  const confirm = useConfirmPhishing();
  const dismiss = useDismissPhishing();
  const conf = confidenceBadge(c.ai_confidence);

  return (
    <div className="rounded-xl border border-border-subtle bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-mono text-[13px] font-medium text-text">{c.domain}</span>
            <a
              href={`https://crt.sh/?q=${encodeURIComponent(c.domain)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="shrink-0 text-text-3 hover:text-teal"
              title="View certificate history on crt.sh"
            >
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          <div className="mt-1 flex items-center gap-2 text-[11px] text-text-3">
            <span>mimics</span>
            <span className="font-mono text-text-2">{c.monitored_domain}</span>
            <span>·</span>
            {/* similarity_score is 0-1; scoreTone expects the canonical 0-100 scale. */}
            <span className={scoreTone(c.similarity_score * 100)}>
              {Math.round(c.similarity_score * 100)}% similar
            </span>
          </div>
        </div>

        {/* Actions. Confirm stays available on an automatically cleared
            candidate: the auto-dismissal is not a person's decision, and
            overriding it must not require an API call by hand. */}
        {(c.status === "pending" || c.status === "auto_dismissed") && (
          <div className="flex shrink-0 gap-1.5">
            <button
              onClick={() => confirm.mutate(c.id)}
              disabled={confirm.isPending}
              className="flex items-center gap-1 rounded border border-red/30 bg-red/10 px-2 py-1 text-[11px] font-medium text-red transition-colors hover:bg-red/20 disabled:opacity-50"
              title="Confirm as phishing"
            >
              <ShieldAlert className="h-3 w-3" /> Confirm
            </button>
            {c.status === "pending" && (
              <button
                onClick={() => dismiss.mutate(c.id)}
                disabled={dismiss.isPending}
                className="flex items-center gap-1 rounded border border-border-subtle px-2 py-1 text-[11px] font-medium text-text-3 transition-colors hover:bg-surface-2 disabled:opacity-50"
                title="Dismiss — not phishing"
              >
                <X className="h-3 w-3" /> Dismiss
              </button>
            )}
          </div>
        )}
        {c.status === "confirmed" && (
          <span className="flex shrink-0 items-center gap-1 rounded border border-red/30 bg-red/10 px-2 py-1 text-[11px] font-medium text-red">
            <ShieldAlert className="h-3 w-3" /> Confirmed
          </span>
        )}
        {c.status === "dismissed" && (
          <span className="flex shrink-0 items-center gap-1 rounded border border-border-subtle px-2 py-1 text-[11px] font-medium text-text-3">
            <Check className="h-3 w-3" /> Dismissed
          </span>
        )}
        {c.status === "auto_dismissed" && (
          <span className="flex shrink-0 items-center gap-1 rounded border border-border-subtle px-2 py-1 text-[11px] font-medium text-text-3">
            <Check className="h-3 w-3" /> {clearedLabel(c)}
          </span>
        )}
      </div>

      {/* Triage verdict (LLM or heuristic) */}
      {c.ai_reasoning && (
        <div className="mt-3 rounded-lg border border-border-subtle bg-surface-2/50 p-2.5">
          <div className="mb-1 flex items-center gap-1.5">
            <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${conf.cls}`}>
              {TRIAGE_SOURCE_LABEL[c.triage_source] ?? "Triage"}: {conf.label} ({Math.round(c.ai_confidence * 100)}%)
            </span>
          </div>
          <p className="text-[11px] leading-relaxed text-text-2">{c.ai_reasoning}</p>
        </div>
      )}

      {/* Cert metadata */}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-text-3">
        <span>Issuer: <span className="text-text-2">{c.issuer || "unknown"}</span></span>
        <span>Cert valid: {c.not_before} → {c.not_after}</span>
        <span>Found {timeAgo(c.detected_at)}</span>
        {c.confirmed_by && <span>by {c.confirmed_by}</span>}
        <button
          className="flex items-center gap-1 text-[11px] text-violet-400 hover:text-violet-300 hover:underline"
          onClick={() => {
            const source = TRIAGE_SOURCE_LABEL[c.triage_source] ?? "Triage";
            const facts = [
              `mimics ${c.monitored_domain}`,
              `${Math.round(c.similarity_score * 100)}% similar`,
              `${source} confidence: ${Math.round(c.ai_confidence * 100)}%`,
            ];
            if (c.ai_reasoning) facts.push(`${source}: ${c.ai_reasoning}`);
            openAssistant({
              subject: `Phishing candidate: ${c.domain}`,
              facts,
              question: "How should we respond and what is the threat model?",
            });
          }}
        >
          <MessageSquare className="h-[9px] w-[9px]" />
          Ask AI →
        </button>
      </div>
    </div>
  );
}

function MonitoredDomainsTab() {
  const { data, isLoading, isError } = useMonitoredDomains();
  const add = useAddMonitoredDomain();
  const remove = useRemoveMonitoredDomain();
  const [input, setInput] = useState("");

  const domains = data?.domains ?? [];

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    const d = input.trim().toLowerCase();
    if (!d) return;
    add.mutate(d, { onSuccess: () => setInput("") });
  };

  return (
    <div>
      {/* Add form */}
      <form onSubmit={handleAdd} className="mb-4 flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Globe className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-3" />
          <input
            type="text"
            placeholder="example.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="h-9 w-full rounded border border-border-subtle bg-surface pl-8 pr-3 text-[13px] text-text placeholder-text-3 focus:outline-none focus:ring-1 focus:ring-teal/40"
          />
        </div>
        <button
          type="submit"
          disabled={add.isPending || !input.trim()}
          className="flex h-9 items-center gap-1.5 rounded bg-teal px-3 text-[13px] font-medium text-black transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          <Plus className="h-4 w-4" /> Monitor
        </button>
      </form>

      {add.isError && (
        <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-[11px] text-amber">
          {String((add.error as Error)?.message ?? "Could not add domain — it may already be monitored.")}
        </div>
      )}

      {isLoading && <Loading />}

      {isError && (
        <ErrorNote message="Could not load monitored domains — the service may be temporarily busy. Refresh to retry." />
      )}

      {!isLoading && !isError && domains.length === 0 && (
        <Empty message="No domains monitored yet. Add a domain above — we'll scan certificate transparency logs every 6 hours for look-alikes that could be used for phishing." />
      )}

      {domains.length > 0 && (
        <div className="rounded-xl border border-border-subtle bg-surface">
          <div className="divide-y divide-border-subtle/50">
            {domains.map((d) => (
              <div key={d.id} className="flex items-center justify-between px-3 py-2.5">
                <div className="flex items-center gap-2.5">
                  <Globe className="h-4 w-4 text-teal" />
                  <span className="font-mono text-[13px] text-text">{d.domain}</span>
                  <span className="text-[11px] text-text-3">added {timeAgo(d.created_at)}</span>
                </div>
                <button
                  onClick={() => remove.mutate(d.domain)}
                  disabled={remove.isPending}
                  className="text-text-3 transition-colors hover:text-red disabled:opacity-50"
                  title="Stop monitoring"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CandidatesTab() {
  const [status, setStatus] = useState("pending");
  const { data, isLoading, isError } = usePhishingCandidates(status);
  const { data: autoData } = usePhishingCandidates("auto_dismissed");
  const candidates = data?.candidates ?? [];
  const autoCount = autoData?.total ?? 0;

  return (
    <div>
      {/* Status filter */}
      <div className="mb-4 flex items-center gap-1">
        {STATUS_TABS.map((s) => (
          <button
            key={s.key}
            onClick={() => setStatus(s.key)}
            title={s.hint}
            className={`rounded px-2.5 py-1 text-[12px] font-medium transition-colors ${
              status === s.key ? "bg-surface-2 text-text" : "text-text-3 hover:text-text-2"
            }`}
          >
            {s.label}
            {s.key === "auto_dismissed" && autoCount > 0 && (
              <span className="ml-1 text-[11px] text-text-3">({autoCount})</span>
            )}
          </button>
        ))}
      </div>

      {isLoading && <Loading />}

      {isError && (
        <ErrorNote message="Could not load phishing candidates — the service may be temporarily busy. Refresh to retry." />
      )}

      {!isLoading && !isError && candidates.length === 0 && (
        <Empty
          message={
            status === "pending"
              ? autoCount > 0
                ? `No domains are awaiting review. ${autoCount} look-alike${autoCount === 1 ? " was" : "s were"} cleared automatically — see "Cleared".`
                : "No pending phishing candidates. Look-alike domains appear here when found in CT logs — add domains to monitor in the Monitored Domains tab."
              : `No ${status.replace("_", " ")} candidates.`
          }
        />
      )}

      {candidates.length > 0 && (
        <div className="space-y-3">
          {candidates.map((c) => (
            <CandidateCard key={c.id} c={c} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Attack surface graph ──────────────────────────────────────────────────────

const SURFACE_PRESETS = [
  {
    id: "exposed",
    label: "Internet-exposed assets",
    cypher: `MATCH (a:Asset)-[r:ExposedToInternet]->(i:Asset)
RETURN a, r, i
ORDER BY a.score DESC
LIMIT 100`,
  },
  {
    id: "exposed-findings",
    label: "Exposed with findings",
    cypher: `MATCH (a:Asset)-[r:ExposedToInternet]->(i:Asset)
WHERE a.score >= ${SCORE_THRESHOLDS.pipeline}
RETURN a, r, i
ORDER BY a.score DESC
LIMIT 50`,
  },
  {
    id: "connected-exposed",
    label: "Exposed → services",
    // Services an exposed asset can reach: the service's security group admits
    // the exposed asset's (AllowsFrom, a self-loop when an SG admits its own
    // members). Sharing a security group alone is not a path.
    cypher: `MATCH (exposed:Asset)-[r3:ExposedToInternet]->(i:Asset {id: 'internet'})
MATCH (exposed)-[r2:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[a:AllowsFrom]->(src)
MATCH (svc:Asset)-[r1:ConnectedViaSG]->(dst)
WHERE svc.id <> exposed.id
RETURN svc, r1, dst, a, src, r2, exposed, r3, i
ORDER BY exposed.score DESC
LIMIT 50`,
  },
] as const;

type SurfacePresetId = typeof SURFACE_PRESETS[number]["id"];

function AttackSurface() {
  const navigate = useNavigate();
  const [activeId, setActiveId] = useState<SurfacePresetId>("exposed");
  const [result, setResult] = useState<GraphResult | undefined>();

  const runQuery = useMutation({
    mutationFn: (cypher: string) =>
      api.post<GraphResult>("/api/graph/cypher", { query: cypher, max_nodes: 300, max_edges: 600 }),
    onSuccess: setResult,
  });

  const activePreset = SURFACE_PRESETS.find((p) => p.id === activeId)!;

  useEffect(() => {
    runQuery.mutate(activePreset.cypher);
  }, [activeId]);

  const gvNodes = useMemo(
    () =>
      (result?.nodes ?? []).map((n) => ({
        id: n.id, label: n.name || n.id, sub: n.type, provider: n.provider,
        account: n.account_id, risk: n.max_score, exposed: n.exposed,
        hasKev: n.has_kev, exploitable: n.exploitable, toxicCombo: n.toxic_combo,
      })),
    [result],
  );
  const gvEdges = useMemo(
    () => (result?.edges ?? []).map((e) => ({ source: e.src_id, target: e.dst_id, label: e.edge_type })),
    [result],
  );

  return (
    <div>
      {/* Preset picker — one dropdown instead of a pill row */}
      <PresetPicker
        className="mb-3"
        presets={SURFACE_PRESETS.map((p) => ({ id: p.id, label: p.label }))}
        activeId={activeId}
        onSelect={(id) => setActiveId(id as SurfacePresetId)}
      />

      <div className="rounded-xl border border-border-subtle bg-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-border-subtle px-3 py-2">
          <div className="flex items-center gap-2">
            <Network className="h-3.5 w-3.5 text-text-3" />
            <span className="text-[11px] font-medium text-text">{activePreset.label}</span>
            {result && (
              <span className="text-[11px] text-text-3">
                · {result.nodes.length} nodes · {result.edges.length} edges
              </span>
            )}
          </div>
          {runQuery.isPending && <span className="text-[11px] text-text-3 animate-pulse">Loading…</span>}
        </div>
        {runQuery.isPending && !result && <div className="flex h-64 items-center justify-center"><Loading /></div>}
        {runQuery.isError && (
          <div className="flex h-32 items-center justify-center">
            <span className="text-[11px] text-red">Query failed — graph may not be ready</span>
          </div>
        )}
        {result && result.nodes.length === 0 && (
          <div className="flex h-32 items-center justify-center">
            <span className="text-[11px] text-text-3">No internet-exposed assets found</span>
          </div>
        )}
        {result && result.nodes.length > 0 && (
          <GraphView
            nodes={gvNodes}
            edges={gvEdges}
            height={460}
            onNodeClick={(id) => navigate({ to: "/investigate/assets/$id", params: { id } })}
          />
        )}
      </div>
    </div>
  );
}

export function DomainMonitor() {
  const [tab, setTab] = useState<Tab>("candidates");
  const { data: candData } = usePhishingCandidates("pending");
  const { data: domData } = useMonitoredDomains();
  const pendingCount = candData?.total ?? 0;
  const domainCount = domData?.domains.length ?? 0;

  return (
    <div>
      <PageHeader
        title="Domain Monitor"
        subtitle="External attack surface, phishing detection, and brand look-alike monitoring."
      />

      {/* Tabs */}
      <div className="mb-4 flex items-center gap-1 border-b border-border-subtle">
        <button
          onClick={() => setTab("candidates")}
          className={`flex items-center gap-1.5 rounded-t px-3 py-2 text-[12px] font-medium transition-colors ${
            tab === "candidates" ? "border-b-2 border-teal text-teal" : "text-text-3 hover:text-text-2"
          }`}
        >
          <Radar className="h-3.5 w-3.5" />
          {/* The count is the pending queue, which means "genuinely
              suspected": automatically cleared candidates carry status=auto_dismissed and
              are counted on their own filter, not here. */}
          Suspected Phishing
          {pendingCount > 0 && (
            <span className="ml-1 rounded bg-red/10 px-1 py-0.5 text-[11px] font-medium text-red">
              {pendingCount}
            </span>
          )}
        </button>
        <button
          onClick={() => setTab("surface")}
          className={`flex items-center gap-1.5 rounded-t px-3 py-2 text-[12px] font-medium transition-colors ${
            tab === "surface" ? "border-b-2 border-teal text-teal" : "text-text-3 hover:text-text-2"
          }`}
        >
          <Network className="h-3.5 w-3.5" />
          Attack Surface
        </button>
        <button
          onClick={() => setTab("domains")}
          className={`flex items-center gap-1.5 rounded-t px-3 py-2 text-[12px] font-medium transition-colors ${
            tab === "domains" ? "border-b-2 border-teal text-teal" : "text-text-3 hover:text-text-2"
          }`}
        >
          <Globe className="h-3.5 w-3.5" />
          Monitored Domains
          {domainCount > 0 && <span className="ml-1 text-[11px] text-text-3">({domainCount})</span>}
        </button>
      </div>

      {tab === "candidates" && <CandidatesTab />}
      {tab === "surface"    && <AttackSurface />}
      {tab === "domains"    && <MonitoredDomainsTab />}

      {/* How it works */}
      <div className="mt-4 rounded-lg border border-border-subtle bg-surface/50 p-4 text-[11px] text-text-3">
        <div className="mb-1 flex items-center gap-1.5 font-medium text-text-2">
          <AlertTriangle className="h-3.5 w-3.5 text-amber" />
          How detection works
        </div>
        Every 6 hours we query certificate transparency logs (crt.sh) for certificates
        whose domain resembles one you monitor — comparing registrable domains with
        edit-distance, homoglyph, affix and label matching (a different TLD counts as a
        material difference, so example.shop is not treated as example.com). Names that are not
        hostnames, and certificates for your own subdomains, are discarded. Each hit is
        triaged by the configured LLM: the ones it clears as benign go straight to “Cleared”
        (marked “Cleared by AI”) with their reasoning, and only genuinely-suspected domains wait
        for you. With no LLM configured, or when the call fails, a similarity heuristic scores
        the hit instead (labelled “Heuristic”), and its verdict alone never clears a hit. Every
        scan also re-scores the waiting hits against the current similarity metric; one that
        falls below the detection threshold moves to “Cleared” (marked “Cleared by re-score”)
        whatever its verdict, with a note saying so in its reasoning. Confirm a
        candidate to flag it for takedown, or dismiss false positives — a dismissal now
        sticks across scans.
      </div>
    </div>
  );
}
