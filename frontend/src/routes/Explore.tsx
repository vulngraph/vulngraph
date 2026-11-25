import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { api, type GraphResult, type GraphStatus, type NLResult } from "../lib/api";
import { graphMultiHopNotice, graphNotReadyNotice } from "../lib/graphStatus";
import { Empty, ErrorNote, KevBadge } from "../components/ui";
import { scoreTone } from "../lib/format";
import { NLQBar } from "../components/NLQBar";
import { GraphView, type GroupBy } from "../components/GraphView";
import { SavedDetections } from "../components/SavedDetections";
import { CypherEditor, type HistoryEntry } from "../components/CypherEditor";
import { type SavedQuery } from "../components/SaveQueryDialog";
import { CYPHER_EXAMPLES, type CypherExample } from "../lib/queryLibrary";

// ── Category accent colours (badge + active card) ────────────────────────────
const CATEGORY_ACCENT: Record<string, { badge: string; active: string; label: string }> = {
  "Internet exposure":          { label: "Exposure",   badge: "border-red/30 text-red bg-red/10",                      active: "border-red/50 bg-red/10"               },
  "IAM / Privilege escalation": { label: "IAM",        badge: "border-amber/30 text-amber bg-amber/10",                active: "border-amber/50 bg-amber/10"           },
  "OIDC / CI-CD":               { label: "OIDC",       badge: "border-purple-400/30 text-purple-400 bg-purple-400/10", active: "border-purple-400/50 bg-purple-400/10" },
  "Attack chains":              { label: "Attack",     badge: "border-red/30 text-red bg-red/10",                      active: "border-red/50 bg-red/10"               },
  "Supply chain":               { label: "Supply",     badge: "border-orange/30 text-orange bg-orange/10",             active: "border-orange/50 bg-orange/10"         },
  "Kubernetes":                 { label: "K8s",        badge: "border-teal/30 text-teal bg-teal/10",                   active: "border-teal/50 bg-teal/10"             },
  "Data":                       { label: "Data",       badge: "border-sky/30 text-sky bg-sky/10",                      active: "border-sky/50 bg-sky/10"               },
  "Permissions & Secrets":      { label: "Perms",    badge: "border-amber/30 text-amber bg-amber/10",                active: "border-amber/50 bg-amber/10"           },
  "Network":                    { label: "Network",  badge: "border-purple-400/30 text-purple-400 bg-purple-400/10", active: "border-purple-400/50 bg-purple-400/10" },
  "Blast radius":               { label: "Blast",    badge: "border-red/30 text-red bg-red/10",                      active: "border-red/50 bg-red/10"               },
  "DNS":                        { label: "DNS",      badge: "border-sky/30 text-sky bg-sky/10",                      active: "border-sky/50 bg-sky/10"               },
  "Load balancers":             { label: "LB",       badge: "border-amber/30 text-amber bg-amber/10",                active: "border-amber/50 bg-amber/10"           },
  "IaC / Ownership":            { label: "IaC",      badge: "border-emerald/30 text-emerald bg-emerald/10",          active: "border-emerald/50 bg-emerald/10"       },
  "SSO / Access":               { label: "SSO",      badge: "border-sky/30 text-sky bg-sky/10",                      active: "border-sky/50 bg-sky/10"               },
  __default:                    { label: "Graph",    badge: "border-border-subtle text-text-3 bg-surface-2",         active: "border-teal/50 bg-teal/10"             },
};

// ── Graph — Cypher workbench ──────────────────────────────────────────────────
// One focused surface: ask in plain English or write Cypher, see the result as
// an interactive graph. The query library provides starter queries; saved
// queries persist in localStorage.

const EXAMPLE_GROUPS = CYPHER_EXAMPLES.reduce<Record<string, typeof CYPHER_EXAMPLES>>((m, ex) => {
  (m[ex.category] ??= []).push(ex);
  return m;
}, {});

// The always-visible starter row — the full library collapses behind a
// disclosure so results aren't pushed ~2000px below the fold.
const FEATURED_IDS = [
  "privesc-chains",
  "exposed-high-risk",
  "internet-to-escalation",
  "sg-open-to-internet",
  "k8s-internet-exposed-services",
  "supply-chain-full-attack-chain",
];
const FEATURED_EXAMPLES = FEATURED_IDS
  .map((id) => CYPHER_EXAMPLES.find((e) => e.id === id))
  .filter((e): e is CypherExample => Boolean(e));

const SAVED_KEY = "graph.savedCypher";
function loadSaved(): SavedQuery[] {
  try {
    const v = JSON.parse(localStorage.getItem(SAVED_KEY) ?? "[]");
    return Array.isArray(v) ? v : [];
  } catch { return []; }
}

const HISTORY_KEY = "graph.queryHistory";
const HISTORY_MAX = 20;
function loadHistory(): HistoryEntry[] {
  try {
    const v = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    return Array.isArray(v) ? v : [];
  } catch { return []; }
}
function saveHistory(entry: HistoryEntry, prev: HistoryEntry[]): HistoryEntry[] {
  // Deduplicate by exact query text, keep most-recent first.
  const deduped = prev.filter((e) => e.query !== entry.query);
  const next = [entry, ...deduped].slice(0, HISTORY_MAX);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  return next;
}

// ── Query suggestions ─────────────────────────────────────────────────────────
// After a graph result loads, we infer which node types are present and surface
// the 3 most relevant library queries as dismissable chips.
// Example ids must exist in CYPHER_EXAMPLES — unknown ids are silently skipped.
const SUGGESTION_RULES: Array<{ nodeType: string; exampleId: string }> = [
  { nodeType: "EC2Instance", exampleId: "exposed-high-risk" },
  { nodeType: "ec2_instance", exampleId: "exposed-high-risk" },
  { nodeType: "IamRole", exampleId: "privesc-chains" },
  { nodeType: "iam_role", exampleId: "privesc-chains" },
  { nodeType: "k8s_service", exampleId: "k8s-internet-exposed-services" },
  { nodeType: "K8sWorkload", exampleId: "k8s-exposed-workload-to-iam-escalation" },
  { nodeType: "Repo", exampleId: "repos-deploying-to-exposed-services" },
  { nodeType: "Package", exampleId: "supply-chain-full-attack-chain" },
  { nodeType: "k8s_certificate", exampleId: "expiring-certs-on-exposed" },
  { nodeType: "acm_certificate", exampleId: "expiring-certs-on-exposed" },
  { nodeType: "dns_record", exampleId: "dns-points-to" },
  { nodeType: "SecurityGroup", exampleId: "sg-open-to-internet" },
];

function buildSuggestions(result: GraphResult | undefined): CypherExample[] {
  if (!result || result.nodes.length === 0) return [];
  const presentTypes = new Set(result.nodes.map((n) => n.type));
  const seen = new Set<string>();
  const suggestions: CypherExample[] = [];
  for (const rule of SUGGESTION_RULES) {
    if (presentTypes.has(rule.nodeType) && !seen.has(rule.exampleId)) {
      const ex = CYPHER_EXAMPLES.find((e) => e.id === rule.exampleId);
      if (ex) {
        seen.add(ex.id);
        suggestions.push(ex);
        if (suggestions.length === 3) break;
      }
    }
  }
  return suggestions;
}

// Default query shown on first open — privilege escalation paths exist in every
// real environment and immediately demonstrate the graph's value.
// Multi-label [r:CanAssume|CanEscalateTo] doesn't return edge vars in Ladybug — nodes render
// but edges are absent. CanEscalateTo is also Identity→Identity (no Identity nodes exist).
// Use single-label CanAssume so the edge binding r is populated.
const DEFAULT_QUERY =
  "MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)\nRETURN a, r, b LIMIT 50";

export function Explore() {
  const navigate = useNavigate();
  const taRef = useRef<HTMLTextAreaElement>(null);
  const workbenchRef = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [activeChipId, setActiveChipId] = useState<string | null>(null);
  const [libraryOpen, setLibraryOpen] = useState(false);
  const [result, setResult] = useState<GraphResult | undefined>(undefined);
  const [saved, setSaved] = useState<SavedQuery[]>(loadSaved);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [showDetections, setShowDetections] = useState(false);
  const [dismissedSuggestions, setDismissedSuggestions] = useState<Set<string>>(new Set());

  function persistSaved(next: SavedQuery[]) {
    setSaved(next);
    localStorage.setItem(SAVED_KEY, JSON.stringify(next));
  }

  const runCypher = useMutation({
    mutationFn: (q: string) => api.post<GraphResult>("/api/graph/cypher", { query: q, max_nodes: 500, max_edges: 2000 }),
    onSuccess: (data, variables) => {
      setResult(data);
      // Record to query history (skip the auto-run default query on first load).
      const entry: HistoryEntry = {
        query: variables,
        timestamp: Date.now(),
        nodeCount: data.nodes?.length ?? 0,
      };
      setHistory((prev) => saveHistory(entry, prev));
    },
    onError: () => {
      // Mark the chip that triggered this run as failed so the user knows
      // not to click it again without investigating.
      if (activeChipId) {
        setFailedQueryIds((s) => new Set(s).add(activeChipId));
        setActiveChipId(null);
      }
    },
  });

  // Auto-run the default query on first load so the graph is never blank.
  useEffect(() => {
    if (!result) runCypher.mutate(DEFAULT_QUERY);
  }, []);

  // Accept Cypher queries dispatched from ChatPanel ("Run in graph" button).
  useEffect(() => {
    function onRunCypher(e: Event) {
      const cypher = (e as CustomEvent<{ cypher: string }>).detail?.cypher;
      if (cypher) {
        setQuery(cypher);
        setActiveChipId(null);
        runCypher.mutate(cypher);
      }
    }
    window.addEventListener("graph:run-cypher", onRunCypher);
    return () => window.removeEventListener("graph:run-cypher", onRunCypher);
  }, []);

  // NLQBar has already run the generated Cypher server-side (POST /api/graph/nl)
  // and the analyst confirmed it in the preview — so land the query in the
  // editor and adopt the result it came with instead of executing it twice.
  function handleNLQ(cypher: string, _label: string, nlResult?: NLResult) {
    setQuery(cypher);
    setActiveChipId(null);
    if (nlResult) {
      setResult(nlResult);
      setHistory((prev) => saveHistory({ query: cypher, timestamp: Date.now(), nodeCount: nlResult.nodes?.length ?? 0 }, prev));
    } else {
      runCypher.mutate(cypher);
    }
  }

  function submitCypher() {
    const q = query.trim();
    if (q) {
      setActiveChipId(null); // manual run — not from a chip
      runCypher.mutate(q);
    }
  }

  const cypherErr = runCypher.error as { status?: number; message?: string } | null;

  // Poll graph readiness so we can show "warming up" instead of empty silence.
  // After a pod restart the worker restores its snapshot or rebuilds Ladybug from CH.
  // A missing engine does not come back by polling, so it is polled slowly too.
  const graphStatus = useQuery({
    queryKey: ["graph-status"],
    queryFn: () => api.get<GraphStatus>("/api/graph/status"),
    refetchInterval: (q) =>
      q.state.data?.ready || q.state.data?.state === "not_configured" ? 30_000 : 8_000,
    staleTime: 5_000,
  });
  // A status read that failed is unknown, not ready.
  const graphNotice = graphNotReadyNotice(
    graphStatus.isError ? { ready: false, state: "unknown" } : graphStatus.data,
  );
  const multiHopNotice = graphMultiHopNotice(graphStatus.data);

  // Track which library queries errored this session. A crashing query poisons
  // Ladybug for all subsequent queries, so we mark it and prevent re-clicking.
  // Lazy — no upfront probing, zero extra Ladybug load.
  const [failedQueryIds, setFailedQueryIds] = useState<Set<string>>(new Set());

  // Compute query suggestions from the current graph result. Only shown when Ladybug
  // is ready and the graph has returned nodes so we have type information to match on.
  const suggestions = useMemo(
    () => (graphStatus.data?.ready ? buildSuggestions(result) : []),
    [result, graphStatus.data?.ready],
  );
  const visibleSuggestions = suggestions.filter((s) => !dismissedSuggestions.has(s.id));

  return (
    <div>
      <div className="mb-1">
        <h1 className="font-display text-xl text-text">Graph</h1>
        <p className="text-[11px] text-text-3">Query your security graph — ask in plain English or write Cypher.</p>
      </div>

      {/* NL Ask box — NLQBar owns the one NL→Cypher path (/api/graph/nl) and
          shows the generated Cypher for review before it touches the editor. */}
      <NLQBar
        className="mb-3"
        onQuery={handleNLQ}
        placeholder="Ask in plain English — e.g. certs expiring in 30 days, repos that deploy to internet-exposed assets, IAM roles that can escalate…"
      />

      {/* Query library — quick-start chips always visible; the full 47-query
          grid collapses behind a disclosure so results stay near the fold. */}
      <div className="mb-3 space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] uppercase tracking-wide text-text-3">Quick starts:</span>
          {FEATURED_EXAMPLES.map((ex) => (
            <button
              key={ex.id}
              onClick={() => {
                setQuery(ex.cypher);
                setActiveChipId(ex.id);
                runCypher.mutate(ex.cypher);
                setTimeout(() => workbenchRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
              }}
              title={ex.desc}
              className={`rounded-full border px-2.5 py-1 text-[12px] transition-colors ${
                activeChipId === ex.id
                  ? "border-teal/50 bg-teal/10 text-teal"
                  : "border-border-subtle text-text-2 hover:border-teal/30 hover:text-text"
              }`}
            >
              {ex.label}
            </button>
          ))}
          <button
            onClick={() => setLibraryOpen((o) => !o)}
            aria-expanded={libraryOpen}
            className="text-[12px] text-teal hover:underline"
          >
            {libraryOpen ? "▴ Hide library" : `Browse all ${CYPHER_EXAMPLES.length} queries ▾`}
          </button>
        </div>
        {libraryOpen && Object.entries(EXAMPLE_GROUPS).map(([cat, exs]) => {
          const accent = CATEGORY_ACCENT[cat] ?? CATEGORY_ACCENT.__default;
          return (
            <div key={cat}>
              <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">{cat}</div>
              <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
                {exs.map((ex) => {
                  const active = activeChipId === ex.id;
                  const failed = failedQueryIds.has(ex.id);
                  return (
                    <button
                      key={ex.id}
                      onClick={() => {
                        setQuery(ex.cypher);
                        setActiveChipId(ex.id);
                        if (failed) setFailedQueryIds((s) => { const n = new Set(s); n.delete(ex.id); return n; });
                        runCypher.mutate(ex.cypher);
                        setTimeout(() => workbenchRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
                      }}
                      title={failed ? "This query errored — click to retry" : ex.cypher}
                      className={`glass rounded-xl border p-3 text-left transition-all activity-shimmer-hover ${
                        failed
                          ? "border-red/30 bg-red/5"
                          : active
                          ? `${accent.active} scale-[1.01]`
                          : "border-border-subtle hover:border-teal/20 hover:bg-surface-2"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-1">
                        <span className={`text-[12px] font-semibold leading-snug ${active ? "text-text" : "text-text-2"} ${failed ? "line-through text-red/60" : ""}`}>
                          {ex.label}{failed ? " ⚠" : ""}
                        </span>
                        <span className={`ml-1 shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ${accent.badge}`}>
                          {accent.label}
                        </span>
                      </div>
                      <p className="mt-1.5 text-[11px] leading-snug text-text-3">
                        {ex.desc}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
        {saved.length > 0 && (
          <div>
            <div className="mb-2 text-[11px] uppercase tracking-wide text-teal/60">★ Saved</div>
            <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
              {saved.map((s) => (
                <div key={s.name} className="glass flex items-center justify-between gap-1 rounded-xl border border-teal/30 bg-teal/5 px-3 py-2.5">
                  <button onClick={() => { setQuery(s.cypher); setActiveChipId(null); runCypher.mutate(s.cypher); }} className="min-w-0 flex-1 truncate text-left text-[12px] font-semibold text-teal hover:text-teal/80" title={s.cypher}>{s.name}</button>
                  <button onClick={() => persistSaved(saved.filter((x) => x.name !== s.name))} className="shrink-0 text-teal/40 hover:text-red" title="Remove">×</button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Query suggestions — dismissable chips shown after graph loads, based on node types */}
      {visibleSuggestions.length > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <span className="text-[11px] uppercase tracking-wide text-text-3">Try:</span>
          {visibleSuggestions.map((s) => (
            <span key={s.id} className="inline-flex items-center gap-1 rounded-full border border-teal/30 bg-teal/5 px-2.5 py-1 text-[11px] text-teal">
              <button
                onClick={() => { setQuery(s.cypher); setActiveChipId(null); runCypher.mutate(s.cypher); }}
                className="hover:underline"
                title={s.cypher}
              >
                {s.label}
              </button>
              <button
                onClick={() => setDismissedSuggestions((prev) => new Set(prev).add(s.id))}
                className="text-teal/40 hover:text-teal"
                aria-label="Dismiss suggestion"
              >×</button>
            </span>
          ))}
        </div>
      )}

      <CypherEditor
        workbenchRef={workbenchRef}
        taRef={taRef}
        query={query}
        onQueryChange={setQuery}
        onSubmit={submitCypher}
        isPending={runCypher.isPending}
        saved={saved}
        onPersistSaved={persistSaved}
        history={history}
        onSelectHistory={setQuery}
        showDetections={showDetections}
        onToggleDetections={() => setShowDetections((v) => !v)}
        onShowDetections={() => setShowDetections(true)}
        onClear={() => { setQuery(""); setResult(undefined); }}
      />

      {/* Errors — immediately below the editor so failures are impossible to miss */}
      {runCypher.isError && (
        <div className={`mt-3 rounded-lg border px-3 py-2 text-[13px] ${isCypherSyntax(cypherErr) ? "border-red/30 bg-red/10 text-red" : "border-amber/30 bg-amber/10 text-amber"}`}>
          {cypherErr?.message || "Query failed — try again"}
        </div>
      )}

      {/* Saved detections panel (detection-as-code) */}
      {showDetections && (
        <div className="mt-3">
          <SavedDetections
            onClose={() => setShowDetections(false)}
            onLoad={(c) => { setQuery(c); setShowDetections(false); }}
          />
        </div>
      )}

      {/* Graph-engine banner — shown until the engine reports a loaded, non-empty build */}
      {graphNotice && (
        <div role="status" className="mt-3 flex items-center gap-2 rounded-lg border border-amber/30 bg-amber/5 px-3 py-2 text-[11px] text-amber">
          <span className="animate-pulse">●</span>
          <span>{graphNotice}</span>
        </div>
      )}

      {/* Engine-limit banner — a node table above one node group (ladybug#1341) */}
      {multiHopNotice && (
        <div role="alert" className="mt-3 rounded-lg border border-amber/30 bg-amber/5 px-3 py-2 text-[11px] text-amber">
          {multiHopNotice}
        </div>
      )}

      {/* Empty state */}
      {!result && !runCypher.isPending && !runCypher.isError && (
        <div className="mt-6 rounded-lg border border-dashed border-border-subtle py-14 text-center">
          <div className="text-sm font-medium text-text-2">Your security graph, queryable</div>
          <div className="mt-1 text-[11px] text-text-3">
            Ask in plain English, pick from the library above, or write Cypher — then Run.
          </div>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            {["Repo → what it deploys", "Privilege escalation", "Internet-exposed KEV", "DNS resolution", "Certs expiring ≤30 days", "K8s services"].map((label) => {
              const ex = CYPHER_EXAMPLES.find((e) => e.label === label);
              return ex ? (
                <button key={label} onClick={() => setQuery(ex.cypher)}
                  className="rounded border border-border-subtle bg-surface px-3 py-1.5 text-[11px] text-text-2 hover:border-teal/30 hover:text-text transition-colors">
                  {label}
                </button>
              ) : null;
            })}
          </div>
        </div>
      )}

      {/* Results */}
      <GraphResult
        result={result}
        navigate={navigate}
        onQueryFromNode={(id) => {
          // Seed the console with the node's outgoing neighbourhood over the Asset-sourced
          // rel types, so the query stays scoped to topology edges and is easy to edit.
          const safeId = id.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
          setQuery(
            `MATCH (n:Asset {id: '${safeId}'})-[r:ConnectedViaSG|ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|AllowsFrom|Binds|ExposedToInternet|RunsPackage]->(m)\nRETURN n, r, m LIMIT 50`
          );
          // Scroll editor into view
          setTimeout(() => taRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
        }}
        onLimit50={() => {
          const limited = withLimit50(query);
          setQuery(limited);
          runCypher.mutate(limited);
        }}
      />
    </div>
  );
}

// Rewrites (or appends) a `LIMIT 50` clause into a Cypher query — used by the
// truncation / too-many-nodes notices' "Limit to 50" action button.
function withLimit50(q: string): string {
  const trimmed = q.trim();
  if (/limit\s+\d+/i.test(trimmed)) return trimmed.replace(/limit\s+\d+/i, "LIMIT 50");
  return `${trimmed}\nLIMIT 50`;
}

// ── Shared ────────────────────────────────────────────────────────────────────

const MAX_RENDER_NODES = 500;
const GROUP_OPTIONS: { value: GroupBy; label: string }[] = [
  { value: "none", label: "None" },
  { value: "account", label: "Account" },
  { value: "provider", label: "Provider" },
  { value: "type", label: "Type" },
];

type GResultNode = GraphResult["nodes"][number];
type GResultEdge = GraphResult["edges"][number];

function mergeGraph(base: GraphResult, extraNodes: GResultNode[], extraEdges: GResultEdge[]): GraphResult {
  const nodes = [...(base.nodes ?? [])];
  const seenN = new Set(nodes.map((n) => n.id));
  for (const n of extraNodes) if (!seenN.has(n.id)) { seenN.add(n.id); nodes.push(n); }
  const edges = [...(base.edges ?? [])];
  const seenE = new Set(edges.map((e) => `${e.src_id}|${e.dst_id}|${e.edge_type}`));
  for (const e of extraEdges) {
    const k = `${e.src_id}|${e.dst_id}|${e.edge_type}`;
    if (!seenE.has(k)) { seenE.add(k); edges.push(e); }
  }
  return {
    nodes, edges, truncated: base.truncated, columns: base.columns, rows: base.rows,
    multi_hop_may_be_incomplete: base.multi_hop_may_be_incomplete,
  };
}

function GraphResult({ result, centerId, navigate, onQueryFromNode, onLimit50 }: { result?: GraphResult; centerId?: string; navigate: ReturnType<typeof useNavigate>; onQueryFromNode?: (id: string) => void; onLimit50?: () => void }) {
  const [groupBy, setGroupBy] = useState<GroupBy>("none");
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [extra, setExtra] = useState<{ nodes: GResultNode[]; edges: GResultEdge[] }>({ nodes: [], edges: [] });
  const [expandingId, setExpandingId] = useState<string | null>(null);

  // Reset expand-additions on every new result, but remember the user's last
  // graph/table choice for the session — don't force back to "graph" each run.
  useEffect(() => { setExtra({ nodes: [], edges: [] }); }, [result]);

  const expand = useMutation({
    mutationFn: (id: string) => api.get<GraphResult>(`/api/graph/expand?id=${encodeURIComponent(id)}`),
    onMutate: (id) => setExpandingId(id),
    onSettled: () => setExpandingId(null),
    onSuccess: (data) => setExtra((prev) => ({
      nodes: [...prev.nodes, ...data.nodes],
      edges: [...prev.edges, ...data.edges],
    })),
  });

  const merged = useMemo(
    () => (result ? mergeGraph(result, extra.nodes, extra.edges) : undefined),
    [result, extra],
  );

  if (!result || !merged) return null;

  const tooMany = merged.nodes.length > MAX_RENDER_NODES;
  const expandedCount = merged.nodes.length - result.nodes.length;
  const scalarRows = merged.rows ?? [];
  const isScalar = scalarRows.length > 0 && merged.nodes.length === 0;

  return (
    <div className="mt-3">
      {/* Stats + view toggle */}
      <div className="mb-2 flex flex-wrap items-center gap-3 text-xs text-text-3">
        {isScalar ? (
          <span>
            <span className="tabular-nums text-text">{scalarRows.length}</span>{" "}
            {scalarRows.length === 1 ? "row" : "rows"}
          </span>
        ) : (
          <span>
            <span className="tabular-nums text-text">{merged.nodes.length}</span> nodes ·{" "}
            <span className="tabular-nums text-text">{merged.edges.length}</span> edges
          </span>
        )}
        {expandedCount > 0 && <span className="text-sky">+{expandedCount} from expand</span>}

        {!isScalar && merged.nodes.length > 0 && (
          <span className="ml-auto flex items-center gap-1">
            {/* Graph / Table toggle */}
            <span className="flex items-center rounded border border-border-subtle p-0.5 mr-2">
              {(["graph", "table"] as const).map((v) => (
                <button key={v} onClick={() => setViewMode(v)}
                  className={`rounded px-2 py-0.5 text-[11px] capitalize transition-colors ${viewMode === v ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}>
                  {v === "graph" ? "⬡ Graph" : "≡ Table"}
                </button>
              ))}
            </span>
            {viewMode === "graph" && !tooMany && (
              <>
                <span className="text-[11px] uppercase">group by</span>
                {GROUP_OPTIONS.map((o) => (
                  <button key={o.value} onClick={() => setGroupBy(o.value)}
                    className={`rounded px-1.5 py-0.5 text-[11px] ${groupBy === o.value ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}>
                    {o.label}
                  </button>
                ))}
              </>
            )}
          </span>
        )}
      </div>

      {expand.isError && <ErrorNote message={(expand.error as Error).message} />}

      {merged.multi_hop_may_be_incomplete && (
        <div role="alert" className="mb-2 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-[11px] text-amber">
          May be incomplete: a graph node table holds more than 131,072 rows, so any multi-hop or variable-length match in this query can have missed relationships. An empty or short result here is not proof that no path exists.
        </div>
      )}

      {merged.truncated && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-[11px] text-amber">
          <span>Results capped at {isScalar ? scalarRows.length : merged.nodes.length}. Narrow the query with a tighter <code className="font-mono">WHERE</code> clause, or cap it below.</span>
          {onLimit50 && (
            <button onClick={onLimit50}
              className="ml-auto shrink-0 rounded border border-amber/40 px-2 py-1 text-[11px] text-amber hover:bg-amber/10 transition-colors">
              Limit to 50 &amp; re-run
            </button>
          )}
        </div>
      )}

      {isScalar ? (
        <ScalarResult columns={merged.columns ?? []} rows={scalarRows} />
      ) : merged.nodes.length === 0 ? (
        <Empty message="No results. Try a different query or check the Ladybug schema — node labels are Asset, Repo, IamRole, Package." />
      ) : viewMode === "table" ? (
        <ResultTable nodes={merged.nodes} edges={merged.edges} navigate={navigate} />
      ) : tooMany ? (
        <div className="glass rounded-lg p-6 text-center">
          <div className="mb-2 text-sm text-text">{merged.nodes.length} nodes</div>
          <div className="mb-3 text-[11px] text-text-3">Too many nodes to render as a graph. Tighten your WHERE clause, or cap it below.</div>
          {onLimit50 && (
            <button onClick={onLimit50}
              className="rounded border border-teal/40 px-3 py-1.5 text-[12px] text-teal hover:bg-teal/10 transition-colors">
              Limit to 50 &amp; re-run
            </button>
          )}
        </div>
      ) : (
        <GraphView
          centerId={centerId}
          groupBy={groupBy}
          nodes={merged.nodes.map((n) => ({
            id: n.id, label: n.name || n.id, sub: n.type, provider: n.provider, account: n.account_id,
            risk: n.max_score, exposed: n.exposed, hasKev: n.has_kev, exploitable: n.exploitable, toxicCombo: n.toxic_combo,
          }))}
          edges={merged.edges.map((e) => ({ source: e.src_id, target: e.dst_id, label: e.edge_type }))}
          onNodeClick={(id) => navigate({ to: "/investigate/assets/$id", params: { id } })}
          onExpand={(id) => expand.mutate(id)}
          onQueryFromNode={onQueryFromNode}
          expandingId={expandingId}
        />
      )}
    </div>
  );
}

// ScalarResult renders aggregate/tabular query output (count/sum/avg, or bare
// property RETURNs) — the rows/columns the graph view can't show. A single
// value (one row, one column) renders as a big number; anything else as a table.
function ScalarResult({ columns, rows }: { columns: string[]; rows: Record<string, unknown>[] }) {
  // Fall back to the union of row keys if the backend didn't send column order.
  const cols = columns.length > 0 ? columns : Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
  const [sort, setSort] = useState<{ col: string; dir: 1 | -1 } | null>(null);

  const fmt = (v: unknown): string => {
    if (v === null || v === undefined) return "—";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  };

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const { col, dir } = sort;
    return [...rows].sort((a, b) => {
      const av = a[col];
      const bv = b[col];
      if (av === bv) return 0;
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [rows, sort]);

  function toggleSort(col: string) {
    setSort((prev) => (prev?.col === col ? (prev.dir === 1 ? { col, dir: -1 } : null) : { col, dir: 1 }));
  }

  if (rows.length === 1 && cols.length === 1) {
    const only = rows[0][cols[0]];
    return (
      <div className="glass rounded-lg p-8 text-center">
        <div className="tabular-nums text-4xl font-semibold text-text">{fmt(only)}</div>
        <div className="mt-1 text-[11px] uppercase tracking-wide text-text-3">{cols[0]}</div>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-1.5 text-[12px] text-text-3">{rows.length} row{rows.length !== 1 ? "s" : ""}</div>
      <div className="overflow-x-auto rounded-lg border border-border-subtle">
        <table className="w-full border-collapse text-[12px]">
          <thead>
            <tr className="border-b border-border-subtle bg-surface">
              {cols.map((c) => (
                <th key={c}>
                  <button
                    onClick={() => toggleSort(c)}
                    className="flex w-full items-center gap-1 px-3 py-2 text-left font-medium text-text-3 uppercase tracking-wide hover:text-text-2 transition-colors"
                  >
                    {c}{sort?.col === c ? (sort.dir === 1 ? " ▲" : " ▼") : ""}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((r, i) => (
              <tr key={i} className="border-b border-border-subtle odd:bg-surface/40 hover:bg-surface transition-colors">
                {cols.map((c) => (
                  <td key={c} className="px-3 py-2 tabular-nums text-text-2">{fmt(r[c])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type NodeSortKey = "name" | "type" | "provider" | "region" | "max_score";

function ResultTable({ nodes, edges, navigate }: { nodes: GResultNode[]; edges: GResultEdge[]; navigate: ReturnType<typeof useNavigate> }) {
  const [sort, setSort] = useState<{ key: NodeSortKey; dir: 1 | -1 } | null>(null);

  const sortedNodes = useMemo(() => {
    if (!sort) return nodes;
    const { key, dir } = sort;
    return [...nodes].sort((a, b) => {
      const av = key === "name" ? (a.name || a.id) : a[key];
      const bv = key === "name" ? (b.name || b.id) : b[key];
      if (av === bv) return 0;
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [nodes, sort]);

  function toggleSort(key: NodeSortKey) {
    setSort((prev) => (prev?.key === key ? (prev.dir === 1 ? { key, dir: -1 } : null) : { key, dir: 1 }));
  }

  function sortArrow(key: NodeSortKey) {
    return sort?.key === key ? (sort.dir === 1 ? " ▲" : " ▼") : "";
  }

  return (
    <div className="space-y-4">
      {/* Nodes table */}
      {nodes.length > 0 && (
        <div>
          <div className="mb-1.5 text-[12px] text-text-3">{nodes.length} row{nodes.length !== 1 ? "s" : ""}</div>
          <div className="overflow-x-auto rounded-lg border border-border-subtle">
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-border-subtle bg-surface">
                  {([["name", "Name"], ["type", "Type"], ["provider", "Provider"], ["region", "Region"], ["max_score", "Score"]] as const).map(([key, label]) => (
                    <th key={key}>
                      <button onClick={() => toggleSort(key)}
                        className="flex w-full items-center gap-1 px-3 py-2 text-left font-medium text-text-3 uppercase tracking-wide hover:text-text-2 transition-colors">
                        {label}{sortArrow(key)}
                      </button>
                    </th>
                  ))}
                  <th className="px-3 py-2 text-left font-medium text-text-3 uppercase tracking-wide">Signals</th>
                </tr>
              </thead>
              <tbody>
                {sortedNodes.map((n) => (
                  <tr key={n.id}
                    onClick={() => navigate({ to: "/investigate/assets/$id", params: { id: n.id } })}
                    className="group cursor-pointer border-b border-border-subtle odd:bg-surface/40 hover:bg-surface transition-colors">
                    <td className="px-3 py-2">
                      <div className="font-medium text-text group-hover:text-teal transition-colors">{n.name || n.id}</div>
                      <div className="font-mono text-[11px] text-text-3 truncate max-w-xs" title={n.id}>{n.id}</div>
                    </td>
                    <td className="px-3 py-2 text-text-2">{n.type}</td>
                    <td className="px-3 py-2">
                      {n.provider && (
                        <span className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] uppercase text-text-3">{n.provider}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-text-3">{n.region ?? "—"}</td>
                    <td className="px-3 py-2">
                      {(n.max_score ?? 0) > 0 && (
                        <span className={`font-medium tabular-nums ${scoreTone(n.max_score ?? 0)}`}>
                          {n.max_score}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1">
                        {n.toxic_combo && <span className="rounded border border-red/30 bg-red/10 px-1 py-0.5 text-[11px] text-red">toxic</span>}
                        {n.exposed && <span className="rounded border border-orange/30 bg-orange/10 px-1 py-0.5 text-[11px] text-orange">exposed</span>}
                        {n.has_kev && <KevBadge />}
                        {n.exploitable && <span className="rounded border border-red/30 bg-red/10 px-1 py-0.5 text-[11px] text-red">exploitable</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Edges table */}
      {edges.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-border-subtle">
          <div className="border-b border-border-subtle bg-surface px-3 py-1.5 text-[12px] uppercase tracking-wide text-text-3">
            Relationships ({edges.length})
          </div>
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-border-subtle bg-surface/50">
                <th className="px-3 py-1.5 text-left font-medium text-text-3">From</th>
                <th className="px-3 py-1.5 text-left font-medium text-text-3">Relationship</th>
                <th className="px-3 py-1.5 text-left font-medium text-text-3">To</th>
              </tr>
            </thead>
            <tbody>
              {edges.map((e, i) => (
                <tr key={i} className="border-b border-border-subtle odd:bg-surface/40 hover:bg-surface">
                  <td
                    className="px-3 py-1.5 font-mono text-[11px] text-teal hover:underline cursor-pointer truncate max-w-xs"
                    onClick={() => navigate({ to: '/investigate/assets/$id', params: { id: e.src_id } })}
                    title={`Open ${e.src_id}`}
                  >{e.src_id}</td>
                  <td className="px-3 py-1.5">
                    <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-teal">{e.edge_type}</span>
                  </td>
                  <td
                    className="px-3 py-1.5 font-mono text-[11px] text-teal hover:underline cursor-pointer truncate max-w-xs"
                    onClick={() => navigate({ to: '/investigate/assets/$id', params: { id: e.dst_id } })}
                    title={`Open ${e.dst_id}`}
                  >{e.dst_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function isCypherSyntax(err: { status?: number } | null): boolean {
  return err?.status === 400;
}
