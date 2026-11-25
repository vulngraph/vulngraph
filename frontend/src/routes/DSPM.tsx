import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import {
  ChevronRight, Database, Eye, FlaskConical, Info, Lock, Network,
} from "lucide-react";
import { api, type GraphResult } from "../lib/api";
import type { GraphNode, GraphEdge, DSPMSummary } from "../lib/api";
import { useQuery } from "@tanstack/react-query";
import { GraphView } from "../components/GraphView";
import { AssetDetailPanel } from "../components/AssetDetailPanel";
import { NLQBar } from "../components/NLQBar";
import { PresetPicker } from "../components/PresetPicker";
import { Empty, Loading, PageHeader } from "../components/ui";
import { typeMetaFor } from "../lib/assetMeta";
import { dataClassStyle, isSensitive, confidenceTitle } from "../lib/dataClasses";
import { scoreTone } from "../lib/format";

// ── Graph presets ─────────────────────────────────────────────────────────────

type ColorKey = "sky" | "teal" | "purple" | "amber" | "red" | "orange";

const PRESETS = [
  {
    id: "landscape",
    icon: Network,
    label: "Data landscape",
    description: "Storage assets mapped to the data classes their names and tags suggest (inferred, not a content scan)",
    color: "purple" as ColorKey,
    cypher: `MATCH (a)-[r:ContainsData]->(dc)
RETURN a, r, dc
LIMIT 200`,
  },
  {
    id: "exposed",
    icon: Eye,
    label: "Exposed / public data",
    description: "Internet-exposed or publicly accessible stores whose names or tags suggest sensitive data",
    color: "red" as ColorKey,
    cypher: `MATCH (a)-[r:ContainsData]->(dc:DataClass)
WHERE dc.id <> 'dataclass:internal' AND (a.exposed = 1 OR a.public = 1)
RETURN a, r, dc
ORDER BY a.score DESC
LIMIT 100`,
  },
  {
    id: "unencrypted",
    icon: Lock,
    label: "Unencrypted sensitive (S3 / RDS)",
    description: "Sensitive stores OBSERVED to have no encryption-at-rest. Among classified store types, encryption is only collected for S3 buckets and RDS instances; every other store reports unknown and is excluded rather than assumed either way",
    color: "amber" as ColorKey,
    cypher: `MATCH (a)-[r:ContainsData]->(dc:DataClass)
WHERE dc.id <> 'dataclass:internal' AND a.encrypted = 0
RETURN a, r, dc
ORDER BY a.score DESC
LIMIT 100`,
  },
  {
    id: "workload-data",
    icon: FlaskConical,
    label: "Workload → data",
    description: "Workloads with network paths to classified storage — the store's security group admits the workload's",
    color: "sky" as ColorKey,
    // Anchored on classified stores and staged through WITH to keep the fan-out
    // bounded. Sharing a security group is not a path: the store's SG must admit
    // the workload's SG (AllowsFrom, a self-loop when an SG admits its members).
    cypher: `MATCH (store:Asset)-[:ContainsData]->(:DataClass)
MATCH (store)-[:ConnectedViaSG]->(sg:Asset)
WITH DISTINCT store, sg LIMIT 100
MATCH (sg)-[a:AllowsFrom]->(wsg:Asset)
MATCH (w:Asset)-[r2:ConnectedViaSG]->(wsg)
WHERE w.id <> store.id
MATCH (store)-[r2b:ConnectedViaSG]->(sg)
MATCH (store)-[r3:ContainsData]->(dc:DataClass)
RETURN w, r2, wsg, a, sg, r2b, store, r3, dc
ORDER BY w.score DESC
LIMIT 50`,
  },
] as const;

type PresetId = typeof PRESETS[number]["id"];

// ── Graph tab ─────────────────────────────────────────────────────────────────

function DataGraph() {
  const navigate = useNavigate();
  const [activeId, setActiveId] = useState<PresetId>("landscape");
  const [nlqLabel, setNlqLabel] = useState<string | null>(null);
  const [result, setResult] = useState<GraphResult | undefined>();

  const runQuery = useMutation({
    mutationFn: (cypher: string) =>
      api.post<GraphResult>("/api/graph/cypher", { query: cypher, max_nodes: 300, max_edges: 600 }),
    onSuccess: setResult,
  });

  const activePreset = PRESETS.find((p) => p.id === activeId)!;

  useEffect(() => {
    setNlqLabel(null);
    runQuery.mutate(activePreset.cypher);
  }, [activeId]);

  function handleNLQ(cypher: string, label: string) {
    setNlqLabel(label);
    runQuery.mutate(cypher);
  }

  const gvNodes = useMemo(
    () =>
      (result?.nodes ?? []).map((n) => ({
        id: n.id,
        label: n.name || n.id,
        sub: n.type,
        provider: n.provider,
        account: n.account_id,
        risk: n.max_score,
        exposed: n.exposed,
        hasKev: n.has_kev,
        exploitable: n.exploitable,
        toxicCombo: n.toxic_combo,
      })),
    [result],
  );
  const gvEdges = useMemo(
    () => (result?.edges ?? []).map((e) => ({ source: e.src_id, target: e.dst_id, label: e.edge_type })),
    [result],
  );

  return (
    <div>
      {/* AI query bar */}
      <NLQBar
        onQuery={handleNLQ}
        placeholder="Ask AI — e.g. 'show me public S3 buckets with PII' or 'databases accessible from internet-exposed services'"
        className="mb-4"
      />

      {/* Preset picker — one dropdown instead of a 4-card grid */}
      <PresetPicker
        className="mb-4"
        presets={PRESETS.map((p) => ({ id: p.id, label: p.label, desc: p.description }))}
        activeId={activeId}
        onSelect={(id) => setActiveId(id as PresetId)}
      />

      {/* Graph canvas */}
      <div className="rounded-xl border border-border-subtle bg-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-border-subtle px-3 py-2">
          <div className="flex items-center gap-2">
            {(() => { const Icon = activePreset.icon; return <Icon className="h-3.5 w-3.5 text-text-3" />; })()}
            <span className="text-[11px] font-medium text-text">{nlqLabel ?? activePreset.label}</span>
            {nlqLabel && (
              <span className="rounded border px-1 py-0.5 text-[11px] font-bold uppercase text-purple-400 bg-purple-400/10 border-purple-400/30">AI</span>
            )}
            {result && (
              <span className="text-[11px] text-text-3">
                · {result.nodes.length} nodes · {result.edges.length} edges
                {result.truncated && " · truncated"}
              </span>
            )}
          </div>
          {runQuery.isPending && <span className="text-[11px] text-text-3 animate-pulse">Loading…</span>}
        </div>

        {runQuery.isPending && !result && <div className="flex h-64 items-center justify-center"><Loading /></div>}
        {runQuery.isError && (
          <div className="flex h-32 items-center justify-center">
            <span className="text-[11px] text-red">Query failed — graph may not be ready. Try after a correlate sweep.</span>
          </div>
        )}
        {result && result.nodes.length === 0 && (
          <div className="flex h-32 items-center justify-center">
            <span className="text-[11px] text-text-3">No results — classification runs after a correlate sweep</span>
          </div>
        )}
        {result && result.nodes.length > 0 && (
          <GraphView
            nodes={gvNodes}
            edges={gvEdges}
            height={500}
            onNodeClick={(id) => navigate({ to: "/investigate/assets/$id", params: { id } })}
          />
        )}
      </div>

      <p className="mt-2 text-[11px] text-text-3">
        Click any node to open asset detail. Double-click to expand its neighbourhood.{" "}
        <Link to="/investigate/graph" className="text-teal hover:underline">Open full Cypher workbench →</Link>
      </p>
    </div>
  );
}

// ── List tab (existing view preserved) ────────────────────────────────────────

interface DataAsset {
  node: GraphNode;
  classes: string[];
  // confidence per class id, from the ContainsData edge. "high" means asserted
  // (an operator tag, or the resource type itself); "medium" means guessed from
  // the resource name.
  confidence: Record<string, string>;
}

// The worklist and the tile counts both come from the DSPM endpoints
// (/api/dspm/stores, /api/dspm/summary). Neither builds Cypher (the Graph tab,
// its NL bar and the asset drawer's classification lookup do): the predicate
// behind a tile and the predicate behind its list are the same server-side
// expression, so they cannot disagree.

// useDSPMSummary fetches the tile counts. Every number is a server-side aggregate
// over the whole graph, not a count of the capped worklist sample.
function useDSPMSummary() {
  return useQuery({
    queryKey: ["dspm-summary"],
    queryFn: () => api.get<DSPMSummary>("/api/dspm/summary"),
    staleTime: 2 * 60 * 1000,
    retry: false,
  });
}

function useDataAssets(lens: DataFilter) {
  return useQuery({
    queryKey: ["dspm-assets", lens],
    queryFn: async () => {
      const result = await api.get<{ nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean }>(
        `/api/dspm/stores?lens=${encodeURIComponent(lens)}`,
      );
      const assetNodes = new Map<string, GraphNode>();
      for (const n of result.nodes) {
        if (n.type === "data_class" || n.id.startsWith("dataclass:")) continue;
        assetNodes.set(n.id, n);
      }
      const assetClasses = new Map<string, Set<string>>();
      const confidence = new Map<string, Record<string, string>>();
      for (const e of result.edges) {
        // Ladybug returns the rel-table label ("ContainsData"); collectors/CH use the
        // edge_type ("contains_data"). Match either so parsing is source-agnostic.
        if (e.edge_type === "ContainsData" || e.edge_type === "contains_data") {
          if (!assetClasses.has(e.src_id)) assetClasses.set(e.src_id, new Set());
          assetClasses.get(e.src_id)!.add(e.dst_id);
          if (e.confidence) {
            const byClass = confidence.get(e.src_id) ?? {};
            byClass[e.dst_id] = e.confidence;
            confidence.set(e.src_id, byClass);
          }
        }
      }
      // No client-side re-rank: the server already ordered the worklist (its
      // own risk formula), and a second, different JS formula here re-ranked
      // it out from under that order without either agreeing.
      const items: DataAsset[] = [];
      for (const [id, classes] of assetClasses) {
        const node = assetNodes.get(id);
        if (node) {
          items.push({ node, classes: Array.from(classes), confidence: confidence.get(id) ?? {} });
        }
      }
      return { items, truncated: result.truncated };
    },
    staleTime: 2 * 60 * 1000,
    retry: false,
  });
}

function DataAssetRow({ item, onOpen }: { item: DataAsset; onOpen: (id: string) => void }) {
  const { node, classes, confidence } = item;
  const { icon: Icon } = typeMetaFor(node.type);
  return (
    <button type="button" onClick={() => onOpen(node.id)}
      className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-surface/60">
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-surface-2">
        <Icon className="h-3.5 w-3.5 text-text-3" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-[13px] font-medium text-text">{node.name}</span>
          {node.public_tier === 2 && (
            <span title="Confirmed public: a collector observed unauthenticated access via bucket policy/ACL, or a publicly-accessible database endpoint."
              className="rounded border border-red/30 bg-red/10 px-1 py-0.5 text-[11px] font-medium uppercase text-red">public</span>
          )}
          {node.public_tier === 1 && (
            <span title="Public access possible: configuration permits exposure (unlocked public-access-block, network-public database, API behind optional auth) but unauthenticated access was never confirmed."
              className="rounded border border-amber/30 bg-amber/10 px-1 py-0.5 text-[11px] font-medium uppercase text-amber">public?</span>
          )}
          {node.public_tier === 3 && (
            <span title="Exposure unknown: the collector could not read this store's public-access configuration (permission denied, throttle, or timeout). A coverage gap to fix — NOT an observed exposure."
              className="rounded border border-border-subtle bg-surface-2 px-1 py-0.5 text-[11px] font-medium uppercase text-text-3">exposure&nbsp;?</span>
          )}
          {node.exposed && (
            <span title="Internet-exposed: reachable from outside the network, independent of whether it's public."
              className="rounded border border-orange/30 bg-orange/10 px-1 py-0.5 text-[11px] font-medium uppercase text-orange">exposed</span>
          )}
          {node.encryption === "unencrypted" && isSensitive(classes) && (
            <span title="Observed to have no encryption at rest. Among classified store types, encryption is only collected for S3 buckets and RDS instances; every other store reports unknown and is marked encryption ?, never badged unencrypted."
              className="rounded border border-amber/30 bg-amber/10 px-1 py-0.5 text-[11px] font-medium uppercase text-amber">unencrypted</span>
          )}
          {node.encryption !== "unencrypted" && node.encryption !== "encrypted" && isSensitive(classes) && (
            <span title="Encryption unknown: encryption at rest was never observed for this store (not collected for its type, or the describe call failed). A coverage gap, not an observed pass or failure."
              className="rounded border border-border-subtle bg-surface-2 px-1 py-0.5 text-[11px] font-medium uppercase text-text-3">encryption&nbsp;?</span>
          )}
        </div>
        <span className="text-[11px] text-text-3">{node.type} · {node.provider}</span>
      </div>
      <div className="flex shrink-0 flex-wrap gap-1 justify-end max-w-[180px]">
        {classes.map((cls) => {
          const s = dataClassStyle(cls);
          const conf = confidence[cls];
          // A guess is marked as one. An asserted class (operator tag, or the
          // resource type itself) is not, so the unmarked badge is the trustworthy
          // one.
          const guessed = conf === "medium";
          return (
            <span key={cls}
              title={confidenceTitle(conf)}
              className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${s.cls}${guessed ? " border-dashed opacity-80" : ""}`}>
              {s.label}{guessed ? "?" : ""}
            </span>
          );
        })}
      </div>
      {(node.max_score ?? 0) > 0 && (
        <span className={`shrink-0 w-8 text-right text-[12px] font-bold tabular-nums ${scoreTone(node.max_score ?? 0)}`}>{node.max_score}</span>
      )}
      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-text-3" />
    </button>
  );
}

// DataFilter is the lens name sent to /api/dspm/stores. The strings match
// explore.DSPMLens exactly — one vocabulary, defined server-side.
//
// There is deliberately no `sensitive AND (exposed OR public)` lens: it is a
// strict SUPERSET of the sensitive public tiers, so two tiles would show one
// fact twice and double the apparent exposure. "network-exposed" (a graph internet path)
// is a genuinely different measurement from the config-level public tiers.
type DataFilter =
  | "all"
  | "sensitive"
  | "secret-vault"
  | "public-confirmed"
  | "public-possible"
  | "public-unobserved"
  | "network-exposed"
  | "unencrypted"
  | "encryption-unknown";

function DataList({ items, truncated, onOpen }: { items: DataAsset[]; truncated: boolean; onOpen: (id: string) => void }) {
  if (items.length === 0) return (
    <Empty message="No stores match this lens. Classification runs on storage resources; the correlate sweep refreshes it." />
  );
  return (
    <>
      {truncated && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-[11px] text-amber">
          Results capped at 500 — use <Link to="/investigate/graph" className="underline">Graph</Link> for the full query.
        </div>
      )}
      <div className="rounded-xl border border-border-subtle bg-surface">
        <div className="grid grid-cols-[1fr_auto_auto_auto] gap-4 border-b border-border-subtle px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-text-3">
          <span>Asset</span><span>Classification</span><span className="w-8 text-right">Score</span><span className="w-4" />
        </div>
        <div className="divide-y divide-border-subtle/50">
          {items.map((item) => <DataAssetRow key={item.node.id} item={item} onOpen={onOpen} />)}
        </div>
      </div>
    </>
  );
}

// ── Shared ────────────────────────────────────────────────────────────────────

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button onClick={onClick}
      className={`flex items-center gap-1.5 rounded-t px-3 py-2 text-[12px] font-medium transition-colors ${active ? "border-b-2 border-teal text-teal" : "text-text-3 hover:text-text-2"}`}>
      {children}
    </button>
  );
}

// ── Summary tiles ──────────────────────────────────────────────────────────────

// RiskTile is one headline count. Clicking it filters the worklist to the SAME
// server-side lens the count came from, so a tile and its list cannot
// disagree.
function RiskTile({ label, sub, count, tone, active, onClick }: {
  label: string; sub: string; count: number; tone: string; active: boolean; onClick: () => void;
}) {
  return (
    <button onClick={onClick}
      className={`rounded-xl border p-3 text-left transition-all ${active ? tone + " ring-1" : "border-border-subtle bg-surface hover:bg-surface-2"}`}>
      <div className={`text-[22px] font-bold tabular-nums leading-none ${count > 0 ? "" : "text-text-3"}`}>{count}</div>
      <div className="mt-1.5 text-[11px] font-semibold text-text-2">{label}</div>
      <div className="text-[11px] leading-tight text-text-3">{sub}</div>
    </button>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

type Tab = "risk" | "graph";

export function DSPM() {
  const [tab, setTab] = useState<Tab>("risk");
  const [filter, setFilter] = useState<DataFilter>("sensitive");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // One request, one source of truth. Every tile below is a server-side aggregate
  // over the whole graph (internal/app/explore/dspm.go), unit-tested there.
  const summaryQ = useDSPMSummary();
  const s = summaryQ.data;

  const { data, isLoading, isError } = useDataAssets(filter);
  // No client-side re-filtering: the server already applied the lens, and a
  // second predicate here would have to agree with it.
  const items = data?.items ?? [];

  const select = (f: DataFilter) => { setFilter(f); setTab("risk"); };

  return (
    <div>
      <PageHeader
        title="Data Security"
        subtitle="Storage classified by likely sensitivity, ranked by the combinations that matter — confirmed-public, internet-reachable, or unencrypted sensitive data."
      />

      {/* The heuristic caveat, served with the numbers. Classifications come from
          resource names and operator tags; nothing here reads object contents, and
          the page must not read as a scan result. */}
      <div className="mb-4 flex items-start gap-2 rounded-lg border border-border-subtle bg-surface-2 px-3 py-2 text-[11px] leading-relaxed text-text-3">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          {s?.caveat ??
            "Classifications are inferred from resource names and operator tags. Nothing here reads object contents, so an inferred class is a lead to verify, not a scan result."}
          {s && (
            <>
              {" "}
              <span className="text-text-2">
                {`${s.confidence.asserted} asserted (operator tag or resource type) · ` +
                  `${s.confidence.inferred} inferred from the resource name` +
                  (s.confidence.unknown > 0 ? ` · ${s.confidence.unknown} unrecorded` : "")}
              </span>
              .
            </>
          )}
        </span>
      </div>

      {/* Headline counts. Confirmed and possible exposure are separate tiles
          because they are separate facts; "exposed" now means a graph internet
          path, not "public OR exposed" (which was a superset of the public tile
          and doubled the apparent exposure). */}
      <div className="mb-2 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        <RiskTile label="Sensitive data stores" sub="buckets + databases, PII / PCI / health / financial"
          count={s?.stores.sensitive ?? 0}
          tone="border-purple-400/50 bg-purple-400/10 ring-purple-400/30"
          active={filter === "sensitive"} onClick={() => select("sensitive")} />
        <RiskTile label="Public — confirmed" sub="unauthenticated access observed"
          count={s?.exposure.public_confirmed ?? 0}
          tone="border-red/50 bg-red/10 ring-red/30"
          active={filter === "public-confirmed"} onClick={() => select("public-confirmed")} />
        <RiskTile label="Public — possible" sub="config permits it, nothing proved it"
          count={s?.exposure.public_possible ?? 0}
          tone="border-amber/50 bg-amber/10 ring-amber/30"
          active={filter === "public-possible"} onClick={() => select("public-possible")} />
        <RiskTile label="Internet-reachable" sub="a graph exposure path reaches it"
          count={s?.exposure.network_exposed ?? 0}
          tone="border-orange/50 bg-orange/10 ring-orange/30"
          active={filter === "network-exposed"} onClick={() => select("network-exposed")} />
        <RiskTile
          label="Unencrypted (S3 / RDS)"
          sub={s ? `observed off · ${s.encryption.coverage_pct}% of stores measured` : "observed off"}
          count={s?.encryption.unencrypted ?? 0}
          tone="border-amber/50 bg-amber/10 ring-amber/30"
          active={filter === "unencrypted"} onClick={() => select("unencrypted")} />
      </div>

      {/* Coverage row. These are measurement gaps, not risks — kept visible and
          visually separate so they are neither hidden nor mistaken for findings. */}
      <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <RiskTile label="Exposure unobserved" sub="public-access config unreadable"
          count={s?.exposure.public_unobserved ?? 0}
          tone="border-border-subtle bg-surface-2 ring-border-subtle"
          active={filter === "public-unobserved"} onClick={() => select("public-unobserved")} />
        <RiskTile label="Encryption unobserved" sub="not collected for this store type"
          count={s?.encryption.unknown ?? 0}
          tone="border-border-subtle bg-surface-2 ring-border-subtle"
          active={filter === "encryption-unknown"} onClick={() => select("encryption-unknown")} />
        <RiskTile label="Secret / vault entries" sub="credentials by resource type, not by inference"
          count={s?.stores.secret_vault ?? 0}
          tone="border-orange/50 bg-orange/10 ring-orange/30"
          active={filter === "secret-vault"} onClick={() => select("secret-vault")} />
        <RiskTile label="All classified" sub="every discovered data store"
          count={s?.stores.total ?? 0}
          tone="border-sky/50 bg-sky/10 ring-sky/30"
          active={filter === "all"} onClick={() => select("all")} />
      </div>

      <div className="mb-4 flex items-center gap-1 border-b border-border-subtle pb-0">
        <TabBtn active={tab === "risk"} onClick={() => setTab("risk")}>
          <Database className="h-3.5 w-3.5" />
          Data risk
          {items.length > 0 && <span className="ml-1 text-[11px] text-text-3">({items.length})</span>}
        </TabBtn>
        <TabBtn active={tab === "graph"} onClick={() => setTab("graph")}>
          <Network className="h-3.5 w-3.5" />
          Explore graph
        </TabBtn>
      </div>

      {tab === "risk" && (
        isLoading ? <Loading /> :
        isError ? (
          <div className="rounded-xl border border-border-subtle bg-surface p-10 text-center">
            <Database className="mx-auto mb-3 h-8 w-8 text-text-3 opacity-40" />
            <p className="text-xs font-medium text-text-2">Graph not ready</p>
            <p className="mt-1 text-xs text-text-3">Classification runs after a correlate sweep.</p>
          </div>
        ) : <DataList items={items} truncated={data?.truncated ?? false} onOpen={setSelectedAssetId} />
      )}
      {tab === "graph" && <DataGraph />}

      <AssetDetailPanel assetId={selectedAssetId} onClose={() => setSelectedAssetId(null)} />
    </div>
  );
}
