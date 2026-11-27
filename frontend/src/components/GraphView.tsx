import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  useNodesState,
  type Edge as RFEdge,
  type Node as RFNode,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useForceLayout } from "./graph/useForceLayout";
import { computeAttackPaths, type AttackPath } from "./graph/attackPaths";
import { edgeLabel, edgeType, shortenLabel, typeLabel } from "./graph/labels";
import { AttackPathPanel } from "./graph/AttackPathPanel";
import { NodeContextMenu, type MenuAction } from "./graph/NodeContextMenu";
import { NodePeekPanel } from "./graph/NodePeekPanel";
import { AssetNode } from "./graph/AssetNode";
import { RelationshipEdge } from "./graph/RelationshipEdge";
import { SUPER_PREFIX, degreeMap, pathToTarget, flatLayout, groupedLayout } from "./graph/layout";
import { GraphLegend } from "./graph/GraphLegend";
import { openAssistant } from "../lib/assistant";

// Custom node + edge registries — module-level for stable references.
const nodeTypes = { asset: AssetNode };
const edgeTypes = { relationship: RelationshipEdge };

// GraphLayout — how the canvas arranges connected nodes. "force" = physics
// (draggable, self-organising); "concentric" = BFS rings around a seed.
export type GraphLayout = "force" | "concentric";

// GraphView renders a small interactive asset/relationship graph. Layout is
// computed here — no force-engine dep. Two modes:
//   • flat    — concentric BFS rings around a center/seed node.
//   • grouped — one super-node per group (account/provider/type), click to expand
//               its members in place. Gives the tidy "products" overview instead
//               of a flat hairball.
// Callers pass normalized nodes/edges so it works for graph queries and blast radius.

export type GroupBy = "none" | "account" | "provider" | "type";

export type GraphViewNode = {
  id: string;
  label: string;
  sub?: string; // secondary line (type)
  risk?: number; // 0–100, drives the node colour + size
  provider?: string;
  account?: string; // account_id / project — grouping key
  findings?: number; // finding count, shown in the peek panel when known
  // Projected security signals (graph node properties) — drive the peek badges.
  exposed?: boolean;
  hasKev?: boolean;
  exploitable?: boolean;
  toxicCombo?: boolean;
};

export type GraphViewEdge = {
  source: string;
  target: string;
  label?: string; // edge_type
};

// sentinelEndpoint maps an edge whose endpoint the query didn't return (Ladybug emits
// an empty id) to the well-known sentinel node it points at, so the edge can still
// render. Today only internet-exposure edges have an unreturned endpoint.
function sentinelEndpoint(label?: string): string {
  const l = (label ?? "").toLowerCase();
  return l === "exposedtointernet" || l === "exposed_to_internet" ? "internet" : "";
}


export function GraphView({
  nodes: rawNodes,
  edges: rawEdges,
  centerId,
  height = 420,
  groupBy = "none",
  layout = "force",
  onNodeClick,
  onExpand,
  expandingId,
  onQueryFromNode,
}: {
  nodes: GraphViewNode[];
  edges: GraphViewEdge[];
  centerId?: string;
  height?: number;
  groupBy?: GroupBy;
  layout?: GraphLayout;
  onNodeClick?: (id: string) => void;
  // onExpand drills into a node's neighbourhood, merging it into the current
  // graph (Neo4j-Browser style). Wired to double-click and the peek "Expand".
  onExpand?: (id: string) => void;
  expandingId?: string | null;
  // onQueryFromNode lets the Cypher workbench build the next query from this
  // node — wired to "Explore →" in the peek panel.
  onQueryFromNode?: (id: string, name: string) => void;
}) {
  const [peek, setPeek] = useState<GraphViewNode | null>(null);
  const [edgePeek, setEdgePeek] = useState<{ type: string; src: string; dst: string } | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // In-graph filtering — refine the rendered result without re-querying.
  const [search, setSearch] = useState("");
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [signalFilter, setSignalFilter] = useState<"all" | "exposed" | "exploitable" | "kev" | "toxic" | "findings">("all");
  // Attack-path storytelling — computed client-side; walk a chain hop-by-hop.
  const [showPaths, setShowPaths] = useState(false);
  const [activePathId, setActivePathId] = useState<string | null>(null);
  const [stepIdx, setStepIdx] = useState(0);
  const [rfApi, setRfApi] = useState<ReactFlowInstance<RFNode, RFEdge> | null>(null);
  // Declutter: nodes hidden via the right-click menu, plus the menu's own state.
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [menu, setMenu] = useState<{ x: number; y: number; node: GraphViewNode } | null>(null);
  // Layout is switchable in-canvas (force ↔ concentric), seeded from the prop.
  const [layoutMode, setLayoutMode] = useState<GraphLayout>(layout);
  // Fullscreen — expand the canvas to fill the viewport.
  const [fullscreen, setFullscreen] = useState(false);

  // Exposure queries (…)-[:ExposedToInternet]->(:Asset {id:'internet'}) return the
  // asset + edge but not the internet sentinel, so Ladybug emits the edge with an
  // EMPTY endpoint. Route those to a synthetic "internet" node so the hub-and-spoke
  // renders instead of disconnected dots. Edges still missing an endpoint are dropped.
  const edges = useMemo<GraphViewEdge[]>(() => {
    return rawEdges
      .map((e) => {
        const label = e.label ? edgeType(e.label) : e.label;
        return { ...e, label, source: e.source || sentinelEndpoint(label), target: e.target || sentinelEndpoint(label) };
      })
      .filter((e) => e.source && e.target && e.source !== e.target);
  }, [rawEdges]);

  // Synthesize a placeholder node for any edge endpoint not in the result set
  // (e.g. the internet sentinel above), so ReactFlow doesn't silently drop the edge.
  const nodes = useMemo<GraphViewNode[]>(() => {
    const present = new Set(rawNodes.map((n) => n.id));
    const extra: GraphViewNode[] = [];
    for (const e of edges) {
      for (const id of [e.source, e.target]) {
        if (id && !present.has(id)) {
          present.add(id);
          extra.push({ id, label: id === "internet" ? "Internet" : id, sub: id === "internet" ? "external" : "" });
        }
      }
    }
    return extra.length > 0 ? [...rawNodes, ...extra] : rawNodes;
  }, [rawNodes, edges]);

  const deg = useMemo(() => degreeMap(edges), [edges]);

  const nodeById = useMemo(() => {
    const m = new Map<string, GraphViewNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  const grouped = useMemo(
    () => (groupBy === "none" ? null : groupedLayout(nodes, groupBy, expanded, deg)),
    [nodes, groupBy, expanded, deg],
  );

  // Force layout runs in a worker for connected, ungrouped graphs. Edgeless and
  // grouped results use the grid / super-node layouts instead.
  const forceEnabled = !grouped && layoutMode === "force" && edges.length > 0;
  const forcePos = useForceLayout(nodes, edges, forceEnabled);

  const computedNodes = useMemo(
    () => (grouped ? grouped.rfNodes : flatLayout(nodes, centerId, edges, deg, forceEnabled ? forcePos : undefined)),
    [grouped, nodes, centerId, edges, deg, forceEnabled, forcePos],
  );

  // Hold nodes in React Flow state so they're draggable; re-sync when the
  // computed layout changes (new query, expand, or force result). Dragging
  // mutates this state and persists until the next layout recompute.
  const [rfNodes, setRfNodes, onRfNodesChange] = useNodesState<RFNode>([]);

  // Track nodes the user explicitly dragged so their positions survive layout
  // recomputes (e.g. force worker finishing, expand adding new nodes). All other
  // nodes always receive the latest computed position: preserving every prior
  // position (including the initial BFS pass) would stop the force layout from
  // ever applying to nodes already on canvas.
  const userDraggedRef = useRef<Set<string>>(new Set());
  useEffect(() => { userDraggedRef.current = new Set(); }, [nodes]);

  useEffect(() => {
    setRfNodes((prev) => {
      const prevPos = new Map(prev.map((n) => [n.id, n.position]));
      return computedNodes.map((n) =>
        userDraggedRef.current.has(n.id) && prevPos.has(n.id)
          ? { ...n, position: prevPos.get(n.id)! }
          : n,
      );
    });
  }, [computedNodes, setRfNodes]);

  // A fresh result clears transient canvas state (hidden set + open menu) so
  // stale ids don't leak across queries.
  useEffect(() => { setHidden(new Set()); setMenu(null); }, [nodes]);

  // Auto-fit after a new query result loads. The force layout settles
  // asynchronously, so we wait ~500 ms before fitting. maxZoom 2.5 lets a small
  // result (a handful of nodes) zoom in enough to be readable instead of sitting
  // as specks under a lower cap; a large graph still fits at whatever zoom shows
  // all of it.
  useEffect(() => {
    if (!rfApi || nodes.length === 0) return;
    const id = setTimeout(() => rfApi.fitView({ padding: 0.25, maxZoom: 2.5, duration: 400 }), 500);
    return () => clearTimeout(id);
  }, [nodes, rfApi]);

  // Attack-path highlight only in flat mode (where individual nodes are visible).
  const highlight = useMemo(
    () => (peek && !grouped ? pathToTarget(peek.id, nodes, edges) : null),
    [peek, grouped, nodes, edges],
  );

  // Click-to-focus: when a node is selected, its 1-hop neighbourhood stays lit
  // and everything else dims — the core Neo4j "click a node, see its world" move.
  const focusSet = useMemo(() => {
    if (!peek || grouped) return null;
    const s = new Set<string>([peek.id]);
    for (const e of edges) {
      if (e.source === peek.id) s.add(e.target);
      if (e.target === peek.id) s.add(e.source);
    }
    return s;
  }, [peek, grouped, edges]);

  // Neighbours of the selected node, grouped for the peek panel's drill-down:
  // what it connects to, by relationship + direction. Pure graph data, no fetch.
  const peekNeighbours = useMemo(() => {
    if (!peek || grouped) return [];
    const out: { rel: string; dir: "out" | "in"; node: GraphViewNode }[] = [];
    for (const e of edges) {
      if (e.source === peek.id) {
        const nb = nodeById.get(e.target);
        if (nb) out.push({ rel: e.label ?? "", dir: "out", node: nb });
      } else if (e.target === peek.id) {
        const nb = nodeById.get(e.source);
        if (nb) out.push({ rel: e.label ?? "", dir: "in", node: nb });
      }
    }
    return out;
  }, [peek, grouped, edges, nodeById]);

  // Candidate attack paths (internet-exposed → admin/high-risk), computed from
  // the rendered subgraph. Only meaningful in flat mode. The baseline ignores
  // hidden nodes; the live set respects break-the-chain so we can report how
  // many paths a hidden node eliminated.
  const baselineAttackPaths = useMemo(
    () => (grouped ? [] : computeAttackPaths(nodes, edges)),
    [grouped, nodes, edges],
  );
  const attackPaths = useMemo(
    () => (grouped ? [] : hidden.size > 0 ? computeAttackPaths(nodes, edges, hidden) : baselineAttackPaths),
    [grouped, nodes, edges, hidden, baselineAttackPaths],
  );
  const activePath = useMemo<AttackPath | null>(
    () => attackPaths.find((p) => p.id === activePathId) ?? null,
    [attackPaths, activePathId],
  );

  // When a path is active it takes over the highlight + focus from peek so the
  // whole chain lights up and everything else dims.
  const pathNodeIds = useMemo(
    () => (activePath ? new Set(activePath.hops.map((h) => h.id)) : null),
    [activePath],
  );
  const effectiveHighlight = activePath ? { nodeIds: pathNodeIds!, edgeKeys: activePath.edgeKeys } : highlight;
  const effectiveFocus = pathNodeIds ?? focusSet;

  // Fly the viewport to a hop as the user steps through a path.
  function flyToHop(path: AttackPath, idx: number) {
    const hop = path.hops[idx];
    const pos = rfNodes.find((n) => n.id === hop?.id)?.position;
    if (pos && rfApi) rfApi.setCenter(pos.x, pos.y, { zoom: 1.1, duration: 500 });
  }

  function selectPath(p: AttackPath) {
    setPeek(null);
    setActivePathId(p.id);
    setStepIdx(0);
    rfApi?.fitView({ nodes: p.hops.map((h) => ({ id: h.id })), padding: 0.2, maxZoom: 1.2, duration: 1200 });
  }

  function clearPath() {
    setActivePathId(null);
    setStepIdx(0);
    rfApi?.fitView({ padding: 0.2, duration: 400 });
  }

  function hideNode(id: string) {
    setHidden((prev) => new Set(prev).add(id));
    if (peek?.id === id) setPeek(null);
  }

  // Isolate: hide everything except this node and its 1-hop neighbours, so a
  // busy graph collapses to "just this thing and what it touches".
  function isolateNode(id: string) {
    const keep = new Set([id]);
    for (const e of edges) {
      if (e.source === id) keep.add(e.target);
      if (e.target === id) keep.add(e.source);
    }
    setHidden(new Set(nodes.filter((n) => !keep.has(n.id)).map((n) => n.id)));
    setPeek(null);
  }

  // Keyboard shortcuts (Neo4j-Browser parity): Esc clears selection/menu,
  // f fits the view. Ignored while typing in the filter box.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target;
      if (t instanceof HTMLElement && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) return;
      if (e.key === "Escape") {
        if (menu) setMenu(null);
        else if (fullscreen) setFullscreen(false);
        else { setPeek(null); setActivePathId(null); }
      } else if (e.key === "f" || e.key === "F") rfApi?.fitView({ padding: 0.2, duration: 400 });
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [rfApi, menu, fullscreen]);

  // Refit when entering/leaving fullscreen so the graph fills the new size.
  //
  // The timer MUST be cleared on unmount. Without cleanup it still fires 60ms
  // after the component is gone and calls fitView on a torn-down React tree —
  // which React Flow turns into a setState-on-unmounted error. In tests that
  // surfaces as a failure attributed to whichever spec happens to be running
  // (e.g. AssetDetail.test.tsx), so it looks like a flake.
  useEffect(() => {
    if (!rfApi) return;
    const t = setTimeout(() => rfApi.fitView({ padding: 0.2, duration: 300 }), 60);
    return () => clearTimeout(t);
  }, [fullscreen, rfApi]);

  // Types present in the current result — drives the filter chips.
  const typesPresent = useMemo(() => {
    const s = new Set<string>();
    for (const n of nodes) if (n.sub) s.add(n.sub);
    return [...s].sort();
  }, [nodes]);

  const filterActive = search.trim() !== "" || hiddenTypes.size > 0 || signalFilter !== "all";

  const matchesFilter = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (n: GraphViewNode | undefined): boolean => {
      if (!n) return true;
      if (n.sub && hiddenTypes.has(n.sub)) return false;
      if (q && !(n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q))) return false;
      switch (signalFilter) {
        case "exposed": return !!n.exposed;
        case "exploitable": return !!n.exploitable;
        case "kev": return !!n.hasKev;
        case "toxic": return !!n.toxicCombo;
        case "findings": return (n.findings ?? 0) > 0 || (n.risk ?? 0) > 0;
        default: return true;
      }
    };
  }, [search, hiddenTypes, signalFilter]);

  // Apply focus + filter dimming to node opacity without recomputing positions
  // (so drags survive). Hidden nodes (right-click → Hide) are dropped entirely.
  const displayNodes = useMemo(() => {
    const base = hidden.size > 0 ? rfNodes.filter((n) => !hidden.has(n.id)) : rfNodes;
    if (!effectiveFocus && !filterActive) return base;
    return base.map((n) => {
      const passes = matchesFilter(nodeById.get(n.id));
      const focused = !effectiveFocus || effectiveFocus.has(n.id);
      const opacity = !passes ? 0.05 : focused ? 1 : 0.1;
      return { ...n, selected: n.id === peek?.id, style: { ...n.style, opacity } };
    });
  }, [rfNodes, hidden, effectiveFocus, filterActive, matchesFilter, nodeById, peek]);

  const rfEdges = useMemo<RFEdge[]>(() => {
    // In grouped mode, route each edge through the visible representative and
    // drop intra-group self-loops; dedupe parallel group↔group edges.
    const seen = new Set<string>();
    const out: RFEdge[] = [];
    edges.forEach((e, i) => {
      if (hidden.has(e.source) || hidden.has(e.target)) return;
      const src = grouped ? grouped.rep.get(e.source) : e.source;
      const dst = grouped ? grouped.rep.get(e.target) : e.target;
      if (!src || !dst || src === dst) return;
      const key = `${src}->${dst}-${e.label ?? ""}`;
      if (grouped) {
        if (seen.has(key)) return;
        seen.add(key);
      }
      const isPrivilege = e.label === "can_assume" || e.label === "can_escalate" || e.label === "can_escalate_to" || e.label === "executes_as" || e.label === "deploys_to";
      const isExposed = e.label === "exposed_to_internet";
      const isProtect = e.label === "protected_by";
      const edgeKey = `${e.source}->${e.target}-${i}`;
      const onPath = effectiveHighlight?.edgeKeys.has(edgeKey) ?? false;
      // Dim edges not on the attack path, or (on plain select) edges that don't
      // touch the focused node.
      const offFocus = focusSet != null && e.source !== peek?.id && e.target !== peek?.id;
      const dimmed = (effectiveHighlight != null && !onPath) || (effectiveHighlight == null && offFocus);
      const baseColor = isExposed ? "#f87171" : isPrivilege ? "#2dd4bf" : isProtect ? "#fbbf24" : "#3f3f46";
      // Show labels only for the selected node's edges or path edges — keeps the
      // canvas clean instead of a fog of always-on 8px text.
      const showLabel = !grouped && (onPath || (peek != null && (e.source === peek.id || e.target === peek.id)));
      const strokeColor = onPath ? "#f0abfc" : baseColor;
      const strokeWidth = onPath ? 5 : isExposed || isPrivilege ? 1.5 : 1;
      out.push({
        id: edgeKey,
        source: src,
        target: dst,
        type: "relationship",
        label: showLabel && e.label ? edgeLabel(e.label) : undefined,
        animated: false, // animation on custom edges would need CSS; keep clean
        data: { onPath },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: onPath ? 14 : 8,
          height: onPath ? 14 : 8,
          color: dimmed ? `${strokeColor}26` : strokeColor,
        },
        style: {
          stroke: strokeColor,
          strokeWidth,
          opacity: dimmed ? 0.05 : onPath ? 1 : 0.75,
        },
      });
    });
    return out;
  }, [edges, grouped, hidden, effectiveHighlight, peek, focusSet]);


  function handleNodeClick(_: unknown, rfNode: { id: string }) {
    setEdgePeek(null); // clear edge selection when clicking a node
    if (rfNode.id.startsWith(SUPER_PREFIX)) {
      const key = rfNode.id.slice(SUPER_PREFIX.length);
      setExpanded((prev) => {
        const next = new Set(prev);
        next.has(key) ? next.delete(key) : next.add(key);
        return next;
      });
      return;
    }
    const node = nodeById.get(rfNode.id);
    if (node) {
      setActivePathId(null);
      setPeek((p) => (p?.id === node.id ? null : node));
    }
  }

  function handleEdgeClick(_: unknown, rfEdge: { id: string; source: string; target: string; label?: unknown }) {
    setPeek(null);
    const edgeType = (rfEdge.label as string | undefined) || edges.find(e => e.source === rfEdge.source && e.target === rfEdge.target)?.label || "";
    const src = nodeById.get(rfEdge.source);
    const dst = nodeById.get(rfEdge.target);
    setEdgePeek({
      type: edgeType,
      src: src?.label || rfEdge.source,
      dst: dst?.label || rfEdge.target,
    });
  }

  function handleNodeDoubleClick(_: unknown, rfNode: { id: string }) {
    if (rfNode.id.startsWith(SUPER_PREFIX) || !onExpand) return;
    onExpand(rfNode.id);
  }

  function handleNodeContextMenu(e: ReactMouseEvent, rfNode: { id: string }) {
    e.preventDefault();
    if (rfNode.id.startsWith(SUPER_PREFIX)) return;
    const node = nodeById.get(rfNode.id);
    if (node) setMenu({ x: e.clientX, y: e.clientY, node });
  }

  const signalFilters: { value: typeof signalFilter; label: string }[] = [
    { value: "all", label: "All" },
    { value: "exposed", label: "Exposed" },
    { value: "exploitable", label: "Exploitable" },
    { value: "kev", label: "KEV" },
    { value: "toxic", label: "Toxic" },
    { value: "findings", label: "Has findings" },
  ];

  return (
    <div className={fullscreen ? "fixed inset-0 z-50 flex flex-col bg-bg p-3" : "relative"}>
      {/* In-graph filter bar — refine the rendered result without re-querying. */}
      {!grouped && nodes.length > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter nodes by name…"
            className="w-44 rounded border border-border-subtle bg-bg px-2 py-1 text-[11px] text-text outline-none focus:border-teal"
          />
          <div className="flex items-center gap-1">
            {signalFilters.map((s) => (
              <button key={s.value} onClick={() => setSignalFilter(s.value)}
                className={`rounded px-1.5 py-0.5 text-[11px] ${signalFilter === s.value ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}>
                {s.label}
              </button>
            ))}
          </div>
          {typesPresent.length > 1 && (
            <div className="flex flex-wrap items-center gap-1">
              <span className="text-[11px] uppercase text-text-3">types</span>
              {typesPresent.map((t) => {
                const hidden = hiddenTypes.has(t);
                return (
                  <button key={t} onClick={() => setHiddenTypes((prev) => { const n = new Set(prev); n.has(t) ? n.delete(t) : n.add(t); return n; })}
                    className={`rounded border px-1.5 py-0.5 text-[11px] ${hidden ? "border-border-subtle text-text-3 line-through" : "border-teal/30 bg-teal/10 text-text-2"}`}>
                    {typeLabel(t)}
                  </button>
                );
              })}
            </div>
          )}
          {filterActive && (
            <button onClick={() => { setSearch(""); setHiddenTypes(new Set()); setSignalFilter("all"); }}
              className="text-[11px] text-text-3 underline hover:text-text-2">clear</button>
          )}
          <div className="ml-auto flex items-center gap-1.5">
            <button onClick={() => setFullscreen((v) => !v)} title={fullscreen ? "Exit fullscreen (Esc)" : "Fullscreen"}
              className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] text-text-2 hover:bg-surface-3">
              {fullscreen ? "⤢ Exit" : "⛶ Fullscreen"}
            </button>
            {hidden.size > 0 && (
              <button onClick={() => setHidden(new Set())}
                className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] text-amber hover:bg-amber/20">
                {hidden.size} hidden · restore
              </button>
            )}
            {edges.length > 0 && (
              <div className="flex items-center gap-0.5 rounded border border-border-subtle p-0.5">
                {(["force", "concentric"] as GraphLayout[]).map((l) => (
                  <button key={l} onClick={() => setLayoutMode(l)}
                    className={`rounded px-1.5 py-0.5 text-[11px] capitalize ${layoutMode === l ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}>
                    {l}
                  </button>
                ))}
              </div>
            )}
            {attackPaths.length > 0 && (
              <button
                onClick={() => { setShowPaths((v) => !v); if (showPaths) clearPath(); }}
                className={`rounded border px-2 py-0.5 text-[11px] font-medium ${showPaths ? "border-fuchsia-400/50 bg-fuchsia-400/15 text-fuchsia-300" : "border-fuchsia-400/30 text-fuchsia-300/80 hover:bg-fuchsia-400/10"}`}>
                ⚡ Attack paths ({attackPaths.length})
              </button>
            )}
          </div>
        </div>
      )}
      <div style={fullscreen ? undefined : { height }} className={`relative rounded-lg border border-border-subtle bg-surface-2 ${fullscreen ? "min-h-0 flex-1" : ""}`}>
        <ReactFlow
          nodes={displayNodes}
          edges={rfEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={onRfNodesChange}
          onInit={setRfApi}
          fitView
          fitViewOptions={{ padding: 0.25, maxZoom: 2.5 }}
          minZoom={0.2}
          proOptions={{ hideAttribution: true }}
          nodesDraggable={!grouped}
          nodesConnectable={false}
          onNodeClick={handleNodeClick}
          onNodeDoubleClick={handleNodeDoubleClick}
          onNodeContextMenu={handleNodeContextMenu}
          onEdgeClick={handleEdgeClick}
          onNodeDragStop={(_, node) => { userDraggedRef.current.add(node.id); }}
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="var(--graph-border-2)" />
          <Controls showInteractive={false} />
          <MiniMap
            pannable
            zoomable
            nodeColor={(n) => (n.style?.background as string) ?? "var(--graph-surface-4)"}
            maskColor="var(--graph-panel-bg)"
            style={{ background: "var(--graph-surface)", border: "1px solid var(--graph-border)" }}
          />
        </ReactFlow>

      {(grouped || onExpand) && !showPaths && (
        <div className="absolute left-2 top-2 z-10 rounded border border-border-subtle bg-bg/90 px-2 py-1 text-[11px] text-text-3 backdrop-blur-sm">
          {grouped ? "Click a group to expand its assets" : "Drag to arrange · double-click to expand · right-click for actions · F to fit"}
        </div>
      )}

      {/* Attack-path walkthrough — list candidate chains, step through one. */}
      {showPaths && attackPaths.length > 0 && (
        <AttackPathPanel
          paths={attackPaths}
          activePath={activePath}
          stepIdx={stepIdx}
          eliminated={baselineAttackPaths.length - attackPaths.length}
          baselineCount={baselineAttackPaths.length}
          onSelect={selectPath}
          onClear={clearPath}
          onStep={(i) => { setStepIdx(i); if (activePath) flyToHop(activePath, i); }}
          onBreak={(id) => { hideNode(id); setActivePathId(null); }}
          onRestore={hidden.size > 0 ? () => setHidden(new Set()) : undefined}
          onClose={() => { setShowPaths(false); clearPath(); }}
        />
      )}

      {/* Right-click context menu — the core "do something with this node" surface. */}
      {menu && (
        <NodeContextMenu
          x={menu.x}
          y={menu.y}
          title={shortenLabel(menu.node.label)}
          actions={[
            ...(onExpand ? [{ label: "⊕ Expand neighbours", onClick: () => onExpand(menu.node.id) }] : []),
            { label: "◎ Focus neighbourhood", onClick: () => { setActivePathId(null); setPeek(menu.node); } },
            { label: "⤢ Isolate (hide others)", onClick: () => isolateNode(menu.node.id) },
            {
              label: "✦ Ask AI about this node",
              onClick: () => {
                const n = menu.node;
                const facts = [`Type: ${n.sub ?? "unknown"}`];
                if (n.risk != null && n.risk > 0) facts.push(`Risk score: ${n.risk}`);
                if (n.exposed) facts.push("internet-exposed");
                if (n.hasKev) facts.push("KEV vulnerability");
                if (n.exploitable) facts.push("exploitable");
                if (n.toxicCombo) facts.push("toxic combo");
                if (n.findings != null && n.findings > 0) facts.push(`${n.findings} findings`);
                openAssistant({
                  subject: `Asset: ${n.label}`,
                  facts,
                  question: "What is the risk and what attack paths lead from or to this asset?",
                });
              },
            },
            { label: "✕ Hide node", onClick: () => hideNode(menu.node.id), danger: true },
            ...(onNodeClick ? [{ label: "→ Open asset", onClick: () => onNodeClick(menu.node.id) }] : []),
          ] as MenuAction[]}
          onClose={() => setMenu(null)}
        />
      )}

      {/* Node peek panel — shows key facts inline, no navigation required */}
      {peek && (
        <NodePeekPanel
          node={peek}
          degree={deg.get(peek.id) ?? 0}
          neighbours={peekNeighbours}
          pathHighlighted={highlight != null}
          expanding={expandingId === peek.id}
          onNeighbourClick={(nid) => { const nb = nodeById.get(nid); if (nb) { setActivePathId(null); setPeek(nb); } }}
          onExpand={onExpand ? () => onExpand(peek.id) : undefined}
          onOpen={onNodeClick ? () => { onNodeClick(peek.id); setPeek(null); } : undefined}
          onQueryFromNode={onQueryFromNode ? () => { onQueryFromNode(peek.id, peek.label); setPeek(null); } : undefined}
          onClose={() => setPeek(null)}
        />
      )}

      {/* Edge peek — click a relationship to see its type and endpoints */}
      {edgePeek && (
        <div className="absolute right-2 top-2 z-10 w-64 rounded-lg border border-teal/30 bg-bg/95 p-3 shadow-lg backdrop-blur-sm">
          <div className="mb-2 flex items-start justify-between">
            <span className="rounded bg-teal/10 px-2 py-0.5 text-[11px] font-medium text-teal">{edgePeek.type || "relationship"}</span>
            <button onClick={() => setEdgePeek(null)} className="text-[11px] text-text-3 hover:text-text-2">✕</button>
          </div>
          <div className="space-y-1 text-[11px]">
            <div className="flex items-center gap-1.5 text-text-3">
              <span className="shrink-0 text-text-2 font-medium">From</span>
              <span className="truncate text-text-2" title={edgePeek.src}>{shortenLabel(edgePeek.src)}</span>
            </div>
            <div className="flex items-center gap-1.5 text-text-3">
              <span className="shrink-0 text-text-2 font-medium">To</span>
              <span className="truncate text-text-2" title={edgePeek.dst}>{shortenLabel(edgePeek.dst)}</span>
            </div>
          </div>
        </div>
      )}

      {!grouped && nodes.length > 0 && <GraphLegend />}
      </div>
    </div>
  );
}
